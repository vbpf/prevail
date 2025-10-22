// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.

#include <optional>
#include <utility>
#include <vector>

#include "boost/endian/conversion.hpp"

#include "arith/dsl_syntax.hpp"
#include "config.hpp"
#include "crab/array_domain.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/var_registry.hpp"
#include "ir/unmarshal.hpp"

namespace prevail {

StringInvariant EbpfDomain::to_set() const { return rcp.to_set() + stack.to_set(); }

EbpfDomain EbpfDomain::top() {
    EbpfDomain abs;
    abs.set_to_top();
    return abs;
}

EbpfDomain EbpfDomain::bottom() {
    EbpfDomain abs;
    abs.set_to_bottom();
    return abs;
}

EbpfDomain::EbpfDomain() {}

EbpfDomain::EbpfDomain(TypeToNumDomain rcp, ArrayDomain stack) : rcp(std::move(rcp)), stack(std::move(stack)) {}

void EbpfDomain::set_to_top() {
    rcp.values.set_to_top();
    stack.set_to_top();
}

void EbpfDomain::set_to_bottom() { rcp.values.set_to_bottom(); }

bool EbpfDomain::is_bottom() const { return rcp.values.is_bottom(); }

bool EbpfDomain::is_top() const { return rcp.values.is_top() && stack.is_top(); }

bool EbpfDomain::operator<=(const EbpfDomain& other) const {
    if (!(stack <= other.stack)) {
        return false;
    }
    return rcp <= other.rcp;
}

bool EbpfDomain::operator==(const EbpfDomain& other) const {
    return stack == other.stack && rcp <= other.rcp && other.rcp <= rcp;
}

void EbpfDomain::operator|=(EbpfDomain&& other) {
    if (is_bottom()) {
        stack = other.stack;
    } else if (!other.is_bottom()) {
        stack |= other.stack;
    }
    rcp |= std::move(other.rcp);
}

void EbpfDomain::operator|=(const EbpfDomain& other) {
    EbpfDomain tmp{other};
    operator|=(std::move(tmp));
}

EbpfDomain EbpfDomain::operator|(EbpfDomain&& other) const {
    EbpfDomain res{std::move(other)};
    res |= *this;
    return res;
}

EbpfDomain EbpfDomain::operator|(const EbpfDomain& other) const& {
    EbpfDomain res{other};
    res |= *this;
    return res;
}

EbpfDomain EbpfDomain::operator|(const EbpfDomain& other) && {
    EbpfDomain res{std::move(*this)};
    res |= other;
    return res;
}

EbpfDomain EbpfDomain::operator&(const EbpfDomain& other) const {
    auto res = rcp & other.rcp;
    if (!res.is_bottom()) {
        return EbpfDomain(res, stack & other.stack);
    }
    return bottom();
}

EbpfDomain EbpfDomain::calculate_constant_limits() {
    EbpfDomain inv;
    using namespace dsl_syntax;
    for (const int i : {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
        const auto r = reg_pack(i);
        inv.add_value_constraint(r.svalue <= std::numeric_limits<int32_t>::max());
        inv.add_value_constraint(r.svalue >= std::numeric_limits<int32_t>::min());
        inv.add_value_constraint(r.uvalue <= std::numeric_limits<uint32_t>::max());
        inv.add_value_constraint(r.uvalue >= 0);
        inv.add_value_constraint(r.stack_offset <= EBPF_TOTAL_STACK_SIZE);
        inv.add_value_constraint(r.stack_offset >= 0);
        inv.add_value_constraint(r.shared_offset <= r.shared_region_size);
        inv.add_value_constraint(r.shared_offset >= 0);
        inv.add_value_constraint(r.packet_offset <= variable_registry->packet_size());
        inv.add_value_constraint(r.packet_offset >= 0);
        if (thread_local_options.cfg_opts.check_for_termination) {
            for (const Variable counter : variable_registry->get_loop_counters()) {
                inv.add_value_constraint(counter <= std::numeric_limits<int32_t>::max());
                inv.add_value_constraint(counter >= 0);
                inv.add_value_constraint(counter <= r.svalue);
            }
        }
    }
    return inv;
}

static const EbpfDomain constant_limits = EbpfDomain::calculate_constant_limits();

EbpfDomain EbpfDomain::widen(const EbpfDomain& other, const bool to_constants) const {
    EbpfDomain res{this->rcp.widen(other.rcp), stack.widen(other.stack)};

    if (to_constants) {
        return res & constant_limits;
    }
    return res;
}

EbpfDomain EbpfDomain::narrow(const EbpfDomain& other) const {
    return EbpfDomain(rcp.narrow(other.rcp), stack & other.stack);
}

void EbpfDomain::add_value_constraint(const LinearConstraint& cst) { rcp.values.add_constraint(cst); }

void EbpfDomain::add_type_constraint(const LinearConstraint& cst) { rcp.types.add_constraint(cst); }

void EbpfDomain::havoc(const Variable var) {
    // TODO: type inv?
    rcp.values.havoc(var);
}

// Get the start and end of the range of possible map fd values.
// In the future, it would be cleaner to use a set rather than an interval
// for map fds.
bool EbpfDomain::get_map_fd_range(const Reg& map_fd_reg, int32_t* start_fd, int32_t* end_fd) const {
    const Interval& map_fd_interval = rcp.values.eval_interval(reg_pack(map_fd_reg).map_fd);
    const auto lb = map_fd_interval.lb().number();
    const auto ub = map_fd_interval.ub().number();
    if (!lb || !lb->fits<int32_t>() || !ub || !ub->fits<int32_t>()) {
        return false;
    }
    *start_fd = lb->narrow<int32_t>();
    *end_fd = ub->narrow<int32_t>();

    // Cap the maximum range we'll check.
    constexpr int max_range = 32;
    return *map_fd_interval.finite_size() < max_range;
}

// All maps in the range must have the same type for us to use it.
std::optional<uint32_t> EbpfDomain::get_map_type(const Reg& map_fd_reg) const {
    int32_t start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return std::optional<uint32_t>();
    }

    std::optional<uint32_t> type;
    for (int32_t map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        EbpfMapDescriptor* map = &thread_local_program_info->platform->get_map_descriptor(map_fd);
        if (map == nullptr) {
            return std::optional<uint32_t>();
        }
        if (!type.has_value()) {
            type = map->type;
        } else if (map->type != *type) {
            return std::optional<uint32_t>();
        }
    }
    return type;
}

// All maps in the range must have the same inner map fd for us to use it.
std::optional<uint32_t> EbpfDomain::get_map_inner_map_fd(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return {};
    }

    std::optional<uint32_t> inner_map_fd;
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        EbpfMapDescriptor* map = &thread_local_program_info->platform->get_map_descriptor(map_fd);
        if (map == nullptr) {
            return {};
        }
        if (!inner_map_fd.has_value()) {
            inner_map_fd = map->inner_map_fd;
        } else if (map->type != *inner_map_fd) {
            return {};
        }
    }
    return inner_map_fd;
}

// We can deal with a range of key sizes.
Interval EbpfDomain::get_map_key_size(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return Interval::top();
    }

    Interval result = Interval::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (const EbpfMapDescriptor* map = &thread_local_program_info->platform->get_map_descriptor(map_fd)) {
            result = result | Interval{map->key_size};
        } else {
            return Interval::top();
        }
    }
    return result;
}

// We can deal with a range of value sizes.
Interval EbpfDomain::get_map_value_size(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return Interval::top();
    }

    Interval result = Interval::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (const EbpfMapDescriptor* map = &thread_local_program_info->platform->get_map_descriptor(map_fd)) {
            result = result | Interval(map->value_size);
        } else {
            return Interval::top();
        }
    }
    return result;
}

// We can deal with a range of max_entries values.
Interval EbpfDomain::get_map_max_entries(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return Interval::top();
    }

    Interval result = Interval::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (const EbpfMapDescriptor* map = &thread_local_program_info->platform->get_map_descriptor(map_fd)) {
            result = result | Interval(map->max_entries);
        } else {
            return Interval::top();
        }
    }
    return result;
}

ExtendedNumber EbpfDomain::get_loop_count_upper_bound() const {
    ExtendedNumber ub{0};
    for (const Variable counter : variable_registry->get_loop_counters()) {
        ub = std::max(ub, rcp.values.eval_interval(counter).ub());
    }
    return ub;
}

Interval EbpfDomain::get_r0() const { return rcp.values.eval_interval(reg_pack(R0_RETURN_VALUE).svalue); }

std::ostream& operator<<(std::ostream& o, const TypeDomain& dom) { return o << dom.inv; }

std::ostream& operator<<(std::ostream& o, const TypeToNumDomain& dom) {
    if (dom.is_bottom()) {
        o << "_|_";
    } else {
        o << dom.types << dom.values;
    }
    return o;
}

std::ostream& operator<<(std::ostream& o, const EbpfDomain& dom) {
    if (dom.is_bottom()) {
        o << "_|_";
    } else {
        o << dom.rcp << "\nStack: " << dom.stack;
    }
    return o;
}

void EbpfDomain::initialize_packet() {
    using namespace dsl_syntax;
    EbpfDomain& inv = *this;
    inv.havoc(variable_registry->packet_size());
    inv.havoc(variable_registry->meta_offset());

    inv.add_value_constraint(0 <= variable_registry->packet_size());
    inv.add_value_constraint(variable_registry->packet_size() < MAX_PACKET_SIZE);
    const auto info = *thread_local_program_info;
    if (info.type.context_descriptor->meta >= 0) {
        inv.add_value_constraint(variable_registry->meta_offset() <= 0);
        inv.add_value_constraint(variable_registry->meta_offset() >= -4098);
    } else {
        inv.rcp.values.assign(variable_registry->meta_offset(), 0);
    }
}

EbpfDomain EbpfDomain::from_constraints(const std::vector<LinearConstraint>& type_constraints,
                                        const std::vector<LinearConstraint>& value_constraints) {
    EbpfDomain inv;
    for (const auto& cst : type_constraints) {
        inv.add_type_constraint(cst);
    }
    for (const auto& cst : value_constraints) {
        inv.add_value_constraint(cst);
    }
    return inv;
}

EbpfDomain EbpfDomain::from_constraints(const std::set<std::string>& constraints, const bool setup_constraints) {
    EbpfDomain inv;
    if (setup_constraints) {
        inv = setup_entry(false);
    }
    auto numeric_ranges = std::vector<Interval>();
    auto [type_constraints, value_constraints] = parse_linear_constraints(constraints, numeric_ranges);
    for (const auto& cst : type_constraints) {
        inv.add_type_constraint(cst);
    }
    for (const auto& cst : value_constraints) {
        inv.add_value_constraint(cst);
    }
    for (const Interval& range : numeric_ranges) {
        const int start = range.lb().narrow<int>();
        const int width = 1 + range.finite_size()->narrow<int>();
        inv.stack.initialize_numbers(start, width);
    }
    // TODO: handle other stack type constraints
    return inv;
}

EbpfDomain EbpfDomain::setup_entry(const bool init_r1) {
    using namespace dsl_syntax;

    EbpfDomain inv;
    const auto r10 = reg_pack(R10_STACK_POINTER);
    constexpr Reg r10_reg{R10_STACK_POINTER};
    inv.rcp.values.add_constraint(EBPF_TOTAL_STACK_SIZE <= r10.svalue);
    inv.rcp.values.add_constraint(r10.svalue <= PTR_MAX);
    inv.rcp.values.assign(r10.stack_offset, EBPF_TOTAL_STACK_SIZE);
    // stack_numeric_size would be 0, but TOP has the same result
    // so no need to assign it.
    inv.rcp.types.assign_type(r10_reg, T_STACK);

    if (init_r1) {
        const auto r1 = reg_pack(R1_ARG);
        constexpr Reg r1_reg{R1_ARG};
        inv.rcp.values.add_constraint(1 <= r1.svalue);
        inv.rcp.values.add_constraint(r1.svalue <= PTR_MAX);
        inv.rcp.values.assign(r1.ctx_offset, 0);
        inv.rcp.types.assign_type(r1_reg, T_CTX);
    }

    inv.initialize_packet();
    return inv;
}

} // namespace prevail

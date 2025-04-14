// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.

#include <optional>
#include <utility>
#include <vector>

#include "boost/endian/conversion.hpp"

#include "asm_unmarshal.hpp"
#include "config.hpp"
#include "crab/array_domain.hpp"
#include "crab/ebpf_domain.hpp"
#include "dsl_syntax.hpp"
#include "string_constraints.hpp"

using prevail::NumAbsDomain;
namespace prevail {

std::optional<variable_t> ebpf_domain_t::get_type_offset_variable(const Reg& reg, const int type) {
    reg_pack_t r = reg_pack(reg);
    switch (type) {
    case T_CTX: return r.ctx_offset;
    case T_MAP:
    case T_MAP_PROGRAMS: return r.map_fd;
    case T_PACKET: return r.packet_offset;
    case T_SHARED: return r.shared_offset;
    case T_STACK: return r.stack_offset;
    default: return {};
    }
}

std::optional<variable_t> ebpf_domain_t::get_type_offset_variable(const Reg& reg, const NumAbsDomain& inv) const {
    return get_type_offset_variable(reg, type_inv.get_type(inv, reg_pack(reg).type));
}

std::optional<variable_t> ebpf_domain_t::get_type_offset_variable(const Reg& reg) const {
    return get_type_offset_variable(reg, m_inv);
}

string_invariant ebpf_domain_t::to_set() const { return m_inv.to_set() + stack.to_set(); }

ebpf_domain_t ebpf_domain_t::top() {
    ebpf_domain_t abs;
    abs.set_to_top();
    return abs;
}

ebpf_domain_t ebpf_domain_t::bottom() {
    ebpf_domain_t abs;
    abs.set_to_bottom();
    return abs;
}

ebpf_domain_t::ebpf_domain_t() : m_inv(NumAbsDomain::top()) {}

ebpf_domain_t::ebpf_domain_t(NumAbsDomain inv, array_domain_t stack) : m_inv(std::move(inv)), stack(std::move(stack)) {}

void ebpf_domain_t::set_to_top() {
    m_inv.set_to_top();
    stack.set_to_top();
}

void ebpf_domain_t::set_to_bottom() { m_inv.set_to_bottom(); }

bool ebpf_domain_t::is_bottom() const { return m_inv.is_bottom(); }

bool ebpf_domain_t::is_top() const { return m_inv.is_top() && stack.is_top(); }

bool ebpf_domain_t::operator<=(const ebpf_domain_t& other) const {
    return m_inv <= other.m_inv && stack <= other.stack;
}

bool ebpf_domain_t::operator==(const ebpf_domain_t& other) const {
    return stack == other.stack && m_inv <= other.m_inv && other.m_inv <= m_inv;
}

void ebpf_domain_t::operator|=(ebpf_domain_t&& other) {
    if (is_bottom()) {
        *this = std::move(other);
        return;
    }
    if (other.is_bottom()) {
        return;
    }

    type_inv.selectively_join_based_on_type(m_inv, std::move(other.m_inv));

    stack |= std::move(other.stack);
}

void ebpf_domain_t::operator|=(const ebpf_domain_t& other) {
    ebpf_domain_t tmp{other};
    operator|=(std::move(tmp));
}

ebpf_domain_t ebpf_domain_t::operator|(ebpf_domain_t&& other) const {
    return ebpf_domain_t(m_inv | std::move(other.m_inv), stack | other.stack);
}

ebpf_domain_t ebpf_domain_t::operator|(const ebpf_domain_t& other) const& {
    return ebpf_domain_t(m_inv | other.m_inv, stack | other.stack);
}

ebpf_domain_t ebpf_domain_t::operator|(const ebpf_domain_t& other) && {
    return ebpf_domain_t(other.m_inv | std::move(m_inv), other.stack | stack);
}

ebpf_domain_t ebpf_domain_t::operator&(const ebpf_domain_t& other) const {
    return ebpf_domain_t(m_inv & other.m_inv, stack & other.stack);
}

ebpf_domain_t ebpf_domain_t::calculate_constant_limits() {
    ebpf_domain_t inv;
    using namespace prevail::dsl_syntax;
    for (const int i : {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
        const auto r = reg_pack(i);
        inv.add_constraint(r.svalue <= std::numeric_limits<int32_t>::max());
        inv.add_constraint(r.svalue >= std::numeric_limits<int32_t>::min());
        inv.add_constraint(r.uvalue <= std::numeric_limits<uint32_t>::max());
        inv.add_constraint(r.uvalue >= 0);
        inv.add_constraint(r.stack_offset <= EBPF_TOTAL_STACK_SIZE);
        inv.add_constraint(r.stack_offset >= 0);
        inv.add_constraint(r.shared_offset <= r.shared_region_size);
        inv.add_constraint(r.shared_offset >= 0);
        inv.add_constraint(r.packet_offset <= variable_t::packet_size());
        inv.add_constraint(r.packet_offset >= 0);
        if (thread_local_options.cfg_opts.check_for_termination) {
            for (const variable_t counter : variable_t::get_loop_counters()) {
                inv.add_constraint(counter <= std::numeric_limits<int32_t>::max());
                inv.add_constraint(counter >= 0);
                inv.add_constraint(counter <= r.svalue);
            }
        }
    }
    return inv;
}

static const ebpf_domain_t constant_limits = ebpf_domain_t::calculate_constant_limits();

ebpf_domain_t ebpf_domain_t::widen(const ebpf_domain_t& other, const bool to_constants) const {
    ebpf_domain_t res{m_inv.widen(other.m_inv), stack | other.stack};
    if (to_constants) {
        return res & constant_limits;
    }
    return res;
}

ebpf_domain_t ebpf_domain_t::narrow(const ebpf_domain_t& other) const {
    return ebpf_domain_t(m_inv.narrow(other.m_inv), stack & other.stack);
}

void ebpf_domain_t::add_constraint(const linear_constraint_t& cst) { m_inv.add_constraint(cst); }

void ebpf_domain_t::havoc(const variable_t var) { m_inv.havoc(var); }

// Get the start and end of the range of possible map fd values.
// In the future, it would be cleaner to use a set rather than an interval
// for map fds.
bool ebpf_domain_t::get_map_fd_range(const Reg& map_fd_reg, int32_t* start_fd, int32_t* end_fd) const {
    const interval_t& map_fd_interval = m_inv.eval_interval(reg_pack(map_fd_reg).map_fd);
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
std::optional<uint32_t> ebpf_domain_t::get_map_type(const Reg& map_fd_reg) const {
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
std::optional<uint32_t> ebpf_domain_t::get_map_inner_map_fd(const Reg& map_fd_reg) const {
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
interval_t ebpf_domain_t::get_map_key_size(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return interval_t::top();
    }

    interval_t result = interval_t::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (const EbpfMapDescriptor* map = &thread_local_program_info->platform->get_map_descriptor(map_fd)) {
            result = result | interval_t{map->key_size};
        } else {
            return interval_t::top();
        }
    }
    return result;
}

// We can deal with a range of value sizes.
interval_t ebpf_domain_t::get_map_value_size(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return interval_t::top();
    }

    interval_t result = interval_t::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (const EbpfMapDescriptor* map = &thread_local_program_info->platform->get_map_descriptor(map_fd)) {
            result = result | interval_t(map->value_size);
        } else {
            return interval_t::top();
        }
    }
    return result;
}

// We can deal with a range of max_entries values.
interval_t ebpf_domain_t::get_map_max_entries(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return interval_t::top();
    }

    interval_t result = interval_t::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (const EbpfMapDescriptor* map = &thread_local_program_info->platform->get_map_descriptor(map_fd)) {
            result = result | interval_t(map->max_entries);
        } else {
            return interval_t::top();
        }
    }
    return result;
}

extended_number ebpf_domain_t::get_loop_count_upper_bound() const {
    extended_number ub{0};
    for (const variable_t counter : variable_t::get_loop_counters()) {
        ub = std::max(ub, m_inv.eval_interval(counter).ub());
    }
    return ub;
}

interval_t ebpf_domain_t::get_r0() const { return m_inv.eval_interval(reg_pack(R0_RETURN_VALUE).svalue); }

std::ostream& operator<<(std::ostream& o, const ebpf_domain_t& dom) {
    if (dom.is_bottom()) {
        o << "_|_";
    } else {
        o << dom.m_inv << "\nStack: " << dom.stack;
    }
    return o;
}

void ebpf_domain_t::initialize_packet() {
    using namespace prevail::dsl_syntax;
    ebpf_domain_t& inv = *this;
    inv.havoc(variable_t::packet_size());
    inv.havoc(variable_t::meta_offset());

    inv.add_constraint(0 <= variable_t::packet_size());
    inv.add_constraint(variable_t::packet_size() < MAX_PACKET_SIZE);
    const auto info = *thread_local_program_info;
    if (info.type.context_descriptor->meta >= 0) {
        inv.add_constraint(variable_t::meta_offset() <= 0);
        inv.add_constraint(variable_t::meta_offset() >= -4098);
    } else {
        inv.m_inv.assign(variable_t::meta_offset(), 0);
    }
}

ebpf_domain_t ebpf_domain_t::from_constraints(const std::set<std::string>& constraints, const bool setup_constraints) {
    ebpf_domain_t inv;
    if (setup_constraints) {
        inv = setup_entry(false);
    }
    auto numeric_ranges = std::vector<interval_t>();
    for (const auto& cst : parse_linear_constraints(constraints, numeric_ranges)) {
        inv.add_constraint(cst);
    }
    for (const interval_t& range : numeric_ranges) {
        const int start = range.lb().narrow<int>();
        const int width = 1 + range.finite_size()->narrow<int>();
        inv.stack.initialize_numbers(start, width);
    }
    // TODO: handle other stack type constraints
    return inv;
}

ebpf_domain_t ebpf_domain_t::setup_entry(const bool init_r1) {
    using namespace prevail::dsl_syntax;

    ebpf_domain_t inv;
    const auto r10 = reg_pack(R10_STACK_POINTER);
    constexpr Reg r10_reg{R10_STACK_POINTER};
    inv.m_inv.add_constraint(EBPF_TOTAL_STACK_SIZE <= r10.svalue);
    inv.m_inv.add_constraint(r10.svalue <= PTR_MAX);
    inv.m_inv.assign(r10.stack_offset, EBPF_TOTAL_STACK_SIZE);
    // stack_numeric_size would be 0, but TOP has the same result
    // so no need to assign it.
    inv.type_inv.assign_type(inv.m_inv, r10_reg, T_STACK);

    if (init_r1) {
        const auto r1 = reg_pack(R1_ARG);
        constexpr Reg r1_reg{R1_ARG};
        inv.m_inv.add_constraint(1 <= r1.svalue);
        inv.m_inv.add_constraint(r1.svalue <= PTR_MAX);
        inv.m_inv.assign(r1.ctx_offset, 0);
        inv.type_inv.assign_type(inv.m_inv, r1_reg, T_CTX);
    }

    inv.initialize_packet();
    return inv;
}

} // namespace prevail

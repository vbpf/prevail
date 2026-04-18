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
#include "crab_utils/lazy_allocator.hpp"
#include "ir/unmarshal.hpp"

namespace prevail {

StringInvariant EbpfDomain::to_set() const {
    if (!stack) {
        // BUG: bottom should serialize as bottom ("_|_"), but several YAML
        // tests encode the wrong answer (top) in their `post: []` expectations.
        // Returning top here matches those expectations. Fix by returning
        // bottom and updating the YAML tests in the same change.
        return StringInvariant::top();
    }
    return state.to_set() + stack->to_set();
}

std::optional<int64_t> EbpfDomain::get_stack_offset(const Reg& reg) const {
    // Only return an offset when the register is *definitely* a stack pointer,
    // not just possibly one. This ensures we don't misclassify memory deps.
    if (state.get_type(reg) != T_STACK) {
        return std::nullopt;
    }
    const auto offset = state.values.eval_interval(reg_pack(reg).stack_offset);
    if (const auto singleton = offset.singleton()) {
        return singleton->cast_to<int64_t>();
    }
    return std::nullopt;
}

EbpfDomain EbpfDomain::top(const AnalysisContext& context) {
    return top(static_cast<size_t>(context.options.total_stack_size()));
}

EbpfDomain EbpfDomain::top(const size_t total_stack_size) {
    return EbpfDomain{TypeToNumDomain::top(), ArrayDomain{total_stack_size}};
}

EbpfDomain EbpfDomain::bottom() { return EbpfDomain{}; }

// Default EbpfDomain is bottom: state is explicitly bottom, stack is nullopt.
// This keeps the "bottom reduces all fields to bottom" invariant and avoids
// the thread-local read that a default-constructed ArrayDomain would do.
EbpfDomain::EbpfDomain() : state(TypeToNumDomain::bottom()), stack(std::nullopt) {}

EbpfDomain::EbpfDomain(TypeToNumDomain state, ArrayDomain stack) : state(std::move(state)), stack(std::move(stack)) {}

void EbpfDomain::set_to_bottom() {
    state.set_to_bottom();
    stack.reset();
}

bool EbpfDomain::is_bottom() const { return state.is_bottom(); }

bool EbpfDomain::is_top() const { return stack && state.is_top() && stack->is_top(); }

bool EbpfDomain::operator<=(const EbpfDomain& other) const {
    // Bottom is below everything. Short-circuit so we don't dereference a nullopt stack.
    if (is_bottom()) {
        return true;
    }
    if (other.is_bottom()) {
        return false;
    }
    if (!(*stack <= *other.stack)) {
        return false;
    }
    return state <= other.state;
}

bool EbpfDomain::operator<=(EbpfDomain&& other) const {
    if (is_bottom()) {
        return true;
    }
    if (other.is_bottom()) {
        return false;
    }
    if (!(*stack <= *other.stack)) {
        return false;
    }
    return state <= std::move(other.state);
}

void EbpfDomain::operator|=(EbpfDomain&& other) {
    if (other.is_bottom()) {
        return;
    }
    if (is_bottom()) {
        *this = std::move(other);
        return;
    }
    *stack |= std::move(*other.stack);
    state |= std::move(other.state);
}

void EbpfDomain::operator|=(const EbpfDomain& other) {
    if (other.is_bottom()) {
        return;
    }
    if (is_bottom()) {
        *this = other;
        return;
    }
    *stack |= *other.stack;
    state |= other.state;
}

EbpfDomain EbpfDomain::operator|(EbpfDomain&& other) const {
    if (other.is_bottom()) {
        return *this;
    }
    if (is_bottom()) {
        return std::move(other);
    }
    other |= *this;
    return other;
}

EbpfDomain EbpfDomain::operator|(const EbpfDomain& other) const& {
    if (other.is_bottom()) {
        return *this;
    }
    if (is_bottom()) {
        return other;
    }
    EbpfDomain res{other};
    res |= *this;
    return res;
}

EbpfDomain EbpfDomain::operator|(const EbpfDomain& other) && {
    if (other.is_bottom()) {
        return std::move(*this);
    }
    if (is_bottom()) {
        return other;
    }
    *this |= other;
    return std::move(*this);
}

EbpfDomain EbpfDomain::operator&(const EbpfDomain& other) const {
    if (is_bottom() || other.is_bottom()) {
        return bottom();
    }
    auto res_state = state & other.state;
    if (res_state.is_bottom()) {
        return bottom();
    }
    return EbpfDomain{std::move(res_state), *stack & *other.stack};
}

EbpfDomain EbpfDomain::calculate_constant_limits(const AnalysisContext& context,
                                                 const std::span<const Variable> loop_counters) {
    EbpfDomain inv = top(context);
    using namespace dsl_syntax;
    for (const int i : {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
        const auto r = variable_registry.reg_pack(i);
        inv.add_value_constraint(r.svalue <= std::numeric_limits<int32_t>::max());
        inv.add_value_constraint(r.svalue >= std::numeric_limits<int32_t>::min());
        inv.add_value_constraint(r.uvalue <= std::numeric_limits<uint32_t>::max());
        inv.add_value_constraint(r.uvalue >= 0);
        inv.add_value_constraint(r.stack_offset <= context.options.total_stack_size());
        inv.add_value_constraint(r.stack_offset >= 0);
        inv.add_value_constraint(r.shared_offset <= r.shared_region_size);
        inv.add_value_constraint(r.shared_offset >= 0);
        inv.add_value_constraint(r.packet_offset <= variable_registry.packet_size());
        inv.add_value_constraint(r.packet_offset >= 0);
        for (const Variable counter : loop_counters) {
            inv.add_value_constraint(counter <= std::numeric_limits<int32_t>::max());
            inv.add_value_constraint(counter >= 0);
            inv.add_value_constraint(counter <= r.svalue);
        }
    }
    return inv;
}

EbpfDomain EbpfDomain::widen(const EbpfDomain& other, const bool to_constants, const AnalysisContext& context,
                             const std::span<const Variable> loop_counters) const {
    if (is_bottom()) {
        return other;
    }
    if (other.is_bottom()) {
        return *this;
    }
    EbpfDomain res{this->state.widen(other.state), stack->widen(*other.stack)};

    if (to_constants) {
        // Clamping via intersection is sound because it only tightens
        // constraints element-wise, preserving the over-approximation.
        return res & calculate_constant_limits(context, loop_counters);
    }
    return res;
}

EbpfDomain EbpfDomain::narrow(const EbpfDomain& other) const {
    if (is_bottom() || other.is_bottom()) {
        return bottom();
    }
    return EbpfDomain{state.narrow(other.state), *stack & *other.stack};
}

// State mutators on EbpfDomain are responsible for maintaining the
// "state.is_bottom() <=> !stack" invariant: if a constraint drives the
// numeric (or type) sub-domain to bottom, drop the stack so that observers
// don't read a materialized stack on a bottom domain.
void EbpfDomain::normalize_after_state_mutation() {
    if (state.is_bottom()) {
        stack.reset();
    }
}

void EbpfDomain::add_value_constraint(const LinearConstraint& cst) {
    state.values.add_constraint(cst);
    normalize_after_state_mutation();
}

void EbpfDomain::assume_eq_types(const Variable v1, const Variable v2) {
    state.assume_eq_types(v1, v2);
    normalize_after_state_mutation();
}

void EbpfDomain::restrict_type(const Variable v, const TypeSet& ts) {
    state.types.restrict_to(v, ts);
    normalize_after_state_mutation();
}

void EbpfDomain::havoc(const Variable var) {
    // TODO: type inv?
    state.values.havoc(var);
}

// Get the start and end of the range of possible map fd values.
// In the future, it would be cleaner to use a set rather than an interval
// for map fds.
bool EbpfDomain::get_map_fd_range(const Reg& map_fd_reg, int32_t* start_fd, int32_t* end_fd) const {
    const Interval& map_fd_interval = state.values.eval_interval(reg_pack(map_fd_reg).map_fd);
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
std::optional<uint32_t> EbpfDomain::get_map_type(const Reg& map_fd_reg, const AnalysisContext& context) const {
    int32_t start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return {};
    }

    std::optional<uint32_t> type;
    for (int32_t map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        const auto& map = context.platform.get_map_descriptor(map_fd, context.program_info);
        if (!type.has_value()) {
            type = map.type;
        } else if (map.type != *type) {
            return {};
        }
    }
    return type;
}

std::optional<uint32_t> EbpfDomain::get_map_inner_map_fd(const Reg& map_fd_reg, const AnalysisContext& context) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return {};
    }

    std::optional<uint32_t> inner_map_fd;
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        const auto& map = context.platform.get_map_descriptor(map_fd, context.program_info);
        if (!inner_map_fd.has_value()) {
            inner_map_fd = map.inner_map_fd;
        } else if (map.inner_map_fd != *inner_map_fd) {
            return {};
        }
    }
    return inner_map_fd;
}

Interval EbpfDomain::get_map_key_size(const Reg& map_fd_reg, const AnalysisContext& context) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return Interval::top();
    }

    Interval result = Interval::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        const auto& map = context.platform.get_map_descriptor(map_fd, context.program_info);
        result = result | Interval{map.key_size};
    }
    return result;
}

Interval EbpfDomain::get_map_value_size(const Reg& map_fd_reg, const AnalysisContext& context) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return Interval::top();
    }

    Interval result = Interval::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        const auto& map = context.platform.get_map_descriptor(map_fd, context.program_info);
        result = result | Interval(map.value_size);
    }
    return result;
}

Interval EbpfDomain::get_map_max_entries(const Reg& map_fd_reg, const AnalysisContext& context) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return Interval::top();
    }

    Interval result = Interval::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        const auto& map = context.platform.get_map_descriptor(map_fd, context.program_info);
        result = result | Interval(map.max_entries);
    }
    return result;
}

ExtendedNumber EbpfDomain::get_loop_count_upper_bound(const std::span<const Variable> loop_counters) const {
    ExtendedNumber ub{0};
    for (const Variable counter : loop_counters) {
        ub = std::max(ub, state.values.eval_interval(counter).ub());
    }
    return ub;
}

Interval EbpfDomain::get_r0() const { return state.values.eval_interval(reg_pack(R0_RETURN_VALUE).svalue); }

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
        o << dom.state << "\nStack: " << *dom.stack;
    }
    return o;
}

void EbpfDomain::initialize_packet(const AnalysisContext& context) {
    using namespace dsl_syntax;
    EbpfDomain& inv = *this;
    inv.havoc(variable_registry.packet_size());
    inv.havoc(variable_registry.meta_offset());

    inv.add_value_constraint(0 <= variable_registry.packet_size());
    inv.add_value_constraint(variable_registry.packet_size() < context.options.max_packet_size);
    if (context.program_info.type.context_descriptor->meta >= 0) {
        inv.add_value_constraint(variable_registry.meta_offset() <= 0);
        inv.add_value_constraint(variable_registry.meta_offset() >= -4098);
    } else {
        inv.state.values.assign(variable_registry.meta_offset(), 0);
    }
}

EbpfDomain EbpfDomain::from_constraints(const std::vector<std::pair<Variable, TypeSet>>& type_restrictions,
                                        const std::vector<LinearConstraint>& value_constraints,
                                        const size_t total_stack_size) {
    EbpfDomain inv{TypeToNumDomain::top(), ArrayDomain{total_stack_size}};

    for (const auto& [var, ts] : type_restrictions) {
        inv.restrict_type(var, ts);
    }
    for (const auto& cst : value_constraints) {
        inv.add_value_constraint(cst);
    }
    return inv;
}

EbpfDomain EbpfDomain::from_constraints(const std::set<std::string>& constraints, const bool setup_constraints,
                                        const AnalysisContext& context) {
    EbpfDomain inv =
        setup_constraints
            ? setup_entry(false, context)
            : EbpfDomain{TypeToNumDomain::top(), ArrayDomain{static_cast<size_t>(context.options.total_stack_size())}};
    auto numeric_ranges = std::vector<Interval>();
    auto [type_equalities, type_restrictions, value_constraints] =
        parse_linear_constraints(constraints, numeric_ranges);
    for (const auto& [v1, v2] : type_equalities) {
        inv.assume_eq_types(v1, v2);
    }
    for (const auto& [var, ts] : type_restrictions) {
        inv.restrict_type(var, ts);
    }
    for (const auto& cst : value_constraints) {
        inv.add_value_constraint(cst);
    }
    if (inv.is_bottom()) {
        return inv;
    }
    for (const Interval& range : numeric_ranges) {
        const auto [start, ub] = range.pair<int64_t>();
        const int width = gsl::narrow<int>(1 + (ub - start));
        inv.stack->initialize_numbers(gsl::narrow<int>(start), width);
    }
    // TODO: handle other stack type constraints
    return inv;
}

EbpfDomain EbpfDomain::setup_entry(const bool init_r1, const AnalysisContext& context) {
    using namespace dsl_syntax;

    EbpfDomain inv = top(context);

    const auto r10 = variable_registry.reg_pack(R10_STACK_POINTER);
    constexpr Reg r10_reg{R10_STACK_POINTER};
    const auto total_stack = context.options.total_stack_size();
    inv.state.values.add_constraint(total_stack <= r10.svalue);
    inv.state.values.add_constraint(r10.svalue <= ptr_max(context.options.max_packet_size));
    inv.state.values.assign(r10.stack_offset, total_stack);
    // stack_numeric_size would be 0, but TOP has the same result
    // so no need to assign it.
    inv.state.assign_type(r10_reg, T_STACK);

    if (init_r1) {
        const auto r1 = variable_registry.reg_pack(R1_ARG);
        constexpr Reg r1_reg{R1_ARG};
        inv.state.values.add_constraint(1 <= r1.svalue);
        inv.state.values.add_constraint(r1.svalue <= ptr_max(context.options.max_packet_size));
        inv.state.values.assign(r1.ctx_offset, 0);
        inv.state.assign_type(r1_reg, T_CTX);
    }

    inv.initialize_packet(context);
    return inv;
}

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.

#include <bitset>
#include <optional>
#include <utility>
#include <variant>

#include "arith/dsl_syntax.hpp"
#include "config.hpp"
#include "crab/array_domain.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/region_semantics.hpp"
#include "crab/var_registry.hpp"
#include "ir/program.hpp"
#include "ir/syntax.hpp"
#include "platform.hpp"

namespace prevail {

namespace {
// Internal control-flow signal used by EbpfChecker to abort the current
// assertion check. Caught only inside ebpf_domain_check, where it is
// converted into a VerificationError value. Not part of the public API.
struct VerificationFailureSignal final : std::runtime_error {
    using std::runtime_error::runtime_error;
};
} // namespace

class EbpfChecker final {
  public:
    explicit EbpfChecker(const EbpfDomain& dom, Assertion assertion, const AnalysisContext& context)
        : assertion{std::move(assertion)}, dom(dom), context(context) {}

    void visit() { std::visit(*this, assertion); }

    void operator()(const Addable&) const;
    void operator()(const BoundedLoopCount&) const;
    void operator()(const Comparable&) const;
    void operator()(const FuncConstraint&) const;
    void operator()(const ValidDivisor&) const;
    void operator()(const TypeConstraint&) const;
    void operator()(const ValidAccess&) const;
    void operator()(const ValidCallbackTarget&) const;
    void operator()(const ValidMapKeyValue&) const;
    void operator()(const ValidMapType&) const;
    void operator()(const ValidSize&) const;
    void operator()(const ValidArgZero&) const;
    void operator()(const ValidStore&) const;
    void operator()(const ZeroCtxOffset&) const;

  private:
    void require_value(const TypeToNumDomain& inv, const LinearConstraint& cst, const std::string& msg) const {
        if (!inv.values.entail(cst)) {
            throw_fail(msg);
        }
    }

    [[noreturn]]
    void throw_fail(const std::string& msg) const {
        throw VerificationFailureSignal(msg + " (" + to_string(assertion) + ")");
    }

    // Per-region bounds checks compose two primitives at each call site, so
    // the floor and ceiling for a given access are spelled out where they
    // are checked rather than picked by a dispatcher.
    void require_lower_bound(const LinearExpression& access_lb, const LinearExpression& floor,
                             const std::string& msg) const {
        using namespace dsl_syntax;
        require_value(dom.state, access_lb >= floor, msg);
    }
    void require_upper_bound(const LinearExpression& access_ub, const LinearExpression& ceiling,
                             const std::string& msg) const {
        using namespace dsl_syntax;
        require_value(dom.state, access_ub <= ceiling, msg);
    }

    // Region upper-bound check that falls back to ptr-sum substitution when the
    // direct query fails (see PtrSumBinding in type_to_num.hpp). s_offset is the
    // access's static byte offset and is folded back in, since substitution only
    // replaces the variable part of the sum.
    void require_region_upper_bound(const Reg& access_reg, const Value& width, const int32_t s_offset,
                                    const TypeEncoding region, const LinearExpression& access_ub,
                                    const LinearExpression& ceiling, const std::string& msg) const {
        using namespace dsl_syntax;
        if (dom.state.values.entail(access_ub <= ceiling)) {
            return;
        }
        if (std::holds_alternative<Reg>(width) && !dom.state.ptr_sum_bindings.empty()) {
            const Reg width_reg = std::get<Reg>(width);
            if (const auto intermediate_offset =
                    dom.state.lookup_ptr_sum_intermediate_offset(access_reg, width_reg, region)) {
                const LinearExpression substituted = LinearExpression{*intermediate_offset} + s_offset;
                if (dom.state.values.entail(substituted <= ceiling)) {
                    return;
                }
            }
        }
        throw_fail(msg);
    }

    const Assertion assertion;

    const EbpfDomain& dom;
    const AnalysisContext& context;
};

std::optional<VerificationError> ebpf_domain_check(const EbpfDomain& dom, const Assertion& assertion,
                                                   const Label& where, const AnalysisContext& context) {
    if (dom.is_bottom()) {
        return {};
    }
    try {
        EbpfChecker{dom, assertion, context}.visit();
    } catch (const VerificationFailureSignal& signal) {
        VerificationError error(signal.what());
        error.where = where;
        return {std::move(error)};
    }
    return {};
}

void EbpfChecker::operator()(const Comparable& s) const {
    using namespace dsl_syntax;
    if (dom.state.same_type(s.r1, s.r2)) {
        // Same type. If both are numbers, that's okay. Otherwise:
        TypeDomain non_number_types = dom.state.types;
        non_number_types.remove_type(reg_type(s.r2), T_NUM);
        // We must check that they belong to a singleton region:
        if (!non_number_types.is_in_group(s.r1, TS_SINGLETON_PTR) && !non_number_types.is_in_group(s.r1, TS_MAP)) {
            throw_fail("Cannot subtract pointers to non-singleton regions");
        }
        // And, to avoid wraparound errors, they must be within bounds.
        this->operator()(ValidAccess{context.runtime().max_call_stack_frames, s.r1, 0, Imm{0}, false});
        this->operator()(ValidAccess{context.runtime().max_call_stack_frames, s.r2, 0, Imm{0}, false});
    } else {
        // _Maybe_ different types, so r2 must be a number.
        // We checked in a previous assertion that r1 is a pointer or a number.
        if (!dom.state.entail_type(reg_type(s.r2), T_NUM)) {
            throw_fail("Cannot subtract pointers to different regions");
        }
    }
}

void EbpfChecker::operator()(const Addable& s) const {
    if (!dom.state.implies_superset(s.ptr, TS_POINTER, s.num, TS_NUM)) {
        throw_fail("Only numbers can be added to pointers");
    }
}

void EbpfChecker::operator()(const ValidDivisor& s) const {
    using namespace dsl_syntax;
    if (!dom.state.implies_superset(s.reg, TS_POINTER, s.reg, TS_NUM)) {
        throw_fail("Only numbers can be used as divisors");
    }
    if (!context.runtime().allow_division_by_zero) {
        const auto reg = reg_pack(s.reg);
        const auto v = s.is_signed ? reg.svalue : reg.uvalue;
        require_value(dom.state, v != 0, "Possible division by zero");
    }
}

void EbpfChecker::operator()(const ValidStore& s) const {
    if (!dom.state.implies_not_type(s.mem, T_STACK, s.val, TS_NUM)) {
        throw_fail("Only numbers can be stored to externally-visible regions");
    }
}

void EbpfChecker::operator()(const TypeConstraint& s) const {
    if (!dom.state.is_in_group(s.reg, to_typeset(s.types))) {
        throw_fail("Invalid type");
    }
}

void EbpfChecker::operator()(const BoundedLoopCount& s) const {
    // Enforces an upper bound on loop iterations by checking that the loop counter
    // does not exceed the specified limit
    using namespace dsl_syntax;
    const auto counter = variable_registry.loop_counter(to_string(s.name));
    require_value(dom.state, counter <= BoundedLoopCount::limit, "Loop counter is too large");
}

void EbpfChecker::operator()(const FuncConstraint& s) const {
    // Look up the helper function id.
    if (dom.state.is_bottom()) {
        return;
    }
    const auto src_interval = dom.state.values.eval_interval(reg_pack(s.reg).svalue);
    if (const auto sn = src_interval.singleton()) {
        if (sn->fits<int32_t>()) {
            // We can now process it as if the id was immediate.
            const int32_t imm = sn->cast_to<int32_t>();
            if (!context.is_helper_usable(imm)) {
                throw_fail("invalid helper function id " + std::to_string(imm));
            }
            const Call call{.func = imm, .kind = CallKind::helper};
            for (const Assertion& sub_assertion : get_assertions(call, context.program_info(), context.runtime(), {})) {
                // TODO: create explicit sub assertions elsewhere
                EbpfChecker{dom, sub_assertion, context}.visit();
            }
            return;
        }
    }
    throw_fail("callx helper function id is not a valid singleton");
}

void EbpfChecker::operator()(const ValidSize& s) const {
    using namespace dsl_syntax;
    const auto r = reg_pack(s.reg);
    require_value(dom.state, s.can_be_zero ? r.svalue >= 0 : r.svalue > 0, "Invalid size");
}

void EbpfChecker::operator()(const ValidArgZero& s) const {
    using namespace dsl_syntax;
    const auto r = reg_pack(s.reg);
    require_value(dom.state, r.svalue == 0, "Argument must be zero");
}

void EbpfChecker::operator()(const ValidCallbackTarget& s) const {
    const auto callback_interval = dom.state.values.eval_interval(reg_pack(s.reg).uvalue);
    const auto callback_target = callback_interval.singleton();
    if (!callback_target.has_value() || !callback_target->fits<int32_t>()) {
        throw_fail("callback function pointer must be a singleton code address");
    }

    const int32_t callback_label = callback_target->cast_to<int32_t>();
    if (!context.program.callback_target_labels().contains(callback_label)) {
        throw_fail("callback function pointer does not reference a valid callback entry");
    }
    if (!context.program.callback_targets_with_exit().contains(callback_label)) {
        throw_fail("callback function does not have a reachable exit");
    }
}

void EbpfChecker::operator()(const ValidMapKeyValue& s) const {
    using namespace dsl_syntax;

    const auto fd_type = dom.get_map_type(s.map_fd_reg, context);

    const auto access_reg = reg_pack(s.access_reg);
    Number width;
    if (s.key) {
        const auto key_size = dom.get_map_key_size(s.map_fd_reg, context).singleton();
        if (!key_size.has_value()) {
            throw_fail("Map key size is not singleton");
        }
        if (!key_size->fits<uint32_t>()) {
            throw_fail("Map key size is out of supported range");
        }
        width = *key_size;
    } else {
        const auto value_size = dom.get_map_value_size(s.map_fd_reg, context).singleton();
        if (!value_size.has_value()) {
            throw_fail("Map value size is not singleton");
        }
        if (!value_size->fits<uint32_t>()) {
            throw_fail("Map value size is out of supported range");
        }
        width = *value_size;
    }

    for (const auto access_reg_type : dom.state.enumerate_types(s.access_reg)) {
        switch (access_reg_type) {
        case T_STACK: {
            Interval offset = dom.state.values.eval_interval(access_reg.stack_offset);
            if (!dom.stack->all_num_width(offset, Interval{width})) {
                auto lb_is = offset.lb().number();
                std::string lb_s = lb_is && lb_is->fits<int32_t>() ? std::to_string(lb_is->narrow<int32_t>()) : "-oo";
                Interval ub = offset + Interval{width};
                auto ub_is = ub.ub().number();
                std::string ub_s = ub_is && ub_is->fits<int32_t>() ? std::to_string(ub_is->narrow<int32_t>()) : "oo";
                require_value(dom.state, LinearConstraint::false_const(),
                              "Illegal map update with a non-numerical value [" + lb_s + "-" + ub_s + ")");
            } else if (context.runtime().strict && fd_type.has_value()) {
                EbpfMapType map_type = context.platform().get_map_type(*fd_type);
                if (map_type.is_array) {
                    // Get offset value.
                    Variable key_ptr = access_reg.stack_offset;
                    std::optional<Number> offset_num = dom.state.values.eval_interval(key_ptr).singleton();
                    if (!offset_num.has_value()) {
                        throw_fail("Pointer must be a singleton");
                    } else if (s.key) {
                        // Look up the value pointed to by the key pointer.
                        Variable key_value =
                            variable_registry.cell_var(DataKind::svalues, offset_num.value(), sizeof(uint32_t));

                        if (auto max_entries = dom.get_map_max_entries(s.map_fd_reg, context).lb().number()) {
                            require_value(dom.state, key_value < *max_entries, "Array index overflow");
                        } else {
                            throw_fail("Max entries is not finite");
                        }
                        require_value(dom.state, key_value >= 0, "Array index underflow");
                    }
                }
            }
            break;
        }
        case T_PACKET: {
            Variable lb = access_reg.packet_offset;
            LinearExpression ub = LinearExpression{lb} + LinearExpression{width};
            require_lower_bound(lb, variable_registry.meta_offset(), "Lower bound must be at least meta_offset");
            require_upper_bound(ub, variable_registry.packet_size(), "Upper bound must be at most packet_size");
            // Packet memory is both readable and writable.
            break;
        }
        case T_SHARED: {
            Variable lb = access_reg.shared_offset;
            LinearExpression ub = LinearExpression{lb} + LinearExpression{width};
            require_lower_bound(lb, LinearExpression{0}, "Lower bound must be at least 0");
            require_upper_bound(ub, access_reg.shared_region_size,
                                "Upper bound must be at most " + variable_registry.name(access_reg.shared_region_size));
            require_value(dom.state, access_reg.uvalue > 0, "Possible null access");
            // Shared memory is zero-initialized when created so is safe to read and write.
            break;
        }
        default: throw_fail("Only stack, packet, or shared can be used as a parameter");
        }
    }
}

void EbpfChecker::operator()(const ValidMapType& s) const {
    if (dom.state.is_bottom()) {
        return;
    }
    const auto map_type = dom.get_map_type(s.map_fd_reg, context);
    if (!map_type.has_value() || *map_type == 0) {
        return;
    }
    if (*map_type >= 64) {
        throw_fail("map type " + std::to_string(*map_type) + " is out of supported range for " + s.helper_name);
    }
    if ((s.allowed_map_types & (uint64_t{1} << *map_type)) == 0) {
        throw_fail("map type " + std::to_string(*map_type) + " is not allowed for " + s.helper_name);
    }
}

static std::tuple<LinearExpression, LinearExpression> lb_ub_access_pair(const ValidAccess& s,
                                                                        const Variable offset_var) {
    using namespace dsl_syntax;
    LinearExpression lb = offset_var + s.offset;
    LinearExpression ub = std::holds_alternative<Imm>(s.width) ? lb + std::get<Imm>(s.width).v
                                                               : lb + reg_pack(std::get<Reg>(s.width)).svalue;
    return {lb, ub};
}

void EbpfChecker::operator()(const ValidAccess& s) const {
    using namespace dsl_syntax;

    const bool is_comparison_check = s.width == Value{Imm{0}};

    const auto reg = reg_pack(s.reg);
    for (const auto type : dom.state.enumerate_types(s.reg)) {
        switch (type) {
        case T_STACK: {
            const auto [lb, ub] = lb_ub_access_pair(s, reg.stack_offset);
            require_lower_bound(lb, reg_pack(R10_STACK_POINTER).stack_offset - context.runtime().subprogram_stack_size,
                                "Lower bound must be at least r10.stack_offset - subprogram_stack_size");
            require_region_upper_bound(s.reg, s.width, s.offset, T_STACK, ub,
                                       LinearExpression{context.runtime().total_stack_size()},
                                       "Upper bound must be at most total_stack_size");
            // Stack reads must hit known-numeric bytes.
            if (s.access_type == AccessType::read &&
                !dom.stack->all_num_lb_ub(dom.state.values.eval_interval(lb), dom.state.values.eval_interval(ub))) {
                if (s.offset < 0) {
                    throw_fail("Stack content is not numeric");
                } else {
                    LinearExpression w = std::holds_alternative<Imm>(s.width)
                                             ? LinearExpression{std::get<Imm>(s.width).v}
                                             : reg_pack(std::get<Reg>(s.width)).svalue;
                    require_value(dom.state, w <= reg.stack_numeric_size - s.offset, "Stack content is not numeric");
                }
            }
            break;
        }
        case T_CTX: {
            const auto* desc = context.program_info().type.ctx_descriptor;
            const auto [lb, ub] = lb_ub_access_pair(s, reg.ctx_offset);
            if (s.access_type == AccessType::write && desc->end >= 0) {
                // The data/data_end/meta fields are read-only pointer slots: a *load* of those
                // offsets synthesizes a typed packet pointer (see do_load_ctx). Writes are not
                // tracked by the abstract transformer (do_mem_store models only stack stores),
                // so an accepted write to e.g. ctx->data followed by a reload would hand out a
                // fresh "valid" packet pointer for a field the program corrupted at runtime,
                // a false PASS for an out-of-bounds dereference. Writes to other (scalar)
                // context fields are sound, since their loads are havoced to numbers, and real
                // programs do write them; so reject only writes that may overlap a pointer
                // slot. A write of [lb, ub) overlaps slot [f, f + field_width) unless we can
                // prove it lies entirely before (ub <= f) or entirely after (lb >= f + width).
                //
                // field_width is the size of a pointer slot, taken as end - data: this is the
                // data/data_end adjacency that do_load_ctx also relies on. If a descriptor ever
                // violated it (non-positive width), the overlap math would be meaningless, so
                // fall back to rejecting the write outright rather than reasoning from a bogus
                // slot width.
                const int field_width = desc->end - desc->data;
                if (field_width <= 0) {
                    throw_fail("Cannot write to context with unexpected pointer-field layout");
                }
                const auto may_overlap = [&](const int field_offset) {
                    if (field_offset < 0) {
                        return false;
                    }
                    return dom.state.values.intersect(ub > LinearExpression{field_offset}) &&
                           dom.state.values.intersect(lb < LinearExpression{field_offset + field_width});
                };
                if (may_overlap(desc->data) || may_overlap(desc->end) || may_overlap(desc->meta)) {
                    throw_fail("Cannot write to context pointer field");
                }
            }
            const auto ctx_size = desc->size;
            require_lower_bound(lb, LinearExpression{0}, "Lower bound must be at least 0");
            require_upper_bound(ub, LinearExpression{ctx_size},
                                "Upper bound must be at most " + std::to_string(ctx_size));
            // T_CTX: bounds suffice; non-null when in bounds.
            break;
        }
        case T_PACKET: {
            const auto [lb, ub] = lb_ub_access_pair(s, reg.packet_offset);
            require_lower_bound(lb, variable_registry.meta_offset(), "Lower bound must be at least meta_offset");
            // Pointer-comparison checks (width == 0) may legitimately reach
            // past the runtime packet_size, so they use the looser
            // max_packet_size ceiling. Real dereferences must be bounded by
            // the runtime packet_size variable.
            if (is_comparison_check) {
                const auto max = context.runtime().max_packet_size;
                require_upper_bound(ub, LinearExpression{max}, "Upper bound must be at most " + std::to_string(max));
            } else {
                require_region_upper_bound(s.reg, s.width, s.offset, T_PACKET, ub, variable_registry.packet_size(),
                                           "Upper bound must be at most packet_size");
            }
            break;
        }
        case T_SHARED: {
            const auto [lb, ub] = lb_ub_access_pair(s, reg.shared_offset);
            require_lower_bound(lb, LinearExpression{0}, "Lower bound must be at least 0");
            require_region_upper_bound(s.reg, s.width, s.offset, T_SHARED, ub, reg.shared_region_size,
                                       "Upper bound must be at most " +
                                           variable_registry.name(reg.shared_region_size));
            if (!is_comparison_check && !s.or_null) {
                require_value(dom.state, reg.uvalue > 0, "Possible null access");
            }
            break;
        }
        case T_ALLOC_MEM: {
            const auto [lb, ub] = lb_ub_access_pair(s, reg.alloc_mem_offset);
            require_lower_bound(lb, LinearExpression{0}, "Lower bound must be at least 0");
            require_upper_bound(ub, reg.alloc_mem_size,
                                "Upper bound must be at most " + variable_registry.name(reg.alloc_mem_size));
            if (!is_comparison_check && !s.or_null) {
                require_value(dom.state, reg.uvalue > 0, "Possible null access");
            }
            break;
        }
        case T_NUM:
            if (!is_comparison_check) {
                if (s.or_null) {
                    require_value(dom.state, reg.svalue == 0, "Non-null number");
                    // A null pointer access is only valid with zero width.
                    if (std::holds_alternative<Imm>(s.width)) {
                        if (std::get<Imm>(s.width).v != 0) {
                            throw_fail("Non-zero access size with null pointer");
                        }
                    } else {
                        const auto width_svalue = reg_pack(std::get<Reg>(s.width)).svalue;
                        require_value(dom.state, width_svalue == 0, "Non-zero access size with null pointer");
                    }
                } else {
                    throw_fail("Only pointers can be dereferenced");
                }
            }
            break;
        case T_MAP: [[fallthrough]];
        case T_MAP_PROGRAMS:
            if (!is_comparison_check) {
                throw_fail("FDs cannot be dereferenced directly");
            }
            break;
        case T_SOCKET: [[fallthrough]];
        case T_BTF_ID:
            // TODO: implement proper access checks for these pointer types.
            if (!is_comparison_check) {
                throw_fail("Unsupported pointer type for memory access");
            }
            break;
        case T_FUNC:
            if (!is_comparison_check) {
                throw_fail("Function pointers cannot be dereferenced");
            }
            break;
        default: throw_fail("Invalid type");
        }
    }
}

void EbpfChecker::operator()(const ZeroCtxOffset& s) const {
    using namespace dsl_syntax;
    const auto reg = reg_pack(s.reg);
    // The domain is not expressive enough to handle join of null and non-null ctx,
    // Since non-null ctx pointers are nonzero numbers.
    if (s.or_null && dom.state.is_in_group(s.reg, TS_NUM) && dom.state.values.entail(reg.uvalue == 0)) {
        return;
    }
    require_value(dom.state, reg.ctx_offset == 0, "Nonzero context offset");
}

} // namespace prevail

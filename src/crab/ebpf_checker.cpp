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
#include "ir/unmarshal.hpp"
#include "platform.hpp"

namespace prevail {

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
    void operator()(const ValidSize&) const;
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
        throw VerificationError(msg + " (" + to_string(assertion) + ")");
    }

    // Single driver for in-region access bounds: requires `access_lb >= floor`
    // and `access_ub <= ceiling` for the region. `packet_size` overrides the
    // T_PACKET upper bound; see region_bounds().
    void require_region_bounds(TypeEncoding type, const RegPack& reg, const LinearExpression& access_lb,
                               const LinearExpression& access_ub,
                               std::optional<Variable> packet_size = std::nullopt) const;

  private:
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
    } catch (VerificationError& error) {
        error.where = where;
        return {error};
    }
    return {};
}

void EbpfChecker::require_region_bounds(const TypeEncoding type, const RegPack& reg, const LinearExpression& access_lb,
                                        const LinearExpression& access_ub,
                                        const std::optional<Variable> packet_size) const {
    using namespace dsl_syntax;
    const auto bounds = region_bounds(type, reg, context, packet_size);
    require_value(dom.state, access_lb >= bounds.lb_floor, bounds.lb_message);
    require_value(dom.state, access_ub <= bounds.ub_ceiling, bounds.ub_message);
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
        this->operator()(ValidAccess{context.options.max_call_stack_frames, s.r1, 0, Imm{0}, false});
        this->operator()(ValidAccess{context.options.max_call_stack_frames, s.r2, 0, Imm{0}, false});
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
    if (!context.options.allow_division_by_zero) {
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
            const Call call = make_call(imm, context.platform(), context.program_info().type);
            for (const Assertion& sub_assertion : get_assertions(call, context.program_info(), context.options, {})) {
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

void EbpfChecker::operator()(const ValidCallbackTarget& s) const {
    const auto callback_interval = dom.state.values.eval_interval(reg_pack(s.reg).svalue);
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
    int width;
    if (s.key) {
        const auto key_size = dom.get_map_key_size(s.map_fd_reg, context).singleton();
        if (!key_size.has_value()) {
            throw_fail("Map key size is not singleton");
        }
        width = key_size->narrow<int>();
    } else {
        const auto value_size = dom.get_map_value_size(s.map_fd_reg, context).singleton();
        if (!value_size.has_value()) {
            throw_fail("Map value size is not singleton");
        }
        width = value_size->narrow<int>();
    }

    for (const auto access_reg_type : dom.state.enumerate_types(s.access_reg)) {
        if (access_reg_type == T_STACK) {
            Interval offset = dom.state.values.eval_interval(access_reg.stack_offset);
            if (!dom.stack->all_num_width(offset, Interval{width})) {
                auto lb_is = offset.lb().number();
                std::string lb_s = lb_is && lb_is->fits<int32_t>() ? std::to_string(lb_is->narrow<int32_t>()) : "-oo";
                Interval ub = offset + Interval{width};
                auto ub_is = ub.ub().number();
                std::string ub_s = ub_is && ub_is->fits<int32_t>() ? std::to_string(ub_is->narrow<int32_t>()) : "oo";
                require_value(dom.state, LinearConstraint::false_const(),
                              "Illegal map update with a non-numerical value [" + lb_s + "-" + ub_s + ")");
            } else if (context.options.strict && fd_type.has_value()) {
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
        } else if (access_reg_type == T_PACKET) {
            Variable lb = access_reg.packet_offset;
            LinearExpression ub = lb + width;
            require_region_bounds(T_PACKET, access_reg, lb, ub);
            // Packet memory is both readable and writable.
        } else if (access_reg_type == T_SHARED) {
            Variable lb = access_reg.shared_offset;
            LinearExpression ub = lb + width;
            require_region_bounds(T_SHARED, access_reg, lb, ub);
            require_value(dom.state, access_reg.svalue > 0, "Possible null access");
            // Shared memory is zero-initialized when created so is safe to read and write.
        } else {
            throw_fail("Only stack, packet, or shared can be used as a parameter");
        }
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
        case T_PACKET: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.packet_offset);
            const std::optional<Variable> packet_size =
                is_comparison_check ? std::optional<Variable>{} : variable_registry.packet_size();
            require_region_bounds(T_PACKET, reg, lb, ub, packet_size);
            // if within bounds, it can never be null
            // Context memory is both readable and writable.
            break;
        }
        case T_STACK: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.stack_offset);
            require_region_bounds(T_STACK, reg, lb, ub);
            // if within bounds, it can never be null
            if (s.access_type == AccessType::read &&
                !dom.stack->all_num_lb_ub(dom.state.values.eval_interval(lb), dom.state.values.eval_interval(ub))) {

                if (s.offset < 0) {
                    throw_fail("Stack content is not numeric");
                } else {
                    using namespace dsl_syntax;
                    LinearExpression w = std::holds_alternative<Imm>(s.width)
                                             ? LinearExpression{std::get<Imm>(s.width).v}
                                             : reg_pack(std::get<Reg>(s.width)).svalue;

                    require_value(dom.state, w <= reg.stack_numeric_size - s.offset, "Stack content is not numeric");
                }
            }
            break;
        }
        case T_CTX: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.ctx_offset);
            require_region_bounds(T_CTX, reg, lb, ub);
            // if within bounds, it can never be null
            // The context is both readable and writable.
            break;
        }
        case T_SHARED: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.shared_offset);
            require_region_bounds(T_SHARED, reg, lb, ub);
            if (!is_comparison_check && !s.or_null) {
                require_value(dom.state, reg.svalue > 0, "Possible null access");
            }
            // Shared memory is zero-initialized when created so is safe to read and write.
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
        case T_ALLOC_MEM: {
            // Treat like shared: offset-bounded access with null check.
            auto [lb, ub] = lb_ub_access_pair(s, reg.alloc_mem_offset);
            require_region_bounds(T_ALLOC_MEM, reg, lb, ub);
            if (!is_comparison_check && !s.or_null) {
                require_value(dom.state, reg.svalue > 0, "Possible null access");
            }
            break;
        }
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

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.

#include <bitset>
#include <optional>
#include <utility>

#include "arith/dsl_syntax.hpp"
#include "config.hpp"
#include "crab/array_domain.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/var_registry.hpp"
#include "ir/program.hpp"
#include "ir/syntax.hpp"
#include "ir/unmarshal.hpp"
#include "platform.hpp"

namespace prevail {

class EbpfChecker final {
  public:
    explicit EbpfChecker(const EbpfDomain& dom, Assertion assertion) : assertion{std::move(assertion)}, dom(dom) {}

    void visit() { std::visit(*this, assertion); }

    void operator()(const Addable&) const;
    void operator()(const BoundedLoopCount&) const;
    void operator()(const Comparable&) const;
    void operator()(const FuncConstraint&) const;
    void operator()(const ValidDivisor&) const;
    void operator()(const TypeConstraint&) const;
    void operator()(const ValidAccess&) const;
    void operator()(const ValidCall&) const;
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

    void require_type(const TypeToNumDomain& inv, const LinearConstraint& cst, const std::string& msg) const {
        if (!inv.types.inv.entail(cst)) {
            throw_fail(msg);
        }
    }

    [[noreturn]]
    void throw_fail(const std::string& msg) const {
        throw VerificationError(msg + " (" + to_string(assertion) + ")");
    }

    // memory check / load / store
    void check_access_stack(const LinearExpression& lb, const LinearExpression& ub) const;
    void check_access_context(const LinearExpression& lb, const LinearExpression& ub) const;
    void check_access_packet(const LinearExpression& lb, const LinearExpression& ub,
                             std::optional<Variable> packet_size) const;
    void check_access_shared(const LinearExpression& lb, const LinearExpression& ub, Variable shared_region_size) const;

  private:
    const Assertion assertion;

    const EbpfDomain& dom;
};

std::optional<VerificationError> ebpf_domain_check(const EbpfDomain& dom, const Assertion& assertion) {
    if (dom.is_bottom()) {
        return {};
    }
    try {
        EbpfChecker{dom, assertion}.visit();
    } catch (const VerificationError& error) {
        return {error};
    }
    return {};
}

void EbpfChecker::check_access_stack(const LinearExpression& lb, const LinearExpression& ub) const {
    using namespace dsl_syntax;
    require_value(dom.rcp, reg_pack(R10_STACK_POINTER).stack_offset - EBPF_SUBPROGRAM_STACK_SIZE <= lb,
                  "Lower bound must be at least r10.stack_offset - EBPF_SUBPROGRAM_STACK_SIZE");
    require_value(dom.rcp, ub <= EBPF_TOTAL_STACK_SIZE, "Upper bound must be at most EBPF_TOTAL_STACK_SIZE");
}

void EbpfChecker::check_access_context(const LinearExpression& lb, const LinearExpression& ub) const {
    using namespace dsl_syntax;
    require_value(dom.rcp, lb >= 0, "Lower bound must be at least 0");
    require_value(dom.rcp, ub <= thread_local_program_info->type.context_descriptor->size,
                  std::string("Upper bound must be at most ") +
                      std::to_string(thread_local_program_info->type.context_descriptor->size));
}

void EbpfChecker::check_access_packet(const LinearExpression& lb, const LinearExpression& ub,
                                      const std::optional<Variable> packet_size) const {
    using namespace dsl_syntax;
    require_value(dom.rcp, lb >= variable_registry->meta_offset(), "Lower bound must be at least meta_offset");
    if (packet_size) {
        require_value(dom.rcp, ub <= *packet_size, "Upper bound must be at most packet_size");
    } else {
        require_value(dom.rcp, ub <= MAX_PACKET_SIZE,
                      std::string{"Upper bound must be at most "} + std::to_string(MAX_PACKET_SIZE));
    }
}

void EbpfChecker::check_access_shared(const LinearExpression& lb, const LinearExpression& ub,
                                      const Variable shared_region_size) const {
    using namespace dsl_syntax;
    require_value(dom.rcp, lb >= 0, "Lower bound must be at least 0");
    require_value(dom.rcp, ub <= shared_region_size,
                  std::string("Upper bound must be at most ") + variable_registry->name(shared_region_size));
}

void EbpfChecker::operator()(const Comparable& s) const {
    using namespace dsl_syntax;
    if (dom.rcp.types.same_type(s.r1, s.r2)) {
        // Same type. If both are numbers, that's okay. Otherwise:
        TypeDomain non_number_types = dom.rcp.types;
        non_number_types.add_constraint(type_is_not_number(s.r2));
        // We must check that they belong to a singleton region:
        if (!non_number_types.is_in_group(s.r1, TypeGroup::singleton_ptr) &&
            !non_number_types.is_in_group(s.r1, TypeGroup::map_fd)) {
            throw_fail("Cannot subtract pointers to non-singleton regions");
        }
        // And, to avoid wraparound errors, they must be within bounds.
        this->operator()(ValidAccess{MAX_CALL_STACK_FRAMES, s.r1, 0, Imm{0}, false});
        this->operator()(ValidAccess{MAX_CALL_STACK_FRAMES, s.r2, 0, Imm{0}, false});
    } else {
        // _Maybe_ different types, so r2 must be a number.
        // We checked in a previous assertion that r1 is a pointer or a number.
        require_type(dom.rcp, type_is_number(s.r2), "Cannot subtract pointers to different regions");
    }
}

void EbpfChecker::operator()(const Addable& s) const {
    if (!dom.rcp.types.implies(type_is_pointer(s.ptr), type_is_number(s.num))) {
        throw_fail("Only numbers can be added to pointers");
    }
}

void EbpfChecker::operator()(const ValidDivisor& s) const {
    using namespace dsl_syntax;
    if (!dom.rcp.types.implies(type_is_pointer(s.reg), type_is_number(s.reg))) {
        throw_fail("Only numbers can be used as divisors");
    }
    if (!thread_local_options.allow_division_by_zero) {
        const auto reg = reg_pack(s.reg);
        const auto v = s.is_signed ? reg.svalue : reg.uvalue;
        require_value(dom.rcp, v != 0, "Possible division by zero");
    }
}

void EbpfChecker::operator()(const ValidStore& s) const {
    if (!dom.rcp.types.implies(type_is_not_stack(s.mem), type_is_number(s.val))) {
        throw_fail("Only numbers can be stored to externally-visible regions");
    }
}

void EbpfChecker::operator()(const TypeConstraint& s) const {
    if (!dom.rcp.types.is_in_group(s.reg, s.types)) {
        throw_fail("Invalid type");
    }
}

void EbpfChecker::operator()(const BoundedLoopCount& s) const {
    // Enforces an upper bound on loop iterations by checking that the loop counter
    // does not exceed the specified limit
    using namespace dsl_syntax;
    const auto counter = variable_registry->loop_counter(to_string(s.name));
    require_value(dom.rcp, counter <= BoundedLoopCount::limit, "Loop counter is too large");
}

void EbpfChecker::operator()(const FuncConstraint& s) const {
    // Look up the helper function id.
    if (dom.rcp.is_bottom()) {
        return;
    }
    const auto src_interval = dom.rcp.values.eval_interval(reg_pack(s.reg).svalue);
    if (const auto sn = src_interval.singleton()) {
        if (sn->fits<int32_t>()) {
            // We can now process it as if the id was immediate.
            const int32_t imm = sn->cast_to<int32_t>();
            if (!thread_local_program_info->platform->is_helper_usable(imm)) {
                throw_fail("invalid helper function id " + std::to_string(imm));
            }
            const Call call = make_call(imm, *thread_local_program_info->platform);
            for (const Assertion& sub_assertion : get_assertions(call, *thread_local_program_info, {})) {
                // TODO: create explicit sub assertions elsewhere
                EbpfChecker{dom, sub_assertion}.visit();
            }
            return;
        }
    }
    throw_fail("callx helper function id is not a valid singleton");
}

void EbpfChecker::operator()(const ValidSize& s) const {
    using namespace dsl_syntax;
    const auto r = reg_pack(s.reg);
    require_value(dom.rcp, s.can_be_zero ? r.svalue >= 0 : r.svalue > 0, "Invalid size");
}

void EbpfChecker::operator()(const ValidCall& s) const {
    if (!s.stack_frame_prefix.empty()) {
        const EbpfHelperPrototype proto = thread_local_program_info->platform->get_helper_prototype(s.func);
        if (proto.return_type == EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED) {
            throw_fail("tail call not supported in subprogram");
        }
    }
}

void EbpfChecker::operator()(const ValidMapKeyValue& s) const {
    using namespace dsl_syntax;

    const auto fd_type = dom.get_map_type(s.map_fd_reg);

    const auto access_reg = reg_pack(s.access_reg);
    int width;
    if (s.key) {
        const auto key_size = dom.get_map_key_size(s.map_fd_reg).singleton();
        if (!key_size.has_value()) {
            throw_fail("Map key size is not singleton");
        }
        width = key_size->narrow<int>();
    } else {
        const auto value_size = dom.get_map_value_size(s.map_fd_reg).singleton();
        if (!value_size.has_value()) {
            throw_fail("Map value size is not singleton");
        }
        width = value_size->narrow<int>();
    }

    for (const auto access_reg_type : dom.rcp.enumerate_types(s.access_reg)) {
        if (access_reg_type == T_STACK) {
            Interval offset = dom.rcp.values.eval_interval(access_reg.stack_offset);
            if (!dom.stack.all_num_width(offset, Interval{width})) {
                auto lb_is = offset.lb().number();
                std::string lb_s = lb_is && lb_is->fits<int32_t>() ? std::to_string(lb_is->narrow<int32_t>()) : "-oo";
                Interval ub = offset + Interval{width};
                auto ub_is = ub.ub().number();
                std::string ub_s = ub_is && ub_is->fits<int32_t>() ? std::to_string(ub_is->narrow<int32_t>()) : "oo";
                require_value(dom.rcp, LinearConstraint::false_const(),
                              "Illegal map update with a non-numerical value [" + lb_s + "-" + ub_s + ")");
            } else if (thread_local_options.strict && fd_type.has_value()) {
                EbpfMapType map_type = thread_local_program_info->platform->get_map_type(*fd_type);
                if (map_type.is_array) {
                    // Get offset value.
                    Variable key_ptr = access_reg.stack_offset;
                    std::optional<Number> offset_num = dom.rcp.values.eval_interval(key_ptr).singleton();
                    if (!offset_num.has_value()) {
                        throw_fail("Pointer must be a singleton");
                    } else if (s.key) {
                        // Look up the value pointed to by the key pointer.
                        Variable key_value =
                            variable_registry->cell_var(DataKind::svalues, offset_num.value(), sizeof(uint32_t));

                        if (auto max_entries = dom.get_map_max_entries(s.map_fd_reg).lb().number()) {
                            require_value(dom.rcp, key_value < *max_entries, "Array index overflow");
                        } else {
                            throw_fail("Max entries is not finite");
                        }
                        require_value(dom.rcp, key_value >= 0, "Array index underflow");
                    }
                }
            }
        } else if (access_reg_type == T_PACKET) {
            Variable lb = access_reg.packet_offset;
            LinearExpression ub = lb + width;
            check_access_packet(lb, ub, {});
            // Packet memory is both readable and writable.
        } else if (access_reg_type == T_SHARED) {
            Variable lb = access_reg.shared_offset;
            LinearExpression ub = lb + width;
            check_access_shared(lb, ub, access_reg.shared_region_size);
            require_value(dom.rcp, access_reg.svalue > 0, "Possible null access");
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
    for (const auto type : dom.rcp.enumerate_types(s.reg)) {
        switch (type) {
        case T_PACKET: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.packet_offset);
            const std::optional<Variable> packet_size =
                is_comparison_check ? std::optional<Variable>{} : variable_registry->packet_size();
            check_access_packet(lb, ub, packet_size);
            // if within bounds, it can never be null
            // Context memory is both readable and writable.
            break;
        }
        case T_STACK: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.stack_offset);
            check_access_stack(lb, ub);
            // if within bounds, it can never be null
            if (s.access_type == AccessType::read &&
                !dom.stack.all_num_lb_ub(dom.rcp.values.eval_interval(lb), dom.rcp.values.eval_interval(ub))) {

                if (s.offset < 0) {
                    throw_fail("Stack content is not numeric");
                } else {
                    using namespace dsl_syntax;
                    LinearExpression w = std::holds_alternative<Imm>(s.width)
                                             ? LinearExpression{std::get<Imm>(s.width).v}
                                             : reg_pack(std::get<Reg>(s.width)).svalue;

                    require_value(dom.rcp, w <= reg.stack_numeric_size - s.offset, "Stack content is not numeric");
                }
            }
            break;
        }
        case T_CTX: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.ctx_offset);
            check_access_context(lb, ub);
            // if within bounds, it can never be null
            // The context is both readable and writable.
            break;
        }
        case T_SHARED: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.shared_offset);
            check_access_shared(lb, ub, reg.shared_region_size);
            if (!is_comparison_check && !s.or_null) {
                require_value(dom.rcp, reg.svalue > 0, "Possible null access");
            }
            // Shared memory is zero-initialized when created so is safe to read and write.
            break;
        }
        case T_NUM:
            if (!is_comparison_check) {
                if (s.or_null) {
                    require_value(dom.rcp, reg.svalue == 0, "Non-null number");
                } else {
                    throw_fail("Only pointers can be dereferenced");
                }
            }
            break;
        case T_MAP:
        case T_MAP_PROGRAMS:
            if (!is_comparison_check) {
                throw_fail("FDs cannot be dereferenced directly");
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
    if (s.or_null && dom.rcp.types.get_type(s.reg) == T_NUM && dom.rcp.values.entail(reg.uvalue == 0)) {
        return;
    }
    require_value(dom.rcp, reg.ctx_offset == 0, "Nonzero context offset");
}

} // namespace prevail

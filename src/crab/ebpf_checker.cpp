// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.

#include <bitset>
#include <optional>
#include <utility>

#include "arith/dsl_syntax.hpp"
#include "asm_syntax.hpp"
#include "asm_unmarshal.hpp"
#include "config.hpp"
#include "crab/array_domain.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/var_registry.hpp"
#include "platform.hpp"
#include "program.hpp"

namespace prevail {

static bool check_require(const NumAbsDomain& inv, const LinearConstraint& cst) {
    if (inv.is_bottom()) {
        return true;
    }
    if (cst.is_contradiction()) {
        return false;
    }
    if (inv.entail(cst)) {
        // XXX: add_redundant(s);
        return true;
    }
    if (inv.intersect(cst)) {
        // XXX: add_error() if imply negation
        return false;
    }
    return false;
}

using OnRequire = std::function<void(NumAbsDomain&, const LinearConstraint&, const std::string&)>;

class EbpfChecker final {
  public:
    explicit EbpfChecker(EbpfDomain& dom, const Assertion& assertion, const OnRequire& on_require)
        : assertion{assertion}, on_require{on_require}, dom(dom), values(dom.rcp.values), stack(dom.stack),
          types(dom.rcp.types) {}

    void visit(const Assertion& assertion) { std::visit(*this, assertion); }

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
    std::string create_warning(const std::string& s) const { return s + " (" + to_string(assertion) + ")"; }

    void require(NumAbsDomain& inv, const LinearConstraint& cst, const std::string& msg) const {
        on_require(inv, cst, create_warning(msg));
    }

    void require(const std::string& msg) const { require(values, LinearConstraint::false_const(), msg); }

    // memory check / load / store
    void check_access_stack(NumAbsDomain& inv, const LinearExpression& lb, const LinearExpression& ub) const;
    void check_access_context(NumAbsDomain& inv, const LinearExpression& lb, const LinearExpression& ub) const;
    void check_access_packet(NumAbsDomain& inv, const LinearExpression& lb, const LinearExpression& ub,
                             std::optional<Variable> packet_size) const;
    void check_access_shared(NumAbsDomain& inv, const LinearExpression& lb, const LinearExpression& ub,
                             Variable shared_region_size) const;

  private:
    const Assertion assertion;
    const OnRequire on_require;

    EbpfDomain& dom;
    // shorthands:
    NumAbsDomain& values;
    ArrayDomain& stack;
    TypeDomain& types;
};

void ebpf_domain_assume(EbpfDomain& dom, const Assertion& assertion) {
    if (dom.is_bottom()) {
        return;
    }
    EbpfChecker{dom, assertion,
                [](NumAbsDomain& inv, const LinearConstraint& cst, const std::string&) {
                    // avoid redundant errors
                    inv.add_constraint(cst);
                }}
        .visit(assertion);
}

std::vector<std::string> ebpf_domain_check(const EbpfDomain& dom, const Assertion& assertion) {
    if (dom.is_bottom()) {
        return {};
    }
    EbpfDomain copy = dom;
    std::vector<std::string> warnings;
    EbpfChecker checker{copy, assertion,
                        [&warnings](const NumAbsDomain& inv, const LinearConstraint& cst, const std::string& msg) {
                            if (!check_require(inv, cst)) {
                                warnings.push_back(msg);
                            }
                        }};
    checker.visit(assertion);
    return warnings;
}

void EbpfChecker::check_access_stack(NumAbsDomain& inv, const LinearExpression& lb, const LinearExpression& ub) const {
    using namespace dsl_syntax;
    const Variable r10_stack_offset = reg_pack(R10_STACK_POINTER).stack_offset;
    const auto interval = inv.eval_interval(r10_stack_offset);
    if (interval.is_singleton()) {
        const int64_t stack_offset = interval.singleton()->cast_to<int64_t>();
        require(inv, lb >= stack_offset - EBPF_SUBPROGRAM_STACK_SIZE,
                "Lower bound must be at least r10.stack_offset - EBPF_SUBPROGRAM_STACK_SIZE");
    }
    require(inv, ub <= EBPF_TOTAL_STACK_SIZE, "Upper bound must be at most EBPF_TOTAL_STACK_SIZE");
}

void EbpfChecker::check_access_context(NumAbsDomain& inv, const LinearExpression& lb,
                                       const LinearExpression& ub) const {
    using namespace dsl_syntax;
    require(inv, lb >= 0, "Lower bound must be at least 0");
    require(inv, ub <= thread_local_program_info->type.context_descriptor->size,
            std::string("Upper bound must be at most ") +
                std::to_string(thread_local_program_info->type.context_descriptor->size));
}

void EbpfChecker::check_access_packet(NumAbsDomain& inv, const LinearExpression& lb, const LinearExpression& ub,
                                      const std::optional<Variable> packet_size) const {
    using namespace dsl_syntax;
    require(inv, lb >= variable_registry->meta_offset(), "Lower bound must be at least meta_offset");
    if (packet_size) {
        require(inv, ub <= *packet_size, "Upper bound must be at most packet_size");
    } else {
        require(inv, ub <= MAX_PACKET_SIZE,
                std::string{"Upper bound must be at most "} + std::to_string(MAX_PACKET_SIZE));
    }
}

void EbpfChecker::check_access_shared(NumAbsDomain& inv, const LinearExpression& lb, const LinearExpression& ub,
                                      const Variable shared_region_size) const {
    using namespace dsl_syntax;
    require(inv, lb >= 0, "Lower bound must be at least 0");
    require(inv, ub <= shared_region_size,
            std::string("Upper bound must be at most ") + variable_registry->name(shared_region_size));
}

void EbpfChecker::operator()(const Comparable& s) const {
    using namespace dsl_syntax;
    if (types.same_type(s.r1, s.r2)) {
        // Same type. If both are numbers, that's okay. Otherwise:
        TypeDomain non_number_types = dom.rcp.types;
        non_number_types.add_constraint(type_is_not_number(s.r2));
        // We must check that they belong to a singleton region:
        if (!non_number_types.is_in_group(s.r1, TypeGroup::singleton_ptr) &&
            !non_number_types.is_in_group(s.r1, TypeGroup::map_fd)) {
            require("Cannot subtract pointers to non-singleton regions");
            return;
        }
        // And, to avoid wraparound errors, they must be within bounds.
        this->operator()(ValidAccess{MAX_CALL_STACK_FRAMES, s.r1, 0, Imm{0}, false});
        this->operator()(ValidAccess{MAX_CALL_STACK_FRAMES, s.r2, 0, Imm{0}, false});
    } else {
        // _Maybe_ different types, so r2 must be a number.
        // We checked in a previous assertion that r1 is a pointer or a number.
        require(dom.rcp.types.inv, type_is_number(s.r2), "Cannot subtract pointers to different regions");
    }
}

void EbpfChecker::operator()(const Addable& s) const {
    if (!types.implies(type_is_pointer(s.ptr), type_is_number(s.num))) {
        require("Only numbers can be added to pointers");
    }
}

void EbpfChecker::operator()(const ValidDivisor& s) const {
    using namespace dsl_syntax;
    if (!types.implies(type_is_pointer(s.reg), type_is_number(s.reg))) {
        require("Only numbers can be used as divisors");
    }
    if (!thread_local_options.allow_division_by_zero) {
        const auto reg = reg_pack(s.reg);
        const auto v = s.is_signed ? reg.svalue : reg.uvalue;
        require(values, v != 0, "Possible division by zero");
    }
}

void EbpfChecker::operator()(const ValidStore& s) const {
    if (!types.implies(type_is_not_stack(s.mem), type_is_number(s.val))) {
        require("Only numbers can be stored to externally-visible regions");
    }
}

void EbpfChecker::operator()(const TypeConstraint& s) const {
    if (!types.is_in_group(s.reg, s.types)) {
        require("Invalid type");
    }
}

void EbpfChecker::operator()(const BoundedLoopCount& s) const {
    // Enforces an upper bound on loop iterations by checking that the loop counter
    // does not exceed the specified limit
    using namespace dsl_syntax;
    const auto counter = variable_registry->loop_counter(to_string(s.name));
    require(values, counter <= s.limit, "Loop counter is too large");
}

void EbpfChecker::operator()(const FuncConstraint& s) const {
    // Look up the helper function id.
    if (!values) {
        return;
    }
    const RegPack& reg = reg_pack(s.reg);
    const auto src_interval = values.eval_interval(reg.svalue);
    if (const auto sn = src_interval.singleton()) {
        if (sn->fits<int32_t>()) {
            // We can now process it as if the id was immediate.
            const int32_t imm = sn->cast_to<int32_t>();
            if (!thread_local_program_info->platform->is_helper_usable(imm)) {
                require("invalid helper function id " + std::to_string(imm));
                return;
            }
            const Call call = make_call(imm, *thread_local_program_info->platform);
            for (const Assertion& sub_assertion : get_assertions(call, *thread_local_program_info, {})) {
                // TODO: create explicit sub assertions elsewhere
                EbpfChecker{dom, sub_assertion, on_require}.visit(sub_assertion);
            }
            return;
        }
    }
    require("callx helper function id is not a valid singleton");
}

void EbpfChecker::operator()(const ValidSize& s) const {
    using namespace dsl_syntax;
    const auto r = reg_pack(s.reg);
    require(values, s.can_be_zero ? r.svalue >= 0 : r.svalue > 0, "Invalid size");
}

void EbpfChecker::operator()(const ValidCall& s) const {
    if (!s.stack_frame_prefix.empty()) {
        const EbpfHelperPrototype proto = thread_local_program_info->platform->get_helper_prototype(s.func);
        if (proto.return_type == EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED) {
            require("tail call not supported in subprogram");
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
            require("Map key size is not singleton");
            return;
        }
        width = key_size->narrow<int>();
    } else {
        const auto value_size = dom.get_map_value_size(s.map_fd_reg).singleton();
        if (!value_size.has_value()) {
            require("Map value size is not singleton");
            return;
        }
        width = value_size->narrow<int>();
    }

    dom.rcp = dom.rcp.join_over_types(s.access_reg, [&](TypeToNumDomain& rcp, TypeEncoding access_reg_type) {
        if (access_reg_type == T_STACK) {
            Interval offset = rcp.values.eval_interval(access_reg.stack_offset);
            if (!stack.all_num(offset, Interval{width})) {
                auto lb_is = offset.lb().number();
                std::string lb_s = lb_is && lb_is->fits<int32_t>() ? std::to_string(lb_is->narrow<int32_t>()) : "-oo";
                Interval ub = offset + Interval{width};
                auto ub_is = ub.ub().number();
                std::string ub_s = ub_is && ub_is->fits<int32_t>() ? std::to_string(ub_is->narrow<int32_t>()) : "oo";
                require(rcp.values, LinearConstraint::false_const(),
                        "Illegal map update with a non-numerical value [" + lb_s + "-" + ub_s + ")");
            } else if (thread_local_options.strict && fd_type.has_value()) {
                EbpfMapType map_type = thread_local_program_info->platform->get_map_type(*fd_type);
                if (map_type.is_array) {
                    // Get offset value.
                    Variable key_ptr = access_reg.stack_offset;
                    std::optional<Number> offset = rcp.values.eval_interval(key_ptr).singleton();
                    if (!offset.has_value()) {
                        require("Pointer must be a singleton");
                    } else if (s.key) {
                        // Look up the value pointed to by the key pointer.
                        Variable key_value =
                            variable_registry->cell_var(DataKind::svalues, offset.value(), sizeof(uint32_t));

                        if (auto max_entries = dom.get_map_max_entries(s.map_fd_reg).lb().number()) {
                            require(rcp.values, key_value < *max_entries, "Array index overflow");
                        } else {
                            require("Max entries is not finite");
                        }
                        require(rcp.values, key_value >= 0, "Array index underflow");
                    }
                }
            }
        } else if (access_reg_type == T_PACKET) {
            Variable lb = access_reg.packet_offset;
            LinearExpression ub = lb + width;
            check_access_packet(rcp.values, lb, ub, {});
            // Packet memory is both readable and writable.
        } else if (access_reg_type == T_SHARED) {
            Variable lb = access_reg.shared_offset;
            LinearExpression ub = lb + width;
            check_access_shared(rcp.values, lb, ub, access_reg.shared_region_size);
            require(rcp.values, access_reg.svalue > 0, "Possible null access");
            // Shared memory is zero-initialized when created so is safe to read and write.
        } else {
            require("Only stack or packet can be used as a parameter");
        }
    });
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
    // join_over_types instead of simple iteration is only needed for assume-assert
    dom.rcp = dom.rcp.join_over_types(s.reg, [&](TypeToNumDomain& rcp, TypeEncoding type) {
        switch (type) {
        case T_PACKET: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.packet_offset);
            check_access_packet(rcp.values, lb, ub,
                                is_comparison_check ? std::optional<Variable>{} : variable_registry->packet_size());
            // if within bounds, it can never be null
            // Context memory is both readable and writable.
            break;
        }
        case T_STACK: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.stack_offset);
            check_access_stack(rcp.values, lb, ub);
            // if within bounds, it can never be null
            if (s.access_type == AccessType::read &&
                !stack.all_num(rcp.values.eval_interval(lb), rcp.values.eval_interval(ub - lb))) {

                if (s.offset < 0) {
                    require("Stack content is not numeric");
                } else {
                    using namespace dsl_syntax;
                    LinearExpression w = std::holds_alternative<Imm>(s.width)
                                             ? LinearExpression{std::get<Imm>(s.width).v}
                                             : reg_pack(std::get<Reg>(s.width)).svalue;

                    require(rcp.values, w <= reg.stack_numeric_size - s.offset, "Stack content is not numeric");
                }
            }
            break;
        }
        case T_CTX: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.ctx_offset);
            check_access_context(rcp.values, lb, ub);
            // if within bounds, it can never be null
            // The context is both readable and writable.
            break;
        }
        case T_SHARED: {
            auto [lb, ub] = lb_ub_access_pair(s, reg.shared_offset);
            check_access_shared(rcp.values, lb, ub, reg.shared_region_size);
            if (!is_comparison_check && !s.or_null) {
                require(rcp.values, reg.svalue > 0, "Possible null access");
            }
            // Shared memory is zero-initialized when created so is safe to read and write.
            break;
        }
        case T_NUM:
            if (!is_comparison_check) {
                if (s.or_null) {
                    require(rcp.values, reg.svalue == 0, "Non-null number");
                } else {
                    require("Only pointers can be dereferenced");
                }
            }
            break;
        case T_MAP:
        case T_MAP_PROGRAMS:
            if (!is_comparison_check) {
                require("FDs cannot be dereferenced directly");
            }
            break;
        default: require("Invalid type"); break;
        }
    });
}

void EbpfChecker::operator()(const ZeroCtxOffset& s) const {
    using namespace dsl_syntax;
    const auto reg = reg_pack(s.reg);
    require(values, reg.ctx_offset == 0, "Nonzero context offset");
}

} // namespace prevail

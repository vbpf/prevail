// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// ReSharper disable CppMemberFunctionMayBeStatic

// This file is eBPF-specific, not derived from CRAB.
#include <functional>
#include <map>
#include <optional>

#include "arith/dsl_syntax.hpp"
#include "arith/variable.hpp"
#include "crab/array_domain.hpp"
#include "crab/ebpf_domain.hpp" // for join_selective
#include "crab/split_dbm.hpp"
#include "crab/type_domain.hpp"
#include "crab/type_encoding.hpp"
#include "crab/var_registry.hpp"
#include "crab_utils/debug.hpp"

namespace prevail {

template <is_enum T>
static void operator++(T& t) {
    t = static_cast<T>(1 + static_cast<std::underlying_type_t<T>>(t));
}

std::vector<DataKind> iterate_kinds(const DataKind lb, const DataKind ub) {
    if (lb > ub) {
        CRAB_ERROR("lower bound ", lb, " is greater than upper bound ", ub);
    }
    if (lb < KIND_MIN || ub > KIND_MAX) {
        CRAB_ERROR("bounds ", lb, " and ", ub, " are out of range");
    }
    std::vector<DataKind> res;
    for (DataKind i = lb; i <= ub; ++i) {
        res.push_back(i);
    }
    return res;
}

std::vector<TypeEncoding> iterate_types(const TypeEncoding lb, const TypeEncoding ub) {
    if (lb > ub) {
        CRAB_ERROR("lower bound ", lb, " is greater than upper bound ", ub);
    }
    if (lb < T_MIN || ub > T_MAX) {
        CRAB_ERROR("bounds ", lb, " and ", ub, " are out of range");
    }
    std::vector<TypeEncoding> res;
    for (TypeEncoding i = lb; i <= ub; ++i) {
        res.push_back(i);
    }
    return res;
}

static constexpr auto S_UNINIT = "uninit";
static constexpr auto S_STACK = "stack";
static constexpr auto S_PACKET = "packet";
static constexpr auto S_CTX = "ctx";
static constexpr auto S_MAP_PROGRAMS = "map_fd_programs";
static constexpr auto S_MAP = "map_fd";
static constexpr auto S_NUM = "number";
static constexpr auto S_SHARED = "shared";

std::string name_of(const DataKind kind) {
    switch (kind) {
    case DataKind::ctx_offsets: return "ctx_offset";
    case DataKind::map_fds: return "map_fd";
    case DataKind::packet_offsets: return "packet_offset";
    case DataKind::shared_offsets: return "shared_offset";
    case DataKind::shared_region_sizes: return "shared_region_size";
    case DataKind::stack_numeric_sizes: return "stack_numeric_size";
    case DataKind::stack_offsets: return "stack_offset";
    case DataKind::svalues: return "svalue";
    case DataKind::types: return "type";
    case DataKind::uvalues: return "uvalue";
    }
    return {};
}

DataKind regkind(const std::string& s) {
    static const std::map<std::string, DataKind> string_to_kind{
        {"type", DataKind::types},
        {"ctx_offset", DataKind::ctx_offsets},
        {"map_fd", DataKind::map_fds},
        {"packet_offset", DataKind::packet_offsets},
        {"shared_offset", DataKind::shared_offsets},
        {"stack_offset", DataKind::stack_offsets},
        {"shared_region_size", DataKind::shared_region_sizes},
        {"stack_numeric_size", DataKind::stack_numeric_sizes},
        {"svalue", DataKind::svalues},
        {"uvalue", DataKind::uvalues},
    };
    if (string_to_kind.contains(s)) {
        return string_to_kind.at(s);
    }
    throw std::runtime_error(std::string() + "Bad kind: " + s);
}

std::ostream& operator<<(std::ostream& os, const TypeEncoding s) {
    switch (s) {
    case T_SHARED: return os << S_SHARED;
    case T_STACK: return os << S_STACK;
    case T_PACKET: return os << S_PACKET;
    case T_CTX: return os << S_CTX;
    case T_NUM: return os << S_NUM;
    case T_MAP: return os << S_MAP;
    case T_MAP_PROGRAMS: return os << S_MAP_PROGRAMS;
    case T_UNINIT: return os << S_UNINIT;
    default: CRAB_ERROR("Unsupported type encoding", s);
    }
}

TypeEncoding string_to_type_encoding(const std::string& s) {
    static std::map<std::string, TypeEncoding> string_to_type{
        {S_UNINIT, T_UNINIT}, {S_MAP_PROGRAMS, T_MAP_PROGRAMS},
        {S_MAP, T_MAP},       {S_NUM, T_NUM},
        {S_CTX, T_CTX},       {S_STACK, T_STACK},
        {S_PACKET, T_PACKET}, {S_SHARED, T_SHARED},
    };
    if (string_to_type.contains(s)) {
        return string_to_type[s];
    }
    throw std::runtime_error(std::string("Unsupported type name: ") + s);
}

RegPack reg_pack(const int i) {
    return {
        variable_registry->reg(DataKind::svalues, i),
        variable_registry->reg(DataKind::uvalues, i),
        variable_registry->reg(DataKind::ctx_offsets, i),
        variable_registry->reg(DataKind::map_fds, i),
        variable_registry->reg(DataKind::packet_offsets, i),
        variable_registry->reg(DataKind::shared_offsets, i),
        variable_registry->reg(DataKind::stack_offsets, i),
        variable_registry->reg(DataKind::types, i),
        variable_registry->reg(DataKind::shared_region_sizes, i),
        variable_registry->reg(DataKind::stack_numeric_sizes, i),
    };
}

static const std::map<TypeEncoding, std::vector<DataKind>> type_to_kinds{
    {T_CTX, {DataKind::ctx_offsets}},
    {T_MAP, {DataKind::map_fds}},
    {T_MAP_PROGRAMS, {DataKind::map_fds}},
    {T_PACKET, {DataKind::packet_offsets}},
    {T_SHARED, {DataKind::shared_offsets, DataKind::shared_region_sizes}},
    {T_STACK, {DataKind::stack_offsets, DataKind::stack_numeric_sizes}},
};

/**
 * @brief Identifies type-specific ("kind") variables that are meaningless for the given domain.
 *
 * @details This function is a helper for the type-aware subsumption check (`operator<=`).
 *
 * **The Core Principle:** In EbpfDomain, a "kind" variable (e.g., `r1.packet_offset`) is
 * only meaningful if the register might have the corresponding type (`T_PACKET`). If the
 * type is absent, the kind variable is conceptually **Bottom**.
 *
 * **Role in Subsumption:** A standard numerical check would incorrectly treat these Bottom
 * variables as Top (unconstrained), failing correct checks like
 *      `{r1.type=T_NUM} <= {r1.type=T_PACKET, r1.packet_offset=5}`
 * This function finds these variables so the `operator<=` can handle them correctly,
 * ensuring the subsumption check is sound.
 *
 * @param[in] dom The numerical domain to inspect.
 * @return A vector of all kind variables that are meaningless (effectively Bottom) in `dom`.
 */
std::vector<Variable> TypeDomain::get_nonexistent_kind_variables(const NumAbsDomain& dom) const {
    std::vector<Variable> res;
    for (const Variable v : variable_registry->get_type_variables()) {
        for (const auto& [type, kinds] : type_to_kinds) {
            if (may_have_type(dom, v, type)) {
                // This type might be present in the register's type set, so its kind
                // variables are meaningful and should not be ignored.
                continue;
            }
            for (const auto kind : kinds) {
                // This type is definitely not present, so any associated kind variables
                // are meaningless for this domain.
                Variable type_offset = variable_registry->kind_var(kind, v);
                res.push_back(type_offset);
            }
        }
    }
    return res;
}

/**
 * @brief Collects type-specific constraints that are present in only one of two domains.
 *
 * @details This function is a helper for the type-aware join operation (`operator|`).
 *
 * **The Core Principle:** In EbpfDomain, a "kind" variable (e.g., `r1.packet_offset`) is
 * only meaningful if the register might have the corresponding type (`T_PACKET`). If the
 * type is absent, the kind variable is conceptually **Bottom**.
 *
 * **Role in Join:** During a join, if one branch has constraints on `packet_offset`
 * (because the type is `T_PACKET`) and the other doesn't, a naive join would lose
 * those constraints. This function identifies such constraints so that the `operator|`
 * can correctly preserve them, creating a sound and precise union of the two states.
 *
 * @param[in] left The numerical domain from the first branch of the join.
 * @param[in] right The numerical domain from the second branch of the join.
 * @return A vector containing the variable, which domain it came from (`true` if left),
 * and its interval value, for each type-specific constraint to be preserved.
 */
std::vector<std::tuple<Variable, bool, Interval>>
TypeDomain::collect_type_dependent_constraints(const NumAbsDomain& left, const NumAbsDomain& right) const {
    std::vector<std::tuple<Variable, bool, Interval>> result;

    for (const Variable& type_var : variable_registry->get_type_variables()) {
        for (const auto& [type, kinds] : type_to_kinds) {
            const bool in_left = may_have_type(left, type_var, type);
            const bool in_right = may_have_type(right, type_var, type);

            // If a type may be present in one domain but not the other, its
            // dependent constraints must be explicitly preserved.
            if (in_left != in_right) {
                // Identify which domain contains the constraints.
                const NumAbsDomain& source = in_left ? left : right;
                for (const DataKind kind : kinds) {
                    Variable var = variable_registry->kind_var(kind, type_var);
                    Interval value = source.eval_interval(var);
                    if (!value.is_top()) {
                        result.emplace_back(var, in_left, value);
                    }
                }
            }
        }
    }

    return result;
}

void TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, const Reg& rhs) {
    inv.assign(reg_pack(lhs).type, reg_pack(rhs).type);
}

void TypeDomain::assign_type(NumAbsDomain& inv, const std::optional<Variable> lhs, const LinearExpression& t) {
    inv.assign(lhs, t);
}

void TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, const std::optional<LinearExpression>& rhs) {
    inv.assign(reg_pack(lhs).type, rhs);
}

void TypeDomain::havoc_type(NumAbsDomain& inv, const Reg& r) { inv.havoc(reg_pack(r).type); }

TypeEncoding TypeDomain::get_type(const NumAbsDomain& inv, const LinearExpression& v) const {
    const auto res = inv.eval_interval(v).singleton();
    if (!res) {
        return T_UNINIT;
    }
    return res->narrow<TypeEncoding>();
}

TypeEncoding TypeDomain::get_type(const NumAbsDomain& inv, const Reg& r) const {
    const auto res = inv.eval_interval(reg_pack(r).type).singleton();
    if (!res) {
        return T_UNINIT;
    }
    return res->narrow<TypeEncoding>();
}

// Check whether a given type value is within the range of a given type variable's value.
bool TypeDomain::may_have_type(const NumAbsDomain& inv, const Reg& r, const TypeEncoding type) const {
    const Interval interval = inv.eval_interval(reg_pack(r).type);
    return interval.contains(type);
}

bool TypeDomain::may_have_type(const NumAbsDomain& inv, const LinearExpression& v, const TypeEncoding type) const {
    const Interval interval = inv.eval_interval(v);
    return interval.contains(type);
}

NumAbsDomain TypeDomain::join_over_types(const NumAbsDomain& inv, const Reg& reg,
                                         const std::function<void(NumAbsDomain&, TypeEncoding)>& transition) const {
    Interval types = inv.eval_interval(reg_pack(reg).type);
    if (types.is_bottom()) {
        return NumAbsDomain::bottom();
    }
    if (types.contains(T_UNINIT)) {
        NumAbsDomain res(inv);
        transition(res, T_UNINIT);
        return res;
    }
    NumAbsDomain res = NumAbsDomain::bottom();
    auto [lb, ub] = types.bound(T_MIN, T_MAX);
    for (TypeEncoding type : iterate_types(lb, ub)) {
        NumAbsDomain tmp(inv);
        transition(tmp, type);
        EbpfDomain::join_selective(res, std::move(tmp)); // res |= tmp;
    }
    return res;
}

NumAbsDomain TypeDomain::join_by_if_else(const NumAbsDomain& inv, const LinearConstraint& condition,
                                         const std::function<void(NumAbsDomain&)>& if_true,
                                         const std::function<void(NumAbsDomain&)>& if_false) const {
    NumAbsDomain true_case(inv.when(condition));
    if_true(true_case);

    NumAbsDomain false_case(inv.when(condition.negate()));
    if_false(false_case);

    return true_case | false_case;
}

static LinearConstraint eq_types(const Reg& a, const Reg& b) {
    using namespace dsl_syntax;
    return eq(reg_pack(a).type, reg_pack(b).type);
}

bool TypeDomain::same_type(const NumAbsDomain& inv, const Reg& a, const Reg& b) const {
    return inv.entail(eq_types(a, b));
}

bool TypeDomain::implies_type(const NumAbsDomain& inv, const LinearConstraint& a, const LinearConstraint& b) const {
    return inv.when(a).entail(b);
}

bool TypeDomain::is_in_group(const NumAbsDomain& inv, const Reg& r, const TypeGroup group) const {
    using namespace dsl_syntax;
    const Variable t = reg_pack(r).type;
    switch (group) {
    case TypeGroup::number: return inv.entail(t == T_NUM);
    case TypeGroup::map_fd: return inv.entail(t == T_MAP);
    case TypeGroup::map_fd_programs: return inv.entail(t == T_MAP_PROGRAMS);
    case TypeGroup::ctx: return inv.entail(t == T_CTX);
    case TypeGroup::packet: return inv.entail(t == T_PACKET);
    case TypeGroup::stack: return inv.entail(t == T_STACK);
    case TypeGroup::shared: return inv.entail(t == T_SHARED);
    case TypeGroup::mem: return inv.entail(t >= T_PACKET);
    case TypeGroup::mem_or_num: return inv.entail(t >= T_NUM) && inv.entail(t != T_CTX);
    case TypeGroup::pointer: return inv.entail(t >= T_CTX);
    case TypeGroup::ptr_or_num: return inv.entail(t >= T_NUM);
    case TypeGroup::stack_or_packet: return inv.entail(t >= T_PACKET) && inv.entail(t <= T_STACK);
    case TypeGroup::singleton_ptr: return inv.entail(t >= T_CTX) && inv.entail(t <= T_STACK);
    default: CRAB_ERROR("Unsupported type group", group);
    }
}

std::string typeset_to_string(const std::vector<TypeEncoding>& items) {
    std::stringstream ss;
    ss << "{";
    for (auto it = items.begin(); it != items.end(); ++it) {
        ss << *it;
        if (std::next(it) != items.end()) {
            ss << ", ";
        }
    }
    ss << "}";
    return ss.str();
}

bool is_singleton_type(const TypeGroup t) {
    switch (t) {
    case TypeGroup::number:
    case TypeGroup::map_fd:
    case TypeGroup::map_fd_programs:
    case TypeGroup::ctx:
    case TypeGroup::packet:
    case TypeGroup::stack:
    case TypeGroup::shared: return true;
    default: return false;
    }
}

std::ostream& operator<<(std::ostream& os, const TypeGroup ts) {
    using namespace prevail;
    static const std::map<TypeGroup, std::string> string_to_type{
        {TypeGroup::number, S_NUM},
        {TypeGroup::map_fd, S_MAP},
        {TypeGroup::map_fd_programs, S_MAP_PROGRAMS},
        {TypeGroup::ctx, S_CTX},
        {TypeGroup::packet, S_PACKET},
        {TypeGroup::stack, S_STACK},
        {TypeGroup::shared, S_SHARED},
        {TypeGroup::mem, typeset_to_string({T_STACK, T_PACKET, T_SHARED})},
        {TypeGroup::pointer, typeset_to_string({T_CTX, T_STACK, T_PACKET, T_SHARED})},
        {TypeGroup::ptr_or_num, typeset_to_string({T_NUM, T_CTX, T_STACK, T_PACKET, T_SHARED})},
        {TypeGroup::stack_or_packet, typeset_to_string({T_STACK, T_PACKET})},
        {TypeGroup::singleton_ptr, typeset_to_string({T_CTX, T_STACK, T_PACKET})},
        {TypeGroup::mem_or_num, typeset_to_string({T_NUM, T_STACK, T_PACKET, T_SHARED})},
    };
    if (string_to_type.contains(ts)) {
        return os << string_to_type.at(ts);
    }
    CRAB_ERROR("Unsupported type group", ts);
}

} // namespace prevail

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

/// Return the kind variables (for example, offset variables) that are meaningless -- that is, whose type is not present
/// in the register's types.  These variables are not used in the domain, so they can be ignored when joining domains.
/// They are effectively Bottom.
std::vector<Variable> TypeDomain::get_nonexistent_variables() const {
    std::vector<Variable> res;
    for (const Variable v : variable_registry->get_type_variables()) {
        for (const auto& [type, kinds] : type_to_kinds) {
            if (has_type(v, type)) {
                // this type is present in the register's types, so the kind variable is meaningful.
                continue;
            }
            for (const auto kind : kinds) {
                // This type is not present in the register's types, so the kind variable is meaningless.
                Variable type_offset = variable_registry->kind_var(kind, v);
                res.push_back(type_offset);
            }
        }
    }
    return res;
}
std::map<Variable, Interval> TypeDomain::recover_type_dependent_constraints(NumAbsDomain& other) const {
    // Some variables are type-specific.  Type-specific variables
    // for a register can exist in the domain whenever the associated
    // type value is present in the register's types interval (and the
    // value is not Top), and are absent otherwise.  That is, we want
    // to track implications of the form
    // "if register R has type=T then R.T_offset has value ...".
    //
    // If a type value is legal in exactly one of the two domains, a
    // normal join operation would remove any type-specific variables
    // from the resulting merged domain since absence from the other
    // would be interpreted to mean Top.
    //
    // However, when the type value is not present in one domain,
    // any type-specific variables for that type are instead to be
    // interpreted as Bottom. So we want to preserve the values of any
    // type-specific variables from the other domain where the type
    // value is legal.
    //
    // Example input:
    //   r1.type=stack, r1.stack_offset=100
    //   r1.type=packet, r1.packet_offset=4
    // Output:
    //   r1.type={stack,packet}, r1.stack_offset=100, r1.packet_offset=4
    std::map<Variable, Interval> result;

    for (const Variable& type_var : variable_registry->get_type_variables()) {
        for (const auto& [type, kinds] : type_to_kinds) {
            const bool in_this = has_type(type_var, type);
            const bool in_other = TypeDomain(other).has_type(type_var, type);

            if (in_this == in_other) {
                continue; // both have or both lack, nothing to do
            }

            const NumAbsDomain& source = in_this ? *inv : other;
            for (const DataKind kind : kinds) {
                Variable v = variable_registry->kind_var(kind, type_var);
                result.emplace(v, source.eval_interval(v));
            }
        }
    }

    return result;
}

void TypeDomain::assign_type(const Reg& lhs, const Reg& rhs) { inv->assign(reg_pack(lhs).type, reg_pack(rhs).type); }

void TypeDomain::assign_type(const std::optional<Variable> lhs, const LinearExpression& t) { inv->assign(lhs, t); }

void TypeDomain::assign_type(const Reg& lhs, const std::optional<LinearExpression>& rhs) {
    inv->assign(reg_pack(lhs).type, rhs);
}

void TypeDomain::havoc_type(const Reg& r) { inv->havoc(reg_pack(r).type); }

TypeEncoding TypeDomain::get_type(const LinearExpression& v) const {
    const auto res = inv->eval_interval(v).singleton();
    if (!res) {
        return T_UNINIT;
    }
    return res->narrow<TypeEncoding>();
}

TypeEncoding TypeDomain::get_type(const Reg& r) const {
    const auto res = inv->eval_interval(reg_pack(r).type).singleton();
    if (!res) {
        return T_UNINIT;
    }
    return res->narrow<TypeEncoding>();
}

// Check whether a given type value is within the range of a given type variable's value.
bool TypeDomain::has_type(const Reg& r, const TypeEncoding type) const {
    const Interval interval = inv->eval_interval(reg_pack(r).type);
    return interval.contains(type);
}

bool TypeDomain::has_type(const LinearExpression& v, const TypeEncoding type) const {
    const Interval interval = inv->eval_interval(v);
    return interval.contains(type);
}

NumAbsDomain TypeDomain::join_over_types(const Reg& reg,
                                         const std::function<void(NumAbsDomain&, TypeEncoding)>& transition) const {
    Interval types = inv->eval_interval(reg_pack(reg).type);
    if (types.is_bottom()) {
        return NumAbsDomain::bottom();
    }
    if (types.contains(T_UNINIT)) {
        NumAbsDomain res(*inv);
        transition(res, T_UNINIT);
        return res;
    }
    NumAbsDomain res = NumAbsDomain::bottom();
    auto [lb, ub] = types.bound(T_MIN, T_MAX);
    for (TypeEncoding type : iterate_types(lb, ub)) {
        NumAbsDomain tmp(*inv);
        transition(tmp, type);
        // auto constraints = TypeDomain(res).recover_type_dependent_constraints(tmp);
        res |= std::move(tmp);
        // for (const auto& [variable, interval] : constraints) {
        //     res.set(variable, interval);
        // }
    }
    return res;
}

NumAbsDomain TypeDomain::join_by_if_else(const LinearConstraint& condition,
                                         const std::function<void(NumAbsDomain&)>& if_true,
                                         const std::function<void(NumAbsDomain&)>& if_false) const {
    NumAbsDomain true_case(inv->when(condition));
    if_true(true_case);

    NumAbsDomain false_case(inv->when(condition.negate()));
    if_false(false_case);

    // auto constraints = TypeDomain(true_case).recover_type_dependent_constraints(false_case);
    // true_case |= std::move(false_case);
    // for (const auto& [variable, interval] : constraints) {
    //     true_case.set(variable, interval);
    // }
    // return true_case;
    return false_case | true_case;
}

static LinearConstraint eq_types(const Reg& a, const Reg& b) {
    using namespace dsl_syntax;
    return eq(reg_pack(a).type, reg_pack(b).type);
}

bool TypeDomain::same_type(const Reg& a, const Reg& b) const { return inv->entail(eq_types(a, b)); }

bool TypeDomain::implies_type(const LinearConstraint& a, const LinearConstraint& b) const {
    return inv->when(a).entail(b);
}

bool TypeDomain::is_in_group(const Reg& r, const TypeGroup group) const {
    using namespace dsl_syntax;
    const Variable t = reg_pack(r).type;
    switch (group) {
    case TypeGroup::number: return inv->entail(t == T_NUM);
    case TypeGroup::map_fd: return inv->entail(t == T_MAP);
    case TypeGroup::map_fd_programs: return inv->entail(t == T_MAP_PROGRAMS);
    case TypeGroup::ctx: return inv->entail(t == T_CTX);
    case TypeGroup::packet: return inv->entail(t == T_PACKET);
    case TypeGroup::stack: return inv->entail(t == T_STACK);
    case TypeGroup::shared: return inv->entail(t == T_SHARED);
    case TypeGroup::mem: return inv->entail(t >= T_PACKET);
    case TypeGroup::mem_or_num: return inv->entail(t >= T_NUM) && inv->entail(t != T_CTX);
    case TypeGroup::pointer: return inv->entail(t >= T_CTX);
    case TypeGroup::ptr_or_num: return inv->entail(t >= T_NUM);
    case TypeGroup::stack_or_packet: return inv->entail(t >= T_PACKET) && inv->entail(t <= T_STACK);
    case TypeGroup::singleton_ptr: return inv->entail(t >= T_CTX) && inv->entail(t <= T_STACK);
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

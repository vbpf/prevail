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
#include "crab/interval.hpp"
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

std::vector<TypeEncoding> TypeDomain::iterate_types(const Reg& reg) const {
    const Interval allowed_types = inv.eval_interval(variable_registry->reg(DataKind::types, reg.v));
    if (!allowed_types) {
        return {};
    }
    if (allowed_types.contains(T_UNINIT)) {
        return {T_UNINIT};
    }
    auto [lb, ub] = allowed_types.bound(T_MIN, T_MAX);
    return prevail::iterate_types(lb, ub);
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

Variable reg_type(const Reg& lhs) { return variable_registry->type_reg(lhs.v); }

void TypeDomain::assign_type(const Reg& lhs, const Reg& rhs) { inv.assign(reg_type(lhs), reg_type(rhs)); }

void TypeDomain::assign_type(const std::optional<Variable> lhs, const LinearExpression& t) { inv.assign(lhs, t); }

void TypeDomain::assign_type(const Reg& lhs, const std::optional<LinearExpression>& rhs) {
    inv.assign(reg_type(lhs), rhs);
}

void TypeDomain::havoc_type(const Reg& r) { inv.havoc(reg_type(r)); }

TypeEncoding TypeDomain::get_type(const LinearExpression& v) const {
    const auto res = inv.eval_interval(v).singleton();
    if (!res) {
        return T_UNINIT;
    }
    return res->narrow<TypeEncoding>();
}

TypeEncoding TypeDomain::get_type(const Reg& r) const {
    const auto res = inv.eval_interval(reg_type(r)).singleton();
    if (!res) {
        return T_UNINIT;
    }
    return res->narrow<TypeEncoding>();
}

// Check whether a given type value is within the range of a given type variable's value.
bool TypeDomain::may_have_type(const Reg& r, const TypeEncoding type) const {
    const Interval interval = inv.eval_interval(reg_type(r));
    return interval.contains(type);
}

bool TypeDomain::may_have_type(const LinearExpression& v, const TypeEncoding type) const {
    const Interval interval = inv.eval_interval(v);
    return interval.contains(type);
}

static LinearConstraint eq_types(const Reg& a, const Reg& b) {
    using namespace dsl_syntax;
    return eq(reg_type(a), reg_type(b));
}

bool TypeDomain::same_type(const Reg& a, const Reg& b) const { return inv.entail(eq_types(a, b)); }

bool TypeDomain::is_in_group(const Reg& r, const TypeGroup group) const {
    using namespace dsl_syntax;
    const Variable t = reg_type(r);
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

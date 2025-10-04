// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <ranges>

#include "arith/variable.hpp"
#include "crab/interval.hpp"
#include "crab/rcp.hpp"
#include "crab/type_domain.hpp"
#include "crab/var_registry.hpp"

namespace prevail {

std::optional<Variable> get_type_offset_variable(const Reg& reg, const int type) {
    RegPack r = reg_pack(reg);
    switch (type) {
    case T_CTX: return r.ctx_offset;
    case T_MAP: return r.map_fd;
    case T_MAP_PROGRAMS: return r.map_fd_programs;
    case T_PACKET: return r.packet_offset;
    case T_SHARED: return r.shared_offset;
    case T_STACK: return r.stack_offset;
    default: return {};
    }
}

std::optional<Variable> TypeToNumDomain::get_type_offset_variable(const Reg& reg) const {
    return prevail::get_type_offset_variable(reg, types.get_type(reg));
}

bool TypeToNumDomain::operator<=(const TypeToNumDomain& other) const {
    if (is_bottom()) {
        return true;
    }
    if (other.is_bottom()) {
        return false;
    }
    // First, check the type domain.
    // For example, if r1 in `this` has type {stack} and r1 in `other` has type {stack, packet},
    // then `this` is less than or equal to `other`.
    if (!(types <= other.types)) {
        return false;
    }
    // Then, check the numeric domain with consideration of type-specific variables.
    TypeToNumDomain tmp{other.types, other.values};
    for (const Variable& v : this->get_nonexistent_kind_variables()) {
        tmp.values.havoc(v);
    }
    return values <= tmp.values;
}

void TypeToNumDomain::join_selective(const TypeToNumDomain& right) {
    if (is_bottom()) {
        *this = std::move(right);
        return;
    }
    if (right.is_bottom()) {
        return;
    }
    auto extra_invariants = collect_type_dependent_constraints(right);
    this->values |= std::move(right.values);
    for (const auto& [variable, interval] : extra_invariants) {
        values.set(variable, interval);
    }
}

void TypeToNumDomain::operator|=(const TypeToNumDomain& other) {
    if (is_bottom()) {
        *this = other;
    }
    if (other.is_bottom()) {
        return;
    }
    this->join_selective(other);
    this->types = types | other.types;
}

TypeToNumDomain TypeToNumDomain::operator&(const TypeToNumDomain& other) const {
    if (auto type_inv = types.meet(other.types)) {
        // TODO: remove unuseful variables from the numeric domain
        return TypeToNumDomain{std::move(*type_inv), values & other.values};
    }
    return TypeToNumDomain{TypeDomain::top(), NumAbsDomain::bottom()};
}

std::vector<Variable> TypeToNumDomain::get_nonexistent_kind_variables() const {
    std::vector<Variable> res;
    for (const Variable v : variable_registry->get_type_variables()) {
        for (const auto& [type, kinds] : type_to_kinds) {
            if (types.may_have_type(v, type)) {
                continue;
            }
            for (const auto kind : kinds) {
                Variable type_offset = variable_registry->kind_var(kind, v);
                res.push_back(type_offset);
            }
        }
    }
    return res;
}

std::vector<std::tuple<Variable, Interval>>
TypeToNumDomain::collect_type_dependent_constraints(const TypeToNumDomain& right) const {
    std::vector<std::tuple<Variable, Interval>> result;

    for (const Variable& type_var : variable_registry->get_type_variables()) {
        for (const auto& [type, kinds] : type_to_kinds) {
            if (kinds.empty()) {
                continue;
            }
            const bool in_left = types.may_have_type(type_var, type);
            const bool in_right = right.types.may_have_type(type_var, type);

            // If a type may be present in one domain but not the other, its
            // dependent constraints must be explicitly preserved.
            if (in_left != in_right) {
                // Identify which domain contains the constraints.
                const NumAbsDomain& source = in_left ? values : right.values;
                for (const DataKind kind : kinds) {
                    Variable var = variable_registry->kind_var(kind, type_var);
                    Interval value = source.eval_interval(var);
                    if (!value.is_top()) {
                        result.emplace_back(var, value);
                    }
                }
            }
        }
    }

    return result;
}

TypeToNumDomain
TypeToNumDomain::join_over_types(const Reg& reg,
                                 const std::function<void(TypeToNumDomain&, TypeEncoding)>& transition) const {
    using namespace dsl_syntax;
    if (!types.is_initialized(reg)) {
        TypeToNumDomain res = *this;
        transition(res, T_UNINIT);
        return res;
    }
    TypeToNumDomain res = bottom();
    const std::vector<TypeEncoding> valid_types = types.iterate_types(reg);
    std::map<TypeEncoding, std::vector<DataKind>> valid_type_to_kinds;
    for (const TypeEncoding type : valid_types) {
        valid_type_to_kinds.emplace(type, type_to_kinds.at(type));
    }
    for (const TypeEncoding type : valid_types) {
        TypeToNumDomain tmp(*this);
        tmp.types.add_constraint(reg_type(reg) == type);
        // This might have changed the type variable of reg.
        // It might also have changed the type variable of other registers, but we don't deal with that.
        for (const auto& [other_type, kinds] : valid_type_to_kinds) {
            if (other_type != type) {
                for (const auto kind : kinds) {
                    tmp.values.havoc(variable_registry->kind_var(kind, reg_type(reg)));
                }
            }
        }
        transition(tmp, type);
        res |= tmp;
    }
    return res;
}

void TypeToNumDomain::assume_type(const LinearConstraint& cst) {
    types.add_constraint(cst);
    if (types.inv.is_bottom()) {
        values.set_to_bottom();
    }
}

void TypeToNumDomain::assign(const Reg& lhs, const Reg& rhs) {
    if (lhs == rhs) {
        return;
    }
    types.assign_type(lhs, rhs);

    values.assign(reg_pack(lhs).svalue, reg_pack(rhs).svalue);
    values.assign(reg_pack(lhs).uvalue, reg_pack(rhs).uvalue);

    for (const auto& type : types.iterate_types(lhs)) {
        for (const auto& kind : type_to_kinds.at(type)) {
            values.havoc(variable_registry->kind_var(kind, reg_type(lhs)));
        }
    }
    for (const auto& type : types.iterate_types(rhs)) {
        for (const auto kind : type_to_kinds.at(type)) {
            const auto lhs_var = variable_registry->kind_var(kind, reg_type(lhs));
            values.assign(lhs_var, variable_registry->kind_var(kind, reg_type(rhs)));
        }
    }
}

TypeToNumDomain TypeToNumDomain::widen(const TypeToNumDomain& other) const {
    auto extra_invariants = collect_type_dependent_constraints(other);

    TypeToNumDomain res{types.widen(other.types), values.widen(other.values)};

    // Now add in the extra invariants saved above.
    for (const auto& [variable, interval] : extra_invariants) {
        res.values.set(variable, interval);
    }
    return res;
}

TypeToNumDomain TypeToNumDomain::narrow(const TypeToNumDomain& rcp) const {
    return TypeToNumDomain{types.narrow(rcp.types), values.narrow(rcp.values)};
}

StringInvariant TypeToNumDomain::to_set() const {
    if (is_bottom()) {
        return StringInvariant::bottom();
    }
    return types.to_set() + values.to_set();
}
} // namespace prevail
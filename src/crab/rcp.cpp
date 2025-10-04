// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <ranges>

#include "arith/variable.hpp"
#include "crab/interval.hpp"
#include "crab/rcp.hpp"
#include "crab/type_domain.hpp"
#include "crab/var_registry.hpp"

namespace prevail {

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
    for (const auto& [variable, in_left, interval] : extra_invariants) {
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

std::vector<std::tuple<Variable, bool, Interval>>
TypeToNumDomain::collect_type_dependent_constraints(const TypeToNumDomain& right) const {
    std::vector<std::tuple<Variable, bool, Interval>> result;

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
                        result.emplace_back(var, in_left, value);
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

    for (const auto& kind : iterate_kinds(DataKind::ctx_offsets)) {
        const auto lhs_var = variable_registry->kind_var(kind, reg_type(lhs));
        values.havoc(lhs_var);
        for (const auto type : kind_to_types.at(kind)) {
            if (types.may_have_type(rhs, type)) {
                values.assign(lhs_var, variable_registry->kind_var(kind, reg_type(rhs)));
                break;
            }
        }
    }
}

TypeToNumDomain TypeToNumDomain::widen(const TypeToNumDomain& rcp) const {
    return TypeToNumDomain{types.widen(rcp.types), values.widen(rcp.values)};
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
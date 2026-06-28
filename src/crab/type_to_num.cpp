// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cassert>
#include <ranges>

#include "arith/dsl_syntax.hpp"
#include "arith/variable.hpp"
#include "crab/interval.hpp"
#include "crab/region_semantics.hpp"
#include "crab/type_domain.hpp"
#include "crab/type_to_num.hpp"
#include "crab/var_registry.hpp"

namespace prevail {

// Intersect two binding tables: an entry survives iff both sides hold the same
// key with an identical record. Shared by join, meet, and widen/narrow.
static std::map<Reg, PtrSumBinding>
intersect_bindings(const std::map<Reg, PtrSumBinding>& left, const std::map<Reg, PtrSumBinding>& right) {
    std::map<Reg, PtrSumBinding> result;
    for (const auto& [intermediate, binding] : left) {
        const auto it = right.find(intermediate);
        if (it != right.end() && it->second == binding) {
            result.emplace(intermediate, binding);
        }
    }
    return result;
}

std::optional<Variable> TypeToNumDomain::primary_kind_variable_for_type(const Reg& reg) const {
    const auto type = types.get_type(reg);
    if (!type) {
        return {};
    }
    return prevail::primary_kind_variable_for_type(reg, *type);
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
    if (!(values <= tmp.values)) {
        return false;
    }
    // Bindings are extra constraints, so `this <= other` requires every binding
    // in `other` to also be in `this`.
    if (other.ptr_sum_bindings.empty()) {
        return true;
    }
    for (const auto& [intermediate, binding] : other.ptr_sum_bindings) {
        const auto it = ptr_sum_bindings.find(intermediate);
        if (it == ptr_sum_bindings.end() || it->second != binding) {
            return false;
        }
    }
    return true;
}

void TypeToNumDomain::join_selective(const TypeToNumDomain& right) {
    if (is_bottom()) {
        *this = right;
        return;
    }
    if (right.is_bottom()) {
        return;
    }
    auto extra_invariants = collect_type_dependent_constraints(right);
    this->values |= right.values;
    for (const auto& [variable, interval] : extra_invariants) {
        values.set(variable, interval);
    }
}

void TypeToNumDomain::operator|=(const TypeToNumDomain& other) {
    if (is_bottom()) {
        *this = other;
        // No return: the zone in `other` may not be fully closed. Falling through
        // to join_selective triggers zone self-join, whose closure step tightens
        // difference constraints (e.g. r2.uvalue-r1.uvalue<=-2 vs <=-1).
    }
    if (other.is_bottom()) {
        return;
    }
    this->ptr_sum_bindings = intersect_bindings(this->ptr_sum_bindings, other.ptr_sum_bindings);
    this->join_selective(other);
    this->types |= other.types;
}

void TypeToNumDomain::operator|=(TypeToNumDomain&& other) {
    if (is_bottom()) {
        *this = other;
    }
    if (other.is_bottom()) {
        return;
    }
    this->ptr_sum_bindings = intersect_bindings(this->ptr_sum_bindings, other.ptr_sum_bindings);
    this->join_selective(other);
    this->types |= std::move(other.types);
}

TypeToNumDomain TypeToNumDomain::operator&(const TypeToNumDomain& other) const {
    if (auto type_inv = types.meet(other.types)) {
        // TODO: remove unuseful variables from the numeric domain
        // Intersect bindings, matching join/widen/narrow. A union would be more
        // precise but needs a soundness story we don't have; intersection just
        // conservatively forgets facts.
        TypeToNumDomain result{std::move(*type_inv), values & other.values};
        result.ptr_sum_bindings = intersect_bindings(ptr_sum_bindings, other.ptr_sum_bindings);
        return result;
    }
    return TypeToNumDomain{TypeDomain::top(), NumAbsDomain::bottom()};
}

TypeToNumDomain TypeToNumDomain::operator&(TypeToNumDomain&& other) const {
    if (auto type_inv = types.meet(std::move(other.types))) {
        // TODO: remove unuseful variables from the numeric domain
        TypeToNumDomain result{std::move(*type_inv), values & std::move(other.values)};
        result.ptr_sum_bindings = intersect_bindings(ptr_sum_bindings, other.ptr_sum_bindings);
        return result;
    }
    return {TypeDomain::top(), NumAbsDomain::bottom()};
}

std::vector<Variable> TypeToNumDomain::get_nonexistent_kind_variables() const {
    std::vector<Variable> res;
    for (const Variable v : types.variables()) {
        for (const auto& [type, kinds] : type_to_kinds) {
            if (types.may_have_type(v, type)) {
                continue;
            }
            for (const auto kind : kinds) {
                Variable type_offset = variable_registry.kind_var(kind, v);
                res.push_back(type_offset);
            }
        }
    }
    return res;
}

std::vector<std::tuple<Variable, Interval>>
TypeToNumDomain::collect_type_dependent_constraints(const TypeToNumDomain& right) const {
    std::vector<std::tuple<Variable, Interval>> result;

    // A variable tracked in only one side can still have differing type info
    // (the other side treats it as top), so we iterate the union.
    std::set<Variable> type_vars;
    for (const Variable v : types.variables()) {
        type_vars.insert(v);
    }
    for (const Variable v : right.types.variables()) {
        type_vars.insert(v);
    }
    for (const Variable& type_var : type_vars) {
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
                    Variable var = variable_registry.kind_var(kind, type_var);
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

std::vector<TypeEncoding> TypeToNumDomain::enumerate_types(const Reg& reg) const {
    if (!types.is_initialized(reg)) {
        return {T_UNINIT};
    }
    return types.iterate_types(reg);
}

TypeToNumDomain
TypeToNumDomain::join_over_types(const Reg& reg,
                                 const std::function<void(TypeToNumDomain&, TypeEncoding)>& transition) const {
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
        tmp.types.restrict_to(reg_type(reg), TypeSet{type});
        // This might have changed the type variable of reg.
        // It might also have changed the type variable of other registers, but we don't deal with that.
        for (const auto& [other_type, kinds] : valid_type_to_kinds) {
            if (other_type != type) {
                for (const auto kind : kinds) {
                    tmp.values.havoc(variable_registry.kind_var(kind, reg_type(reg)));
                }
            }
        }
        transition(tmp, type);
        res |= tmp;
    }
    return res;
}

void TypeToNumDomain::havoc_all_locations_having_type(const TypeEncoding type) {
    // Precondition: caller must have checked !is_bottom(). Currently survives a
    // bottom domain only because TypeDomain::variables_with_type returns empty
    // when bottom; encode the assumption so a future change there fails loudly.
    assert(!is_bottom());
    for (const Variable type_variable : types.variables_with_type(type)) {
        types.havoc_type(type_variable);
        values.havoc(variable_registry.kind_var(DataKind::uvalues, type_variable));
        for (const DataKind kind : type_to_kinds.at(type)) {
            values.havoc(variable_registry.kind_var(kind, type_variable));
        }
    }
    // Drop every binding in the region just havoced.
    if (!ptr_sum_bindings.empty()) {
        std::erase_if(ptr_sum_bindings,
                      [type](const auto& kv) { return kv.second.region == type; });
    }
}

void TypeToNumDomain::assign(const Reg& lhs, const Reg& rhs) {
    if (lhs == rhs) {
        return;
    }
    invalidate_ptr_sum_bindings_for(lhs);

    types.assign_type(lhs, rhs);

    values.assign(reg_pack(lhs).uvalue, reg_pack(rhs).uvalue);

    for (const auto& type : types.iterate_types(lhs)) {
        for (const auto& kind : type_to_kinds.at(type)) {
            values.havoc(variable_registry.kind_var(kind, reg_type(lhs)));
        }
    }
    for (const auto& type : types.iterate_types(rhs)) {
        for (const auto kind : type_to_kinds.at(type)) {
            const auto lhs_var = variable_registry.kind_var(kind, reg_type(lhs));
            values.assign(lhs_var, variable_registry.kind_var(kind, reg_type(rhs)));
        }
    }
}

void TypeToNumDomain::havoc_offsets(const Reg& reg) {
    invalidate_ptr_sum_bindings_for(reg);
    const RegPack r = reg_pack(reg);
    values.havoc(r.ctx_offset);
    values.havoc(r.map_fd);
    values.havoc(r.map_fd_programs);
    values.havoc(r.packet_offset);
    values.havoc(r.shared_offset);
    values.havoc(r.shared_region_size);
    values.havoc(r.stack_offset);
    values.havoc(r.stack_numeric_size);
    values.havoc(r.socket_offset);
    values.havoc(r.btf_id_offset);
    values.havoc(r.alloc_mem_offset);
    values.havoc(r.alloc_mem_size);
}

void TypeToNumDomain::havoc_register_except_type(const Reg& reg) {
    invalidate_ptr_sum_bindings_for(reg);
    for (const DataKind kind : iterate_kinds()) {
        values.havoc(variable_registry.reg(kind, reg.v));
    }
}

void TypeToNumDomain::havoc_register(const Reg& reg) {
    // havoc_register_except_type below invalidates bindings.
    types.havoc_type(reg);
    havoc_register_except_type(reg);
}

TypeToNumDomain TypeToNumDomain::widen(const TypeToNumDomain& other) const {
    // Unlike join, widen must NOT re-add type-dependent constraints:
    // narrowing the widened result can defeat termination (see #960).
    TypeToNumDomain result{types.widen(other.types), values.widen(other.values)};
    result.ptr_sum_bindings = intersect_bindings(ptr_sum_bindings, other.ptr_sum_bindings);
    return result;
}

TypeToNumDomain TypeToNumDomain::narrow(const TypeToNumDomain& other) const {
    TypeToNumDomain result{types.narrow(other.types), values.narrow(other.values)};
    result.ptr_sum_bindings = intersect_bindings(ptr_sum_bindings, other.ptr_sum_bindings);
    return result;
}

void TypeToNumDomain::bind_ptr_sum(const Reg& intermediate, const Reg& ptr_src, const Reg& num_src,
                                    const TypeEncoding region) {
    ptr_sum_bindings[intermediate] = PtrSumBinding{ptr_src, num_src, region};
}

void TypeToNumDomain::invalidate_ptr_sum_bindings_for(const Reg& reg) {
    if (ptr_sum_bindings.empty()) {
        return;
    }
    std::erase_if(ptr_sum_bindings, [&reg](const auto& kv) {
        const auto& [intermediate, binding] = kv;
        return intermediate == reg || binding.ptr_src == reg || binding.num_src == reg;
    });
}

std::optional<Variable>
TypeToNumDomain::lookup_ptr_sum_intermediate_offset(const Reg& ptr_src, const Reg& num_src,
                                                    const TypeEncoding region) const {
    using namespace dsl_syntax;
    const auto ptr_src_offset = prevail::primary_kind_variable_for_type(ptr_src, region);
    const auto& num_src_svalue = reg_pack(num_src).svalue;
    for (const auto& [intermediate, binding] : ptr_sum_bindings) {
        if (binding.region != region) {
            continue;
        }
        // Skip if the intermediate's type drifted out of the region.
        if (!types.is_initialized(intermediate) || !types.may_have_type(intermediate, binding.region)) {
            continue;
        }
        // Match ptr_src / num_src directly or via a DBM equality edge
        // (handles clang's post-check MOV into a helper-argument slot).
        if (binding.ptr_src != ptr_src) {
            if (!ptr_src_offset) {
                continue;
            }
            const auto binding_ptr_src_offset = prevail::primary_kind_variable_for_type(binding.ptr_src, region);
            if (!binding_ptr_src_offset || !values.entail(eq(*binding_ptr_src_offset, *ptr_src_offset))) {
                continue;
            }
        }
        if (binding.num_src != num_src) {
            const auto& binding_num_src_svalue = reg_pack(binding.num_src).svalue;
            if (!values.entail(eq(binding_num_src_svalue, num_src_svalue))) {
                continue;
            }
        }
        return prevail::primary_kind_variable_for_type(intermediate, region);
    }
    return {};
}

StringInvariant TypeToNumDomain::to_set() const {
    if (is_bottom()) {
        return StringInvariant::bottom();
    }
    return types.to_set() + values.to_set();
}
} // namespace prevail
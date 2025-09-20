// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <functional>
#include <optional>

#include "arith/variable.hpp"
#include "asm_syntax.hpp" // for Reg
#include "crab/array_domain.hpp"
#include "crab/type_encoding.hpp"

namespace prevail {

struct RegPack {
    Variable svalue; // int64_t value.
    Variable uvalue; // uint64_t value.
    Variable ctx_offset;
    Variable map_fd;
    Variable packet_offset;
    Variable shared_offset;
    Variable stack_offset;
    Variable type;
    Variable shared_region_size;
    Variable stack_numeric_size;
};

RegPack reg_pack(int i);
inline RegPack reg_pack(const Reg r) { return reg_pack(r.v); }

struct TypeDomain {
    void assign_type(NumAbsDomain& inv, const Reg& lhs, const Reg& rhs);
    void assign_type(NumAbsDomain& inv, const Reg& lhs, const std::optional<LinearExpression>& rhs);
    void assign_type(NumAbsDomain& inv, std::optional<Variable> lhs, const LinearExpression& t);

    void havoc_type(NumAbsDomain& inv, const Reg& r);

    [[nodiscard]]
    TypeEncoding get_type(const NumAbsDomain& inv, const LinearExpression& v) const;
    [[nodiscard]]
    TypeEncoding get_type(const NumAbsDomain& inv, const Reg& r) const;

    [[nodiscard]]
    bool may_have_type(const NumAbsDomain& inv, const LinearExpression& v, TypeEncoding type) const;
    [[nodiscard]]
    bool may_have_type(const NumAbsDomain& inv, const Reg& r, TypeEncoding type) const;

    [[nodiscard]]
    bool same_type(const NumAbsDomain& inv, const Reg& a, const Reg& b) const;
    [[nodiscard]]
    bool implies_type(const NumAbsDomain& inv, const LinearConstraint& a, const LinearConstraint& b) const;

    [[nodiscard]]
    NumAbsDomain join_over_types(const NumAbsDomain& inv, const Reg& reg,
                                 const std::function<void(NumAbsDomain&, TypeEncoding)>& transition) const;
    [[nodiscard]]
    NumAbsDomain join_by_if_else(const NumAbsDomain& inv, const LinearConstraint& condition,
                                 const std::function<void(NumAbsDomain&)>& if_true,
                                 const std::function<void(NumAbsDomain&)>& if_false) const;

    std::vector<Variable> get_nonexistent_kind_variables(const NumAbsDomain& dom) const;
    std::vector<DataKind> get_valid_kinds(const NumAbsDomain& dom, const Reg& r) const;
    std::vector<std::tuple<Variable, bool, Interval>>
    collect_type_dependent_constraints(const NumAbsDomain& left, const NumAbsDomain& right) const;

    void selectively_join_based_on_type(NumAbsDomain& dst, NumAbsDomain&& src) const;
    void add_extra_invariant(const NumAbsDomain& dst, std::map<Variable, Interval>& extra_invariants,
                             Variable type_variable, TypeEncoding type, DataKind kind, const NumAbsDomain& src) const;

    [[nodiscard]]
    bool is_in_group(const NumAbsDomain& inv, const Reg& r, TypeGroup group) const;
};

} // namespace prevail

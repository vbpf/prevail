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
    NumAbsDomain* inv;
    explicit TypeDomain(NumAbsDomain& inv) : inv(&inv) {}

    void assign_type(const Reg& lhs, const Reg& rhs);
    void assign_type(const Reg& lhs, const std::optional<LinearExpression>& rhs);
    void assign_type(std::optional<Variable> lhs, const LinearExpression& t);

    void havoc_type(const Reg& r);

    [[nodiscard]]
    TypeEncoding get_type(const LinearExpression& v) const;
    [[nodiscard]]
    TypeEncoding get_type(const Reg& r) const;

    [[nodiscard]]
    bool has_type(const LinearExpression& v, TypeEncoding type) const;
    [[nodiscard]]
    bool has_type(const Reg& r, TypeEncoding type) const;

    [[nodiscard]]
    bool same_type(const Reg& a, const Reg& b) const;
    [[nodiscard]]
    bool implies_type(const LinearConstraint& a, const LinearConstraint& b) const;

    [[nodiscard]]
    NumAbsDomain join_over_types(const Reg& reg,
                                 const std::function<void(NumAbsDomain&, TypeEncoding)>& transition) const;
    [[nodiscard]]
    NumAbsDomain join_by_if_else(const LinearConstraint& condition, const std::function<void(NumAbsDomain&)>& if_true,
                                 const std::function<void(NumAbsDomain&)>& if_false) const;
    std::map<Variable, Interval> recover_type_dependent_constraints(NumAbsDomain& other) const;
    std::vector<Variable> get_nonexistent_kind_variables() const;
    std::vector<DataKind> get_valid_kinds(const Reg& r) const;
    [[nodiscard]]
    bool is_in_group(const Reg& r, TypeGroup group) const;
};

} // namespace prevail

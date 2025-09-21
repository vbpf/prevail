// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <functional>
#include <optional>
#include <tuple>
#include <vector>

#include "arith/progvar.hpp"
#include "asm_syntax.hpp" // for Reg
#include "crab/array_domain.hpp"
#include "crab/type_encoding.hpp"

namespace prevail {

struct RegPack {
    ProgVar svalue; // int64_t value.
    ProgVar uvalue; // uint64_t value.
    ProgVar ctx_offset;
    ProgVar map_fd;
    ProgVar packet_offset;
    ProgVar shared_offset;
    ProgVar stack_offset;
    ProgVar type;
    ProgVar shared_region_size;
    ProgVar stack_numeric_size;
};

RegPack reg_pack(int i);
inline RegPack reg_pack(const Reg r) { return reg_pack(r.v); }

struct TypeDomain {
    void assign_type(NumAbsDomain& inv, const Reg& lhs, const Reg& rhs);
    void assign_type(NumAbsDomain& inv, const Reg& lhs, const std::optional<LinearExpression>& rhs);
    void assign_type(NumAbsDomain& inv, const std::optional<ProgVar>& lhs, const LinearExpression& t);

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

    std::vector<ProgVar> get_nonexistent_kind_variables(const NumAbsDomain& dom) const;
    std::vector<std::tuple<ProgVar, bool, Interval>>
    collect_type_dependent_constraints(const NumAbsDomain& left, const NumAbsDomain& right) const;

    [[nodiscard]]
    bool is_in_group(const NumAbsDomain& inv, const Reg& r, TypeGroup group) const;
};

} // namespace prevail

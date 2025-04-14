// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <functional>
#include <optional>

#include "asm_syntax.hpp" // for Reg
#include "crab/array_domain.hpp"
#include "crab/type_encoding.hpp"
#include "crab/variable.hpp"

namespace prevail {

struct reg_pack_t {
    variable_t svalue; // int64_t value.
    variable_t uvalue; // uint64_t value.
    variable_t ctx_offset;
    variable_t map_fd;
    variable_t packet_offset;
    variable_t shared_offset;
    variable_t stack_offset;
    variable_t type;
    variable_t shared_region_size;
    variable_t stack_numeric_size;
};

reg_pack_t reg_pack(int i);
inline reg_pack_t reg_pack(const Reg r) { return reg_pack(r.v); }

struct TypeDomain {
    void assign_type(NumAbsDomain& inv, const Reg& lhs, const Reg& rhs);
    void assign_type(NumAbsDomain& inv, const Reg& lhs, const std::optional<linear_expression_t>& rhs);
    void assign_type(NumAbsDomain& inv, std::optional<variable_t> lhs, const linear_expression_t& t);

    void havoc_type(NumAbsDomain& inv, const Reg& r);

    [[nodiscard]]
    type_encoding_t get_type(const NumAbsDomain& inv, const linear_expression_t& v) const;
    [[nodiscard]]
    type_encoding_t get_type(const NumAbsDomain& inv, const Reg& r) const;

    [[nodiscard]]
    bool has_type(const NumAbsDomain& inv, const linear_expression_t& v, type_encoding_t type) const;
    [[nodiscard]]
    bool has_type(const NumAbsDomain& inv, const Reg& r, type_encoding_t type) const;

    [[nodiscard]]
    bool same_type(const NumAbsDomain& inv, const Reg& a, const Reg& b) const;
    [[nodiscard]]
    bool implies_type(const NumAbsDomain& inv, const linear_constraint_t& a, const linear_constraint_t& b) const;

    [[nodiscard]]
    NumAbsDomain join_over_types(const NumAbsDomain& inv, const Reg& reg,
                                 const std::function<void(NumAbsDomain&, type_encoding_t)>& transition) const;
    [[nodiscard]]
    NumAbsDomain join_by_if_else(const NumAbsDomain& inv, const linear_constraint_t& condition,
                                 const std::function<void(NumAbsDomain&)>& if_true,
                                 const std::function<void(NumAbsDomain&)>& if_false) const;
    void selectively_join_based_on_type(NumAbsDomain& dst, NumAbsDomain&& src) const;
    void add_extra_invariant(const NumAbsDomain& dst, std::map<variable_t, interval_t>& extra_invariants,
                             variable_t type_variable, type_encoding_t type, data_kind_t kind,
                             const NumAbsDomain& src) const;

    [[nodiscard]]
    bool is_in_group(const NumAbsDomain& inv, const Reg& r, TypeGroup group) const;
};

} // namespace prevail

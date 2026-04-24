// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <string>

#include "analysis_context.hpp"
#include "arith/linear_expression.hpp"
#include "arith/variable.hpp"
#include "crab/type_encoding.hpp"
#include "crab/var_registry.hpp"
#include "ir/syntax.hpp"

namespace prevail {

/// True for pointer types whose in-region accesses are bounds-checked by
/// `region_bounds`. Other pointer types (T_SOCKET, T_BTF_ID, T_MAP,
/// T_MAP_PROGRAMS, T_FUNC) are not directly dereferenceable in this verifier.
inline constexpr bool is_region_access_type(const TypeEncoding type) {
    switch (type) {
    case T_STACK:
    case T_CTX:
    case T_PACKET:
    case T_SHARED:
    case T_ALLOC_MEM: return true;
    default: return false;
    }
}

/// The first kind variable (in the sense of `type_to_kinds`) that represents
/// `reg`'s value under interpretation `type`. For region pointer types this
/// is the in-region offset; for T_MAP / T_MAP_PROGRAMS it is the file
/// descriptor. Returns nullopt for T_NUM (the universal svalue/uvalue is
/// used instead), T_FUNC, and T_UNINIT.
///
/// "Primary" because some region types own additional kind variables -- e.g.,
/// T_SHARED also owns shared_region_size, T_STACK owns stack_numeric_size,
/// T_ALLOC_MEM owns alloc_mem_size. Those are accessed via RegPack directly,
/// not through this function.
std::optional<Variable> primary_kind_variable_for_type(const Reg& reg, TypeEncoding type);

/// Address-range bounds an in-region access must satisfy. Used by checker
/// callers as: `require access_lb >= lb_floor; require access_ub <= ub_ceiling`.
/// Messages are diagnostic-only and resolved at the bounds-construction site so
/// they can mention concrete numbers (e.g. ctx_descriptor->size).
struct RegionBounds {
    LinearExpression lb_floor;
    std::string lb_message;
    LinearExpression ub_ceiling;
    std::string ub_message;
};

/// Bounds for a region-typed access. Defined for T_STACK, T_CTX, T_PACKET,
/// T_SHARED, T_ALLOC_MEM. For other types the caller should not invoke this.
///
/// `packet_size` overrides the T_PACKET upper bound. When nullopt, the
/// upper bound is options.max_packet_size; pass `variable_registry.packet_size()`
/// to bound by the runtime packet size variable.
RegionBounds region_bounds(TypeEncoding type, const RegPack& reg, const AnalysisContext& ctx,
                           std::optional<Variable> packet_size = std::nullopt);

} // namespace prevail

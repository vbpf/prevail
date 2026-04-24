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
/// `region_bounds` and have a meaningful `region_offset_variable`. Other
/// pointer types (T_SOCKET, T_BTF_ID, T_MAP, T_MAP_PROGRAMS, T_FUNC) are
/// not directly dereferenceable in this verifier.
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

/// Per-register variable that holds the in-region offset of `reg` when it has
/// pointer type `type`. Returns nullopt for non-region types (T_NUM, T_FUNC,
/// T_UNINIT). This is the central source of truth for the type -> kind-variable
/// mapping; see `region_bounds` for the matching bounds rules.
std::optional<Variable> region_offset_variable(const Reg& reg, TypeEncoding type);

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

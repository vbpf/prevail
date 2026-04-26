// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <string>

#include "analysis_context.hpp"
#include "arith/dsl_syntax.hpp"
#include "arith/linear_expression.hpp"
#include "arith/variable.hpp"
#include "crab/type_encoding.hpp"
#include "crab/type_to_num.hpp"
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

/// Bounds are partitioned by the *shape* of context the ceiling is read from:
/// - context-derived: T_STACK, T_CTX, and T_PACKET *when no runtime override
///   is supplied* (ceiling comes from `AnalysisContext::options`).
/// - reg-derived: T_SHARED, T_ALLOC_MEM (ceiling is a kind variable on `RegPack`).
/// - T_PACKET *with* a runtime override: a separate overload that takes the
///   `packet_size` Variable directly. This is the dereference path; sites that
///   actually read or write packet bytes must use it. The context-derived
///   T_PACKET overload uses the looser `max_packet_size` ceiling and is only
///   correct for pointer-comparison checks (no actual access).
template <TypeEncoding T>
concept CtxDerivedCeiling = (T == T_STACK || T == T_CTX || T == T_PACKET);

template <TypeEncoding T>
concept RegDerivedCeiling = (T == T_SHARED || T == T_ALLOC_MEM);

template <TypeEncoding T>
    requires CtxDerivedCeiling<T>
RegionBounds region_bounds(const AnalysisContext& ctx) {
    using namespace dsl_syntax;
    if constexpr (T == T_STACK) {
        return {.lb_floor = reg_pack(R10_STACK_POINTER).stack_offset - ctx.options.subprogram_stack_size,
                .lb_message = "Lower bound must be at least r10.stack_offset - subprogram_stack_size",
                .ub_ceiling = LinearExpression{ctx.options.total_stack_size()},
                .ub_message = "Upper bound must be at most total_stack_size"};
    } else if constexpr (T == T_CTX) {
        const auto ctx_size = ctx.program_info().type.ctx_descriptor->size;
        return {.lb_floor = LinearExpression{0},
                .lb_message = "Lower bound must be at least 0",
                .ub_ceiling = LinearExpression{ctx_size},
                .ub_message = std::string("Upper bound must be at most ") + std::to_string(ctx_size)};
    } else { // T_PACKET, static ceiling: pointer-comparison checks only.
        return {.lb_floor = variable_registry.meta_offset(),
                .lb_message = "Lower bound must be at least meta_offset",
                .ub_ceiling = LinearExpression{ctx.options.max_packet_size},
                .ub_message =
                    std::string("Upper bound must be at most ") + std::to_string(ctx.options.max_packet_size)};
    }
}

template <TypeEncoding T>
    requires RegDerivedCeiling<T>
RegionBounds region_bounds(const RegPack& reg) {
    if constexpr (T == T_SHARED) {
        return {.lb_floor = LinearExpression{0},
                .lb_message = "Lower bound must be at least 0",
                .ub_ceiling = reg.shared_region_size,
                .ub_message =
                    std::string("Upper bound must be at most ") + variable_registry.name(reg.shared_region_size)};
    } else { // T_ALLOC_MEM
        return {.lb_floor = LinearExpression{0},
                .lb_message = "Lower bound must be at least 0",
                .ub_ceiling = reg.alloc_mem_size,
                .ub_message = std::string("Upper bound must be at most ") + variable_registry.name(reg.alloc_mem_size)};
    }
}

/// T_PACKET with a runtime ceiling. Use at every site that actually reads or
/// writes packet bytes (direct ValidAccess dereferences, helper key/value
/// buffers via ValidMapKeyValue). Pass `variable_registry.packet_size()`.
template <TypeEncoding T>
    requires(T == T_PACKET)
RegionBounds region_bounds(Variable packet_size) {
    return {.lb_floor = variable_registry.meta_offset(),
            .lb_message = "Lower bound must be at least meta_offset",
            .ub_ceiling = packet_size,
            .ub_message = "Upper bound must be at most packet_size"};
}

} // namespace prevail

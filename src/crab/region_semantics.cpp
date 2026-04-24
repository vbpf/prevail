// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <stdexcept>
#include <string>

#include "arith/dsl_syntax.hpp"
#include "crab/region_semantics.hpp"
#include "crab/type_to_num.hpp"
#include "crab/var_registry.hpp"

namespace prevail {

std::optional<Variable> primary_kind_variable_for_type(const Reg& reg, const TypeEncoding type) {
    RegPack r = reg_pack(reg);
    switch (type) {
    case T_CTX: return r.ctx_offset;
    case T_MAP: return r.map_fd;
    case T_MAP_PROGRAMS: return r.map_fd_programs;
    case T_PACKET: return r.packet_offset;
    case T_SHARED: return r.shared_offset;
    case T_STACK: return r.stack_offset;
    case T_SOCKET: return r.socket_offset;
    case T_BTF_ID: return r.btf_id_offset;
    case T_ALLOC_MEM: return r.alloc_mem_offset;
    default: return {};
    }
}

RegionBounds region_bounds(const TypeEncoding type, const RegPack& reg, const AnalysisContext& ctx,
                           const std::optional<Variable> packet_size) {
    using namespace dsl_syntax;
    switch (type) {
    case T_STACK:
        return {.lb_floor = reg_pack(R10_STACK_POINTER).stack_offset - ctx.options.subprogram_stack_size,
                .lb_message = "Lower bound must be at least r10.stack_offset - subprogram_stack_size",
                .ub_ceiling = LinearExpression{ctx.options.total_stack_size()},
                .ub_message = "Upper bound must be at most total_stack_size"};
    case T_CTX: {
        const auto ctx_size = ctx.program_info().type.ctx_descriptor->size;
        return {.lb_floor = LinearExpression{0},
                .lb_message = "Lower bound must be at least 0",
                .ub_ceiling = LinearExpression{ctx_size},
                .ub_message = std::string("Upper bound must be at most ") + std::to_string(ctx_size)};
    }
    case T_PACKET:
        if (packet_size) {
            return {.lb_floor = variable_registry.meta_offset(),
                    .lb_message = "Lower bound must be at least meta_offset",
                    .ub_ceiling = *packet_size,
                    .ub_message = "Upper bound must be at most packet_size"};
        }
        return {.lb_floor = variable_registry.meta_offset(),
                .lb_message = "Lower bound must be at least meta_offset",
                .ub_ceiling = LinearExpression{ctx.options.max_packet_size},
                .ub_message =
                    std::string("Upper bound must be at most ") + std::to_string(ctx.options.max_packet_size)};
    case T_SHARED:
        return {.lb_floor = LinearExpression{0},
                .lb_message = "Lower bound must be at least 0",
                .ub_ceiling = reg.shared_region_size,
                .ub_message =
                    std::string("Upper bound must be at most ") + variable_registry.name(reg.shared_region_size)};
    case T_ALLOC_MEM:
        return {.lb_floor = LinearExpression{0},
                .lb_message = "Lower bound must be at least 0",
                .ub_ceiling = reg.alloc_mem_size,
                .ub_message = std::string("Upper bound must be at most ") + variable_registry.name(reg.alloc_mem_size)};
    default:
        // The caller is expected to gate by region type (e.g., the checker's
        // ValidAccess switch). Reaching this point is a programming error -
        // throw unconditionally so the contract is enforced in release builds
        // too (assert would be stripped under NDEBUG).
        throw std::logic_error("region_bounds called on non-region type");
    }
}

} // namespace prevail

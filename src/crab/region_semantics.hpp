// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>

#include "arith/variable.hpp"
#include "crab/type_encoding.hpp"
#include "ir/syntax.hpp"

namespace prevail {

/// True for pointer types whose in-region accesses are bounds-checked. Other
/// pointer types (T_SOCKET, T_BTF_ID, T_MAP, T_MAP_PROGRAMS, T_FUNC) are not
/// directly dereferenceable in this verifier.
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

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <optional>

#include <gsl/narrow>

#include "ir/syntax.hpp"
#include "spec/ebpf_base.h"

namespace prevail {

/// Map an ABI argument-type tag to the resolved single-arg kind it implies,
/// or std::nullopt for tags that are not single-arg (pair members, sizes,
/// DONTCARE/UNSUPPORTED sentinels, etc.). Shared by helper and kfunc
/// resolution; each caller decides how to handle nullopt (silent fallback
/// vs. set-unsupported).
[[nodiscard]]
inline std::optional<ArgSingle::Kind> to_arg_single_kind(const ebpf_argument_type_t t) {
    switch (t) {
    case EBPF_ARGUMENT_TYPE_ANYTHING: return ArgSingle::Kind::ANYTHING;
    case EBPF_ARGUMENT_TYPE_PTR_TO_STACK:
    case EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL: return ArgSingle::Kind::PTR_TO_STACK;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP:
    case EBPF_ARGUMENT_TYPE_CONST_PTR_TO_MAP: return ArgSingle::Kind::MAP_FD;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS: return ArgSingle::Kind::MAP_FD_PROGRAMS;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY: return ArgSingle::Kind::PTR_TO_MAP_KEY;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE:
    case EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MAP_VALUE: return ArgSingle::Kind::PTR_TO_MAP_VALUE;
    case EBPF_ARGUMENT_TYPE_PTR_TO_CTX:
    case EBPF_ARGUMENT_TYPE_PTR_TO_CTX_OR_NULL: return ArgSingle::Kind::PTR_TO_CTX;
    case EBPF_ARGUMENT_TYPE_PTR_TO_FUNC: return ArgSingle::Kind::PTR_TO_FUNC;
    default: return std::nullopt;
    }
}

/// Map an ABI argument-type tag to the resolved pair kind for the pointer
/// half of a (ptr, size) pair, or std::nullopt for tags that do not
/// participate as a pair pointer. The size half is conveyed separately via
/// EBPF_ARGUMENT_TYPE_CONST_SIZE / EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO.
[[nodiscard]]
inline std::optional<ArgPair::Kind> to_arg_pair_kind(const ebpf_argument_type_t t) {
    switch (t) {
    case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM_OR_NULL: return ArgPair::Kind::PTR_TO_READABLE_MEM;
    case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM:
    case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL: return ArgPair::Kind::PTR_TO_WRITABLE_MEM;
    default: return std::nullopt;
    }
}

/// Outcome of consuming one position in the helper/kfunc argument list.
/// Callers use it to advance the loop index and to format their own
/// "unsupported" diagnostic so error wording (helper vs. kfunc) stays
/// caller-controlled.
enum class ArgOutcome {
    Single,         ///< Single-arg consumed; caller advances i by 1.
    Pair,           ///< (ptr, size) pair consumed; caller advances i by 2.
    Stop,           ///< DONTCARE reached; remaining positions are unused.
    Unavailable,    ///< Argument type is not supported on this platform.
    MismatchedSize, ///< Pointer arg not followed by CONST_SIZE/CONST_SIZE_OR_ZERO.
};

/// Process a single position in the argument array, populating
/// `contract` with whatever single or pair entry it implies. The args
/// span has DONTCARE sentinels at index 0 and the last index, so
/// `args[i + 1]` is always in bounds for `i` in the caller's loop range.
[[nodiscard]]
inline ArgOutcome process_arg(CallContract& contract, const std::array<ebpf_argument_type_t, 7>& args, const size_t i) {
    const Reg reg{gsl::narrow<uint8_t>(i)};
    switch (args[i]) {
    case EBPF_ARGUMENT_TYPE_DONTCARE: return ArgOutcome::Stop;
    case EBPF_ARGUMENT_TYPE_UNSUPPORTED: return ArgOutcome::Unavailable;
    case EBPF_ARGUMENT_TYPE_CONST_SIZE:
    case EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: return ArgOutcome::MismatchedSize;
    case EBPF_ARGUMENT_TYPE_PTR_TO_CONST_STR: return ArgOutcome::Unavailable;
    case EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON:
    case EBPF_ARGUMENT_TYPE_PTR_TO_SOCK_COMMON:
        contract.singles.push_back({ArgSingle::Kind::PTR_TO_SOCKET, false, reg});
        return ArgOutcome::Single;
    case EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID:
    case EBPF_ARGUMENT_TYPE_PTR_TO_PERCPU_BTF_ID:
        contract.singles.push_back({ArgSingle::Kind::PTR_TO_BTF_ID, false, reg});
        return ArgOutcome::Single;
    case EBPF_ARGUMENT_TYPE_PTR_TO_ALLOC_MEM:
        contract.singles.push_back({ArgSingle::Kind::PTR_TO_ALLOC_MEM, false, reg});
        return ArgOutcome::Single;
    case EBPF_ARGUMENT_TYPE_PTR_TO_SPIN_LOCK:
        contract.singles.push_back({ArgSingle::Kind::PTR_TO_SPIN_LOCK, false, reg});
        return ArgOutcome::Single;
    case EBPF_ARGUMENT_TYPE_PTR_TO_TIMER:
        contract.singles.push_back({ArgSingle::Kind::PTR_TO_TIMER, false, reg});
        return ArgOutcome::Single;
    case EBPF_ARGUMENT_TYPE_CONST_ALLOC_SIZE_OR_ZERO:
        contract.singles.push_back({ArgSingle::Kind::CONST_SIZE_OR_ZERO, false, reg});
        contract.alloc_size_reg = reg;
        return ArgOutcome::Single;
    case EBPF_ARGUMENT_TYPE_PTR_TO_LONG:
        contract.singles.push_back({ArgSingle::Kind::PTR_TO_WRITABLE_LONG, false, reg});
        return ArgOutcome::Single;
    case EBPF_ARGUMENT_TYPE_PTR_TO_INT:
        contract.singles.push_back({ArgSingle::Kind::PTR_TO_WRITABLE_INT, false, reg});
        return ArgOutcome::Single;
    case EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_CTX_OR_NULL:
        if (const auto kind = to_arg_single_kind(args[i])) {
            contract.singles.push_back({*kind, true, reg});
            return ArgOutcome::Single;
        }
        return ArgOutcome::Unavailable;
    case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM:
    case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL: {
        if (args[i + 1] != EBPF_ARGUMENT_TYPE_CONST_SIZE && args[i + 1] != EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO) {
            return ArgOutcome::MismatchedSize;
        }
        const auto pair_kind = to_arg_pair_kind(args[i]);
        if (!pair_kind) {
            return ArgOutcome::Unavailable;
        }
        const bool can_be_zero = (args[i + 1] == EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO);
        const bool or_null = args[i] == EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL ||
                             args[i] == EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM_OR_NULL ||
                             args[i] == EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL;
        contract.pairs.push_back({*pair_kind, or_null, reg, Reg{gsl::narrow<uint8_t>(i + 1)}, can_be_zero});
        return ArgOutcome::Pair;
    }
    default:
        if (const auto kind = to_arg_single_kind(args[i])) {
            contract.singles.push_back({*kind, false, reg});
            return ArgOutcome::Single;
        }
        return ArgOutcome::Unavailable;
    }
}

} // namespace prevail

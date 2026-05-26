// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>

#include "spec/ebpf_base.h"

namespace prevail {

constexpr uint64_t map_type_bit(uint32_t type) { return uint64_t{1} << type; }
// A helper function's prototype is expressed by this struct.
struct EbpfHelperPrototype {
    const char* name{};

    // The return value is returned in register R0.
    ebpf_return_type_t return_type{};

    // Arguments are passed in registers R1 to R5.
    ebpf_argument_type_t argument_type[5]{};

    // Side effect: can this helper perform packet reallocation.
    bool reallocate_packet{};

    // If R1 holds a context, then this holds a pointer to the context descriptor.
    const ebpf_ctx_descriptor_t* ctx_descriptor{};

    // Bitmask of argument positions (0-4 for R1-R5) that must be provably zero.
    uint8_t zero_args_mask{};

    // Whether this helper may sleep (forbidden in non-sleepable programs).
    bool might_sleep{};

    // Bitmask of platform-specific map types that may be passed to this helper.
    // Zero means any map type is accepted; bit N set means map type N is allowed.
    uint64_t allowed_map_types{};

    bool unsupported = false;
};
} // namespace prevail

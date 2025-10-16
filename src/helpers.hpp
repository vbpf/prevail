// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_base.h"

namespace prevail {
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
    const ebpf_context_descriptor_t* context_descriptor{};

    bool unsupported = false;
};
} // namespace prevail

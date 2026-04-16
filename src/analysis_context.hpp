// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cassert>

#include "config.hpp"
#include "crab/var_registry.hpp"
#include "platform.hpp"
#include "spec/type_descriptors.hpp"

namespace prevail {

/// Per-analysis inputs threaded explicitly through the verifier.
///
/// `VariableRegistry` is intentionally NOT here. The registry is a global
/// name-interning service (like `malloc`), not per-analysis state: the same
/// name always maps to the same id, so analyses can freely share one instance.
/// Domain code reaches for the global `variable_registry` directly.
struct AnalysisContext {
    const ProgramInfo& program_info;
    const ebpf_verifier_options_t& options;
    const ebpf_platform_t& platform;
};

[[nodiscard]]
inline AnalysisContext thread_local_analysis_context() {
    const ProgramInfo& program_info = thread_local_program_info.get();
    assert(program_info.platform != nullptr && "program_info.platform must be set before analysis");
    return AnalysisContext{
        .program_info = program_info,
        .options = thread_local_options,
        .platform = *program_info.platform,
    };
}

} // namespace prevail

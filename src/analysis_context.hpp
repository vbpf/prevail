// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "spec/type_descriptors.hpp"

namespace prevail {

/// Per-analysis inputs threaded explicitly through the verifier.
///
/// Non-owning: holds references to a `ProgramInfo`, options, and platform that
/// must outlive every call that receives this context. An `AnalysisContext` is
/// scoped to a single analysis; do not cache one beyond the call that built it.
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

} // namespace prevail

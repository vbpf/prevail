// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "ir/program.hpp"
#include "spec/type_descriptors.hpp"

namespace prevail {

/// Per-analysis inputs threaded explicitly through the verifier.
///
/// Non-owning: holds references to a `Program`, its `ProgramInfo`, options, and
/// platform that must outlive every call that receives this context. An
/// `AnalysisContext` is scoped to a single analysis; do not cache one beyond
/// the call that built it.
///
/// The distinction between `program` and `program_info` reflects the split
/// between analysis-prep facts and loader facts:
///   - `program_info` (== `program.info()`) holds loader outputs: platform
///     reference, program type, map descriptors, line info, builtin call
///     offsets. Stable after ELF load.
///   - `program` additionally exposes analysis-prep outputs derived from the
///     CFG -- currently `callback_target_labels()` and
///     `callback_targets_with_exit()`. These are populated by
///     `Program::from_sequence` and have no meaning on a bare `ProgramInfo`.
///
/// `VariableRegistry` is intentionally NOT here. The registry is a global
/// name-interning service (like `malloc`), not per-analysis state: the same
/// name always maps to the same id, so analyses can freely share one instance.
/// Domain code reaches for the global `variable_registry` directly.
struct AnalysisContext {
    const Program& program;
    const ProgramInfo& program_info;
    const ebpf_verifier_options_t& options;
    const ebpf_platform_t& platform;
};

} // namespace prevail

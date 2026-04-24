// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <utility>

#include "config.hpp"
#include "ir/program.hpp"
#include "spec/type_descriptors.hpp"

namespace prevail {

/// Owning bundle of per-analysis inputs threaded through the verifier.
///
/// `AnalysisContext` holds the `Program` and `ebpf_verifier_options_t` by
/// value. The immutable platform (`ebpf_platform_t`) and loader-produced
/// `ProgramInfo` are reached via accessors off `program.info()`; they are
/// not separate members because they are already reachable from `program`
/// and keeping them as parallel references invited the kind of
/// silently-mismatched-pair bug that PR #1091 flagged.
///
/// Ownership wins this gives us:
///   - analyze() and compute_failure_slices() do not need a separate
///     `Program` parameter -- the program lives in the context;
///   - the dangling-reference trap in the previous make_context() (which
///     returned an AnalysisContext full of references) is gone;
///   - callers move a Program in once and then talk through the context
///     for every subsequent analysis step.
///
/// `VariableRegistry` is intentionally NOT here. The registry is a global
/// name-interning service (like `malloc`), not per-analysis state: the same
/// name always maps to the same id, so analyses can freely share one
/// instance. Domain code reaches for the global `variable_registry` directly.
struct AnalysisContext {
    Program program;
    ebpf_verifier_options_t options;

    AnalysisContext(Program p, ebpf_verifier_options_t o) : program(std::move(p)), options(std::move(o)) {}

    const ProgramInfo& program_info() const { return program.info(); }
    const ebpf_platform_t& platform() const { return *program.info().platform; }
};

} // namespace prevail

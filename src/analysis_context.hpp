// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cassert>

#include "config.hpp"
#include "crab/var_registry.hpp"
#include "platform.hpp"
#include "spec/type_descriptors.hpp"

namespace prevail {

/// Semantic inputs for one verifier analysis run.
///
/// This first context is intentionally a thin wrapper over the objects that are
/// still stored in thread-local compatibility state.  Passing it explicitly
/// makes the checker and transformer dependencies auditable without changing
/// ownership or lifetime rules in the same migration step.
struct AnalysisContext {
    const ProgramInfo& program_info;
    const ebpf_verifier_options_t& options;
    const ebpf_platform_t& platform;
    // `variables` is const from the client's perspective: its public API is
    // a pure function of already-known names. Factory calls like
    // `variables.reg(...)` still intern new ids through an internal `mutable`
    // cache. Callers never need to mutate the registry object itself, so we
    // hold it by const reference. See var_registry.hpp for the rationale.
    const VariableRegistry& variables;
};

[[nodiscard]]
inline AnalysisContext thread_local_analysis_context() {
    const ProgramInfo& program_info = thread_local_program_info.get();
    assert(program_info.platform != nullptr && "program_info.platform must be set before analysis");
    return AnalysisContext{
        .program_info = program_info,
        .options = thread_local_options,
        .platform = *program_info.platform,
        .variables = variable_registry.get(),
    };
}

} // namespace prevail

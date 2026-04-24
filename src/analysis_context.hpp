// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <utility>

#include "config.hpp"
#include "ir/program.hpp"
#include "spec/type_descriptors.hpp"

namespace prevail {

/// Bundle of per-analysis inputs: the `Program` being analysed and the
/// options controlling it. Owned by value so the context is
/// self-contained -- the Program cannot be moved out from under the
/// analysis, and a context cannot outlive its Program.
///
/// `program_info()` and `platform()` are accessors, not fields: both are
/// reachable from `program`, so storing them as parallel references would
/// let `context.program_info` disagree with `context.program.info()`.
///
/// `VariableRegistry` is intentionally not here. The registry is a global
/// name-interning service (like `malloc`), not per-analysis state: the
/// same name always maps to the same id, so analyses can freely share one
/// instance. Domain code reaches for the global `variable_registry`
/// directly.
struct AnalysisContext {
    Program program;
    ebpf_verifier_options_t options;

    AnalysisContext(Program p, ebpf_verifier_options_t o) : program(std::move(p)), options(std::move(o)) {}

    const ProgramInfo& program_info() const { return program.info(); }
    const ebpf_platform_t& platform() const { return *program.info().platform; }
};

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "ir/program.hpp"
#include "result.hpp"

namespace prevail {

AnalysisResult analyze(const Program& prog);
AnalysisResult analyze(const Program& prog, const StringInvariant& entry_invariant);
inline bool verify(const Program& prog) { return !analyze(prog).failed; }

void ebpf_verifier_clear_thread_local_state();

struct ThreadLocalGuard {
    ThreadLocalGuard() = default;
    ~ThreadLocalGuard() { ebpf_verifier_clear_thread_local_state(); }
};

} // namespace prevail

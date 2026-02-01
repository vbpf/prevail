// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <exception>

#include "ir/program.hpp"
#include "result.hpp"

namespace prevail {

AnalysisResult analyze(const Program& prog);
AnalysisResult analyze(const Program& prog, const StringInvariant& entry_invariant);
void ebpf_verifier_clear_thread_local_state();
inline bool verify(const Program& prog) {
    try {
        return !analyze(prog).failed;
    } catch (const std::exception&) {
        ebpf_verifier_clear_thread_local_state();
        return false;
    }
}

struct ThreadLocalGuard {
    ThreadLocalGuard() = default;
    ~ThreadLocalGuard() { ebpf_verifier_clear_thread_local_state(); }
    ThreadLocalGuard(const ThreadLocalGuard&) = delete;
    ThreadLocalGuard& operator=(const ThreadLocalGuard&) = delete;
    ThreadLocalGuard(ThreadLocalGuard&&) = delete;
    ThreadLocalGuard& operator=(ThreadLocalGuard&&) = delete;
};

} // namespace prevail

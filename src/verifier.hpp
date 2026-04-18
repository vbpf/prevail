// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <exception>

#include "analysis_context.hpp"
#include "ir/program.hpp"
#include "result.hpp"

namespace prevail {

AnalysisResult analyze(const Program& prog, const ebpf_verifier_options_t& options);
AnalysisResult analyze(const Program& prog, const StringInvariant& entry_invariant,
                       const ebpf_verifier_options_t& options);
AnalysisResult analyze(const Program& prog);
AnalysisResult analyze(const Program& prog, const StringInvariant& entry_invariant);
AnalysisResult analyze(const Program& prog, const AnalysisContext& context);
AnalysisResult analyze(const Program& prog, const StringInvariant& entry_invariant, const AnalysisContext& context);
void ebpf_verifier_clear_thread_local_state();
inline bool verify(const Program& prog, const ebpf_verifier_options_t& options) {
    try {
        return !analyze(prog, options).failed;
    } catch (const std::exception&) {
        ebpf_verifier_clear_thread_local_state();
        return false;
    }
}
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

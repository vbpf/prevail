// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <map>
#include <optional>

#include "crab/ebpf_domain.hpp"
#include "ir/program.hpp"

namespace prevail {

enum class InvariantPoint {
    pre,
    post,
};

enum class ObservationCheckMode {
    // Default: supports partial observations.
    consistent,
    // Stricter: ok iff observation entails invariant (C ⊑ A); useful only when the observation is near-complete.
    entailed,
};

struct ObservationCheckResult {
    bool ok = false;
    std::string message;
};

struct InvariantMapPair {
    EbpfDomain pre;
    std::optional<VerificationError> error;
    EbpfDomain post;
};

struct AnalysisResult {
    std::map<Label, InvariantMapPair> invariants;
    bool failed = false;
    int max_loop_count{};
    Interval exit_value = Interval::top();

    [[nodiscard]]
    bool is_valid_after(const Label& label, const StringInvariant& state) const;

    [[nodiscard]]
    ObservationCheckResult
    check_observation_at_label(const Label& label, InvariantPoint point, const StringInvariant& observation,
                               ObservationCheckMode mode = ObservationCheckMode::consistent) const;

    [[nodiscard]]
    bool is_consistent_before(const Label& label, const StringInvariant& observation) const;

    [[nodiscard]]
    bool is_consistent_after(const Label& label, const StringInvariant& observation) const;

    [[nodiscard]]
    StringInvariant invariant_at(const Label& label) const;

    [[nodiscard]]
    std::optional<VerificationError> find_first_error() const;

    [[nodiscard]]
    std::map<Label, std::vector<std::string>> find_unreachable(const Program& prog) const;
};

void print_error(std::ostream& os, const VerificationError& error);
void print_invariants(std::ostream& os, const Program& prog, bool simplify, const AnalysisResult& result);
void print_unreachable(std::ostream& os, const Program& prog, const AnalysisResult& result);

} // namespace prevail

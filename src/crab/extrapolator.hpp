// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <functional>
#include <span>

#include "arith/variable.hpp"
#include "crab/ebpf_domain.hpp"

namespace prevail {

struct AnalysisContext;

/// Fixpoint acceleration strategy for a single abstract domain.
///
/// Constructed once per analysis with the constant limits and loop counter
/// variables. Immutable after construction — all per-cycle state is local
/// to compute_fixpoint.
///
/// Has no knowledge of control flow, programs, or loop structure.
class Extrapolator final {
  public:
    using Step = std::function<EbpfDomain(const EbpfDomain&)>;

    Extrapolator(const AnalysisContext& context, std::span<const Variable> loop_counters);

    /// Run the ascending (widening) and descending (narrowing) sequences to
    /// convergence. The step function maps an invariant to the new pre-state
    /// obtained by executing the loop body.
    [[nodiscard]]
    EbpfDomain compute_fixpoint(EbpfDomain initial, const Step& step) const;

    [[nodiscard]]
    std::span<const Variable> loop_counters() const {
        return loop_counters_;
    }

  private:
    EbpfDomain constant_limits_;
    std::vector<Variable> loop_counters_;

    static constexpr unsigned int widening_delay_ = 2;
    static constexpr unsigned int max_descending_iterations_ = 2000000;
};

} // namespace prevail

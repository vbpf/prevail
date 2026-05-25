// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "extrapolator.hpp"

#include "analysis_context.hpp"

namespace prevail {

Extrapolator::Extrapolator(const AnalysisContext& context, const std::span<const Variable> loop_counters)
    : constant_limits_(EbpfDomain::calculate_constant_limits(context, loop_counters)),
      loop_counters_(loop_counters.begin(), loop_counters.end()) {}

EbpfDomain Extrapolator::compute_fixpoint(EbpfDomain invariant, const Step& step) const {
    // Ascending (widening) sequence.
    for (unsigned int iteration = 0;;) {
        EbpfDomain new_pre = step(invariant);
        if (new_pre <= invariant) {
            invariant = std::move(new_pre);
            break;
        }
        ++iteration;
        if (iteration < widening_delay_) {
            invariant = invariant | new_pre;
        } else {
            invariant = invariant.widen(new_pre);
            if (iteration == widening_delay_) {
                invariant = invariant & constant_limits_;
            }
        }
    }

    // Descending (narrowing) sequence.
    for (unsigned int iteration = 0;;) {
        EbpfDomain new_pre = step(invariant);
        if (invariant <= new_pre) {
            break;
        }
        if (++iteration > max_descending_iterations_) {
            break;
        }
        if (iteration == 1) {
            invariant = invariant & new_pre;
        } else {
            invariant = invariant.narrow(new_pre);
        }
    }

    return invariant;
}

} // namespace prevail

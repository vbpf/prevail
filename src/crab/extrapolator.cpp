// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "extrapolator.hpp"

#include "analysis_context.hpp"

namespace prevail {

Extrapolator::Extrapolator(const AnalysisContext& context, const std::span<const Variable> loop_counters)
    : widening_thresholds_(EbpfDomain::calculate_widening_thresholds(context, loop_counters)),
      loop_counters_(loop_counters.begin(), loop_counters.end()) {}

EbpfDomain Extrapolator::compute_fixpoint(EbpfDomain invariant, const Step& step) const {
    // Ascending (widening) sequence. `basis` is the raw widened state: the left
    // operand of the next widen and the target of the inclusion test.
    // `invariant` is its normalized form (same concretization, plus
    // closure-implied edges), used to run the loop body. Widening the
    // normalized form instead lets closure recover each dropped relation at a
    // slightly larger weight, and the sequence need not stabilize. Testing
    // inclusion against the basis ties the exit to what the widening
    // stabilizes: once a widen leaves the basis unchanged, the syntactic
    // inclusion test succeeds. The type-aware `operator<=` is not usable here:
    // it projects kind variables out of the right operand, which is unsound on
    // an unclosed DBM.
    EbpfDomain basis = invariant;
    for (unsigned int iteration = 0;;) {
        EbpfDomain new_pre = step(invariant);
        if (new_pre.is_included_in_raw_basis(basis)) {
            invariant = std::move(new_pre);
            break;
        }
        ++iteration;
        if (iteration < widening_delay_) {
            // A join is already normalized: basis and invariant coincide.
            basis = basis | new_pre;
            invariant = basis;
            continue;
        }
        if (iteration == widening_delay_) {
            // First widen: widening with thresholds. Only thresholds the state
            // being widened already satisfies are kept, so the result is still
            // an upper bound of every state seen so far.
            //
            // Convergence relies on the thresholds being applied at exactly
            // one widen: they normalize the basis when at least one is
            // selected, and a basis normalized at every widen need not
            // stabilize (see above). Do not move them into every widen.
            const EbpfDomain before = basis | new_pre;
            basis = basis.widen_raw(new_pre);
            basis.add_widening_thresholds(before, widening_thresholds_, loop_counters_);
        } else {
            basis = basis.widen_raw(new_pre);
        }
        invariant = basis;
        invariant.normalize_closure();
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
        EbpfDomain refined;
        if (iteration == 1) {
            refined = invariant & new_pre;
        } else {
            refined = invariant.narrow(new_pre);
        }

        // Narrowing is descending, so refined <= invariant by construction. The reverse ordering means narrowing
        // made no semantic progress. Retain the result so any canonicalized representation or auxiliary stack-cell
        // metadata is preserved.
        const bool narrowing_fixpoint = invariant <= refined;
        invariant = std::move(refined);
        if (narrowing_fixpoint) {
            break;
        }
    }

    return invariant;
}

} // namespace prevail

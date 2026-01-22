// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <map>
#include <ranges>
#include <sstream>

#include "crab/ebpf_domain.hpp"
#include "ir/program.hpp"
#include "result.hpp"

namespace prevail {

bool AnalysisResult::is_valid_after(const Label& label, const StringInvariant& state) const {
    const EbpfDomain abstract_state =
        EbpfDomain::from_constraints(state.value(), thread_local_options.setup_constraints);
    return abstract_state <= invariants.at(label).post;
}

ObservationCheckResult AnalysisResult::check_observation_at_label(const Label& label, const InvariantPoint point,
                                                                  const StringInvariant& observation,
                                                                  const ObservationCheckMode mode) const {
    const auto it = invariants.find(label);
    if (it == invariants.end()) {
        return {.ok = false, .message = "No invariant available for label " + to_string(label)};
    }
    const auto& inv_pair = it->second;
    const EbpfDomain& abstract_state = (point == InvariantPoint::pre) ? inv_pair.pre : inv_pair.post;

    const EbpfDomain observed_state =
        observation.is_bottom()
            ? EbpfDomain::bottom()
            : EbpfDomain::from_constraints(observation.value(), thread_local_options.setup_constraints);

    if (observed_state.is_bottom()) {
        return {.ok = false, .message = "Observation constraints are unsatisfiable (domain is bottom)"};
    }

    if (abstract_state.is_bottom()) {
        return {.ok = false, .message = "Invariant at label is bottom (unreachable)"};
    }

    switch (mode) {
    case ObservationCheckMode::entailed:
        if (observed_state <= abstract_state) {
            return {.ok = true, .message = ""};
        }
        return {.ok = false, .message = "Invariant does not entail the observation (C ⊑ A is false)"};

    case ObservationCheckMode::consistent:
        // Default: consistency / satisfiability.
        if ((abstract_state & observed_state).is_bottom()) {
            return {.ok = false, .message = "Observation contradicts invariant (meet is bottom)"};
        }
        return {.ok = true, .message = ""};
    }

    return {.ok = false, .message = "Unsupported observation check mode"};
}

bool AnalysisResult::is_consistent_before(const Label& label, const StringInvariant& observation) const {
    return check_observation_at_label(label, InvariantPoint::pre, observation, ObservationCheckMode::consistent).ok;
}

bool AnalysisResult::is_consistent_after(const Label& label, const StringInvariant& observation) const {
    return check_observation_at_label(label, InvariantPoint::post, observation, ObservationCheckMode::consistent).ok;
}

StringInvariant AnalysisResult::invariant_at(const Label& label) const { return invariants.at(label).post.to_set(); }

std::optional<VerificationError> AnalysisResult::find_first_error() const {
    for (const auto& inv_pair : invariants | std::views::values) {
        if (inv_pair.pre.is_bottom()) {
            continue;
        }
        if (inv_pair.error) {
            return inv_pair.error;
        }
    }
    return {};
}

std::map<Label, std::vector<std::string>> AnalysisResult::find_unreachable(const Program& prog) const {
    std::map<Label, std::vector<std::string>> unreachable;
    for (const auto& [label, inv_pair] : invariants) {
        if (inv_pair.pre.is_bottom()) {
            continue;
        }
        if (const auto passume = std::get_if<Assume>(&prog.instruction_at(label))) {
            if (inv_pair.post.is_bottom() && !inv_pair.error) {
                const auto s = to_string(*passume);
                unreachable[label].emplace_back(to_string(label) + ": Code becomes unreachable (" + s + ")");
            }
        }
    }
    return unreachable;
}

} // namespace prevail

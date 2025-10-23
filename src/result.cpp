// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <map>

#include "crab/ebpf_domain.hpp"
#include "ir/program.hpp"
#include "result.hpp"

namespace prevail {

bool AnalysisResult::is_valid_after(const Label& label, const StringInvariant& state) const {
    const EbpfDomain abstract_state =
        EbpfDomain::from_constraints(state.value(), thread_local_options.setup_constraints);
    return abstract_state <= invariants.at(label).post;
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

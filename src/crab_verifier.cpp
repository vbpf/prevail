// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/**
 *  This module is about selecting the numerical and memory domains, initiating
 *  the verification process and returning the results.
 **/

#include <map>
#include <ranges>
#include <string>

#include "asm_syntax.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"
#include "crab/var_registry.hpp"
#include "crab_utils/lazy_allocator.hpp"
#include "crab_verifier.hpp"
#include "elf_loader.hpp"
#include "string_constraints.hpp"

using std::string;

namespace prevail {
thread_local LazyAllocator<ProgramInfo> thread_local_program_info;
thread_local ebpf_verifier_options_t thread_local_options;
void ebpf_verifier_clear_before_analysis();

bool Invariants::is_valid_after(const Label& label, const StringInvariant& state) const {
    const EbpfDomain abstract_state =
        EbpfDomain::from_constraints(state.value(), thread_local_options.setup_constraints);
    return abstract_state <= invariants.at(label).post;
}

StringInvariant Invariants::invariant_at(const Label& label) const { return invariants.at(label).post.to_set(); }

Interval Invariants::exit_value() const { return invariants.at(Label::exit).post.get_r0(); }

int Invariants::max_loop_count() const {
    ExtendedNumber max_loop_count{0};
    // Gather the upper bound of loop counts from post-invariants.
    for (const auto& inv_pair : std::views::values(invariants)) {
        max_loop_count = std::max(max_loop_count, inv_pair.post.get_loop_count_upper_bound());
    }
    const auto m = max_loop_count.number();
    if (m && m->fits<int32_t>()) {
        return m->cast_to<int32_t>();
    }
    return std::numeric_limits<int>::max();
}

Invariants analyze(const Program& prog, EbpfDomain&& entry_invariant) {
    return Invariants{run_forward_analyzer(prog, std::move(entry_invariant))};
}

Invariants analyze(const Program& prog) {
    ebpf_verifier_clear_before_analysis();
    return analyze(prog, EbpfDomain::setup_entry(thread_local_options.setup_constraints));
}

Invariants analyze(const Program& prog, const StringInvariant& entry_invariant) {
    ebpf_verifier_clear_before_analysis();
    return analyze(prog, EbpfDomain::from_constraints(entry_invariant.value(), thread_local_options.setup_constraints));
}

bool Invariants::verified(const Program& prog) const {
    for (const auto& [label, inv_pair] : invariants) {
        if (inv_pair.pre.is_bottom()) {
            continue;
        }
        for (const Assertion& assertion : prog.assertions_at(label)) {
            if (!ebpf_domain_check(inv_pair.pre, assertion).empty()) {
                return false;
            }
        }
    }
    return true;
}

Report Invariants::check_assertions(const Program& prog) const {
    Report report;
    for (const auto& [label, inv_pair] : invariants) {
        if (inv_pair.pre.is_bottom()) {
            continue;
        }
        for (const Assertion& assertion : prog.assertions_at(label)) {
            const auto warnings = ebpf_domain_check(inv_pair.pre, assertion);
            for (const auto& msg : warnings) {
                report.warnings[label].emplace_back(msg);
            }
        }
        if (const auto passume = std::get_if<Assume>(&prog.instruction_at(label))) {
            if (inv_pair.post.is_bottom()) {
                const auto s = to_string(*passume);
                report.reachability[label].emplace_back("Code becomes unreachable (" + s + ")");
            }
        }
    }
    return report;
}

void ebpf_verifier_clear_before_analysis() {
    clear_thread_local_state();
    variable_registry.clear();
}

void ebpf_verifier_clear_thread_local_state() {
    CrabStats::clear_thread_local_state();
    thread_local_program_info.clear();
    clear_thread_local_state();
    SplitDBM::clear_thread_local_state();
}
} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <iosfwd>
#include <map>
#include <optional>
#include <set>
#include <vector>

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

/// Dependencies of an instruction: what registers and stack locations it reads/writes.
/// Populated during forward analysis when collect_instruction_deps is enabled.
struct InstructionDeps {
    std::set<Reg> regs_read;
    std::set<Reg> regs_written;
    std::set<Reg> regs_clobbered;    // Registers killed/overwritten without reading (e.g., R1-R5 after call)
    std::set<int64_t> stack_read;    // Concrete stack offsets when known
    std::set<int64_t> stack_written; // Concrete stack offsets when known
};

/// Extract the registers and stack offsets read/written by an instruction.
/// @param ins The instruction to analyze.
/// @param pre_state The abstract state before the instruction (for resolving pointer values).
/// @return The dependencies of the instruction.
InstructionDeps extract_instruction_deps(const Instruction& ins, const EbpfDomain& pre_state);

/// Extract the registers referenced by an assertion.
/// Used to seed backward slicing from the point of failure.
/// @param assertion The assertion to analyze.
/// @return The set of registers the assertion depends on.
std::set<Reg> extract_assertion_registers(const Assertion& assertion);

struct InvariantMapPair {
    EbpfDomain pre;
    std::optional<VerificationError> error;
    EbpfDomain post;
    std::optional<InstructionDeps> deps; // Populated when collect_instruction_deps is set
};

/// State that is relevant at a specific program point.
/// Used to filter what parts of the invariant to display.
struct RelevantState {
    std::set<Reg> registers;
    std::set<int64_t> stack_offsets; // Relative stack offsets (e.g., Mem.access.offset values like -8)

    /// Check if a constraint string (e.g., "r1.type=number") involves a relevant register.
    [[nodiscard]]
    bool is_relevant_constraint(const std::string& constraint) const;
};

/// Stream manipulator to filter invariant output to only relevant registers.
/// Usage: os << invariant_filter(&relevant_state) << domain;
/// To clear: os << invariant_filter(nullptr) << domain;
struct invariant_filter {
    const RelevantState* state;
    explicit invariant_filter(const RelevantState* s) : state(s) {}
};

/// Get the current invariant filter from a stream (nullptr if none).
const RelevantState* get_invariant_filter(std::ostream& os);

/// Set the invariant filter on a stream.
std::ostream& operator<<(std::ostream& os, const invariant_filter& filter);

/// A minimal diagnostic slice of a verification failure.
/// Contains labels that contributed to the failure, with per-label
/// tracking of which registers/stack locations are relevant.
struct FailureSlice {
    /// The label where this failure occurred.
    Label failing_label;

    /// The error at this failure point.
    VerificationError error;

    /// Per-label relevant state. Keys are the impacted labels.
    /// At each label, indicates which registers and stack offsets
    /// should be displayed in the invariant.
    std::map<Label, RelevantState> relevance;

    /// Convenience: get all impacted labels.
    [[nodiscard]]
    std::set<Label> impacted_labels() const {
        std::set<Label> result;
        for (const auto& [label, _] : relevance) {
            result.insert(label);
        }
        return result;
    }
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

    /// Parameters for compute_failure_slices to avoid swapping size_t arguments.
    struct SliceParams {
        size_t max_steps = 200; ///< Maximum worklist items to process per failure.
        size_t max_slices = 0;  ///< Maximum number of slices to compute (0 = all).
    };

    /// Compute failure slices for verification errors.
    /// Returns one slice per failure, each containing the set of impacted labels.
    [[nodiscard]]
    std::vector<FailureSlice> compute_failure_slices(const Program& prog, SliceParams params) const;

    [[nodiscard]]
    std::vector<FailureSlice> compute_failure_slices(const Program& prog) const {
        return compute_failure_slices(prog, SliceParams{});
    }
};

void print_error(std::ostream& os, const VerificationError& error);
void print_invariants(std::ostream& os, const Program& prog, bool simplify, const AnalysisResult& result);
void print_unreachable(std::ostream& os, const Program& prog, const AnalysisResult& result);

/// Print invariants filtered to only show labels in the given set.
/// Used to print a failure slice in context.
/// @param compact If true, skip invariant output and only show instructions.
/// @param relevance If provided, only show assertions involving relevant registers.
void print_invariants_filtered(std::ostream& os, const Program& prog, bool simplify, const AnalysisResult& result,
                               const std::set<Label>& filter, bool compact = false,
                               const std::map<Label, RelevantState>* relevance = nullptr);

/// Print all failure slices in a structured diagnostic format.
/// @param compact If true, skip detailed invariants for smaller output.
void print_failure_slices(std::ostream& os, const Program& prog, bool simplify, const AnalysisResult& result,
                          const std::vector<FailureSlice>& slices, bool compact = false);

} // namespace prevail

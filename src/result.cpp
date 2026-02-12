// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <map>
#include <ranges>
#include <regex>
#include <sstream>

#include "crab/ebpf_domain.hpp"
#include "ir/program.hpp"
#include "result.hpp"
#include "spec/ebpf_base.h"
#include "spec/vm_isa.hpp"

namespace prevail {

// Stream-local storage index for invariant filter
static int invariant_filter_index() {
    static const int index = std::ios_base::xalloc();
    return index;
}

const RelevantState* get_invariant_filter(std::ostream& os) {
    return static_cast<const RelevantState*>(os.pword(invariant_filter_index()));
}

std::ostream& operator<<(std::ostream& os, const invariant_filter& filter) {
    os.pword(invariant_filter_index()) = const_cast<void*>(static_cast<const void*>(filter.state));
    return os;
}

bool RelevantState::is_relevant_constraint(const std::string& constraint) const {
    // Extract the register or stack reference from the constraint.
    // Constraints look like: "r1.type=number", "r2.svalue=[0, 100]", "s[4088...4095].type=ctx"
    // Relational constraints: "r1.svalue-r8.svalue<=-100", "r0.svalue=r3.svalue+2"
    // Also handle: "packet_size=54", "meta_offset=[-4098, 0]"

    // Track whether we matched any known pattern.  When at least one pattern
    // fires but nothing is relevant we return false; the conservative
    // `return true` at the end only applies to truly unparseable constraints.
    bool parsed_any_pattern = false;

    // Check for ANY register mentioned in the constraint (not just at start).
    // This handles relational constraints like "r1.svalue-r8.svalue<=100".
    static const std::regex reg_pattern(R"(r(\d+)\.)");
    std::sregex_iterator it(constraint.begin(), constraint.end(), reg_pattern);
    std::sregex_iterator end;

    while (it != end) {
        parsed_any_pattern = true;
        const uint8_t reg_num = static_cast<uint8_t>(std::stoi((*it)[1].str()));
        if (registers.contains(Reg{reg_num})) {
            return true; // At least one relevant register is mentioned
        }
        ++it;
    }

    // Precompute absolute stack offsets once to avoid repeated conversion in loops
    std::vector<int64_t> abs_stack_offsets;
    abs_stack_offsets.reserve(stack_offsets.size());
    for (const auto& rel_offset : stack_offsets) {
        abs_stack_offsets.push_back(EBPF_TOTAL_STACK_SIZE + rel_offset);
    }

    // Check for stack range pattern: s[start...end]
    static const std::regex stack_range_pattern(R"(s\[(\d+)\.\.\.(\d+)\])");
    std::sregex_iterator stack_it(constraint.begin(), constraint.end(), stack_range_pattern);
    while (stack_it != end) {
        parsed_any_pattern = true;
        const int64_t abs_start = std::stoll((*stack_it)[1].str());
        const int64_t abs_end = std::stoll((*stack_it)[2].str());
        for (const auto& abs_offset : abs_stack_offsets) {
            if (abs_offset >= abs_start && abs_offset <= abs_end) {
                return true; // Overlaps within the constraint range
            }
        }
        ++stack_it;
    }

    // Check for single-offset stack pattern: s[offset]
    static const std::regex stack_single_pattern(R"(s\[(\d+)\]\.)");
    std::sregex_iterator single_it(constraint.begin(), constraint.end(), stack_single_pattern);
    while (single_it != end) {
        parsed_any_pattern = true;
        const int64_t abs_pos = std::stoll((*single_it)[1].str());
        for (const auto& abs_offset : abs_stack_offsets) {
            if (abs_offset == abs_pos) {
                return true;
            }
        }
        ++single_it;
    }

    // Global constraints (packet_size, meta_offset) - always show for context
    if (constraint.starts_with("packet_size") || constraint.starts_with("meta_offset")) {
        return true;
    }

    // A known pattern was parsed but nothing matched — the constraint is irrelevant.
    if (parsed_any_pattern) {
        return false;
    }

    // If we can't parse it at all, show it (conservative)
    return true;
}

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

/// Extract the registers and stack offsets read/written by an instruction.
/// Used to populate InstructionDeps during forward analysis.
InstructionDeps extract_instruction_deps(const Instruction& ins, const EbpfDomain& pre_state) {
    InstructionDeps deps;

    std::visit(
        [&](const auto& v) {
            using T = std::decay_t<decltype(v)>;

            if constexpr (std::is_same_v<T, Bin>) {
                // dst = dst op src (or dst = src for MOV/MOVSX)
                deps.regs_written.insert(v.dst);
                if (v.op != Bin::Op::MOV && v.op != Bin::Op::MOVSX8 && v.op != Bin::Op::MOVSX16 &&
                    v.op != Bin::Op::MOVSX32) {
                    // Non-move ops also read dst
                    deps.regs_read.insert(v.dst);
                }
                if (const auto* reg = std::get_if<Reg>(&v.v)) {
                    deps.regs_read.insert(*reg);
                }
            } else if constexpr (std::is_same_v<T, Un>) {
                // dst = op(dst)
                deps.regs_read.insert(v.dst);
                deps.regs_written.insert(v.dst);
            } else if constexpr (std::is_same_v<T, LoadMapFd> || std::is_same_v<T, LoadMapAddress>) {
                deps.regs_written.insert(v.dst);
            } else if constexpr (std::is_same_v<T, Mem>) {
                deps.regs_read.insert(v.access.basereg);
                if (v.is_load) {
                    // Load: value = *(basereg + offset)
                    if (const auto* dst_reg = std::get_if<Reg>(&v.value)) {
                        deps.regs_written.insert(*dst_reg);
                    }
                    // Track stack read if base is a stack pointer (R10 or derived)
                    if (v.access.basereg.v == R10_STACK_POINTER) {
                        deps.stack_read.insert(v.access.offset);
                    } else if (const auto stack_off = pre_state.get_stack_offset(v.access.basereg)) {
                        // basereg is a stack pointer with known offset from R10
                        // Compute the actual stack slot: stack_off is absolute (e.g., 4096),
                        // convert to relative from R10: relative = offset + (stack_off - EBPF_TOTAL_STACK_SIZE)
                        deps.stack_read.insert(v.access.offset + (*stack_off - EBPF_TOTAL_STACK_SIZE));
                    }
                } else {
                    // Store: *(basereg + offset) = value
                    if (const auto* src_reg = std::get_if<Reg>(&v.value)) {
                        deps.regs_read.insert(*src_reg);
                    }
                    // Track stack write if base is a stack pointer (R10 or derived)
                    if (v.access.basereg.v == R10_STACK_POINTER) {
                        deps.stack_written.insert(v.access.offset);
                    } else if (const auto stack_off = pre_state.get_stack_offset(v.access.basereg)) {
                        deps.stack_written.insert(v.access.offset + (*stack_off - EBPF_TOTAL_STACK_SIZE));
                    }
                }
            } else if constexpr (std::is_same_v<T, Atomic>) {
                deps.regs_read.insert(v.access.basereg);
                deps.regs_read.insert(v.valreg);
                if (v.fetch) {
                    deps.regs_written.insert(v.valreg);
                }
                // Track stack read/write if base is a stack pointer (R10 or derived)
                if (v.access.basereg.v == R10_STACK_POINTER) {
                    deps.stack_read.insert(v.access.offset);
                    deps.stack_written.insert(v.access.offset);
                } else if (const auto stack_off = pre_state.get_stack_offset(v.access.basereg)) {
                    const auto adjusted_off = v.access.offset + (*stack_off - EBPF_TOTAL_STACK_SIZE);
                    deps.stack_read.insert(adjusted_off);
                    deps.stack_written.insert(adjusted_off);
                }
            } else if constexpr (std::is_same_v<T, Call>) {
                // Calls read R1-R5 as arguments, write R0 as return value,
                // and clobber R1-R5 (caller-saved registers are killed).
                // Separate clobbers from writes so backward slicing can:
                // - Stop propagation for post-call uses of R1-R5 (they're killed)
                // - Still trace R1-R5 as read-deps when R0 is relevant-after (args affect return)
                for (uint8_t i = 1; i <= 5; ++i) {
                    deps.regs_read.insert(Reg{i});      // Arguments feed into return value
                    deps.regs_clobbered.insert(Reg{i}); // Killed after call
                }
                deps.regs_written.insert(Reg{0}); // Return value
            } else if constexpr (std::is_same_v<T, CallLocal>) {
                // Local (macro-inlined) calls:
                // - read R1-R5 as arguments
                // - write R0 as return value
                // - clobber R1-R5 (caller-saved)
                // - adjust frame pointer R10 (save/restore callee-saved regs)
                for (uint8_t i = 1; i <= 5; ++i) {
                    deps.regs_read.insert(Reg{i});      // Arguments
                    deps.regs_clobbered.insert(Reg{i}); // Killed after call
                }
                deps.regs_written.insert(Reg{0});  // Return value
                deps.regs_read.insert(Reg{10});    // Frame pointer read
                deps.regs_written.insert(Reg{10}); // Frame pointer adjusted
            } else if constexpr (std::is_same_v<T, Callx>) {
                // Indirect call: reads the function pointer and R1-R5,
                // writes R0, and clobbers R1-R5.
                deps.regs_read.insert(v.func);
                for (uint8_t i = 1; i <= 5; ++i) {
                    deps.regs_read.insert(Reg{i});      // Arguments
                    deps.regs_clobbered.insert(Reg{i}); // Killed after call
                }
                deps.regs_written.insert(Reg{0});
            } else if constexpr (std::is_same_v<T, Exit>) {
                deps.regs_read.insert(Reg{0}); // Return value
                if (!v.stack_frame_prefix.empty()) {
                    // Subprogram return restores callee-saved registers and frame pointer.
                    for (uint8_t i = R6; i <= R9; ++i) {
                        deps.regs_written.insert(Reg{i});
                    }
                    deps.regs_written.insert(Reg{R10_STACK_POINTER});
                }
            } else if constexpr (std::is_same_v<T, Jmp>) {
                if (v.cond) {
                    deps.regs_read.insert(v.cond->left);
                    if (const auto* reg = std::get_if<Reg>(&v.cond->right)) {
                        deps.regs_read.insert(*reg);
                    }
                }
            } else if constexpr (std::is_same_v<T, Assume>) {
                deps.regs_read.insert(v.cond.left);
                if (const auto* reg = std::get_if<Reg>(&v.cond.right)) {
                    deps.regs_read.insert(*reg);
                }
            } else if constexpr (std::is_same_v<T, Packet>) {
                if (v.regoffset) {
                    deps.regs_read.insert(*v.regoffset);
                }
                deps.regs_written.insert(Reg{0}); // Result in R0
                // Packet clobbers caller-saved registers R1-R5 without reading them
                for (uint8_t i = 1; i <= 5; ++i) {
                    deps.regs_clobbered.insert(Reg{i});
                }
            }
            // Undefined and IncrementLoopCounter have no register deps
        },
        ins);

    return deps;
}

/// Extract the registers referenced by an assertion.
/// Used to seed backward slicing from the point of failure.
std::set<Reg> extract_assertion_registers(const Assertion& assertion) {
    return std::visit(
        [](const auto& a) -> std::set<Reg> {
            using T = std::decay_t<decltype(a)>;

            if constexpr (std::is_same_v<T, Comparable>) {
                return {a.r1, a.r2};
            } else if constexpr (std::is_same_v<T, Addable>) {
                return {a.ptr, a.num};
            } else if constexpr (std::is_same_v<T, ValidDivisor>) {
                return {a.reg};
            } else if constexpr (std::is_same_v<T, ValidAccess>) {
                std::set<Reg> regs{a.reg};
                if (const auto* r = std::get_if<Reg>(&a.width)) {
                    regs.insert(*r);
                }
                return regs;
            } else if constexpr (std::is_same_v<T, ValidStore>) {
                return {a.mem, a.val};
            } else if constexpr (std::is_same_v<T, ValidSize>) {
                return {a.reg};
            } else if constexpr (std::is_same_v<T, ValidMapKeyValue>) {
                return {a.access_reg, a.map_fd_reg};
            } else if constexpr (std::is_same_v<T, ValidCall>) {
                // ValidCall checks function validity, no direct register deps
                return {};
            } else if constexpr (std::is_same_v<T, TypeConstraint>) {
                return {a.reg};
            } else if constexpr (std::is_same_v<T, FuncConstraint>) {
                return {a.reg};
            } else if constexpr (std::is_same_v<T, ZeroCtxOffset>) {
                return {a.reg};
            } else if constexpr (std::is_same_v<T, BoundedLoopCount>) {
                // Loop counter, not a register
                return {};
            }
            return {};
        },
        assertion);
}

std::vector<FailureSlice> AnalysisResult::compute_failure_slices(const Program& prog, const SliceParams params) const {
    const auto max_steps = params.max_steps;
    const auto max_slices = params.max_slices;
    std::vector<FailureSlice> slices;

    // Find all labels with errors
    for (const auto& [label, inv_pair] : invariants) {
        if (inv_pair.pre.is_bottom()) {
            continue; // Unreachable
        }
        if (!inv_pair.error) {
            continue; // No error here
        }

        // Check if we've reached the max slices limit
        if (max_slices > 0 && slices.size() >= max_slices) {
            break;
        }

        FailureSlice slice{
            .failing_label = label,
            .error = *inv_pair.error,
            .relevance = {},
        };

        // Seed relevant registers from the actual failing assertion.
        // Forward analysis stops at the first failing assertion, which may not be
        // assertions[0]. Replay the checks against the pre-state to identify
        // the actual failing assertion and seed relevance from it.
        RelevantState initial_relevance;
        const auto& assertions = prog.assertions_at(label);
        bool found_failing = false;
        for (const auto& assertion : assertions) {
            if (ebpf_domain_check(inv_pair.pre, assertion, label)) {
                for (const auto& reg : extract_assertion_registers(assertion)) {
                    initial_relevance.registers.insert(reg);
                }
                found_failing = true;
                break;
            }
        }
        // Fallback: if no failing assertion was identified (shouldn't happen),
        // or if the failing assertion has no register deps, aggregate all assertions.
        if (!found_failing || initial_relevance.registers.empty()) {
            for (const auto& assertion : assertions) {
                for (const auto& reg : extract_assertion_registers(assertion)) {
                    initial_relevance.registers.insert(reg);
                }
            }
        }

        // Always include the failing label in the slice, even if no registers were extracted
        // (e.g., ValidCall, BoundedLoopCount assertions have no register deps)

        // `visited` tracks all explored labels for deduplication during backward traversal.
        // `slice_labels` tracks only labels that interact with relevant registers (the output slice).
        std::map<Label, RelevantState> visited;
        std::set<Label> conservative_visited; // Dedup for empty-relevance labels in conservative mode
        std::map<Label, RelevantState> slice_labels;

        // Worklist: (label, relevant_state_after_this_label)
        std::vector<std::pair<Label, RelevantState>> worklist;
        worklist.emplace_back(label, initial_relevance);

        // When the seed has no register/stack deps (e.g., BoundedLoopCount),
        // perform a conservative backward walk so the slice still shows the
        // loop structure and control flow leading to the failure.
        const bool conservative_mode = initial_relevance.registers.empty() && initial_relevance.stack_offsets.empty();

        size_t steps = 0;

        // Hoist the parent lookup for the failing label outside the hot loop;
        // it is invariant and parents_of() may return a temporary.
        const auto parents_of_fail = prog.cfg().parents_of(label);

        while (!worklist.empty() && steps < max_steps) {
            auto [current_label, relevant_after] = worklist.back();
            worklist.pop_back();

            // Skip if nothing is relevant — unless we're in conservative mode
            // (empty-seed assertions like BoundedLoopCount) or this is the failing label.
            if (!conservative_mode && current_label != label && relevant_after.registers.empty() &&
                relevant_after.stack_offsets.empty()) {
                continue;
            }

            // Merge with existing relevance at this label (for deduplication)
            auto& existing = visited[current_label];
            const size_t prev_size = existing.registers.size() + existing.stack_offsets.size();
            existing.registers.insert(relevant_after.registers.begin(), relevant_after.registers.end());
            existing.stack_offsets.insert(relevant_after.stack_offsets.begin(), relevant_after.stack_offsets.end());
            const size_t new_size = existing.registers.size() + existing.stack_offsets.size();

            // If no new relevance was added, skip (already processed with same or broader relevance).
            // In conservative mode with empty relevance, use a separate visited set for dedup.
            if (new_size == prev_size) {
                if (prev_size > 0) {
                    continue;
                }
                // Empty relevance (conservative mode): skip if we already visited this label
                if (!conservative_visited.insert(current_label).second) {
                    continue;
                }
            }

            // Compute what's relevant BEFORE this instruction using deps
            RelevantState relevant_before;
            const auto inv_it = invariants.find(current_label);
            if (inv_it != invariants.end() && inv_it->second.deps) {
                const auto& deps = *inv_it->second.deps;

                // Start with what's relevant after
                relevant_before = relevant_after;

                // Remove registers that are written by this instruction
                // (they weren't relevant before their definition)
                for (const auto& reg : deps.regs_written) {
                    relevant_before.registers.erase(reg);
                }

                // Remove registers that are clobbered (killed without reading).
                // These stop propagation for post-instruction uses but don't add read-deps.
                for (const auto& reg : deps.regs_clobbered) {
                    relevant_before.registers.erase(reg);
                }

                // Determine if this instruction contributes to the slice.
                // An instruction contributes when it writes to a relevant register/stack slot,
                // or when it is a control-flow decision (Jmp/Assume) that reads relevant registers.
                bool instruction_contributes = false;
                for (const auto& reg : deps.regs_written) {
                    if (relevant_after.registers.contains(reg)) {
                        instruction_contributes = true;
                        break;
                    }
                }
                for (const auto& offset : deps.stack_written) {
                    if (relevant_after.stack_offsets.contains(offset)) {
                        instruction_contributes = true;
                        break;
                    }
                }

                // Control-flow instructions (Jmp/Assume) that read relevant registers
                // contribute to the slice because they shape the path to the failure.
                if (!instruction_contributes) {
                    const auto& ins = prog.instruction_at(current_label);
                    if (std::holds_alternative<Jmp>(ins) || std::holds_alternative<Assume>(ins)) {
                        for (const auto& reg : deps.regs_read) {
                            if (relevant_after.registers.contains(reg)) {
                                instruction_contributes = true;
                                break;
                            }
                        }
                    }
                }

                // Immediate path guard: when the current label is a direct predecessor
                // of the failing label and is an Assume instruction, its condition
                // registers are causally relevant — they determine reachability.
                if (std::holds_alternative<Assume>(prog.instruction_at(current_label))) {
                    if (std::find(parents_of_fail.begin(), parents_of_fail.end(), current_label) !=
                        parents_of_fail.end()) {
                        instruction_contributes = true;
                    }
                }

                // At the failing label, the assertion depends on registers the instruction
                // reads (e.g., base pointer r3 in a store). Since stores write to memory
                // not registers, instruction_contributes would be false without this.
                if (current_label == label) {
                    instruction_contributes = true;
                }

                // In conservative mode (empty seed, e.g., BoundedLoopCount), include all
                // reachable labels so the slice shows the loop structure and control flow.
                if (conservative_mode) {
                    instruction_contributes = true;
                }

                if (instruction_contributes) {
                    for (const auto& reg : deps.regs_read) {
                        relevant_before.registers.insert(reg);
                    }
                    for (const auto& offset : deps.stack_read) {
                        relevant_before.stack_offsets.insert(offset);
                    }
                }

                // Remove stack locations that are written by this instruction,
                // but preserve offsets that are also read (read-modify-write, e.g., Atomic).
                // Done before storing to slice_labels for consistency with register handling
                // (written registers are removed before storage at lines 476-478).
                for (const auto& offset : deps.stack_written) {
                    if (!deps.stack_read.contains(offset)) {
                        relevant_before.stack_offsets.erase(offset);
                    }
                }

                if (instruction_contributes) {
                    // Only include contributing labels in the output slice.
                    // Store relevant_before so pre-invariant filtering shows the
                    // instruction's read-deps (the true upstream dependencies).
                    slice_labels[current_label] = relevant_before;
                }
            } else {
                // No deps available: conservatively treat this label as contributing
                // and propagate all current relevance to predecessors.
                relevant_before = relevant_after;
                slice_labels[current_label] = relevant_before;
            }

            // Add predecessors to worklist
            for (const auto& parent : prog.cfg().parents_of(current_label)) {
                worklist.emplace_back(parent, relevant_before);
            }

            ++steps;
        }

        // Expand join points: for any traversed label that is a join point
        // (≥2 predecessors) where at least one predecessor is already in the slice,
        // add the join-point label itself and all predecessors that have invariants.
        // This ensures the causal trace shows converging paths that cause precision loss.
        // Note: predecessors may not be in `visited` if the worklist budget was exhausted
        // before reaching them, so we check the invariant map directly.
        std::map<Label, RelevantState> join_expansion;
        for (const auto& [v_label, v_relevance] : visited) {
            const auto& parents = prog.cfg().parents_of(v_label);
            if (parents.size() < 2) {
                continue;
            }
            // Check that at least one predecessor is in the slice (this join is relevant)
            bool has_slice_parent = false;
            for (const auto& parent : parents) {
                if (slice_labels.contains(parent)) {
                    has_slice_parent = true;
                    break;
                }
            }
            if (!has_slice_parent) {
                continue;
            }
            // Include the join-point label itself so the printing code can display
            // per-predecessor state at this join.
            if (!slice_labels.contains(v_label)) {
                join_expansion[v_label] = v_relevance;
            }
            // Include all predecessors so the join display is complete.
            // Use visited relevance if available, otherwise use the join-point's relevance.
            for (const auto& parent : parents) {
                if (slice_labels.contains(parent) || join_expansion.contains(parent)) {
                    continue;
                }
                const auto& rel = visited.contains(parent) ? visited.at(parent) : v_relevance;
                join_expansion[parent] = rel;
            }
        }
        slice_labels.insert(join_expansion.begin(), join_expansion.end());

        // Build the slice from contributing labels only
        slice.relevance = std::move(slice_labels);
        slices.push_back(std::move(slice));
    }

    return slices;
}

} // namespace prevail

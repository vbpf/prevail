// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "analysis_engine.hpp"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace prevail_mcp {

AnalysisEngine::AnalysisEngine(PlatformOps* ops) : ops_(ops) {
    // Initialize options from platform defaults.
    auto defaults = ops_->default_options();
    current_opts_.check_termination = defaults.cfg_opts.check_for_termination;
    current_opts_.allow_division_by_zero = defaults.allow_division_by_zero;
    current_opts_.strict = defaults.strict;
}

bool AnalysisEngine::session_matches(const std::string& elf_path, const std::string& section,
                                     const std::string& program, const std::string& type) const {
    if (!session_) {
        return false;
    }
    if (session_->elf_path != elf_path || session_->section != section || session_->program_name != program ||
        session_type_ != type) {
        return false;
    }
    // Re-analyze if the file has been modified since last analysis.
    try {
        return std::filesystem::last_write_time(elf_path) == session_->file_mtime;
    } catch (const std::filesystem::filesystem_error&) {
        return false; // File no longer accessible — force re-analysis.
    }
}

std::vector<ProgramEntry> AnalysisEngine::list_programs(const std::string& elf_path) {
    return ops_->list_programs(elf_path);
}

const AnalysisSession& AnalysisEngine::analyze(const std::string& elf_path, const std::string& section,
                                               const std::string& program, const std::string& type,
                                               std::optional<bool> check_termination,
                                               std::optional<bool> allow_division_by_zero,
                                               std::optional<bool> strict) {
    // Apply any explicit option overrides.
    VerificationOptions new_opts = current_opts_;
    if (check_termination.has_value()) {
        new_opts.check_termination = *check_termination;
    }
    if (allow_division_by_zero.has_value()) {
        new_opts.allow_division_by_zero = *allow_division_by_zero;
    }
    if (strict.has_value()) {
        new_opts.strict = *strict;
    }

    // If options changed, invalidate the current session.
    if (new_opts != current_opts_) {
        session_.reset();
        current_opts_ = new_opts;
    }

    // Reuse the current session if it matches.
    if (session_matches(elf_path, section, program, type)) {
        return *session_;
    }

    // Different program — discard old session and run fresh analysis.
    session_.reset();

    ops_->prepare_tls(type);

    // Determine target program using the new ElfObject API.
    std::string target_section = section;
    std::string target_program = program;
    if (target_section.empty() && target_program.empty()) {
        auto entries = list_programs(elf_path);
        for (const auto& entry : entries) {
            if (entry.section != ".text") {
                target_section = entry.section;
                target_program = entry.function;
                break;
            }
        }
        if (target_section.empty() && !entries.empty()) {
            target_section = entries.front().section;
            target_program = entries.front().function;
        }
    }

    try {
        auto tls_guard = std::make_unique<prevail::ThreadLocalGuard>();

        prevail::ebpf_verifier_options_t options = ops_->default_options();
        options.cfg_opts.check_for_termination = current_opts_.check_termination;
        options.allow_division_by_zero = current_opts_.allow_division_by_zero;
        options.strict = current_opts_.strict;
        options.verbosity_opts.print_failures = true;
        options.verbosity_opts.print_line_info = true;
        options.verbosity_opts.collect_instruction_deps = true;

        prevail::ElfObject elf(elf_path, options, ops_->platform());
        const auto& raw_progs = elf.get_programs(target_section, target_program);

        if (raw_progs.empty()) {
            throw std::runtime_error("Program not found: " + target_program + " in " + elf_path);
        }
        const auto& found = raw_progs.front();

        std::vector<std::vector<std::string>> notes;
        auto prog_or_error = prevail::unmarshal(found, notes, options);
        if (auto* err = std::get_if<std::string>(&prog_or_error)) {
            throw std::runtime_error("Unmarshal error: " + *err);
        }
        auto& inst_seq = std::get<prevail::InstructionSeq>(prog_or_error);

        prevail::Program prog = prevail::Program::from_sequence(inst_seq, found.info, options);
        prevail::AnalysisResult result = prevail::analyze(prog);

        // Build session with serialized invariants (while TLS is alive).
        AnalysisSession session;
        session.elf_path = elf_path;
        session.section = found.section_name;
        session.program_name = found.function_name;
        session.inst_seq = std::move(inst_seq);
        session.program = std::move(prog);
        session.failed = result.failed;
        session.max_loop_count = result.max_loop_count;
        session.exit_value = result.exit_value;
        session.file_mtime = std::filesystem::last_write_time(elf_path);

        for (const auto& [label, inv_pair] : result.invariants) {
            AnalysisSession::SerializedInvariant si;
            si.pre_is_bottom = inv_pair.pre.is_bottom();
            try {
                if (!si.pre_is_bottom) {
                    si.pre = inv_pair.pre.to_set();
                }
                if (!inv_pair.post.is_bottom()) {
                    si.post = inv_pair.post.to_set();
                }
            } catch (const std::exception& e) {
                std::cerr << "prevail_mcp: warning: failed to serialize invariant at label " << label.from << ": "
                          << e.what() << std::endl;
            }
            if (inv_pair.error.has_value()) {
                si.error_message = inv_pair.error->what();
                si.error_label = inv_pair.error->where;
            }
            session.invariants.emplace(label, std::move(si));
        }

        // Build source maps from BTF line info.
        int pc = 0;
        for (const auto& [label, inst, line_info] : session.inst_seq) {
            if (line_info.has_value()) {
                session.pc_to_source[pc] = *line_info;
                auto src_key = std::make_pair(line_info->file_name, static_cast<int>(line_info->line_number));
                session.source_to_pcs[src_key].push_back(pc);
            }
            pc += prevail::size(inst);
        }

        // Build PC → Label lookup.
        for (const auto& [label, inv] : session.invariants) {
            session.pc_to_labels[label.from].push_back(label);
        }

        // Keep live state for check_constraint and slicing.
        session.live_result = std::move(result);
        session.tls_guard = std::move(tls_guard);

        session_ = std::move(session);
        session_type_ = type;
        return *session_;

    } catch (...) {
        throw;
    }
}

// ─── Live session operations ───────────────────────────────────────────────────

prevail::ObservationCheckResult
AnalysisEngine::check_constraint(const std::string& elf_path, const std::string& section, const std::string& program,
                                 const std::string& type, const prevail::Label& label, prevail::InvariantPoint point,
                                 const prevail::StringInvariant& observation, const std::string& mode_str) {
    // analyze() ensures the session is live.
    analyze(elf_path, section, program, type);

    if (mode_str == "proven") {
        auto it = session_->live_result->invariants.find(label);
        if (it == session_->live_result->invariants.end()) {
            return {.ok = false, .message = "No invariant available for label"};
        }
        const auto& abstract_state = (point == prevail::InvariantPoint::post) ? it->second.post : it->second.pre;
        if (abstract_state.is_bottom()) {
            return {.ok = false, .message = "Invariant at label is bottom (unreachable)"};
        }

        const auto observed_state = observation.is_bottom()
                                        ? prevail::EbpfDomain::bottom()
                                        : prevail::EbpfDomain::from_constraints(
                                              observation.value(), prevail::thread_local_options.setup_constraints);
        if (observed_state.is_bottom()) {
            return {.ok = false, .message = "Observation constraints are unsatisfiable"};
        }

        if (abstract_state <= observed_state) {
            return {.ok = true, .message = ""};
        }
        return {.ok = false,
                .message = "Invariant does not prove the constraint (A ⊑ C is false). "
                           "The verifier's state includes possibilities outside the observation."};
    }

    auto mode =
        (mode_str == "entailed") ? prevail::ObservationCheckMode::entailed : prevail::ObservationCheckMode::consistent;
    return session_->live_result->check_observation_at_label(label, point, observation, mode);
}

prevail::StringInvariant AnalysisEngine::get_live_invariant(const prevail::Label& label,
                                                            prevail::InvariantPoint point) const {
    if (!session_ || !session_->live_result) {
        return prevail::StringInvariant::bottom();
    }
    auto it = session_->live_result->invariants.find(label);
    if (it == session_->live_result->invariants.end()) {
        return prevail::StringInvariant::bottom();
    }
    const auto& abstract_state = (point == prevail::InvariantPoint::post) ? it->second.post : it->second.pre;
    if (abstract_state.is_bottom()) {
        return prevail::StringInvariant::bottom();
    }
    return abstract_state.to_set();
}

std::vector<prevail::FailureSlice>
AnalysisEngine::compute_failure_slices(const std::string& elf_path, const std::string& section,
                                       const std::string& program, const std::string& type,
                                       const prevail::Program& prog, size_t max_slices, size_t max_steps) {
    analyze(elf_path, section, program, type);

    prevail::AnalysisResult::SliceParams params;
    params.max_slices = max_slices;
    params.max_steps = max_steps;
    return session_->live_result->compute_failure_slices(prog, params);
}

prevail::FailureSlice AnalysisEngine::compute_slice_from_label(const std::string& elf_path, const std::string& section,
                                                               const std::string& program, const std::string& type,
                                                               const prevail::Program& prog,
                                                               const prevail::Label& label,
                                                               const prevail::RelevantState& seed, size_t max_steps) {
    analyze(elf_path, section, program, type);

    prevail::RelevantState effective_seed = seed;
    if (effective_seed.registers.empty() && effective_seed.stack_offsets.empty()) {
        for (const auto& a : prog.assertions_at(label)) {
            for (const auto& reg : prevail::extract_assertion_registers(a)) {
                effective_seed.registers.insert(reg);
            }
        }
        if (effective_seed.registers.empty()) {
            auto deps = prevail::extract_instruction_deps(prog.instruction_at(label), prevail::EbpfDomain::top());
            for (const auto& reg : deps.regs_read) {
                effective_seed.registers.insert(reg);
            }
        }
    }

    return session_->live_result->compute_slice_from_label(prog, label, effective_seed, max_steps);
}

} // namespace prevail_mcp

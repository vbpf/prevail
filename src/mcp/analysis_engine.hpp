// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

/// @file Analysis engine: runs the PREVAIL pipeline and holds a single live session.

#include "platform_ops.hpp"
#include "prevail_headers.hpp"

#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace prevail_mcp {

/// Verification options that affect analysis results.
/// Defaults come from the platform (PlatformOps::default_options()).
struct VerificationOptions {
    bool check_termination;
    bool allow_division_by_zero;
    bool strict;

    bool operator==(const VerificationOptions& other) const {
        return check_termination == other.check_termination &&
               allow_division_by_zero == other.allow_division_by_zero && strict == other.strict;
    }
    bool operator!=(const VerificationOptions& other) const { return !(*this == other); }
};

/// Holds all outputs from a single verification run.
/// The session is always "live" — it retains both pre-serialized invariants
/// (for tools that iterate or display them) and the live AnalysisResult with
/// EbpfDomain objects (for check_constraint and backward slicing).
/// Only one session exists at a time; analyzing a different program discards it.
struct AnalysisSession {
    std::string elf_path;
    std::string section;
    std::string program_name;

    // The instruction sequence (labels + instructions + btf_line_info).
    prevail::InstructionSeq inst_seq;

    // The CFG program (for instruction_at, assertions_at, cfg navigation).
    prevail::Program program;

    // Overall result metadata.
    bool failed = false;
    int max_loop_count = 0;
    prevail::Interval exit_value = prevail::Interval::top();

    /// Pre-serialized invariant data per label (serialized while TLS is alive).
    struct SerializedInvariant {
        prevail::StringInvariant pre;
        prevail::StringInvariant post;
        std::optional<std::string> error_message;  // VerificationError::what().
        std::optional<prevail::Label> error_label; // VerificationError::where.
        bool pre_is_bottom = false;
    };
    std::map<prevail::Label, SerializedInvariant> invariants;

    // Derived: PC → source line info (built from BTF in InstructionSeq).
    std::map<int, prevail::btf_line_info_t> pc_to_source;

    // Derived: (file, line) → list of PCs.
    std::map<std::pair<std::string, int>, std::vector<int>> source_to_pcs;

    // Derived: PC → labels in the invariant map that have this PC as .from.
    std::map<int, std::vector<prevail::Label>> pc_to_labels;

    // Live state: TLS guard keeps variable_registry alive for EbpfDomain ops.
    // live_result must be declared BEFORE tls_guard so it is destroyed FIRST
    // (C++ destroys members in reverse declaration order), ensuring EbpfDomain
    // objects are cleaned up while the thread-local state is still valid.
    std::optional<prevail::AnalysisResult> live_result;
    std::unique_ptr<prevail::ThreadLocalGuard> tls_guard;

    // File modification time at analysis time (for staleness detection).
    std::filesystem::file_time_type file_mtime;
};

/// Runs the PREVAIL pipeline and holds a single live session.
/// Re-analyzes when a different program or different options are requested.
class AnalysisEngine {
  public:
    explicit AnalysisEngine(PlatformOps* ops);

    /// Run analysis on the given ELF file (or return the current session if it
    /// matches). Keeps TLS alive so check_constraint and slicing work without
    /// re-analyzing. Option overrides only take effect if explicitly provided;
    /// nullopt preserves the current setting.
    /// @param type  Optional program type name override (e.g. "xdp", "bind").
    /// @throws std::runtime_error on ELF parse, unmarshal, or analysis failure.
    const AnalysisSession& analyze(const std::string& elf_path, const std::string& section = "",
                                   const std::string& program = "", const std::string& type = "",
                                   std::optional<bool> check_termination = std::nullopt,
                                   std::optional<bool> allow_division_by_zero = std::nullopt,
                                   std::optional<bool> strict = std::nullopt);

    /// Check constraints against the live AnalysisResult (re-analyzes if needed).
    /// @param mode_str  "consistent", "entailed", or "proven".
    prevail::ObservationCheckResult check_constraint(const std::string& elf_path, const std::string& section,
                                                     const std::string& program, const std::string& type,
                                                     const prevail::Label& label, prevail::InvariantPoint point,
                                                     const prevail::StringInvariant& observation,
                                                     const std::string& mode_str);

    /// Get the invariant at a label from the live session (calls to_set() on demand).
    /// @returns StringInvariant::bottom() if no session, label not found, or state is bottom.
    prevail::StringInvariant get_live_invariant(const prevail::Label& label, prevail::InvariantPoint point) const;

    /// Compute failure slices from the live session (re-analyzes if needed).
    std::vector<prevail::FailureSlice> compute_failure_slices(const std::string& elf_path, const std::string& section,
                                                              const std::string& program, const std::string& type,
                                                              const prevail::Program& prog, size_t max_slices = 1,
                                                              size_t max_steps = 200);

    /// Compute a backward slice from an arbitrary label (re-analyzes if needed).
    prevail::FailureSlice compute_slice_from_label(const std::string& elf_path, const std::string& section,
                                                   const std::string& program, const std::string& type,
                                                   const prevail::Program& prog, const prevail::Label& label,
                                                   const prevail::RelevantState& seed = {}, size_t max_steps = 200);

    /// List all programs in an ELF file.
    std::vector<ProgramEntry> list_programs(const std::string& elf_path);

    /// Get the current verification options.
    const VerificationOptions& options() const { return current_opts_; }

    /// Get the platform pointer.
    const prevail::ebpf_platform_t* platform() const { return ops_->platform(); }

    /// Get the platform ops.
    PlatformOps* ops() const { return ops_; }

  private:
    /// Check if the current session matches the requested program and options.
    bool session_matches(const std::string& elf_path, const std::string& section, const std::string& program,
                         const std::string& type) const;

    PlatformOps* ops_;
    std::optional<AnalysisSession> session_;
    std::string session_type_;          // Program type override used for the current session.
    VerificationOptions current_opts_;  // Current verification options (applied to session_).
};

} // namespace prevail_mcp

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <stdexcept>
#include <string>

namespace prevail {
struct prepare_cfg_options {
    /// When true, verifies that the program terminates.
    bool check_for_termination = false;
    /// When true, ensures the program has a valid exit block.
    bool must_have_exit = true;
};

struct verbosity_options_t {
    /// When true, prints simplified control flow graph by merging chains into basic blocks.
    bool simplify = true;

    /// Print the invariants for each basic block.
    bool print_invariants = false;

    /// Print failures that occur during verification.
    bool print_failures = false;

    /// When printing the control flow graph, print the line number of each instruction.
    bool print_line_info = false;

    /// Print the BTF types in JSON format.
    bool dump_btf_types_json = false;

    /// Collect instruction dependencies for failure slice computation.
    /// When true, the forward analysis annotates each instruction with
    /// the registers and stack offsets it reads/writes, enabling efficient
    /// backward slicing for failure diagnostics.
    bool collect_instruction_deps = false;

    /// When printing failure slices, omit per-label pre/post invariants and
    /// per-predecessor join-point detail — emit only the control-flow summary
    /// and the instruction trace.
    bool compact_slice = false;
};

struct ebpf_verifier_options_t {
    // Options that control how the control flow graph is built.
    prepare_cfg_options cfg_opts;

    // False to use actual map fd's, true to use mock fd's.
    bool mock_map_fds = true;

    // True to do additional checks for some things that would fail at runtime.
    bool strict = false;

    // True to allow division by zero and assume BPF ISA defined semantics.
    bool allow_division_by_zero = true;

    // Set up the entry constraints for a BPF program.
    bool setup_constraints = true;

    // True if the ELF file is built on a big endian system.
    bool big_endian = false;

    // Per-subprogram stack frame size in bytes.
    int subprogram_stack_size = 512;

    // Maximum number of nested function calls.
    int max_call_stack_frames = 8;

    // Maximum packet size in bytes (upper bound on packet_size).
    int max_packet_size = 0xffff;

    static constexpr int MAX_SUBPROGRAM_STACK_SIZE = 1024 * 1024;
    static constexpr int MAX_CALL_STACK_FRAMES_LIMIT = 128;
    static constexpr int MAX_PACKET_SIZE_LIMIT = (1 << 30);

    [[nodiscard]]
    int total_stack_size() const noexcept {
        return max_call_stack_frames * subprogram_stack_size;
    }

    void validate() const {
        if (subprogram_stack_size <= 0 || subprogram_stack_size > MAX_SUBPROGRAM_STACK_SIZE) {
            throw std::invalid_argument("subprogram_stack_size must be in [1, " +
                                        std::to_string(MAX_SUBPROGRAM_STACK_SIZE) + "], got " +
                                        std::to_string(subprogram_stack_size));
        }
        if (max_call_stack_frames <= 0 || max_call_stack_frames > MAX_CALL_STACK_FRAMES_LIMIT) {
            throw std::invalid_argument("max_call_stack_frames must be in [1, " +
                                        std::to_string(MAX_CALL_STACK_FRAMES_LIMIT) + "], got " +
                                        std::to_string(max_call_stack_frames));
        }
        if (max_packet_size <= 0 || max_packet_size > MAX_PACKET_SIZE_LIMIT) {
            throw std::invalid_argument("max_packet_size must be in [1, " + std::to_string(MAX_PACKET_SIZE_LIMIT) +
                                        "], got " + std::to_string(max_packet_size));
        }
    }

    verbosity_options_t verbosity_opts;
};

struct ebpf_verifier_stats_t {
    int total_errors{};
    int max_loop_count{};
};

} // namespace prevail

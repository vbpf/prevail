// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <limits>
#include <stdexcept>
#include <string>

#include "spec/ebpf_base.h"

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
    int subprogram_stack_size = EBPF_SUBPROGRAM_STACK_SIZE;

    // Maximum valid subprogram stack size (bounded by int32 range used in the numeric domain).
    static constexpr int max_subprogram_stack_size = std::numeric_limits<int32_t>::max() / MAX_CALL_STACK_FRAMES;

    // Total stack size across all nested frames.
    [[nodiscard]]
    int total_stack_size() const noexcept {
        return MAX_CALL_STACK_FRAMES * subprogram_stack_size;
    }

    // Validate that the stack size is within acceptable bounds.
    void validate_stack_size() const {
        if (subprogram_stack_size <= 0) {
            throw std::invalid_argument("subprogram_stack_size must be positive, got " +
                                        std::to_string(subprogram_stack_size));
        }
        if (subprogram_stack_size > max_subprogram_stack_size) {
            throw std::invalid_argument("subprogram_stack_size " + std::to_string(subprogram_stack_size) +
                                        " is too large (max " + std::to_string(max_subprogram_stack_size) + ")");
        }
    }

    verbosity_options_t verbosity_opts;
};

struct ebpf_verifier_stats_t {
    int total_errors{};
    int max_loop_count{};
};

extern thread_local ebpf_verifier_options_t thread_local_options;
} // namespace prevail

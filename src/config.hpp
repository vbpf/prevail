// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

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

    verbosity_options_t verbosity_opts;
};

struct ebpf_verifier_stats_t {
    int total_errors{};
    int max_loop_count{};
};

extern thread_local ebpf_verifier_options_t thread_local_options;
} // namespace prevail

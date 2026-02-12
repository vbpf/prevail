// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>
#include <filesystem>
#include <sstream>

#include "ebpf_verifier.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"

using namespace prevail;

// Helper to check if a test sample file exists
static bool sample_exists(const std::string& filename) { return std::filesystem::exists(filename); }

// Helper to load a program, run analysis with deps collection, and compute slices
static std::vector<FailureSlice> get_failure_slices(const std::string& filename, const std::string& section) {
    ebpf_verifier_options_t options{};
    options.verbosity_opts.collect_instruction_deps = true;

    auto raw_progs = read_elf(filename, section, "", options, &g_ebpf_platform_linux);
    REQUIRE(raw_progs.size() == 1);

    const RawProgram& raw_prog = raw_progs.back();
    auto prog_or_error = unmarshal(raw_prog, options);
    auto inst_seq = std::get_if<InstructionSeq>(&prog_or_error);
    REQUIRE(inst_seq != nullptr);

    const Program prog = Program::from_sequence(*inst_seq, raw_prog.info, options);
    auto result = analyze(prog);

    return result.compute_failure_slices(prog);
}

// Test that extract_instruction_deps correctly identifies register reads/writes
TEST_CASE("extract_instruction_deps for Bin instruction", "[failure_slice][deps]") {
    // r1 = r1 + r2 should read r1, r2 and write r1
    Bin bin_add{Bin::Op::ADD, Reg{1}, Reg{2}, true, false};
    Instruction ins = bin_add;
    EbpfDomain dom = EbpfDomain::top();

    auto deps = extract_instruction_deps(ins, dom);

    REQUIRE(deps.regs_written.contains(Reg{1}));
    REQUIRE(deps.regs_read.contains(Reg{1})); // ADD also reads dst
    REQUIRE(deps.regs_read.contains(Reg{2}));
}

TEST_CASE("extract_instruction_deps for MOV instruction", "[failure_slice][deps]") {
    // r1 = r2 should read r2 and write r1 (but not read r1)
    Bin bin_mov{Bin::Op::MOV, Reg{1}, Reg{2}, true, false};
    Instruction ins = bin_mov;
    EbpfDomain dom = EbpfDomain::top();

    auto deps = extract_instruction_deps(ins, dom);

    REQUIRE(deps.regs_written.contains(Reg{1}));
    REQUIRE_FALSE(deps.regs_read.contains(Reg{1})); // MOV doesn't read dst
    REQUIRE(deps.regs_read.contains(Reg{2}));
}

TEST_CASE("extract_instruction_deps for Mem load", "[failure_slice][deps]") {
    // r1 = *(r10 - 8) should read r10, write r1, and read stack[-8]
    Mem mem_load{Deref{8, Reg{10}, -8}, Reg{1}, true};
    Instruction ins = mem_load;
    EbpfDomain dom = EbpfDomain::top();

    auto deps = extract_instruction_deps(ins, dom);

    REQUIRE(deps.regs_written.contains(Reg{1}));
    REQUIRE(deps.regs_read.contains(Reg{10}));
    REQUIRE(deps.stack_read.contains(-8));
}

TEST_CASE("extract_instruction_deps for Mem store", "[failure_slice][deps]") {
    // *(r10 - 8) = r1 should read r10, r1 and write stack[-8]
    Mem mem_store{Deref{8, Reg{10}, -8}, Reg{1}, false};
    Instruction ins = mem_store;
    EbpfDomain dom = EbpfDomain::top();

    auto deps = extract_instruction_deps(ins, dom);

    REQUIRE(deps.regs_read.contains(Reg{10}));
    REQUIRE(deps.regs_read.contains(Reg{1}));
    REQUIRE(deps.stack_written.contains(-8));
}

// Test that extract_assertion_registers correctly identifies assertion dependencies
TEST_CASE("extract_assertion_registers for ValidAccess", "[failure_slice][deps]") {
    ValidAccess va{0, Reg{1}, 0, Imm{8}, false, AccessType::read};
    Assertion assertion = va;

    auto regs = extract_assertion_registers(assertion);

    REQUIRE(regs.contains(Reg{1}));
}

TEST_CASE("extract_assertion_registers for Comparable", "[failure_slice][deps]") {
    Comparable comp{Reg{1}, Reg{2}, false};
    Assertion assertion = comp;

    auto regs = extract_assertion_registers(assertion);

    REQUIRE(regs.contains(Reg{1}));
    REQUIRE(regs.contains(Reg{2}));
}

TEST_CASE("extract_assertion_registers for ValidDivisor", "[failure_slice][deps]") {
    ValidDivisor vd{Reg{3}, false};
    Assertion assertion = vd;

    auto regs = extract_assertion_registers(assertion);

    REQUIRE(regs.contains(Reg{3}));
}

TEST_CASE("extract_assertion_registers for BoundedLoopCount", "[failure_slice][deps]") {
    BoundedLoopCount blc{Label{0}};
    Assertion assertion = blc;

    auto regs = extract_assertion_registers(assertion);

    REQUIRE(regs.empty());
}

// Integration tests using real failing programs
TEST_CASE("failure slice for badmapptr.o", "[failure_slice][integration]") {
    const std::string sample = "ebpf-samples/build/badmapptr.o";
    if (!sample_exists(sample)) {
        SKIP("Sample file not found: " << sample);
    }
    auto slices = get_failure_slices(sample, "test");

    REQUIRE(slices.size() == 1);
    REQUIRE(slices[0].relevance.size() == 2); // Labels 2 and 4
    REQUIRE(slices[0].relevance.contains(slices[0].failing_label));

    // The failure is about r1 type (map_fd is not in {number, ctx, stack, packet, shared})
    auto& failing_relevance = slices[0].relevance.at(slices[0].failing_label);
    REQUIRE(failing_relevance.registers.size() == 1);
    REQUIRE(failing_relevance.registers.contains(Reg{1}));
}

TEST_CASE("failure slice for exposeptr.o", "[failure_slice][integration]") {
    const std::string sample = "ebpf-samples/build/exposeptr.o";
    if (!sample_exists(sample)) {
        SKIP("Sample file not found: " << sample);
    }
    auto slices = get_failure_slices(sample, ".text");

    REQUIRE(slices.size() == 1);
    REQUIRE(slices[0].relevance.size() > 0);

    // The failure involves map update with registers r1, r3
    auto& failing_relevance = slices[0].relevance.at(slices[0].failing_label);
    // At minimum r3 should be relevant (the value being stored)
    REQUIRE(failing_relevance.registers.size() > 0);
}

TEST_CASE("failure slice for nullmapref.o", "[failure_slice][integration]") {
    const std::string sample = "ebpf-samples/build/nullmapref.o";
    if (!sample_exists(sample)) {
        SKIP("Sample file not found: " << sample);
    }
    auto slices = get_failure_slices(sample, "test");

    REQUIRE(slices.size() >= 1);
    // Slice should have at least the failing label
    REQUIRE(slices[0].relevance.size() >= 1);
}

// Test print_failure_slices produces output
TEST_CASE("print_failure_slices produces structured output", "[failure_slice][print]") {
    const std::string sample = "ebpf-samples/build/badmapptr.o";
    if (!sample_exists(sample)) {
        SKIP("Sample file not found: " << sample);
    }
    ebpf_verifier_options_t options{};
    options.verbosity_opts.collect_instruction_deps = true;

    auto raw_progs = read_elf(sample, "test", "", options, &g_ebpf_platform_linux);
    REQUIRE(raw_progs.size() == 1);

    const RawProgram& raw_prog = raw_progs.back();
    auto prog_or_error = unmarshal(raw_prog, options);
    auto inst_seq = std::get_if<InstructionSeq>(&prog_or_error);
    REQUIRE(inst_seq != nullptr);

    const Program prog = Program::from_sequence(*inst_seq, raw_prog.info, options);
    auto result = analyze(prog);
    auto slices = result.compute_failure_slices(prog);

    std::stringstream output;
    print_failure_slices(output, prog, false, result, slices);

    std::string output_str = output.str();

    // Check expected sections are present
    REQUIRE(output_str.find("[ERROR]") != std::string::npos);
    REQUIRE(output_str.find("[LOCATION]") != std::string::npos);
    REQUIRE(output_str.find("[RELEVANT REGISTERS]") != std::string::npos);
    REQUIRE(output_str.find("[SLICE SIZE]") != std::string::npos);
    REQUIRE(output_str.find("[CAUSAL TRACE]") != std::string::npos);
}

// Test that passing programs produce no slices
TEST_CASE("passing program produces no failure slices", "[failure_slice][integration]") {
    const std::string sample = "ebpf-samples/build/stackok.o";
    if (!sample_exists(sample)) {
        SKIP("Sample file not found: " << sample);
    }
    ebpf_verifier_options_t options{};
    options.verbosity_opts.collect_instruction_deps = true;

    auto raw_progs = read_elf(sample, ".text", "", options, &g_ebpf_platform_linux);
    REQUIRE(raw_progs.size() == 1);

    const RawProgram& raw_prog = raw_progs.back();
    auto prog_or_error = unmarshal(raw_prog, options);
    auto inst_seq = std::get_if<InstructionSeq>(&prog_or_error);
    REQUIRE(inst_seq != nullptr);

    const Program prog = Program::from_sequence(*inst_seq, raw_prog.info, options);
    auto result = analyze(prog);

    REQUIRE_FALSE(result.failed);

    auto slices = result.compute_failure_slices(prog);
    REQUIRE(slices.empty());
}

// Test that Assume control-dependency logic includes guard condition registers.
// When an Assume is a direct predecessor of the failing label, its condition
// registers should appear as relevant in the slice.
TEST_CASE("assume guard registers become relevant in slice", "[failure_slice][integration]") {
    const std::string sample = "ebpf-samples/build/dependent_read.o";
    if (!sample_exists(sample)) {
        SKIP("Sample file not found: " << sample);
    }
    auto slices = get_failure_slices(sample, "xdp");

    REQUIRE(slices.size() >= 1);
    const auto& slice = slices[0];
    REQUIRE(slice.relevance.size() > 0);

    // Check that at least one Assume label is in the slice
    // (the guard condition that determines reachability of the failing label)
    ebpf_verifier_options_t options{};
    options.verbosity_opts.collect_instruction_deps = true;
    auto raw_progs = read_elf(sample, "xdp", "", options, &g_ebpf_platform_linux);
    REQUIRE(raw_progs.size() == 1);
    auto prog_or_error = unmarshal(raw_progs.back(), options);
    auto inst_seq = std::get_if<InstructionSeq>(&prog_or_error);
    REQUIRE(inst_seq != nullptr);
    const Program prog = Program::from_sequence(*inst_seq, raw_progs.back().info, options);

    bool found_assume_in_slice = false;
    for (const auto& [label, relevance] : slice.relevance) {
        if (std::holds_alternative<Assume>(prog.instruction_at(label))) {
            found_assume_in_slice = true;
            // The Assume's condition registers should be in the relevance set
            REQUIRE(relevance.registers.size() > 0);
            break;
        }
    }
    REQUIRE(found_assume_in_slice);
}

TEST_CASE("empty seed assertion still includes failing label", "[failure_slice][integration]") {
    const std::string sample = "ebpf-samples/build/bounded_loop.o";
    if (!sample_exists(sample)) {
        SKIP("Sample file not found: " << sample);
    }
    auto slices = get_failure_slices(sample, "test");
    if (slices.empty()) {
        // bounded_loop may pass verification depending on build; skip if so
        SKIP("Program passed verification (no failure slices)");
    }

    // The slice should still contain the failing label even with no register deps
    for (const auto& slice : slices) {
        auto labels = slice.impacted_labels();
        REQUIRE(labels.contains(slice.failing_label));
    }
}

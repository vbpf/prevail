// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
//
// Targeted tests for the named preparation passes behind Program::from_sequence.
// Each test exercises an invariant that is otherwise implicit in the pipeline and
// would silently break if a pass were reordered, skipped, or modified.

#include <optional>

#include <catch2/catch_all.hpp>

#include "ir/program.hpp"
#include "ir/syntax.hpp"
#include "platform.hpp"

using namespace prevail;

namespace {

ProgramInfo default_info() {
    return ProgramInfo{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec"),
    };
}

LabeledInstruction at(const int index, Instruction ins) { return {Label{index}, std::move(ins), std::nullopt}; }

Condition eq0_zero_is64() { return Condition{.op = Condition::Op::EQ, .left = Reg{0}, .right = Imm{0}, .is64 = true}; }

} // namespace

TEST_CASE("pass_connect_edges rejects an empty instruction sequence", "[passes]") {
    const ProgramInfo info = default_info();
    const InstructionSeq empty;
    REQUIRE_THROWS_WITH(Program::from_sequence(empty, info, {}),
                        Catch::Matchers::ContainsSubstring("empty instruction sequence"));
}

TEST_CASE("pass_connect_edges short-circuits when a conditional target equals fallthrough", "[passes]") {
    // The true-branch target is also the fallthrough label, so no synthetic Assume jump-labels
    // should be created -- just a plain add_child edge.
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    seq.push_back(at(0, Jmp{.cond = eq0_zero_is64(), .target = Label{1}}));
    seq.push_back(at(1, Exit{}));

    const Program prog = Program::from_sequence(seq, info, {});
    size_t jump_labels = 0;
    for (const Label& label : prog.labels()) {
        if (label.isjump()) {
            ++jump_labels;
        }
    }
    REQUIRE(jump_labels == 0);
}

TEST_CASE("pass_connect_edges materialises Assume labels on a conditional jump", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    seq.push_back(at(0, Jmp{.cond = eq0_zero_is64(), .target = Label{2}}));
    seq.push_back(at(1, Exit{}));
    seq.push_back(at(2, Exit{}));

    const Program prog = Program::from_sequence(seq, info, {});
    size_t assume_labels = 0;
    for (const Label& label : prog.labels()) {
        if (label.isjump()) {
            REQUIRE(std::holds_alternative<Assume>(prog.instruction_at(label)));
            ++assume_labels;
        }
    }
    REQUIRE(assume_labels == 2);
}

TEST_CASE("pass_connect_edges rejects a jump to an undefined label", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    seq.push_back(at(0, Jmp{.cond = eq0_zero_is64(), .target = Label{42}}));
    seq.push_back(at(1, Exit{}));
    REQUIRE_THROWS_WITH(Program::from_sequence(seq, info, {}),
                        Catch::Matchers::ContainsSubstring("jump to undefined label"));
}

TEST_CASE("pass_connect_edges rejects fallthrough past the last instruction", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    seq.push_back(at(0, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true}));
    REQUIRE_THROWS_WITH(Program::from_sequence(seq, info, {}),
                        Catch::Matchers::ContainsSubstring("fallthrough in last instruction"));
}

TEST_CASE("pass_lower_pseudo_loads rewrites VARIABLE_ADDR to an lddw Bin MOV", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    seq.push_back(at(0, LoadPseudo{
                            .dst = Reg{1},
                            .addr = {.kind = PseudoAddress::Kind::VARIABLE_ADDR, .imm = 0x1234, .next_imm = 0x5678},
                        }));
    seq.push_back(at(1, Exit{}));

    const Program prog = Program::from_sequence(seq, info, {});
    const auto* bin = std::get_if<Bin>(&prog.instruction_at(Label{0}));
    REQUIRE(bin != nullptr);
    REQUIRE(bin->op == Bin::Op::MOV);
    REQUIRE(bin->lddw);
    const auto* imm = std::get_if<Imm>(&bin->v);
    REQUIRE(imm != nullptr);
    const uint64_t expected = (static_cast<uint64_t>(static_cast<uint32_t>(0x5678)) << 32) |
                              static_cast<uint64_t>(static_cast<uint32_t>(0x1234));
    REQUIRE(imm->v == expected);
}

TEST_CASE("pass_lower_pseudo_loads preserves CODE_ADDR as LoadPseudo", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    seq.push_back(at(0, LoadPseudo{
                            .dst = Reg{1},
                            .addr = {.kind = PseudoAddress::Kind::CODE_ADDR, .imm = 2, .next_imm = 0},
                        }));
    seq.push_back(at(1, Exit{}));
    seq.push_back(at(2, Exit{}));

    const Program prog = Program::from_sequence(seq, info, {});
    const auto* pseudo = std::get_if<LoadPseudo>(&prog.instruction_at(Label{0}));
    REQUIRE(pseudo != nullptr);
    REQUIRE(pseudo->addr.kind == PseudoAddress::Kind::CODE_ADDR);
}

TEST_CASE("pass_lower_pseudo_loads rejects an out-of-range map index", "[passes]") {
    const ProgramInfo info = default_info(); // empty map_descriptors
    InstructionSeq seq;
    seq.push_back(at(0, LoadPseudo{
                            .dst = Reg{1},
                            .addr = {.kind = PseudoAddress::Kind::MAP_BY_IDX, .imm = 5, .next_imm = 0},
                        }));
    seq.push_back(at(1, Exit{}));
    REQUIRE_THROWS_WITH(Program::from_sequence(seq, info, {}),
                        Catch::Matchers::ContainsSubstring("invalid map index 5"));
}

TEST_CASE("pass_compute_callback_metadata excludes Exit labels and synthetic jump labels", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    // Conditional jump produces two synthetic Assume jump-labels; both must be excluded.
    seq.push_back(at(0, Jmp{.cond = eq0_zero_is64(), .target = Label{3}}));
    seq.push_back(at(1, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{1}, .is64 = true}));
    seq.push_back(at(2, Exit{}));
    seq.push_back(at(3, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{2}, .is64 = true}));
    seq.push_back(at(4, Exit{}));

    const Program prog = Program::from_sequence(seq, info, {});
    const auto& targets = prog.info().callback_target_labels;
    REQUIRE(targets.contains(0));
    REQUIRE(targets.contains(1));
    REQUIRE(targets.contains(3));
    REQUIRE_FALSE(targets.contains(2)); // Exit
    REQUIRE_FALSE(targets.contains(4)); // Exit
}

TEST_CASE("pass_compute_callback_metadata marks callbacks that reach an Exit", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    seq.push_back(at(0, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true}));
    seq.push_back(at(1, Exit{}));

    const Program prog = Program::from_sequence(seq, info, {});
    REQUIRE(prog.info().callback_target_labels.contains(0));
    REQUIRE(prog.info().callback_targets_with_exit.contains(0));
}

TEST_CASE("pass_insert_termination_counters adds a counter at a WTO loop head", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    // label 0 -> label 1 -> unconditional jump back to label 0 (self-loop at head 0).
    seq.push_back(at(0, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true}));
    seq.push_back(at(1, Jmp{.cond = std::nullopt, .target = Label{0}}));

    ebpf_verifier_options_t options;
    options.cfg_opts.check_for_termination = true;
    options.cfg_opts.must_have_exit = false; // cycle without an exit is fine for this test
    const Program prog = Program::from_sequence(seq, info, options);

    bool found_counter = false;
    for (const Label& label : prog.labels()) {
        if (std::holds_alternative<IncrementLoopCounter>(prog.instruction_at(label))) {
            found_counter = true;
            break;
        }
    }
    REQUIRE(found_counter);
}

TEST_CASE("pass_insert_termination_counters is off by default", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    seq.push_back(at(0, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true}));
    seq.push_back(at(1, Jmp{.cond = std::nullopt, .target = Label{0}}));

    ebpf_verifier_options_t options;
    options.cfg_opts.must_have_exit = false;
    // check_for_termination defaults to false.
    const Program prog = Program::from_sequence(seq, info, options);

    for (const Label& label : prog.labels()) {
        REQUIRE_FALSE(std::holds_alternative<IncrementLoopCounter>(prog.instruction_at(label)));
    }
}

TEST_CASE("pass_extract_assertions populates assertions for every label in the CFG", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    seq.push_back(at(0, Jmp{.cond = eq0_zero_is64(), .target = Label{2}}));
    seq.push_back(at(1, Exit{}));
    seq.push_back(at(2, Exit{}));

    const Program prog = Program::from_sequence(seq, info, {});
    // assertions_at throws via CRAB_ERROR if a label is missing from m_assertions.
    for (const Label& label : prog.labels()) {
        REQUIRE_NOTHROW(prog.assertions_at(label));
    }
}

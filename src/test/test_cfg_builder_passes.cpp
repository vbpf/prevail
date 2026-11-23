// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
//
// Targeted tests for the named preparation passes behind Program::from_sequence.
// Each test exercises an invariant that is otherwise implicit in the pipeline and
// would silently break if a pass were reordered, skipped, or modified.

#include <chrono>
#include <optional>

#include <catch2/catch_all.hpp>

#include "ir/program.hpp"
#include "ir/syntax.hpp"
#include "platform.hpp"
#include "verifier.hpp"

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

TEST_CASE("pass_connect_edges short-circuits", "[passes]") {
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

TEST_CASE("pass_validate_instruction_support rejects VARIABLE_ADDR", "[passes]") {
    // The immediate is a variable id, not the loaded address: lowering it to a scalar MOV
    // would let the analysis decide a comparison with that id at verification time.
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    seq.push_back(at(0, LoadPseudo{
                            .dst = Reg{1},
                            .addr = {.kind = PseudoAddress::Kind::VARIABLE_ADDR, .imm = 0x1234, .next_imm = 0},
                        }));
    seq.push_back(at(1, Exit{}));

    REQUIRE_THROWS_WITH(Program::from_sequence(seq, info, {}),
                        Catch::Matchers::ContainsSubstring("not implemented: lddw variable_addr pseudo"));
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

TEST_CASE("pass_validate_instruction_support restricts the map types of a sleepable program", "[passes][map]") {
    constexpr uint32_t hash = 1;
    constexpr uint32_t lpm_trie = 11;
    constexpr uint32_t devmap = 14;
    const auto info_for = [](const std::string& section, const uint32_t map_type) {
        ProgramInfo info{
            .platform = &g_ebpf_platform_linux,
            .type = g_ebpf_platform_linux.get_program_type(section, ""),
        };
        info.map_descriptors.get_mutable().push_back(EbpfMapDescriptor{
            .original_fd = 1, .type = map_type, .key_size = 8, .value_size = 8, .max_entries = 16, .inner_map_fd = -1});
        return info;
    };
    // Each way of referring to the map: by fd, by the address of its value, and by index before lowering.
    const std::vector<Instruction> loads{
        LoadMapFd{.dst = Reg{1}, .mapfd = 1},
        LoadMapAddress{.dst = Reg{1}, .mapfd = 1, .offset = 0},
        LoadPseudo{.dst = Reg{1}, .addr = {.kind = PseudoAddress::Kind::MAP_BY_IDX, .imm = 0, .next_imm = 0}},
        LoadPseudo{.dst = Reg{1}, .addr = {.kind = PseudoAddress::Kind::MAP_VALUE_BY_IDX, .imm = 0, .next_imm = 0}},
    };
    const auto program = [](const Instruction& load) {
        InstructionSeq seq;
        seq.push_back(at(0, load));
        seq.push_back(at(1, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true}));
        seq.push_back(at(2, Exit{}));
        return seq;
    };
    for (const Instruction& load : loads) {
        CAPTURE(load);
        for (const std::string section : {"lsm.s/file_open", "fentry.s/f", "syscall/f"}) {
            CAPTURE(section);
            REQUIRE_THROWS_WITH(Program::from_sequence(program(load), info_for(section, lpm_trie), {}),
                                Catch::Matchers::ContainsSubstring(
                                    "rejected: map type 11 is not allowed in a sleepable program (at 0)"));
            REQUIRE_THROWS_WITH(
                Program::from_sequence(program(load), info_for(section, devmap), {}),
                Catch::Matchers::ContainsSubstring("map type 14 is not allowed in a sleepable program"));
            REQUIRE_NOTHROW(Program::from_sequence(program(load), info_for(section, hash), {}));
            // Type 0 says nothing about the map.
            REQUIRE_NOTHROW(Program::from_sequence(program(load), info_for(section, 0), {}));
        }
        // A program that cannot sleep may use any map type.
        REQUIRE_NOTHROW(Program::from_sequence(program(load), info_for("lsm/file_open", lpm_trie), {}));
    }
}

TEST_CASE("pass_inline_local_calls returns a successful tail call to the caller of the subprogram", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    seq.push_back(at(0, CallLocal{.target = Label{2}}));
    seq.push_back(at(1, Exit{}));
    seq.push_back(at(2, Call{.func = 12})); // bpf_tail_call
    seq.push_back(at(3, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true}));
    seq.push_back(at(4, Exit{}));

    const Program prog = Program::from_sequence(seq, info, {});
    // The inlined tail-call site has the fall-through (tail call failed) and a synthetic
    // Exit of the inlined frame (tail call succeeded, the target returned to the caller).
    const Label tail_exit{2, 1, "0"};
    REQUIRE(prog.cfg().children_of(Label{2, -1, "0"}) == std::set{tail_exit, Label{3, -1, "0"}});
    REQUIRE(prog.instruction_at(tail_exit) == Instruction{Exit{.stack_frame_prefix = "0", .after_tail_call = true}});
    REQUIRE(prog.cfg().children_of(tail_exit) == std::set{Label{1}});
    // Outside an inlined frame nothing under verification runs after a successful tail call.
    REQUIRE(prog.cfg().children_of(Label{2}) == std::set{Label{3}});
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
    const auto& targets = prog.callback_target_labels();
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
    REQUIRE(prog.callback_target_labels().contains(0));
    REQUIRE(prog.callback_targets_with_exit().contains(0));
}

TEST_CASE("pass_compute_callback_metadata does not mark callbacks that cannot reach an Exit", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    // label 0 -> label 1 -> unconditional jump back to label 0: no path to an Exit.
    seq.push_back(at(0, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true}));
    seq.push_back(at(1, Jmp{.cond = std::nullopt, .target = Label{0}}));

    VerifierOptions options;
    options.must_have_exit = false; // cycle without an exit is fine for this test
    const Program prog = Program::from_sequence(seq, info, options);
    REQUIRE(prog.callback_target_labels().contains(0));
    REQUIRE(prog.callback_target_labels().contains(1));
    REQUIRE(prog.callback_targets_with_exit().empty());
}

TEST_CASE("pass_compute_callback_metadata is not quadratic in program size", "[passes]") {
    // A long straight-line program with a single Exit at the end: a forward search per label
    // visits O(n^2) nodes, which takes over a minute at this size instead of a fraction of a second.
    constexpr int n = 20000;
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    for (int i = 0; i < n; i++) {
        seq.push_back(at(i, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true}));
    }
    seq.push_back(at(n, Exit{}));

    const auto start = std::chrono::steady_clock::now();
    const Program prog = Program::from_sequence(seq, info, {});
    REQUIRE(std::chrono::steady_clock::now() - start < std::chrono::seconds(10));
    REQUIRE(prog.callback_target_labels().size() == n);
    REQUIRE(prog.callback_targets_with_exit().size() == n);
}

TEST_CASE("pass_insert_termination_counters adds a counter at a WTO loop head", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    // label 0 -> label 1 -> unconditional jump back to label 0 (self-loop at head 0).
    seq.push_back(at(0, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true}));
    seq.push_back(at(1, Jmp{.cond = std::nullopt, .target = Label{0}}));

    VerifierOptions options;
    options.runtime.check_for_termination = true;
    options.must_have_exit = false; // cycle without an exit is fine for this test
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

    VerifierOptions options;
    options.must_have_exit = false;
    // check_for_termination defaults to false.
    const Program prog = Program::from_sequence(seq, info, options);

    for (const Label& label : prog.labels()) {
        REQUIRE_FALSE(std::holds_alternative<IncrementLoopCounter>(prog.instruction_at(label)));
    }
}

TEST_CASE("pass_inline_local_calls bounds the number of inlined call instances", "[passes]") {
    const ProgramInfo info = default_info();
    InstructionSeq seq;
    // entry -> call subprogram -> call subprogram -> exit: two call instances to inline.
    seq.push_back(at(0, CallLocal{.target = Label{3}}));
    seq.push_back(at(1, CallLocal{.target = Label{3}}));
    seq.push_back(at(2, Exit{}));
    seq.push_back(at(3, Exit{}));

    VerifierOptions options;
    options.runtime.max_inlined_calls = 2;
    REQUIRE_NOTHROW(Program::from_sequence(seq, info, options));

    options.runtime.max_inlined_calls = 1;
    REQUIRE_THROWS_WITH(Program::from_sequence(seq, info, options),
                        Catch::Matchers::ContainsSubstring("too many inlined local calls"));
}

TEST_CASE("AnalysisResult reports maximum nested BPF-to-BPF call depth", "[passes][stats]") {
    const ProgramInfo info = default_info();

    SECTION("does not count the entry frame") {
        InstructionSeq seq;
        seq.push_back(at(0, Exit{}));

        const Program prog = Program::from_sequence(seq, info, {});
        REQUIRE(analyze(prog, {}).max_call_depth == 0);
    }

    SECTION("counts nested local calls") {
        InstructionSeq seq;
        // entry -> call subprogram 1 -> call subprogram 2 -> exit.
        seq.push_back(at(0, CallLocal{.target = Label{2}}));
        seq.push_back(at(1, Exit{}));
        seq.push_back(at(2, CallLocal{.target = Label{4}}));
        seq.push_back(at(3, Exit{}));
        seq.push_back(at(4, Exit{}));

        const Program prog = Program::from_sequence(seq, info, {});
        REQUIRE(analyze(prog, {}).max_call_depth == 2);
    }

    SECTION("excludes unreachable nested local calls") {
        InstructionSeq seq;
        seq.push_back(at(0, Exit{}));
        // These calls are retained and inlined during CFG preparation, but are unreachable from entry.
        seq.push_back(at(1, CallLocal{.target = Label{3}}));
        seq.push_back(at(2, Exit{}));
        seq.push_back(at(3, CallLocal{.target = Label{5}}));
        seq.push_back(at(4, Exit{}));
        seq.push_back(at(5, Exit{}));

        const Program prog = Program::from_sequence(seq, info, {});
        REQUIRE(analyze(prog, {}).max_call_depth == 0);
    }

    SECTION("preserves call depth after verification failure") {
        InstructionSeq seq;
        seq.push_back(at(0, CallLocal{.target = Label{2}}));
        seq.push_back(at(1, Exit{}));
        seq.push_back(at(2, CallLocal{.target = Label{4}}));
        seq.push_back(at(3, Exit{}));
        // This is one byte below the innermost 512-byte frame.
        seq.push_back(at(4, Mem{
                                .access = {.width = 1, .basereg = Reg{R10_STACK_POINTER}, .offset = -513},
                                .value = Imm{0},
                                .is_load = false,
                            }));
        seq.push_back(at(5, Exit{}));

        const Program prog = Program::from_sequence(seq, info, {});
        const AnalysisResult result = analyze(prog, {});
        REQUIRE(result.failed);
        REQUIRE(result.max_call_depth == 2);
    }
}

TEST_CASE("xdp_md.data_meta is not assumed to precede data", "[verify][ctx]") {
    const ProgramInfo info{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("xdp", ""),
    };
    const Reg data{2};
    const Reg data_meta{3};
    InstructionSeq seq;
    seq.push_back(at(0, Mem{.access = {.width = 4, .basereg = Reg{1}, .offset = 0}, .value = data, .is_load = true}));
    seq.push_back(
        at(1, Mem{.access = {.width = 4, .basereg = Reg{1}, .offset = 8}, .value = data_meta, .is_load = true}));

    SECTION("code guarded by data_meta > data is verified") {
        // A Linux driver without XDP metadata support publishes data_meta == data + 1,
        // so the store through the forged pointer below is reachable and must be rejected.
        const Condition meta_le_data{.op = Condition::Op::LE, .left = data_meta, .right = data, .is64 = true};
        seq.push_back(at(2, Jmp{.cond = meta_le_data, .target = Label{5}}));
        seq.push_back(at(3, Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = Imm{0x41414141}, .is64 = true}));
        seq.push_back(
            at(4, Mem{.access = {.width = 8, .basereg = Reg{4}, .offset = 0}, .value = Reg{4}, .is_load = false}));
        seq.push_back(at(5, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{2}, .is64 = true}));
        seq.push_back(at(6, Exit{}));

        REQUIRE(analyze(Program::from_sequence(seq, info, {}), {}).failed);
    }

    SECTION("metadata is accessible after the customary bounds check") {
        // if (data_meta + 4 > data) goto exit; r0 = *(u32 *)data_meta
        seq.push_back(at(2, Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = data_meta, .is64 = true}));
        seq.push_back(at(3, Bin{.op = Bin::Op::ADD, .dst = Reg{4}, .v = Imm{4}, .is64 = true}));
        const Condition end_gt_data{.op = Condition::Op::GT, .left = Reg{4}, .right = data, .is64 = true};
        seq.push_back(at(4, Jmp{.cond = end_gt_data, .target = Label{6}}));
        seq.push_back(
            at(5, Mem{.access = {.width = 4, .basereg = data_meta, .offset = 0}, .value = Reg{0}, .is_load = true}));
        seq.push_back(at(6, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{2}, .is64 = true}));
        seq.push_back(at(7, Exit{}));

        const AnalysisResult result = analyze(Program::from_sequence(seq, info, {}), {});
        REQUIRE_FALSE(result.failed);
        // The read must be reachable, or the check above proves nothing.
        REQUIRE_FALSE(result.invariants.at(Label{5}).pre.is_bottom());
    }

    SECTION("a reloaded data_meta carries the bounds check of the first load") {
        // if (data_meta + 4 > data) goto exit; r5 = ctx->data_meta; r0 = *(u32 *)r5
        seq.push_back(at(2, Bin{.op = Bin::Op::MOV, .dst = Reg{4}, .v = data_meta, .is64 = true}));
        seq.push_back(at(3, Bin{.op = Bin::Op::ADD, .dst = Reg{4}, .v = Imm{4}, .is64 = true}));
        const Condition end_gt_data{.op = Condition::Op::GT, .left = Reg{4}, .right = data, .is64 = true};
        seq.push_back(at(4, Jmp{.cond = end_gt_data, .target = Label{7}}));
        seq.push_back(
            at(5, Mem{.access = {.width = 4, .basereg = Reg{1}, .offset = 8}, .value = Reg{5}, .is_load = true}));
        seq.push_back(
            at(6, Mem{.access = {.width = 4, .basereg = Reg{5}, .offset = 0}, .value = Reg{0}, .is_load = true}));
        seq.push_back(at(7, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{2}, .is64 = true}));
        seq.push_back(at(8, Exit{}));

        const AnalysisResult result = analyze(Program::from_sequence(seq, info, {}), {});
        REQUIRE_FALSE(result.failed);
        REQUIRE_FALSE(result.invariants.at(Label{6}).pre.is_bottom());
    }
}

TEST_CASE("the access that a map grants to the program is enforced", "[verify][map]") {
    using Access = EbpfMapAccess;
    constexpr Reg r0{0}, r1{1}, r2{2}, r3{3}, r4{4}, r10{R10_STACK_POINTER};
    const Label done{1000};
    const auto mov = [](const Reg dst, const Value v) {
        return Bin{.op = Bin::Op::MOV, .dst = dst, .v = v, .is64 = true};
    };
    const auto add = [](const Reg dst, const Value v) {
        return Bin{.op = Bin::Op::ADD, .dst = dst, .v = v, .is64 = true};
    };
    const auto mem = [](const Reg base, const Value v, const bool is_load) {
        return Mem{.access = {.width = 8, .basereg = base, .offset = 0}, .value = v, .is_load = is_load};
    };
    const Call lookup{.func = 1}; // map_lookup_elem
    const Call update{.func = 2}; // map_update_elem
    const Call erase{.func = 3};  // map_delete_elem
    const Jmp if_null_done{.cond = eq0_zero_is64(), .target = done};

    // Hash maps with fds 1 and 2, 4-byte keys and 8-byte values. The program stores a zero key and value at r10 - 8,
    // points r2 and r3 to it, sets r4 = 0 and r1 = map 1, then runs `body` and returns 0.
    const auto accepts = [&](const Access map1, const Access map2, const std::vector<Instruction>& body) {
        ProgramInfo info = default_info();
        for (const auto& [fd, access] : {std::pair{1, map1}, std::pair{2, map2}}) {
            info.map_descriptors.get_mutable().push_back(EbpfMapDescriptor{.original_fd = fd,
                                                                           .type = 1,
                                                                           .key_size = 4,
                                                                           .value_size = 8,
                                                                           .max_entries = 1,
                                                                           .inner_map_fd = -1,
                                                                           .program_access = access});
        }
        std::vector<Instruction> code{
            Mem{.access = {.width = 8, .basereg = r10, .offset = -8}, .value = Imm{0}, .is_load = false},
            mov(r2, r10),
            add(r2, Imm{static_cast<uint64_t>(-8)}),
            mov(r3, r2),
            mov(r4, Imm{0}),
            LoadMapFd{.dst = r1, .mapfd = 1},
        };
        code.insert(code.end(), body.begin(), body.end());
        InstructionSeq seq;
        for (Instruction& ins : code) {
            seq.push_back(at(static_cast<int>(seq.size()), std::move(ins)));
        }
        seq.push_back({done, mov(r0, Imm{0}), std::nullopt});
        seq.push_back({Label{1001}, Exit{}, std::nullopt});
        return !analyze(Program::from_sequence(seq, info, {}), {}).failed;
    };

    const std::vector<Instruction> load{lookup, if_null_done, mem(r0, r1, true)};
    const std::vector<Instruction> store{lookup, if_null_done, mem(r0, Imm{0}, false)};
    const std::vector<Instruction> atomic_add{
        lookup, if_null_done, mov(r4, Imm{0}),
        Atomic{
            .op = Atomic::Op::ADD, .fetch = false, .access = {.width = 8, .basereg = r0, .offset = 0}, .valreg = r4}};
    const std::vector<Instruction> update_elem{update};
    const std::vector<Instruction> delete_elem{erase};
    // map_update_elem on map 2 with a value that map_update_elem reads from a value of map 1.
    const std::vector<Instruction> update_from_value{lookup,          if_null_done,
                                                     mov(r3, r0),     LoadMapFd{.dst = r1, .mapfd = 2},
                                                     mov(r2, r10),    add(r2, Imm{static_cast<uint64_t>(-8)}),
                                                     mov(r4, Imm{0}), update};
    // map_lookup_elem on map 1 or map 2. The body starts at label 6.
    const auto on_either_map = [&](const Instruction& access) {
        return std::vector<Instruction>{Call{.func = 5}, // ktime_get_ns
                                        mov(r2, r10),
                                        add(r2, Imm{static_cast<uint64_t>(-8)}),
                                        LoadMapFd{.dst = r1, .mapfd = 1},
                                        Jmp{.cond = eq0_zero_is64(), .target = Label{12}},
                                        LoadMapFd{.dst = r1, .mapfd = 2},
                                        lookup,
                                        if_null_done,
                                        access};
    };
    // The address of the value of map 1, as for a global variable.
    const auto direct = [&](const bool is_load) {
        return std::vector<Instruction>{LoadMapAddress{.dst = r0, .mapfd = 1, .offset = 0},
                                        mem(r0, is_load ? Value{r1} : Value{Imm{0}}, is_load)};
    };

    for (const auto& body :
         {load, store, atomic_add, update_elem, delete_elem, update_from_value, direct(true), direct(false)}) {
        REQUIRE(accepts(Access::read_write, Access::read_write, body));
    }

    REQUIRE(accepts(Access::read_only, Access::read_write, load));
    REQUIRE(accepts(Access::read_only, Access::read_write, update_from_value));
    REQUIRE(accepts(Access::read_only, Access::read_write, direct(true)));
    REQUIRE_FALSE(accepts(Access::read_only, Access::read_write, store));
    REQUIRE_FALSE(accepts(Access::read_only, Access::read_write, atomic_add));
    REQUIRE_FALSE(accepts(Access::read_only, Access::read_write, update_elem));
    REQUIRE_FALSE(accepts(Access::read_only, Access::read_write, delete_elem));
    REQUIRE_FALSE(accepts(Access::read_only, Access::read_write, direct(false)));
    REQUIRE_FALSE(accepts(Access::read_write, Access::read_only, update_from_value)); // Updates map 2.

    REQUIRE(accepts(Access::write_only, Access::read_write, store));
    REQUIRE(accepts(Access::write_only, Access::read_write, update_elem));
    REQUIRE(accepts(Access::write_only, Access::read_write, delete_elem));
    REQUIRE(accepts(Access::write_only, Access::read_write, direct(false)));
    REQUIRE_FALSE(accepts(Access::write_only, Access::read_write, load));
    REQUIRE_FALSE(accepts(Access::write_only, Access::read_write, atomic_add));
    REQUIRE_FALSE(accepts(Access::write_only, Access::read_write, update_from_value));
    REQUIRE_FALSE(accepts(Access::write_only, Access::read_write, direct(true)));

    // A value of either map may be accessed only as both maps allow.
    const Instruction load_value = mem(r0, r1, true);
    const Instruction store_value = mem(r0, Imm{0}, false);
    REQUIRE(accepts(Access::read_only, Access::read_write, on_either_map(load_value)));
    REQUIRE_FALSE(accepts(Access::read_only, Access::read_write, on_either_map(store_value)));
    REQUIRE(accepts(Access::write_only, Access::read_write, on_either_map(store_value)));
    REQUIRE_FALSE(accepts(Access::write_only, Access::read_write, on_either_map(load_value)));
    REQUIRE_FALSE(accepts(Access::read_only, Access::write_only, on_either_map(load_value)));
    REQUIRE_FALSE(accepts(Access::read_only, Access::write_only, on_either_map(store_value)));
}

TEST_CASE("AnalysisResult reports the loop iterations of all loops together", "[passes][stats]") {
    const ProgramInfo info = default_info();
    VerifierOptions options;
    options.runtime.check_for_termination = true;

    // A chain of loops, each of which advances r0 by 10: `do { r0 += 1; } while (r0 < 10 * (i + 1));`
    const int loops = GENERATE(0, 1, 3);
    InstructionSeq seq;
    seq.push_back(at(0, Bin{.op = Bin::Op::MOV, .dst = Reg{0}, .v = Imm{0}, .is64 = true}));
    for (int i = 0; i < loops; i++) {
        const Imm bound{static_cast<uint64_t>(10 * (i + 1))};
        const Condition more{.op = Condition::Op::LT, .left = Reg{0}, .right = bound, .is64 = true};
        seq.push_back(at(2 * i + 1, Bin{.op = Bin::Op::ADD, .dst = Reg{0}, .v = Imm{1}, .is64 = true}));
        seq.push_back(at(2 * i + 2, Jmp{.cond = more, .target = Label{2 * i + 1}}));
    }
    seq.push_back(at(2 * loops + 1, Exit{}));

    const AnalysisResult result = analyze(Program::from_sequence(seq, info, options), options);
    REQUIRE_FALSE(result.failed);
    REQUIRE(result.max_loop_count == 10 * loops);
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

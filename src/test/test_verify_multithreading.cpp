// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

static void test_analyze_thread(const Program* prog, const ProgramInfo* info, bool* res) {
    try {
        thread_local_program_info.set(*info);
        *res = verify(*prog);
    } catch (...) {
        *res = false;
    }
}

// Test multithreading
TEST_CASE("multithreading", "[verify][multithreading]") {
    const auto& raw_progs1 = verify_test::read_elf_cached("ebpf-samples/bpf_cilium_test/bpf_netdev.o", "2/1", "", {},
                                                          &g_ebpf_platform_linux);
    REQUIRE(raw_progs1.size() == 1);
    RawProgram raw_prog1 = raw_progs1.back();
    auto prog_or_error1 = unmarshal(raw_prog1, {});
    auto inst_seq1 = std::get_if<InstructionSeq>(&prog_or_error1);
    REQUIRE(inst_seq1);
    const Program prog1 = Program::from_sequence(*inst_seq1, raw_prog1.info, {});

    const auto& raw_progs2 = verify_test::read_elf_cached("ebpf-samples/bpf_cilium_test/bpf_netdev.o", "2/2", "", {},
                                                          &g_ebpf_platform_linux);
    REQUIRE(raw_progs2.size() == 1);
    RawProgram raw_prog2 = raw_progs2.back();
    auto prog_or_error2 = unmarshal(raw_prog2, {});
    auto inst_seq2 = std::get_if<InstructionSeq>(&prog_or_error2);
    REQUIRE(inst_seq2);
    const Program prog2 = Program::from_sequence(*inst_seq2, raw_prog2.info, {});

    bool res1 = false;
    bool res2 = false;
    std::thread a(test_analyze_thread, &prog1, &raw_prog1.info, &res1);
    std::thread b(test_analyze_thread, &prog2, &raw_prog2.info, &res2);
    a.join();
    b.join();

    REQUIRE(res1);
    REQUIRE(res2);
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

static void test_analyze_thread(const prevail::Program* prog, const prevail::ProgramInfo* info, bool* res) {
    try {
        prevail::thread_local_program_info.set(*info);
        *res = prevail::verify(*prog);
    } catch (...) {
        *res = false;
    }
}

// Test multithreading
TEST_CASE("multithreading", "[verify][multithreading]") {
    const auto& raw_progs1 = verify_test::read_elf_cached("ebpf-samples/bpf_cilium_test/bpf_netdev.o", "2/1", "", {},
                                                          &prevail::g_ebpf_platform_linux);
    REQUIRE(raw_progs1.size() == 1);
    prevail::RawProgram raw_prog1 = raw_progs1.back();
    auto inst_seq1 = prevail::unmarshal(raw_prog1, {});
    REQUIRE(inst_seq1.has_value());
    const prevail::Program prog1 = prevail::Program::from_sequence(*inst_seq1, raw_prog1.info, {});

    const auto& raw_progs2 = verify_test::read_elf_cached("ebpf-samples/bpf_cilium_test/bpf_netdev.o", "2/2", "", {},
                                                          &prevail::g_ebpf_platform_linux);
    REQUIRE(raw_progs2.size() == 1);
    prevail::RawProgram raw_prog2 = raw_progs2.back();
    auto inst_seq2 = prevail::unmarshal(raw_prog2, {});
    REQUIRE(inst_seq2.has_value());
    const prevail::Program prog2 = prevail::Program::from_sequence(*inst_seq2, raw_prog2.info, {});

    bool res1 = false;
    bool res2 = false;
    std::thread a(test_analyze_thread, &prog1, &raw_prog1.info, &res1);
    std::thread b(test_analyze_thread, &prog2, &raw_prog2.info, &res2);
    a.join();
    b.join();

    REQUIRE(res1);
    REQUIRE(res2);
}

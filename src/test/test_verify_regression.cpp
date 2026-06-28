// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// Regression tests for soundness fixes using local ELF samples in test-data/regression/.

#include "test_verify.hpp"

// Regression test for assign_valid_ptr svalue havoc bug.
// The program performs two sequential map lookups on a hash map. Without the
// fix, stale svalue constraints from the first lookup's null-check cause the
// second lookup's null branch to appear unreachable, hiding an unsafe null
// pointer dereference.
TEST_CASE("regression/map_sequential_lookup_unsafe", "[verify][regression]") {
    auto raw_progs = verify_test::read_elf_cached("test-data/regression/map_sequential_lookup_unsafe.o", ".text", "",
                                                  {}, &prevail::g_ebpf_platform_linux);
    REQUIRE(raw_progs.size() == 1);
    auto& raw_prog = raw_progs[0];
    bool rejected = false;
    try {
        const auto prog_or_error = prevail::unmarshal(raw_prog, {});
        const auto inst_seq = std::get_if<prevail::InstructionSeq>(&prog_or_error);
        if (!inst_seq) {
            rejected = true;
        } else {
            const prevail::Program prog = prevail::Program::from_sequence(*inst_seq, raw_prog.info, {});
            rejected = (prevail::verify(prog, {}) == false);
        }
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    REQUIRE(rejected);
}

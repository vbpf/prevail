// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

static prevail::Program prepare(const std::string& section) {
    const auto& raw_progs = verify_test::read_elf_cached("ebpf-samples/bpf_cilium_test/bpf_netdev.o", section, "", {},
                                                         &prevail::g_ebpf_platform_linux);
    REQUIRE(raw_progs.size() == 1);
    prevail::RawProgram raw_prog = raw_progs.back();
    auto prog_or_error = prevail::unmarshal(raw_prog, {});
    auto inst_seq = std::get_if<prevail::InstructionSeq>(&prog_or_error);
    REQUIRE(inst_seq);
    return prevail::Program::from_sequence(*inst_seq, raw_prog.info, {});
}

static void test_analyze_thread(const prevail::Program* prog, bool* res) {
    try {
        *res = prevail::verify(*prog, {});
    } catch (...) {
        *res = false;
    }
}

// Test multithreading
TEST_CASE("multithreading", "[verify][multithreading]") {
    const prevail::Program prog1 = prepare("2/1");
    const prevail::Program prog2 = prepare("2/2");

    bool res1 = false;
    bool res2 = false;
    std::thread a(test_analyze_thread, &prog1, &res1);
    std::thread b(test_analyze_thread, &prog2, &res2);
    a.join();
    b.join();

    REQUIRE(res1);
    REQUIRE(res2);
}

// Two programs from the same ELF must share the immutable platform by pointer
// while their per-program callback metadata diverges in CONTENT. A regression
// where callback_target_labels() aliased through a global or thread-local would
// make both programs report the same set and this test would fail.
TEST_CASE("multi-program sharing invariant", "[verify][multithreading]") {
    const prevail::Program prog1 = prepare("2/1");
    const prevail::Program prog2 = prepare("2/2");

    // Immutable platform is shared by pointer across programs.
    REQUIRE(prog1.info().platform == prog2.info().platform);
    REQUIRE(prog1.info().platform == &prevail::g_ebpf_platform_linux);

    // Analysis-prep facts are per-Program, not shared. Different programs have
    // different instruction streams and therefore different eligible-callback-target
    // sets; if the two Programs somehow share the same storage (e.g. a static
    // thread_local smuggled into a getter) the sets would compare equal and one of
    // these assertions would fail.
    const bool info_diverges = prog1.info().builtin_call_offsets != prog2.info().builtin_call_offsets ||
                               prog1.info().line_info.size() != prog2.info().line_info.size();
    const bool callback_diverges = prog1.callback_target_labels() != prog2.callback_target_labels() ||
                                   prog1.callback_targets_with_exit() != prog2.callback_targets_with_exit();
    REQUIRE((info_diverges || callback_diverges));
}

// Analyse three programs sequentially on the same thread. A regression where
// per-program state leaked into shared (global or thread-local) storage would
// surface here as verification success depending on previously-analysed
// programs.
TEST_CASE("multi-program sequential analysis", "[verify][multithreading]") {
    const prevail::Program prog1 = prepare("2/1");
    const prevail::Program prog2 = prepare("2/2");
    const prevail::Program prog3 = prepare("2/3");

    REQUIRE(prevail::verify(prog1, {}));
    REQUIRE(prevail::verify(prog2, {}));
    REQUIRE(prevail::verify(prog3, {}));

    // Re-verifying an earlier program after later ones must still succeed.
    REQUIRE(prevail::verify(prog1, {}));
}

// Analyse three programs in three threads. Extends the existing two-thread
// test to catch regressions that would only surface under wider concurrent
// access to the shared immutable platform.
TEST_CASE("multi-program parallel analysis", "[verify][multithreading]") {
    const prevail::Program prog1 = prepare("2/1");
    const prevail::Program prog2 = prepare("2/2");
    const prevail::Program prog3 = prepare("2/3");

    bool res1 = false;
    bool res2 = false;
    bool res3 = false;
    std::thread a(test_analyze_thread, &prog1, &res1);
    std::thread b(test_analyze_thread, &prog2, &res2);
    std::thread c(test_analyze_thread, &prog3, &res3);
    a.join();
    b.join();
    c.join();

    REQUIRE(res1);
    REQUIRE(res2);
    REQUIRE(res3);
}

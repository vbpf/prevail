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

// Two programs analysed concurrently must both verify; per-program analysis
// state must not leak through shared mutable storage.
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

// Immutable platform is shared across programs by pointer; per-program
// loader and analysis-prep data are not. If a getter started aliasing
// through a static/thread_local, the two programs would expose identical
// content and this test would fail.
TEST_CASE("multi-program sharing invariant", "[verify][multithreading]") {
    const prevail::Program prog1 = prepare("2/1");
    const prevail::Program prog2 = prepare("2/2");

    REQUIRE(prog1.info().platform == prog2.info().platform);
    REQUIRE(prog1.info().platform == &prevail::g_ebpf_platform_linux);

    // Different instruction streams produce different loader and callback-target
    // sets. At least one of these pairs must differ in content.
    const bool info_diverges = prog1.info().builtin_call_offsets != prog2.info().builtin_call_offsets ||
                               prog1.info().line_info.size() != prog2.info().line_info.size();
    const bool callback_diverges = prog1.callback_target_labels() != prog2.callback_target_labels() ||
                                   prog1.callback_targets_with_exit() != prog2.callback_targets_with_exit();
    REQUIRE((info_diverges || callback_diverges));
}

// Sequential analyses must be independent: re-verifying an earlier program
// after later ones still succeeds. A regression leaking per-program state
// through global or thread-local storage would make results depend on
// analysis order.
TEST_CASE("multi-program sequential analysis", "[verify][multithreading]") {
    const prevail::Program prog1 = prepare("2/1");
    const prevail::Program prog2 = prepare("2/2");
    const prevail::Program prog3 = prepare("2/3");

    REQUIRE(prevail::verify(prog1, {}));
    REQUIRE(prevail::verify(prog2, {}));
    REQUIRE(prevail::verify(prog3, {}));
    REQUIRE(prevail::verify(prog1, {}));
}

// Three concurrent analyses over a shared immutable platform must all succeed.
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

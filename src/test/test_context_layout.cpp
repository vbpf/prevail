// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>

#include "platform.hpp"
#include "test/parse.hpp"
#include "verifier.hpp"

using namespace prevail;

namespace {

/// Whether the program `lines; r0 = 0; exit` of the given section passes on `platform`.
bool accepts_context_program(const ebpf_platform_t& platform, std::vector<std::string> lines,
                             const std::string& section) {
    lines.emplace_back("r0 = 0");
    lines.emplace_back("exit");
    const ProgramInfo info{.platform = &platform, .type = platform.get_program_type(section, "")};
    InstructionSeq instructions;
    for (size_t i = 0; i < lines.size(); ++i) {
        instructions.emplace_back(Label{static_cast<int>(i)}, parse_instruction(lines[i], {}, info.type), std::nullopt);
    }
    return !analyze({Program::from_sequence(instructions, info, {}), {}}).failed;
}

} // namespace

// Linux runs a load from the perf_event context as a load from the object behind the field at its offset:
// a whole word of the interrupted pt_regs, or sample_period or addr, which it loads whole and then narrows
// (pe_prog_is_valid_access, pe_prog_convert_ctx_access). A narrower or unaligned load of a pt_regs word is
// therefore not the load that executes, and its result is not bounded by its own width.
TEST_CASE("Linux perf_event context admits only the accesses of its fields", "[context][platform]") {
    const auto accepts = [](const std::string& access) {
        return accepts_context_program(g_ebpf_platform_linux, {access}, "perf_event");
    };
    SECTION("whole words of pt_regs") {
        CHECK(accepts("r3 = *(u64 *)(r1 + 0)"));
        CHECK(accepts("r3 = *(u64 *)(r1 + 8)"));
        CHECK(accepts("r3 = *(u64 *)(r1 + 160)"));
    }
    SECTION("parts of a pt_regs word") {
        CHECK_FALSE(accepts("r3 = *(u8 *)(r1 + 0)"));
        CHECK_FALSE(accepts("r3 = *(u16 *)(r1 + 8)"));
        CHECK_FALSE(accepts("r3 = *(u32 *)(r1 + 16)"));
        CHECK_FALSE(accepts("r3 = *(u32 *)(r1 + 164)"));
        CHECK_FALSE(accepts("r3 = *(u64 *)(r1 + 4)"));
    }
    SECTION("sample_period and addr, whole or narrowed") {
        CHECK(accepts("r3 = *(u64 *)(r1 + 168)"));
        CHECK(accepts("r3 = *(u32 *)(r1 + 172)"));
        CHECK(accepts("r3 = *(u16 *)(r1 + 176)"));
        CHECK(accepts("r3 = *(u8 *)(r1 + 183)"));
    }
    SECTION("unaligned, straddling and out of bounds") {
        CHECK_FALSE(accepts("r3 = *(u32 *)(r1 + 170)"));
        CHECK_FALSE(accepts("r3 = *(u64 *)(r1 + 172)"));
        CHECK_FALSE(accepts("r3 = *(u64 *)(r1 + 184)"));
    }
    SECTION("stores") { CHECK_FALSE(accepts("*(u64 *)(r1 + 168) = 0")); }
    // A program type without a layout keeps treating its context as memory of the descriptor's size.
    SECTION("a context without a layout") {
        CHECK(accepts_context_program(g_ebpf_platform_linux, {"r3 = *(u8 *)(r1 + 1)"}, "kprobe/x"));
    }
}

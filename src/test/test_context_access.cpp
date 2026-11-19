// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>

#include "arith/dsl_syntax.hpp"
#include "crab/ebpf_domain.hpp"
#include "platform.hpp"
#include "test/parse.hpp"
#include "verifier.hpp"

using namespace prevail;

namespace {

AnalysisContext context_program(const ebpf_platform_t& platform, const std::vector<std::string>& lines,
                                const std::string& section = "xdp", const std::map<std::string, Label>& labels = {}) {
    const ProgramInfo info{.platform = &platform, .type = platform.get_program_type(section, "")};
    InstructionSeq instructions;
    for (size_t i = 0; i < lines.size(); ++i) {
        instructions.emplace_back(Label{static_cast<int>(i)}, parse_instruction(lines[i], labels, info.type),
                                  std::nullopt);
    }
    return {Program::from_sequence(instructions, info, {}), {}};
}

// Stores need a program type whose context is writable; Linux keeps the XDP context read-only.
const std::string writable_ctx_section = "classifier";

bool accepts_context_program(const ebpf_platform_t& platform, std::vector<std::string> lines,
                             const std::string& section = "xdp") {
    lines.emplace_back("r0 = 0");
    lines.emplace_back("exit");
    return !analyze(context_program(platform, lines, section)).failed;
}

} // namespace

TEST_CASE("Linux context accesses require an unshifted base", "[context][platform]") {
    const auto& platform = g_ebpf_platform_linux;
    SECTION("issue 1256 register offset") {
        CHECK_FALSE(accepts_context_program(platform, {"r2 = 8", "r1 += r2", "r3 = *(u32 *)(r1 + 0)"}));
    }
    SECTION("immediate offset") {
        CHECK_FALSE(accepts_context_program(platform, {"r1 += 8", "r3 = *(u32 *)(r1 + 0)"}));
    }
    SECTION("instruction offset cannot cancel a shifted base") {
        CHECK_FALSE(accepts_context_program(platform, {"r1 += 8", "r3 = *(u32 *)(r1 - 8)"}));
    }
    SECTION("copy of a shifted base") {
        CHECK_FALSE(accepts_context_program(platform, {"r1 += 8", "r2 = r1", "r3 = *(u32 *)(r2 + 0)"}));
    }
    SECTION("store through a shifted base") {
        CHECK_FALSE(accepts_context_program(platform, {"r1 += 12", "*(u32 *)(r1 + 0) = 0"}, writable_ctx_section));
    }
    SECTION("atomic through a shifted base") {
        CHECK_FALSE(accepts_context_program(platform, {"r1 += 16", "r2 = 1", "lock *(u32 *)(r1 + 0) += r2"},
                                            writable_ctx_section));
    }
    SECTION("constant instruction offset") { CHECK(accepts_context_program(platform, {"r3 = *(u32 *)(r1 + 8)"})); }
    SECTION("unshifted store") {
        CHECK(accepts_context_program(platform, {"*(u32 *)(r1 + 12) = 0"}, writable_ctx_section));
    }
    SECTION("unmodified copy") { CHECK(accepts_context_program(platform, {"r2 = r1", "r3 = *(u32 *)(r2 + 8)"})); }
    SECTION("zero register offset") {
        CHECK(accepts_context_program(platform, {"r2 = 0", "r1 += r2", "r3 = *(u32 *)(r1 + 8)"}));
    }
    SECTION("restored base") {
        CHECK(accepts_context_program(platform, {"r1 += 8", "r1 -= 8", "r3 = *(u32 *)(r1 + 8)"}));
    }
}

TEST_CASE("Linux context offset guard checks all possible base offsets", "[context][platform]") {
    using namespace dsl_syntax;
    const auto context = context_program(g_ebpf_platform_linux, {"r0 = 0", "exit"});
    const auto pre = EbpfDomain::from_constraints({{reg_type(Reg{1}), TypeSet{T_CTX}}},
                                                  {reg_pack(1).ctx_offset >= 0, reg_pack(1).ctx_offset <= 4});
    const ValidAccess access{1, Reg{1}, 0, Imm{4}, false, AccessType::read};
    const auto error = ebpf_domain_check(pre, access, Label{0}, context);
    REQUIRE(error.has_value());
    CHECK(error->message.find("Nonzero context offset") != std::string::npos);

    // Width-zero assertions model pointer comparisons, not context field lowering.
    const ValidAccess comparison{1, Reg{1}, 0, Imm{0}, false};
    CHECK_FALSE(ebpf_domain_check(pre, comparison, Label{0}, context).has_value());
}

TEST_CASE("Flat context platforms retain shifted base accesses", "[context][platform]") {
    CHECK_FALSE(ebpf_platform_t{}.context_access_requires_zero_offset);
    CHECK(g_ebpf_platform_linux.context_access_requires_zero_offset);
    auto flat = g_ebpf_platform_linux;
    flat.context_access_requires_zero_offset = false;
    CHECK(accepts_context_program(flat, {"r2 = 8", "r1 += r2", "r3 = *(u32 *)(r1 + 0)"}));
    CHECK(accepts_context_program(flat, {"r1 += 12", "*(u32 *)(r1 + 0) = 0"}, writable_ctx_section));
}

namespace {

// A program that first runs `guard`, which tests the context pointer against null and jumps to
// <out> (the final `r0 = 0`) when it is non-null, so `behind` runs only on the null edge.
bool accepts_behind_null_context(const std::string& section, const std::vector<std::string>& guard,
                                 const std::string& behind) {
    std::vector<std::string> lines = guard;
    lines.emplace_back("r2 = 0x41414141");
    lines.emplace_back(behind);
    const std::map<std::string, Label> labels{{"<out>", Label{static_cast<int>(lines.size())}}};
    lines.emplace_back("r0 = 0");
    lines.emplace_back("exit");
    return !analyze(context_program(g_ebpf_platform_linux, lines, section, labels)).failed;
}

} // namespace

TEST_CASE("Code behind a null test of the context is verified", "[context][platform]") {
    // Linux starts syscall and raw tracepoint programs with r1 == 0 when BPF_PROG_RUN is given no
    // context, so the null edge of the test is live. The entry state used to assume r1 >= 1, which
    // made that edge bottom: every assertion behind it held vacuously and a store through an
    // arbitrary scalar passed (ANT-2026-G2LJNAOQ).
    const std::vector<std::vector<std::string>> guards{
        {"if r1 != 0 goto <out>"},
        {"r3 = r1", "if r3 != 0 goto <out>"},
        {"r4 = 0", "if r1 != r4 goto <out>"},
        {"*(u64 *)(r10 - 8) = r1", "r5 = *(u64 *)(r10 - 8)", "if r5 != 0 goto <out>"},
    };
    // The non-null fact is dropped for every program type: where the hook always supplies a
    // context (XDP) the null edge is dead at run time, and checking it is merely conservative.
    for (const std::string section : {"syscall/", "raw_tp/", "xdp"}) {
        for (const auto& guard : guards) {
            CAPTURE(section, guard);
            CHECK_FALSE(accepts_behind_null_context(section, guard, "*(u64 *)(r2 + 0) = r2"));
            CHECK(accepts_behind_null_context(section, guard, "*(u64 *)(r10 - 16) = r2"));
        }
    }
}

TEST_CASE("Context accesses behind a null test rely on the runtime contract", "[context][platform]") {
    // A context access is checked through ctx_offset alone, so it is accepted even on the edge
    // where r1 == 0. That is sound only because a runtime does not start a program that accesses
    // its context without one (Linux: ctx_size_in >= max_ctx_offset). This case pins down that
    // reliance, so that changing it is a deliberate decision.
    for (const std::string section : {"syscall/", "raw_tp/"}) {
        CAPTURE(section);
        CHECK(accepts_behind_null_context(section, {"if r1 != 0 goto <out>"}, "r3 = *(u64 *)(r1 + 0)"));
    }
}

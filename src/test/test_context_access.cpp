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

AnalysisContext context_program(const ebpf_platform_t& platform, const std::vector<std::string>& lines) {
    const ProgramInfo info{.platform = &platform, .type = platform.get_program_type("xdp", "")};
    InstructionSeq instructions;
    for (size_t i = 0; i < lines.size(); ++i) {
        instructions.emplace_back(Label{static_cast<int>(i)}, parse_instruction(lines[i], {}, info.type), std::nullopt);
    }
    return {Program::from_sequence(instructions, info, {}), {}};
}

bool accepts_context_program(const ebpf_platform_t& platform, std::vector<std::string> lines) {
    lines.emplace_back("r0 = 0");
    lines.emplace_back("exit");
    return !analyze(context_program(platform, lines)).failed;
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
        CHECK_FALSE(accepts_context_program(platform, {"r1 += 12", "*(u32 *)(r1 + 0) = 0"}));
    }
    SECTION("atomic through a shifted base") {
        CHECK_FALSE(accepts_context_program(platform, {"r1 += 16", "r2 = 1", "lock *(u32 *)(r1 + 0) += r2"}));
    }
    SECTION("constant instruction offset") { CHECK(accepts_context_program(platform, {"r3 = *(u32 *)(r1 + 8)"})); }
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
    CHECK(accepts_context_program(flat, {"r1 += 12", "*(u32 *)(r1 + 0) = 0"}));
}

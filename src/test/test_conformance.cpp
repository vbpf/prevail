// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// Conformance tests using direct parsing from bpf_conformance_core.
// Tests verify soundness: the expected return value must be within
// the verifier's computed range.

#include <catch2/catch_all.hpp>

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>

#include <bpf_conformance_core/bpf_conformance.h>
#include <bpf_conformance_core/bpf_test_parser.h>

#include "spec/vm_isa.hpp"
#include "test/ebpf_yaml.hpp"

/**
 * @brief Run a conformance test by parsing the test file directly and
 * verifying that the expected result is sound (within the verifier's range).
 *
 * @param filename Test file name relative to external/bpf_conformance/tests/
 * @param expect_verification_failure If true, expect verification to fail
 */
static void test_conformance(const std::string& filename, bool expect_verification_failure = false) {
    const std::filesystem::path test_path = "external/bpf_conformance/tests/" + filename;

    // Parse the test file to get memory, expected result, and instructions
    auto [input_memory, expected_value, expected_error, instructions] = parse_test_file(test_path);

    // Surface any expected error from the test file for diagnostic purposes
    if (!expected_error.empty()) {
        INFO("Test file specifies expected error: " << expected_error);
    }

    // Skip tests with no instructions
    if (instructions.empty()) {
        SKIP("Test file has no instructions");
        return;
    }

    // Convert ebpf_inst (from bpf_conformance_core) to EbpfInst
    // Both are layout-compatible, so we can use reinterpret_cast on a span
    static_assert(sizeof(ebpf_inst) == sizeof(prevail::EbpfInst));
    static_assert(alignof(ebpf_inst) == alignof(prevail::EbpfInst));
    static_assert(offsetof(ebpf_inst, opcode) == offsetof(prevail::EbpfInst, opcode));
    static_assert(offsetof(ebpf_inst, offset) == offsetof(prevail::EbpfInst, offset));
    static_assert(offsetof(ebpf_inst, imm) == offsetof(prevail::EbpfInst, imm));
    const std::span<const prevail::EbpfInst> ebpf_instructions{
        reinterpret_cast<const prevail::EbpfInst*>(instructions.data()), instructions.size()};

    // Run the verifier
    const auto result = prevail::run_conformance_test_case(input_memory, ebpf_instructions, false);

    if (expect_verification_failure) {
        // We expect verification to fail for this test
        if (!result.error_reason.empty()) {
            INFO("Error reason: " << result.error_reason);
        }
        REQUIRE_FALSE(result.success);
        return;
    }

    // Verification should succeed
    REQUIRE(result.success);

    // Soundness check: the expected value must be within the verifier's range
    // This is the key improvement - we check containment rather than exact equality
    const auto expected_signed = static_cast<int64_t>(expected_value);
    const bool is_sound = result.r0_value.contains(expected_signed);

    INFO("Expected value: 0x" << std::hex << expected_value << " (" << std::dec << expected_signed << ")");
    INFO("Verifier range: " << result.r0_value);

    REQUIRE(is_sound);
}

// Standard test macro - checks soundness (expected value is within verifier's range)
#define TEST_CONFORMANCE(filename) \
    TEST_CASE("conformance_check " filename, "[conformance]") { test_conformance(filename); }

// Tests that are expected to fail verification (the program is rejected)
#define TEST_CONFORMANCE_VERIFICATION_FAILED(filename) \
    TEST_CASE("conformance_check " filename, "[conformance]") { test_conformance(filename, true); }

TEST_CONFORMANCE("add.data")
TEST_CONFORMANCE("add64.data")
TEST_CONFORMANCE("alu-arith.data")
TEST_CONFORMANCE("alu-bit.data")
TEST_CONFORMANCE("alu64-arith.data")
TEST_CONFORMANCE("alu64-bit.data")
TEST_CONFORMANCE("arsh32-imm.data")
TEST_CONFORMANCE("arsh32-imm-high.data")
TEST_CONFORMANCE("arsh32-imm-neg.data")
TEST_CONFORMANCE("arsh32-reg.data")
TEST_CONFORMANCE("arsh32-reg-high.data")
TEST_CONFORMANCE("arsh32-reg-neg.data")
TEST_CONFORMANCE("arsh64-imm.data")
TEST_CONFORMANCE("arsh64-imm-high.data")
TEST_CONFORMANCE("arsh64-imm-neg.data")
TEST_CONFORMANCE("arsh64-reg.data")
TEST_CONFORMANCE("arsh64-reg-high.data")
TEST_CONFORMANCE("arsh64-reg-neg.data")
TEST_CONFORMANCE("be16-high.data")
TEST_CONFORMANCE("be16.data")
TEST_CONFORMANCE("be32-high.data")
TEST_CONFORMANCE("be32.data")
TEST_CONFORMANCE("be64.data")
TEST_CONFORMANCE("bswap16.data")
TEST_CONFORMANCE("bswap32.data")
TEST_CONFORMANCE("bswap64.data")
TEST_CONFORMANCE("call_local.data")
TEST_CONFORMANCE("call_unwind_fail.data")
TEST_CONFORMANCE("callx.data")
TEST_CONFORMANCE("div32-by-zero-reg.data")
TEST_CONFORMANCE("div32-by-zero-reg-2.data")
TEST_CONFORMANCE("div32-high-divisor.data")
TEST_CONFORMANCE("div32-imm.data")
TEST_CONFORMANCE("div32-reg.data")
TEST_CONFORMANCE("div64-by-zero-reg.data")
TEST_CONFORMANCE("div64-imm.data")
TEST_CONFORMANCE("div64-negative-imm.data")
TEST_CONFORMANCE("div64-negative-reg.data")
TEST_CONFORMANCE("div64-reg.data")
TEST_CONFORMANCE("exit-not-last.data")
TEST_CONFORMANCE("exit.data")
TEST_CONFORMANCE("j-signed-imm.data")
TEST_CONFORMANCE("ja32.data")
TEST_CONFORMANCE("jeq-imm.data")
TEST_CONFORMANCE("jeq-reg.data")
TEST_CONFORMANCE("jeq32-imm.data")
TEST_CONFORMANCE("jeq32-reg.data")
TEST_CONFORMANCE("jge-imm.data")
TEST_CONFORMANCE("jge-reg.data")
TEST_CONFORMANCE("jge32-imm.data")
TEST_CONFORMANCE("jge32-reg.data")
TEST_CONFORMANCE("jgt-imm.data")
TEST_CONFORMANCE("jgt-reg.data")
TEST_CONFORMANCE("jgt32-imm.data")
TEST_CONFORMANCE("jgt32-reg.data")
TEST_CONFORMANCE("jit-bounce.data")
TEST_CONFORMANCE("jle-imm.data")
TEST_CONFORMANCE("jle-reg.data")
TEST_CONFORMANCE("jle32-imm.data")
TEST_CONFORMANCE("jle32-reg.data")
TEST_CONFORMANCE("jlt-imm.data")
TEST_CONFORMANCE("jlt-reg.data")
TEST_CONFORMANCE("jlt32-imm.data")
TEST_CONFORMANCE("jlt32-reg.data")
TEST_CONFORMANCE("jne-reg.data")
TEST_CONFORMANCE("jne32-imm.data")
TEST_CONFORMANCE("jne32-reg.data")
TEST_CONFORMANCE("jset-imm.data")
TEST_CONFORMANCE("jset-reg.data")
TEST_CONFORMANCE("jset32-imm.data")
TEST_CONFORMANCE("jset32-reg.data")
TEST_CONFORMANCE("jsge-imm.data")
TEST_CONFORMANCE("jsge-reg.data")
TEST_CONFORMANCE("jsge32-imm.data")
TEST_CONFORMANCE("jsge32-reg.data")
TEST_CONFORMANCE("jsgt-imm.data")
TEST_CONFORMANCE("jsgt-reg.data")
TEST_CONFORMANCE("jsgt32-imm.data")
TEST_CONFORMANCE("jsgt32-reg.data")
TEST_CONFORMANCE("jsle-imm.data")
TEST_CONFORMANCE("jsle-reg.data")
TEST_CONFORMANCE("jsle32-imm.data")
TEST_CONFORMANCE("jsle32-reg.data")
TEST_CONFORMANCE("jslt-imm.data")
TEST_CONFORMANCE("jslt-reg.data")
TEST_CONFORMANCE("jslt32-imm.data")
TEST_CONFORMANCE("jslt32-reg.data")
TEST_CONFORMANCE("lddw.data")
TEST_CONFORMANCE("lddw2.data")
TEST_CONFORMANCE("ldxb-all.data")
TEST_CONFORMANCE("ldxb.data")
TEST_CONFORMANCE("ldxdw.data")
TEST_CONFORMANCE("ldxh-all.data")
TEST_CONFORMANCE("ldxh-all2.data")
TEST_CONFORMANCE("ldxh-same-reg.data")
TEST_CONFORMANCE("ldxh.data")
TEST_CONFORMANCE("ldxw-all.data")
TEST_CONFORMANCE("ldxw.data")
TEST_CONFORMANCE("le16.data")
TEST_CONFORMANCE("le16-high.data")
TEST_CONFORMANCE("le32.data")
TEST_CONFORMANCE("le32-high.data")
TEST_CONFORMANCE("le64.data")
TEST_CONFORMANCE("lock_add.data")
TEST_CONFORMANCE("lock_add32.data")
TEST_CONFORMANCE("lock_and.data")
TEST_CONFORMANCE("lock_and32.data")
TEST_CONFORMANCE("lock_cmpxchg.data")
TEST_CONFORMANCE("lock_cmpxchg32.data")
TEST_CONFORMANCE("lock_fetch_add.data")
TEST_CONFORMANCE("lock_fetch_add32.data")
TEST_CONFORMANCE("lock_fetch_and.data")
TEST_CONFORMANCE("lock_fetch_and32.data")
TEST_CONFORMANCE("lock_fetch_or.data")
TEST_CONFORMANCE("lock_fetch_or32.data")
TEST_CONFORMANCE("lock_fetch_xor.data")
TEST_CONFORMANCE("lock_fetch_xor32.data")
TEST_CONFORMANCE("lock_or.data")
TEST_CONFORMANCE("lock_or32.data")
TEST_CONFORMANCE("lock_xchg.data")
TEST_CONFORMANCE("lock_xchg32.data")
TEST_CONFORMANCE("lock_xor.data")
TEST_CONFORMANCE("lock_xor32.data")
TEST_CONFORMANCE("lsh32-imm.data")
TEST_CONFORMANCE("lsh32-imm-high.data")
TEST_CONFORMANCE("lsh32-imm-neg.data")
TEST_CONFORMANCE("lsh32-reg.data")
TEST_CONFORMANCE("lsh32-reg-high.data")
TEST_CONFORMANCE("lsh32-reg-neg.data")
TEST_CONFORMANCE("lsh64-imm.data")
TEST_CONFORMANCE("lsh64-imm-high.data")
TEST_CONFORMANCE("lsh64-imm-neg.data")
TEST_CONFORMANCE("lsh64-reg.data")
TEST_CONFORMANCE("lsh64-reg-high.data")
TEST_CONFORMANCE("lsh64-reg-neg.data")
TEST_CONFORMANCE_VERIFICATION_FAILED("mem-len.data")
TEST_CONFORMANCE("mod-by-zero-reg.data")
TEST_CONFORMANCE("mod.data")
TEST_CONFORMANCE("mod32.data")
TEST_CONFORMANCE("mod64-by-zero-reg.data")
TEST_CONFORMANCE("mod64.data")
TEST_CONFORMANCE("mov.data")
TEST_CONFORMANCE("mov64.data")
TEST_CONFORMANCE("mov64-sign-extend.data")
TEST_CONFORMANCE("movsx1632-reg.data")
TEST_CONFORMANCE("movsx1664-reg.data")
TEST_CONFORMANCE("movsx3264-reg.data")
TEST_CONFORMANCE("movsx832-reg.data")
TEST_CONFORMANCE("movsx864-reg.data")
TEST_CONFORMANCE("mul32-imm.data")
TEST_CONFORMANCE("mul32-intmin-by-negone-imm.data")
TEST_CONFORMANCE("mul32-intmin-by-negone-reg.data")
TEST_CONFORMANCE("mul32-reg-overflow.data")
TEST_CONFORMANCE("mul32-reg.data")
TEST_CONFORMANCE("mul64-imm.data")
TEST_CONFORMANCE("mul64-intmin-by-negone-imm.data")
TEST_CONFORMANCE("mul64-intmin-by-negone-reg.data")
TEST_CONFORMANCE("mul64-reg.data")
TEST_CONFORMANCE("neg.data")
TEST_CONFORMANCE("neg32-intmin-imm.data")
TEST_CONFORMANCE("neg32-intmin-reg.data")
TEST_CONFORMANCE("neg64.data")
TEST_CONFORMANCE("neg64-intmin-imm.data")
TEST_CONFORMANCE("neg64-intmin-reg.data")
TEST_CONFORMANCE("prime.data")
TEST_CONFORMANCE("rsh32-imm.data")
TEST_CONFORMANCE("rsh32-imm-high.data")
TEST_CONFORMANCE("rsh32-imm-neg.data")
TEST_CONFORMANCE("rsh32-reg.data")
TEST_CONFORMANCE("rsh32-reg-high.data")
TEST_CONFORMANCE("rsh32-reg-neg.data")
TEST_CONFORMANCE("rsh64-imm.data")
TEST_CONFORMANCE("rsh64-imm-high.data")
TEST_CONFORMANCE("rsh64-imm-neg.data")
TEST_CONFORMANCE("rsh64-reg.data")
TEST_CONFORMANCE("rsh64-reg-high.data")
TEST_CONFORMANCE("rsh64-reg-neg.data")
TEST_CONFORMANCE("sdiv32-by-zero-imm.data")
TEST_CONFORMANCE("sdiv32-by-zero-reg.data")
TEST_CONFORMANCE("sdiv32-imm.data")
TEST_CONFORMANCE("sdiv32-intmin-by-negone-imm.data")
TEST_CONFORMANCE("sdiv32-intmin-by-negone-reg.data")
TEST_CONFORMANCE("sdiv32-reg.data")
TEST_CONFORMANCE("sdiv64-by-zero-imm.data")
TEST_CONFORMANCE("sdiv64-by-zero-reg.data")
TEST_CONFORMANCE("sdiv64-imm.data")
TEST_CONFORMANCE("sdiv64-intmin-by-negone-imm.data")
TEST_CONFORMANCE("sdiv64-intmin-by-negone-reg.data")
TEST_CONFORMANCE("sdiv64-reg.data")
TEST_CONFORMANCE("smod32-intmin-by-negone-imm.data")
TEST_CONFORMANCE("smod32-intmin-by-negone-reg.data")
TEST_CONFORMANCE("smod32-neg-by-neg-imm.data")
TEST_CONFORMANCE("smod32-neg-by-neg-reg.data")
TEST_CONFORMANCE("smod32-neg-by-pos-imm.data")
TEST_CONFORMANCE("smod32-neg-by-pos-reg.data")
TEST_CONFORMANCE("smod32-neg-by-zero-imm.data")
TEST_CONFORMANCE("smod32-neg-by-zero-reg.data")
TEST_CONFORMANCE("smod32-pos-by-neg-imm.data")
TEST_CONFORMANCE("smod32-pos-by-neg-reg.data")
TEST_CONFORMANCE("smod64-intmin-by-negone-imm.data")
TEST_CONFORMANCE("smod64-intmin-by-negone-reg.data")
TEST_CONFORMANCE("smod64-neg-by-neg-imm.data")
TEST_CONFORMANCE("smod64-neg-by-neg-reg.data")
TEST_CONFORMANCE("smod64-neg-by-pos-imm.data")
TEST_CONFORMANCE("smod64-neg-by-pos-reg.data")
TEST_CONFORMANCE("smod64-neg-by-zero-imm.data")
TEST_CONFORMANCE("smod64-neg-by-zero-reg.data")
TEST_CONFORMANCE("smod64-pos-by-neg-imm.data")
TEST_CONFORMANCE("smod64-pos-by-neg-reg.data")
TEST_CONFORMANCE("stack.data")
TEST_CONFORMANCE("stb.data")
TEST_CONFORMANCE("stdw.data")
TEST_CONFORMANCE("sth.data")
TEST_CONFORMANCE("stw.data")
TEST_CONFORMANCE("stxb-all.data")
TEST_CONFORMANCE("stxb-all2.data")
TEST_CONFORMANCE("stxb-chain.data")
TEST_CONFORMANCE("stxb.data")
TEST_CONFORMANCE("stxdw.data")
TEST_CONFORMANCE("stxh.data")
TEST_CONFORMANCE("stxw.data")
TEST_CONFORMANCE("swap16.data")
TEST_CONFORMANCE("swap32.data")
TEST_CONFORMANCE("swap64.data")
TEST_CONFORMANCE("subnet.data")

// RFC 9669 generated tests (kept as individual test cases, matching the pattern above).
TEST_CONFORMANCE("rfc9669_add32.data")
TEST_CONFORMANCE("rfc9669_add64.data")
TEST_CONFORMANCE("rfc9669_and32.data")
TEST_CONFORMANCE("rfc9669_and64.data")
TEST_CONFORMANCE("rfc9669_arsh32.data")
TEST_CONFORMANCE("rfc9669_arsh64.data")
TEST_CONFORMANCE("rfc9669_be16.data")
TEST_CONFORMANCE("rfc9669_be32.data")
TEST_CONFORMANCE("rfc9669_be64.data")
TEST_CONFORMANCE("rfc9669_bswap16.data")
TEST_CONFORMANCE("rfc9669_bswap32.data")
TEST_CONFORMANCE("rfc9669_bswap64.data")
TEST_CONFORMANCE("rfc9669_call_local.data")
TEST_CONFORMANCE("rfc9669_div32.data")
TEST_CONFORMANCE("rfc9669_div64.data")
TEST_CONFORMANCE("rfc9669_exit.data")
TEST_CONFORMANCE("rfc9669_ja.data")
TEST_CONFORMANCE("rfc9669_ja32.data")
TEST_CONFORMANCE("rfc9669_jeq.data")
TEST_CONFORMANCE("rfc9669_jge.data")
TEST_CONFORMANCE("rfc9669_jgt.data")
TEST_CONFORMANCE("rfc9669_jle.data")
TEST_CONFORMANCE("rfc9669_jlt.data")
TEST_CONFORMANCE("rfc9669_jne.data")
TEST_CONFORMANCE("rfc9669_jset.data")
TEST_CONFORMANCE("rfc9669_jsge.data")
TEST_CONFORMANCE("rfc9669_jsgt.data")
TEST_CONFORMANCE("rfc9669_jsle.data")
TEST_CONFORMANCE("rfc9669_jslt.data")
TEST_CONFORMANCE("rfc9669_lddw.data")
TEST_CONFORMANCE("rfc9669_ldxb.data")
TEST_CONFORMANCE("rfc9669_ldxdw.data")
TEST_CONFORMANCE("rfc9669_ldxh.data")
TEST_CONFORMANCE("rfc9669_ldxsb.data")
TEST_CONFORMANCE("rfc9669_ldxsh.data")
TEST_CONFORMANCE("rfc9669_ldxsw.data")
TEST_CONFORMANCE("rfc9669_ldxw.data")
TEST_CONFORMANCE("rfc9669_le16.data")
TEST_CONFORMANCE("rfc9669_le32.data")
TEST_CONFORMANCE("rfc9669_le64.data")
TEST_CONFORMANCE("rfc9669_lock_add32.data")
TEST_CONFORMANCE("rfc9669_lock_add64.data")
TEST_CONFORMANCE("rfc9669_lock_and32.data")
TEST_CONFORMANCE("rfc9669_lock_and64.data")
TEST_CONFORMANCE("rfc9669_lock_cmpxchg32.data")
TEST_CONFORMANCE("rfc9669_lock_cmpxchg64.data")
TEST_CONFORMANCE("rfc9669_lock_fetch_add32.data")
TEST_CONFORMANCE("rfc9669_lock_fetch_add64.data")
TEST_CONFORMANCE("rfc9669_lock_or32.data")
TEST_CONFORMANCE("rfc9669_lock_or64.data")
TEST_CONFORMANCE("rfc9669_lock_xchg32.data")
TEST_CONFORMANCE("rfc9669_lock_xchg64.data")
TEST_CONFORMANCE("rfc9669_lock_xor32.data")
TEST_CONFORMANCE("rfc9669_lock_xor64.data")
TEST_CONFORMANCE("rfc9669_lsh32.data")
TEST_CONFORMANCE("rfc9669_lsh64.data")
TEST_CONFORMANCE("rfc9669_mod32.data")
TEST_CONFORMANCE("rfc9669_mod64.data")
TEST_CONFORMANCE("rfc9669_mov32.data")
TEST_CONFORMANCE("rfc9669_mov64.data")
TEST_CONFORMANCE("rfc9669_movsx.data")
TEST_CONFORMANCE("rfc9669_mul32.data")
TEST_CONFORMANCE("rfc9669_mul64.data")
TEST_CONFORMANCE("rfc9669_neg32.data")
TEST_CONFORMANCE("rfc9669_neg64.data")
TEST_CONFORMANCE("rfc9669_or32.data")
TEST_CONFORMANCE("rfc9669_or64.data")
TEST_CONFORMANCE("rfc9669_rsh32.data")
TEST_CONFORMANCE("rfc9669_rsh64.data")
TEST_CONFORMANCE("rfc9669_sdiv32.data")
TEST_CONFORMANCE("rfc9669_sdiv64.data")
TEST_CONFORMANCE("rfc9669_smod32.data")
TEST_CONFORMANCE("rfc9669_smod64.data")
TEST_CONFORMANCE("rfc9669_stb.data")
TEST_CONFORMANCE("rfc9669_stdw.data")
TEST_CONFORMANCE("rfc9669_sth.data")
TEST_CONFORMANCE("rfc9669_stw.data")
TEST_CONFORMANCE("rfc9669_stxb.data")
TEST_CONFORMANCE("rfc9669_stxdw.data")
TEST_CONFORMANCE("rfc9669_stxh.data")
TEST_CONFORMANCE("rfc9669_stxw.data")
TEST_CONFORMANCE("rfc9669_sub32.data")
TEST_CONFORMANCE("rfc9669_sub64.data")
TEST_CONFORMANCE("rfc9669_swap16.data")
TEST_CONFORMANCE("rfc9669_swap32.data")
TEST_CONFORMANCE("rfc9669_swap64.data")
TEST_CONFORMANCE("rfc9669_xor32.data")
TEST_CONFORMANCE("rfc9669_xor64.data")

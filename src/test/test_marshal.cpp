// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <ranges>

#include <catch2/catch_all.hpp>

#include "ebpf_verifier.hpp"
#include "ir/marshal.hpp"
#include "ir/program.hpp"
#include "ir/unmarshal.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"

using namespace prevail;

// Below we define a tample of instruction templates that specify
// what values each field are allowed to contain.  We first define
// a set of sentinel values that mean certain types of wildcards.
// For example, MEM_OFFSET and JMP_OFFSET are different wildcards
// for the 'offset' field of an instruction.  Any non-sentinel values
// in an instruction template are treated as literals.

constexpr int MEM_OFFSET = 3;                           // Any valid memory offset value.
constexpr int JMP_OFFSET = 5;                           // Any valid jump offset value.
constexpr int DST = 7;                                  // Any destination register number.
constexpr int HELPER_ID = 8;                            // Any helper ID.
constexpr int SRC = 9;                                  // Any source register number.
constexpr int IMM = -1;                                 // Any imm value.
constexpr int INVALID_REGISTER = R10_STACK_POINTER + 1; // Not a valid register.

struct EbpfInstructionTemplate {
    EbpfInst inst;
    bpf_conformance_groups_t groups;
};

// The following table is derived from the table in the Appendix of the
// BPF ISA specification (https://datatracker.ietf.org/doc/draft-ietf-bpf-isa/).
static const EbpfInstructionTemplate instruction_template[] = {
    // {opcode, dst, src, offset, imm}, group
    {{0x04, DST, 0, 0, IMM}, bpf_conformance_groups_t::base32},
    {{0x05, 0, 0, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x06, 0, 0, 0, JMP_OFFSET}, bpf_conformance_groups_t::base32},
    {{0x07, DST, 0, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x0c, DST, SRC, 0, 0}, bpf_conformance_groups_t::base32},
    {{0x0f, DST, SRC, 0, 0}, bpf_conformance_groups_t::base64},
    {{0x14, DST, 0, 0, IMM}, bpf_conformance_groups_t::base32},
    {{0x15, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0x16, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0x17, DST, 0, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x18, DST, 0, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x18, DST, 1, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x18, DST, 2, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x18, DST, 3, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x18, DST, 4, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x18, DST, 5, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x18, DST, 6, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x1c, DST, SRC, 0, 0}, bpf_conformance_groups_t::base32},
    {{0x1d, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x1e, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x1f, DST, SRC, 0, 0}, bpf_conformance_groups_t::base64},
    {{0x20, 0, 0, 0, IMM}, bpf_conformance_groups_t::packet},
    {{0x24, DST, 0, 0, IMM}, bpf_conformance_groups_t::divmul32},
    {{0x25, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0x26, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0x27, DST, 0, 0, IMM}, bpf_conformance_groups_t::divmul64},
    {{0x28, 0, 0, 0, IMM}, bpf_conformance_groups_t::packet},
    {{0x2c, DST, SRC, 0, 0}, bpf_conformance_groups_t::divmul32},
    {{0x2d, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x2e, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x2f, DST, SRC, 0, 0}, bpf_conformance_groups_t::divmul64},
    {{0x30, 0, 0, 0, IMM}, bpf_conformance_groups_t::packet},
    {{0x34, DST, 0, 0, IMM}, bpf_conformance_groups_t::divmul32},
    {{0x34, DST, 0, 1, IMM}, bpf_conformance_groups_t::divmul32},
    {{0x35, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0x36, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0x37, DST, 0, 0, IMM}, bpf_conformance_groups_t::divmul64},
    {{0x37, DST, 0, 1, IMM}, bpf_conformance_groups_t::divmul64},
    {{0x3c, DST, SRC, 0, 0}, bpf_conformance_groups_t::divmul32},
    {{0x3c, DST, SRC, 1, 0}, bpf_conformance_groups_t::divmul32},
    {{0x3d, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x3e, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x3f, DST, SRC, 0, 0}, bpf_conformance_groups_t::divmul64},
    {{0x3f, DST, SRC, 1, 0}, bpf_conformance_groups_t::divmul64},
    {{0x40, 0, SRC, 0, IMM}, bpf_conformance_groups_t::packet},
    {{0x44, DST, 0, 0, IMM}, bpf_conformance_groups_t::base32},
    {{0x45, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0x46, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0x47, DST, 0, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x48, 0, SRC, 0, IMM}, bpf_conformance_groups_t::packet},
    {{0x4c, DST, SRC, 0, 0}, bpf_conformance_groups_t::base32},
    {{0x4d, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x4e, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x4f, DST, SRC, 0, 0}, bpf_conformance_groups_t::base64},
    {{0x50, 0, SRC, 0, IMM}, bpf_conformance_groups_t::packet},
    {{0x54, DST, 0, 0, IMM}, bpf_conformance_groups_t::base32},
    {{0x55, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0x56, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0x57, DST, 0, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x5c, DST, SRC, 0, 0}, bpf_conformance_groups_t::base32},
    {{0x5d, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x5e, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x5f, DST, SRC, 0, 0}, bpf_conformance_groups_t::base64},
    {{0x61, DST, SRC, MEM_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x62, DST, 0, MEM_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0x63, DST, SRC, MEM_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x64, DST, 0, 0, IMM}, bpf_conformance_groups_t::base32},
    {{0x65, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0x66, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0x67, DST, 0, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x69, DST, SRC, MEM_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x6a, DST, 0, MEM_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0x6b, DST, SRC, MEM_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x6c, DST, SRC, 0, 0}, bpf_conformance_groups_t::base32},
    {{0x6d, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x6e, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x6f, DST, SRC, 0, 0}, bpf_conformance_groups_t::base64},
    {{0x71, DST, SRC, MEM_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x72, DST, 0, MEM_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0x73, DST, SRC, MEM_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x74, DST, 0, 0, IMM}, bpf_conformance_groups_t::base32},
    {{0x75, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0x76, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0x77, DST, 0, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0x79, DST, SRC, MEM_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x7a, DST, 0, MEM_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0x7b, DST, SRC, MEM_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x7c, DST, SRC, 0, 0}, bpf_conformance_groups_t::base32},
    {{0x7d, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x7e, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0x7f, DST, SRC, 0, 0}, bpf_conformance_groups_t::base64},
    {{0x81, DST, SRC, MEM_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x84, DST, 0, 0, 0}, bpf_conformance_groups_t::base32},
    {{0x85, 0, 0, 0, HELPER_ID}, bpf_conformance_groups_t::base32},
    {{0x85, 0, 1, 0, JMP_OFFSET}, bpf_conformance_groups_t::base32},
    {{0x85, 0, 2, 0, IMM}, bpf_conformance_groups_t::base32},
    {{0x87, DST, 0, 0, 0}, bpf_conformance_groups_t::base64},
    {{0x89, DST, SRC, MEM_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x8d, DST, 0, 0, 0}, bpf_conformance_groups_t::callx},
    {{0x91, DST, SRC, MEM_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0x94, DST, 0, 0, IMM}, bpf_conformance_groups_t::divmul32},
    {{0x94, DST, 0, 1, IMM}, bpf_conformance_groups_t::divmul32},
    {{0x95, 0, 0, 0, 0}, bpf_conformance_groups_t::base32},
    {{0x97, DST, 0, 0, IMM}, bpf_conformance_groups_t::divmul64},
    {{0x97, DST, 0, 1, IMM}, bpf_conformance_groups_t::divmul64},
    {{0x9c, DST, SRC, 0, 0}, bpf_conformance_groups_t::divmul32},
    {{0x9c, DST, SRC, 1, 0}, bpf_conformance_groups_t::divmul32},
    {{0x9f, DST, SRC, 0, 0}, bpf_conformance_groups_t::divmul64},
    {{0x9f, DST, SRC, 1, 0}, bpf_conformance_groups_t::divmul64},
    {{0xa4, DST, 0, 0, IMM}, bpf_conformance_groups_t::base32},
    {{0xa5, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0xa6, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0xa7, DST, 0, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0xac, DST, SRC, 0, 0}, bpf_conformance_groups_t::base32},
    {{0xad, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0xae, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0xaf, DST, SRC, 0, 0}, bpf_conformance_groups_t::base64},
    {{0xb4, DST, 0, 0, IMM}, bpf_conformance_groups_t::base32},
    {{0xb5, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0xb6, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0xb7, DST, 0, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0xbc, DST, SRC, 0, 0}, bpf_conformance_groups_t::base32},
    {{0xbc, DST, SRC, 8, 0}, bpf_conformance_groups_t::base32},
    {{0xbc, DST, SRC, 16, 0}, bpf_conformance_groups_t::base32},
    {{0xbd, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0xbe, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0xbf, DST, SRC, 0, 0}, bpf_conformance_groups_t::base64},
    {{0xbf, DST, SRC, 8, 0}, bpf_conformance_groups_t::base64},
    {{0xbf, DST, SRC, 16, 0}, bpf_conformance_groups_t::base64},
    {{0xbf, DST, SRC, 32, 0}, bpf_conformance_groups_t::base64},
    {{0xc3, DST, SRC, MEM_OFFSET, 0x00}, bpf_conformance_groups_t::atomic32},
    {{0xc3, DST, SRC, MEM_OFFSET, 0x01}, bpf_conformance_groups_t::atomic32},
    {{0xc3, DST, SRC, MEM_OFFSET, 0x40}, bpf_conformance_groups_t::atomic32},
    {{0xc3, DST, SRC, MEM_OFFSET, 0x41}, bpf_conformance_groups_t::atomic32},
    {{0xc3, DST, SRC, MEM_OFFSET, 0x50}, bpf_conformance_groups_t::atomic32},
    {{0xc3, DST, SRC, MEM_OFFSET, 0x51}, bpf_conformance_groups_t::atomic32},
    {{0xc3, DST, SRC, MEM_OFFSET, 0xa0}, bpf_conformance_groups_t::atomic32},
    {{0xc3, DST, SRC, MEM_OFFSET, 0xa1}, bpf_conformance_groups_t::atomic32},
    {{0xc3, DST, SRC, MEM_OFFSET, 0xe1}, bpf_conformance_groups_t::atomic32},
    {{0xc3, DST, SRC, MEM_OFFSET, 0xf1}, bpf_conformance_groups_t::atomic32},
    {{0xc4, DST, 0, 0, IMM}, bpf_conformance_groups_t::base32},
    {{0xc5, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0xc6, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0xc7, DST, 0, 0, IMM}, bpf_conformance_groups_t::base64},
    {{0xcc, DST, SRC, 0, 0}, bpf_conformance_groups_t::base32},
    {{0xcd, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0xce, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
    {{0xcf, DST, SRC, 0, 0}, bpf_conformance_groups_t::base64},
    {{0xd4, DST, 0, 0, 0x10}, bpf_conformance_groups_t::base32},
    {{0xd4, DST, 0, 0, 0x20}, bpf_conformance_groups_t::base32},
    {{0xd4, DST, 0, 0, 0x40}, bpf_conformance_groups_t::base64},
    {{0xd5, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base64},
    {{0xd6, DST, 0, JMP_OFFSET, IMM}, bpf_conformance_groups_t::base32},
    {{0xd7, DST, 0, 0, 0x10}, bpf_conformance_groups_t::base32},
    {{0xd7, DST, 0, 0, 0x20}, bpf_conformance_groups_t::base32},
    {{0xd7, DST, 0, 0, 0x40}, bpf_conformance_groups_t::base64},
    {{0xdb, DST, SRC, MEM_OFFSET, 0x00}, bpf_conformance_groups_t::atomic64},
    {{0xdb, DST, SRC, MEM_OFFSET, 0x01}, bpf_conformance_groups_t::atomic64},
    {{0xdb, DST, SRC, MEM_OFFSET, 0x40}, bpf_conformance_groups_t::atomic64},
    {{0xdb, DST, SRC, MEM_OFFSET, 0x41}, bpf_conformance_groups_t::atomic64},
    {{0xdb, DST, SRC, MEM_OFFSET, 0x50}, bpf_conformance_groups_t::atomic64},
    {{0xdb, DST, SRC, MEM_OFFSET, 0x51}, bpf_conformance_groups_t::atomic64},
    {{0xdb, DST, SRC, MEM_OFFSET, 0xa0}, bpf_conformance_groups_t::atomic64},
    {{0xdb, DST, SRC, MEM_OFFSET, 0xa1}, bpf_conformance_groups_t::atomic64},
    {{0xdb, DST, SRC, MEM_OFFSET, 0xe1}, bpf_conformance_groups_t::atomic64},
    {{0xdb, DST, SRC, MEM_OFFSET, 0xf1}, bpf_conformance_groups_t::atomic64},
    {{0xdc, DST, 0, 0, 0x10}, bpf_conformance_groups_t::base32},
    {{0xdc, DST, 0, 0, 0x20}, bpf_conformance_groups_t::base32},
    {{0xdc, DST, 0, 0, 0x40}, bpf_conformance_groups_t::base64},
    {{0xdd, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base64},
    {{0xde, DST, SRC, JMP_OFFSET, 0}, bpf_conformance_groups_t::base32},
};

// Verify that we can successfully unmarshal an instruction.
static void check_unmarshal_succeed(const EbpfInst& ins, const ebpf_platform_t& platform = g_ebpf_platform_linux) {
    const ProgramInfo info{.platform = &platform, .type = platform.get_program_type("unspec", "unspec")};
    constexpr EbpfInst exit{.opcode = INST_OP_EXIT};
    const InstructionSeq parsed =
        std::get<InstructionSeq>(unmarshal(RawProgram{"", "", 0, "", {ins, exit, exit}, info}, thread_local_options));
    REQUIRE(parsed.size() == 3);
}

// Verify that we can successfully unmarshal a 64-bit immediate instruction.
static void check_unmarshal_succeed(EbpfInst inst1, EbpfInst inst2,
                                    const ebpf_platform_t& platform = g_ebpf_platform_linux) {
    const ProgramInfo info{.platform = &platform, .type = platform.get_program_type("unspec", "unspec")};
    constexpr EbpfInst exit{.opcode = INST_OP_EXIT};
    const InstructionSeq parsed = std::get<InstructionSeq>(
        unmarshal(RawProgram{"", "", 0, "", {inst1, inst2, exit, exit}, info}, thread_local_options));
    REQUIRE(parsed.size() == 3);
}

// Verify that if we unmarshal an instruction and then re-marshal it,
// we get what we expect.
static void compare_unmarshal_marshal(const EbpfInst& ins, const EbpfInst& expected_result,
                                      const ebpf_platform_t& platform = g_ebpf_platform_linux) {
    ProgramInfo info{.platform = &platform, .type = platform.get_program_type("unspec", "unspec")};
    constexpr EbpfInst exit{.opcode = INST_OP_EXIT};
    const InstructionSeq inst_seq =
        std::get<InstructionSeq>(unmarshal(RawProgram{"", "", 0, "", {ins, exit, exit}, info}, thread_local_options));
    REQUIRE(inst_seq.size() == 3);
    auto [_, single, _2] = inst_seq.front();
    (void)_;  // unused
    (void)_2; // unused
    std::vector<EbpfInst> marshaled = marshal(single, 0);
    REQUIRE(marshaled.size() == 1);
    EbpfInst result = marshaled.back();
    REQUIRE(memcmp(&expected_result, &result, sizeof(result)) == 0);
}

// Verify that if we unmarshal two instructions and then re-marshal it,
// we get what we expect.
static void compare_unmarshal_marshal(const EbpfInst& ins1, const EbpfInst& ins2, const EbpfInst& expected_result) {
    ProgramInfo info{.platform = &g_ebpf_platform_linux,
                     .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")};
    constexpr EbpfInst exit{.opcode = INST_OP_EXIT};
    InstructionSeq parsed = std::get<InstructionSeq>(
        unmarshal(RawProgram{"", "", 0, "", {ins1, ins2, exit, exit}, info}, thread_local_options));
    REQUIRE(parsed.size() == 3);
    auto [_, single, _2] = parsed.front();
    (void)_;  // unused
    (void)_2; // unused
    std::vector<EbpfInst> marshaled = marshal(single, 0);
    REQUIRE(marshaled.size() == 1);
    EbpfInst result = marshaled.back();
    REQUIRE(memcmp(&expected_result, &result, sizeof(result)) == 0);
}

// Verify that if we unmarshal a 64-bit immediate instruction and then re-marshal it,
// we get what we expect.
static void compare_unmarshal_marshal(const EbpfInst& ins1, const EbpfInst& ins2, const EbpfInst& expected_result1,
                                      const EbpfInst& expected_result2) {
    ProgramInfo info{.platform = &g_ebpf_platform_linux,
                     .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")};
    constexpr EbpfInst exit{.opcode = INST_OP_EXIT};
    const InstructionSeq inst_seq = std::get<InstructionSeq>(
        unmarshal(RawProgram{"", "", 0, "", {ins1, ins2, exit, exit}, info}, thread_local_options));
    REQUIRE(inst_seq.size() == 3);
    auto [_, single, _2] = inst_seq.front();
    (void)_;  // unused
    (void)_2; // unused
    std::vector<EbpfInst> marshaled = marshal(single, 0);
    REQUIRE(marshaled.size() == 2);
    EbpfInst result1 = marshaled.front();
    REQUIRE(memcmp(&expected_result1, &result1, sizeof(result1)) == 0);
    EbpfInst result2 = marshaled.back();
    REQUIRE(memcmp(&expected_result2, &result2, sizeof(result2)) == 0);
}

// Verify that if we marshal an instruction and then unmarshal it,
// we get the original.
static void compare_marshal_unmarshal(const Instruction& ins, bool double_cmd = false,
                                      const ebpf_platform_t& platform = g_ebpf_platform_linux) {
    ProgramInfo info{.platform = &platform, .type = platform.get_program_type("unspec", "unspec")};
    const InstructionSeq inst_seq =
        std::get<InstructionSeq>(unmarshal(RawProgram{"", "", 0, "", marshal(ins, 0), info}, thread_local_options));
    REQUIRE(inst_seq.size() == 1);
    auto [_, single, _2] = inst_seq.back();
    (void)_;  // unused
    (void)_2; // unused
    REQUIRE(single == ins);
}

static void check_marshal_unmarshal_fail(const Instruction& ins, const std::string& expected_error_message,
                                         const ebpf_platform_t& platform = g_ebpf_platform_linux) {
    const ProgramInfo info{.platform = &platform, .type = platform.get_program_type("unspec", "unspec")};
    auto result = unmarshal(RawProgram{"", "", 0, "", marshal(ins, 0), info}, thread_local_options);
    auto* error_message = std::get_if<std::string>(&result);
    REQUIRE(error_message != nullptr);
    REQUIRE(*error_message == expected_error_message);
}

static void check_unmarshal_fail(EbpfInst inst, const std::string& expected_error_message,
                                 const ebpf_platform_t& platform = g_ebpf_platform_linux) {
    ProgramInfo info{.platform = &platform, .type = platform.get_program_type("unspec", "unspec")};
    std::vector insns = {inst};
    auto result = unmarshal(RawProgram{"", "", 0, "", insns, info}, thread_local_options);
    auto* error_message = std::get_if<std::string>(&result);
    REQUIRE(error_message != nullptr);
    REQUIRE(*error_message == expected_error_message);
}

static void check_unmarshal_fail_goto(EbpfInst inst, const std::string& expected_error_message,
                                      const ebpf_platform_t& platform = g_ebpf_platform_linux) {
    ProgramInfo info{.platform = &platform, .type = platform.get_program_type("unspec", "unspec")};
    constexpr EbpfInst exit{.opcode = INST_OP_EXIT};
    std::vector insns{inst, exit, exit};
    auto result = unmarshal(RawProgram{"", "", 0, "", insns, info}, thread_local_options);
    auto* error_message = std::get_if<std::string>(&result);
    REQUIRE(error_message != nullptr);
    REQUIRE(*error_message == expected_error_message);
}

// Check that unmarshaling a 64-bit immediate instruction fails.
static void check_unmarshal_fail(EbpfInst inst1, EbpfInst inst2, const std::string& expected_error_message,
                                 const ebpf_platform_t& platform = g_ebpf_platform_linux) {
    ProgramInfo info{.platform = &platform, .type = platform.get_program_type("unspec", "unspec")};
    std::vector insns{inst1, inst2};
    auto result = unmarshal(RawProgram{"", "", 0, "", insns, info}, thread_local_options);
    auto* error_message = std::get_if<std::string>(&result);
    REQUIRE(error_message != nullptr);
    REQUIRE(*error_message == expected_error_message);
}

static Call unmarshal_single_call(const EbpfInst& call_inst, const ProgramInfo& info) {
    constexpr EbpfInst exit{.opcode = INST_OP_EXIT};
    const auto parsed = unmarshal(RawProgram{"", "", 0, "", {call_inst, exit, exit}, info}, thread_local_options);
    auto* inst_seq = std::get_if<InstructionSeq>(&parsed);
    REQUIRE(inst_seq != nullptr);
    REQUIRE(inst_seq->size() == 3);
    auto* call = std::get_if<Call>(&std::get<1>((*inst_seq)[0]));
    REQUIRE(call != nullptr);
    return *call;
}

template <typename T>
static bool has_assertion(const std::vector<Assertion>& assertions, const T& expected) {
    return std::any_of(assertions.begin(), assertions.end(), [&](const Assertion& assertion) {
        const auto* typed = std::get_if<T>(&assertion);
        return typed != nullptr && *typed == expected;
    });
}

static constexpr auto ws = {1, 2, 4, 8};

TEST_CASE("disasm_marshal", "[disasm][marshal]") {
    SECTION("Bin") {
        SECTION("Reg src") {
            auto ops = {Bin::Op::MOV,  Bin::Op::ADD,  Bin::Op::SUB,    Bin::Op::MUL,     Bin::Op::UDIV,   Bin::Op::UMOD,
                        Bin::Op::OR,   Bin::Op::AND,  Bin::Op::LSH,    Bin::Op::RSH,     Bin::Op::ARSH,   Bin::Op::XOR,
                        Bin::Op::SDIV, Bin::Op::SMOD, Bin::Op::MOVSX8, Bin::Op::MOVSX16, Bin::Op::MOVSX32};
            for (const auto op : ops) {
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Reg{2}, .is64 = true});
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Reg{2}, .is64 = false});
            }
        }
        SECTION("Imm src") {
            // MOVSX* instructions are not defined for Imm, only Reg.
            auto ops = {Bin::Op::MOV,  Bin::Op::ADD, Bin::Op::SUB,  Bin::Op::MUL, Bin::Op::UDIV,
                        Bin::Op::UMOD, Bin::Op::OR,  Bin::Op::AND,  Bin::Op::LSH, Bin::Op::RSH,
                        Bin::Op::ARSH, Bin::Op::XOR, Bin::Op::SDIV, Bin::Op::SMOD};
            for (const auto op : ops) {
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Imm{2}, .is64 = false});
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Imm{2}, .is64 = true});
            }
            SECTION("LDDW") {
                compare_marshal_unmarshal(
                    Bin{.op = Bin::Op::MOV, .dst = Reg{1}, .v = Imm{2}, .is64 = true, .lddw = true}, true);
            }
            SECTION("r10") {
                check_marshal_unmarshal_fail(Bin{.op = Bin::Op::ADD, .dst = Reg{10}, .v = Imm{4}, .is64 = true},
                                             "0: invalid target r10\n");
            }
        }
    }
    SECTION("Neg") {
        compare_marshal_unmarshal(Un{.op = Un::Op::NEG, .dst = Reg{1}, .is64 = false});
        compare_marshal_unmarshal(Un{.op = Un::Op::NEG, .dst = Reg{1}, .is64 = true});
    }
    SECTION("Endian") {
        // FIX: `.is64` comes from the instruction class (BPF_ALU or BPF_ALU64) but is unused since it can be derived
        // from `.op`.
        {
            auto ops = {
                Un::Op::BE16, Un::Op::BE32, Un::Op::BE64, Un::Op::LE16, Un::Op::LE32, Un::Op::LE64,
            };
            for (const auto op : ops) {
                compare_marshal_unmarshal(Un{.op = op, .dst = Reg{1}, .is64 = false});
            }
        }
        {
            auto ops = {
                Un::Op::SWAP16,
                Un::Op::SWAP32,
                Un::Op::SWAP64,
            };
            for (const auto op : ops) {
                compare_marshal_unmarshal(Un{.op = op, .dst = Reg{1}, .is64 = true});
            }
        }
    }

    SECTION("LoadMapFd") { compare_marshal_unmarshal(LoadMapFd{.dst = Reg{1}, .mapfd = 1}, true); }
    SECTION("LoadMapAddress") {
        compare_marshal_unmarshal(LoadMapAddress{.dst = Reg{1}, .mapfd = 1, .offset = 4}, true);
    }

    SECTION("Jmp") {
        auto ops = {Condition::Op::EQ, Condition::Op::GT, Condition::Op::GE, Condition::Op::SET,
                    // Condition::Op::NSET, does not exist in ebpf
                    Condition::Op::NE, Condition::Op::SGT, Condition::Op::SGE, Condition::Op::LT, Condition::Op::LE,
                    Condition::Op::SLT, Condition::Op::SLE};
        SECTION("goto offset") {
            EbpfInst jmp_offset{.opcode = INST_OP_JA16, .offset = 1};
            compare_unmarshal_marshal(jmp_offset, jmp_offset);

            // JA32 +1 is equivalent to JA16 +1 since the offset fits in 16 bits.
            compare_unmarshal_marshal(EbpfInst{.opcode = INST_OP_JA32, .imm = 1}, jmp_offset);
        }
        SECTION("Reg right") {
            for (const auto op : ops) {
                Condition cond{.op = op, .left = Reg{1}, .right = Reg{2}, .is64 = true};
                compare_marshal_unmarshal(Jmp{.cond = cond, .target = Label(0)});

                // The following should fail unmarshalling since it jumps past the end of the instruction set.
                check_marshal_unmarshal_fail(Jmp{.cond = cond, .target = Label(1)}, "0: jump out of bounds\n");
            }
        }
        SECTION("Imm right") {
            for (const auto op : ops) {
                Condition cond{.op = op, .left = Reg{1}, .right = Imm{2}, .is64 = true};
                compare_marshal_unmarshal(Jmp{.cond = cond, .target = Label(0)});

                // The following should fail unmarshalling since it jumps past the end of the instruction set.
                check_marshal_unmarshal_fail(Jmp{.cond = cond, .target = Label(1)}, "0: jump out of bounds\n");
            }
        }
    }

    SECTION("Call") {
        for (int func : {1, 17}) {
            compare_marshal_unmarshal(Call{func});
        }

        // Test callx without support: decode still succeeds.
        check_unmarshal_succeed(EbpfInst{.opcode = INST_OP_CALLX});

        // Test callx with support.  Note that callx puts the register number in 'dst' not 'src'.
        ebpf_platform_t platform = g_ebpf_platform_linux;
        platform.supported_conformance_groups |= bpf_conformance_groups_t::callx;
        compare_marshal_unmarshal(Callx{8}, false, platform);
        EbpfInst callx{.opcode = INST_OP_CALLX, .dst = 8};
        compare_unmarshal_marshal(callx, callx, platform);
        check_unmarshal_fail({.opcode = INST_OP_CALLX, .dst = 11}, "0: bad register\n", platform);
        check_unmarshal_fail({.opcode = INST_OP_CALLX, .dst = 8, .imm = 8}, "0: nonzero imm for op 0x8d\n", platform);

        // clang prior to v19 put the register into 'imm' instead of 'dst' so we treat it as equivalent.
        compare_unmarshal_marshal(EbpfInst{.opcode = /* 0x8d */ INST_OP_CALLX, .imm = 8}, callx, platform);
        check_unmarshal_fail({.opcode = INST_OP_CALLX, .imm = 11}, "0: bad register\n", platform);
        check_unmarshal_fail({.opcode = INST_OP_CALLX, .imm = -1}, "0: bad register\n", platform);
    }

    SECTION("Exit") { compare_marshal_unmarshal(Exit{}); }

    SECTION("Packet") {
        for (int w : ws) {
            if (w != 8) {
                compare_marshal_unmarshal(Packet{.width = w, .offset = 7, .regoffset = {}});
                compare_marshal_unmarshal(Packet{.width = w, .offset = 7, .regoffset = Reg{2}});
            }
        }
    }

    SECTION("Atomic") {
        for (int w : ws) {
            if (w == 4 || w == 8) {
                Deref access{.width = w, .basereg = Reg{2}, .offset = 17};
                compare_marshal_unmarshal(
                    Atomic{.op = Atomic::Op::ADD, .fetch = false, .access = access, .valreg = Reg{1}});
                compare_marshal_unmarshal(
                    Atomic{.op = Atomic::Op::ADD, .fetch = true, .access = access, .valreg = Reg{1}});
                compare_marshal_unmarshal(
                    Atomic{.op = Atomic::Op::OR, .fetch = false, .access = access, .valreg = Reg{1}});
                compare_marshal_unmarshal(
                    Atomic{.op = Atomic::Op::OR, .fetch = true, .access = access, .valreg = Reg{1}});
                compare_marshal_unmarshal(
                    Atomic{.op = Atomic::Op::AND, .fetch = false, .access = access, .valreg = Reg{1}});
                compare_marshal_unmarshal(
                    Atomic{.op = Atomic::Op::AND, .fetch = true, .access = access, .valreg = Reg{1}});
                compare_marshal_unmarshal(
                    Atomic{.op = Atomic::Op::XOR, .fetch = false, .access = access, .valreg = Reg{1}});
                compare_marshal_unmarshal(
                    Atomic{.op = Atomic::Op::XOR, .fetch = true, .access = access, .valreg = Reg{1}});
                check_marshal_unmarshal_fail(
                    Atomic{.op = Atomic::Op::XCHG, .fetch = false, .access = access, .valreg = Reg{1}},
                    "0: unsupported immediate\n");
                compare_marshal_unmarshal(
                    Atomic{.op = Atomic::Op::XCHG, .fetch = true, .access = access, .valreg = Reg{1}});
                check_marshal_unmarshal_fail(
                    Atomic{.op = Atomic::Op::CMPXCHG, .fetch = false, .access = access, .valreg = Reg{1}},
                    "0: unsupported immediate\n");
                compare_marshal_unmarshal(
                    Atomic{.op = Atomic::Op::CMPXCHG, .fetch = true, .access = access, .valreg = Reg{1}});
            }
        }
    }
}

TEST_CASE("marshal", "[disasm][marshal]") {
    SECTION("Load") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        Mem m{.access = access, .value = Reg{3}, .is_load = true};
        auto ins = marshal(m, 0).at(0);
        EbpfInst expect{
            .opcode = gsl::narrow<uint8_t>(INST_CLS_LD | INST_MODE_MEM | width_to_opcode(1) | 0x1),
            .dst = 3,
            .src = 4,
            .offset = 6,
            .imm = 0,
        };
        REQUIRE(ins.dst == expect.dst);
        REQUIRE(ins.src == expect.src);
        REQUIRE(ins.offset == expect.offset);
        REQUIRE(ins.imm == expect.imm);
        REQUIRE(ins.opcode == expect.opcode);
    }
    SECTION("Load Imm") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        REQUIRE_THROWS(marshal(Mem{.access = access, .value = Imm{3}, .is_load = true}, 0));
    }
    SECTION("Store") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        auto ins = marshal(Mem{.access = access, .value = Reg{3}, .is_load = false}, 0).at(0);
        REQUIRE(ins.src == 3);
        REQUIRE(ins.dst == 4);
        REQUIRE(ins.offset == 6);
        REQUIRE(ins.imm == 0);
        REQUIRE(ins.opcode == (uint8_t)(INST_CLS_ST | INST_MODE_MEM | width_to_opcode(1) | 0x1));
    }
    SECTION("StoreImm") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        auto ins = marshal(Mem{.access = access, .value = Imm{3}, .is_load = false}, 0).at(0);
        REQUIRE(ins.src == 0);
        REQUIRE(ins.dst == 4);
        REQUIRE(ins.offset == 6);
        REQUIRE(ins.imm == 3);
        REQUIRE(ins.opcode == (uint8_t)(INST_CLS_ST | INST_MODE_MEM | width_to_opcode(1) | 0x0));
    }
}

TEST_CASE("disasm_marshal_Mem", "[disasm][marshal]") {
    SECTION("Load") {
        for (const int w : ws) {
            Deref access;
            access.basereg = Reg{4};
            access.offset = 6;
            access.width = w;
            compare_marshal_unmarshal(Mem{.access = access, .value = Reg{3}, .is_load = true});
        }
    }
    SECTION("Load R10") {
        Deref access;
        access.basereg = Reg{0};
        access.offset = 0;
        access.width = 8;
        check_marshal_unmarshal_fail(Mem{.access = access, .value = Reg{10}, .is_load = true},
                                     "0: cannot modify r10\n");
    }
    SECTION("Store Register") {
        for (const int w : ws) {
            Deref access;
            access.basereg = Reg{9};
            access.offset = 8;
            access.width = w;
            compare_marshal_unmarshal(Mem{.access = access, .value = Reg{4}, .is_load = false});
        }
    }
    SECTION("Store Immediate") {
        for (const int w : ws) {
            Deref access;
            access.basereg = Reg{10};
            access.offset = 2;
            access.width = w;
            compare_marshal_unmarshal(Mem{.access = access, .value = Imm{5}, .is_load = false});
        }
    }
}

TEST_CASE("unmarshal extension opcodes", "[disasm][marshal]") {
    // Merge (rX <<= 32; rX >>>= 32) into wX = rX.
    compare_unmarshal_marshal(EbpfInst{.opcode = INST_ALU_OP_LSH | INST_SRC_IMM | INST_CLS_ALU64, .dst = 1, .imm = 32},
                              EbpfInst{.opcode = INST_ALU_OP_RSH | INST_SRC_IMM | INST_CLS_ALU64, .dst = 1, .imm = 32},
                              EbpfInst{.opcode = INST_ALU_OP_MOV | INST_SRC_REG | INST_CLS_ALU, .dst = 1, .src = 1});

    // Merge (rX <<= 32; rX >>= 32)  into rX s32= rX.
    compare_unmarshal_marshal(
        EbpfInst{.opcode = INST_ALU_OP_LSH | INST_SRC_IMM | INST_CLS_ALU64, .dst = 1, .imm = 32},
        EbpfInst{.opcode = INST_ALU_OP_ARSH | INST_SRC_IMM | INST_CLS_ALU64, .dst = 1, .imm = 32},
        EbpfInst{.opcode = INST_ALU_OP_MOV | INST_SRC_REG | INST_CLS_ALU64, .dst = 1, .src = 1, .offset = 32});
}

// Check that unmarshaling an invalid instruction fails with a given message.
static void check_unmarshal_instruction_fail(EbpfInst& inst, const std::string& message,
                                             const ebpf_platform_t& platform = g_ebpf_platform_linux) {
    if (inst.offset == JMP_OFFSET) {
        inst.offset = 1;
        check_unmarshal_fail_goto(inst, message);
    } else if (inst.opcode == INST_OP_LDDW_IMM) {
        check_unmarshal_fail(inst, EbpfInst{}, message, platform);
    } else {
        check_unmarshal_fail(inst, message, platform);
    }
}

static ebpf_platform_t get_template_platform(const EbpfInstructionTemplate& previous_template) {
    ebpf_platform_t platform = g_ebpf_platform_linux;
    platform.supported_conformance_groups |= previous_template.groups;
    return platform;
}

// Check whether an instruction matches an instruction template that may have wildcards.
static bool matches_template_inst(const EbpfInst inst, const EbpfInst template_inst) {
    if (inst.opcode != template_inst.opcode) {
        return false;
    }
    if (inst.dst != template_inst.dst && template_inst.dst != DST) {
        return false;
    }
    if (inst.src != template_inst.src && template_inst.src != SRC) {
        return false;
    }
    if (inst.offset != template_inst.offset && template_inst.offset != MEM_OFFSET &&
        template_inst.offset != JMP_OFFSET) {
        return false;
    }
    if (inst.imm != template_inst.imm && template_inst.imm != IMM && template_inst.imm != JMP_OFFSET) {
        return false;
    }
    return true;
}

// Check that various 'dst' variations between two valid instruction templates fail.
static void check_instruction_dst_variations(const EbpfInstructionTemplate& previous_template,
                                             const std::optional<const EbpfInstructionTemplate> next_template) {
    EbpfInst inst = previous_template.inst;
    const ebpf_platform_t platform = get_template_platform(previous_template);
    if (inst.dst == DST) {
        inst.dst = INVALID_REGISTER;
        check_unmarshal_instruction_fail(inst, "0: bad register\n", platform);
    } else {
        // This instruction doesn't put a register number in the 'dst' field.
        // Just try the next value unless that's what the next template has.
        inst.dst++;
        if (!next_template || !matches_template_inst(inst, next_template->inst)) {
            std::ostringstream oss;
            if (inst.dst == 1) {
                oss << "0: nonzero dst for register op 0x" << std::hex << static_cast<int>(inst.opcode) << std::endl;
            } else {
                oss << "0: bad instruction op 0x" << std::hex << static_cast<int>(inst.opcode) << std::endl;
            }
            check_unmarshal_instruction_fail(inst, oss.str(), platform);
        }
    }
}

// Check that various 'src' variations between two valid instruction templates fail.
static void check_instruction_src_variations(const EbpfInstructionTemplate& previous_template,
                                             const std::optional<const EbpfInstructionTemplate> next_template) {
    EbpfInst inst = previous_template.inst;
    const ebpf_platform_t platform = get_template_platform(previous_template);
    if (inst.src == SRC) {
        inst.src = INVALID_REGISTER;
        check_unmarshal_instruction_fail(inst, "0: bad register\n", platform);
    } else {
        // This instruction doesn't put a register number in the 'src' field.
        // Just try the next value unless that's what the next template has.
        inst.src++;
        if (!next_template || !matches_template_inst(inst, next_template->inst)) {
            std::ostringstream oss;
            oss << "0: bad instruction op 0x" << std::hex << static_cast<int>(inst.opcode) << std::endl;
            check_unmarshal_instruction_fail(inst, oss.str(), platform);
        }
    }
}

// Check that various 'offset' variations between two valid instruction templates fail.
static void check_instruction_offset_variations(const EbpfInstructionTemplate& previous_template,
                                                const std::optional<const EbpfInstructionTemplate> next_template) {
    EbpfInst inst = previous_template.inst;
    const ebpf_platform_t platform = get_template_platform(previous_template);
    if (inst.offset == JMP_OFFSET) {
        inst.offset = 0; // Not a valid jump offset.
        check_unmarshal_instruction_fail(inst, "0: jump out of bounds\n", platform);
    } else if (inst.offset != MEM_OFFSET) {
        // This instruction limits what can appear in the 'offset' field.
        // Just try the next value unless that's what the next template has.
        inst.offset++;
        if (!next_template || !matches_template_inst(inst, next_template->inst)) {
            std::ostringstream oss;
            if (inst.offset == 1 &&
                (!next_template || next_template->inst.opcode != inst.opcode || next_template->inst.offset == 0)) {
                oss << "0: nonzero offset for op 0x" << std::hex << static_cast<int>(inst.opcode) << std::endl;
            } else {
                oss << "0: invalid offset for op 0x" << std::hex << static_cast<int>(inst.opcode) << std::endl;
            }
            check_unmarshal_instruction_fail(inst, oss.str(), platform);
        }
    }
}

// Check that various 'imm' variations between two valid instruction templates fail.
static void check_instruction_imm_variations(const EbpfInstructionTemplate& previous_template,
                                             const std::optional<const EbpfInstructionTemplate> next_template) {
    EbpfInst inst = previous_template.inst;
    const ebpf_platform_t platform = get_template_platform(previous_template);
    if (inst.imm == JMP_OFFSET) {
        inst.imm = 0; // Not a valid jump offset.
        check_unmarshal_instruction_fail(inst, "0: jump out of bounds\n", platform);
    } else if (inst.imm != IMM && inst.imm != HELPER_ID) {
        // This instruction limits what can appear in the 'imm' field.
        // Just try the next value unless that's what the next template has.
        inst.imm++;
        if (!next_template || !matches_template_inst(inst, next_template->inst)) {
            std::ostringstream oss;
            if (inst.imm == 1) {
                oss << "0: nonzero imm for op 0x" << std::hex << static_cast<int>(inst.opcode) << std::endl;
            } else {
                oss << "0: unsupported immediate" << std::endl;
            }
            check_unmarshal_instruction_fail(inst, oss.str(), platform);
        }
    }

    // Some instructions only permit non-zero imm values.
    // If the next template is for one of those, check the zero value now.
    if (next_template && (previous_template.inst.opcode != next_template->inst.opcode) &&
        (next_template->inst.imm > 0) && (next_template->inst.imm != HELPER_ID) &&
        (next_template->inst.imm != JMP_OFFSET)) {
        inst = next_template->inst;
        inst.imm = 0;
        check_unmarshal_instruction_fail(inst, "0: unsupported immediate\n");
    }
}

// Check that various variations between two valid instruction templates fail.
static void check_instruction_variations(const std::optional<const EbpfInstructionTemplate> previous_template,
                                         const std::optional<const EbpfInstructionTemplate> next_template) {
    if (previous_template) {
        check_instruction_dst_variations(*previous_template, next_template);
        check_instruction_src_variations(*previous_template, next_template);
        check_instruction_offset_variations(*previous_template, next_template);
        check_instruction_imm_variations(*previous_template, next_template);
    }

    // Check any invalid opcodes in between the previous and next templates.
    const int previous_opcode = previous_template ? previous_template->inst.opcode : -1;
    const int next_opcode = next_template ? next_template->inst.opcode : 0x100;
    for (int opcode = previous_opcode + 1; opcode < next_opcode; opcode++) {
        const EbpfInst inst{.opcode = static_cast<uint8_t>(opcode)};
        std::ostringstream oss;
        oss << "0: bad instruction op 0x" << std::hex << opcode << std::endl;
        check_unmarshal_fail(inst, oss.str());
    }
}

TEST_CASE("fail unmarshal bad instructions", "[disasm][marshal]") {
    constexpr size_t template_count = std::size(instruction_template);

    // Check any variations before the first template.
    check_instruction_variations({}, instruction_template[0]);

    for (size_t index = 1; index < template_count; index++) {
        check_instruction_variations(instruction_template[index - 1], instruction_template[index]);
    }

    // Check any remaining variations after the last template.
    check_instruction_variations(instruction_template[template_count - 1], {});
}

TEST_CASE("check unmarshal conformance groups", "[disasm][marshal]") {
    for (const auto& current : instruction_template) {
        // Try unmarshaling without support. Decoding should still succeed; rejection happens later.
        ebpf_platform_t platform = g_ebpf_platform_linux;
        platform.supported_conformance_groups &= ~current.groups;
        EbpfInst without_support = current.inst;
        if (without_support.offset == JMP_OFFSET) {
            without_support.offset = 1;
        }
        if (without_support.imm == JMP_OFFSET) {
            without_support.imm = 1;
        }
        if (without_support.opcode == INST_OP_LDDW_IMM) {
            check_unmarshal_succeed(without_support, EbpfInst{}, platform);
        } else {
            check_unmarshal_succeed(without_support, platform);
        }

        // Try unmarshaling with support.
        platform.supported_conformance_groups |= current.groups;
        EbpfInst inst = current.inst;
        if (inst.offset == JMP_OFFSET) {
            inst.offset = 1;
        }
        if (inst.imm == JMP_OFFSET) {
            inst.imm = 1;
        }
        if (inst.opcode == INST_OP_LDDW_IMM) {
            check_unmarshal_succeed(inst, EbpfInst{}, platform);
        } else {
            check_unmarshal_succeed(inst, platform);
        }
    }
}

TEST_CASE("check unmarshal legacy opcodes", "[disasm][marshal]") {
    // The following opcodes are deprecated and should no longer be used.
    static uint8_t supported_legacy_opcodes[] = {0x20, 0x28, 0x30, 0x40, 0x48, 0x50};
    for (const uint8_t opcode : supported_legacy_opcodes) {
        compare_unmarshal_marshal(EbpfInst{.opcode = opcode}, EbpfInst{.opcode = opcode});
    }

    // Disable legacy packet instruction support. Decoding should still succeed.
    ebpf_platform_t platform = g_ebpf_platform_linux;
    platform.supported_conformance_groups &= ~bpf_conformance_groups_t::packet;
    for (const uint8_t opcode : supported_legacy_opcodes) {
        check_unmarshal_succeed(EbpfInst{.opcode = opcode}, platform);
    }
}

TEST_CASE("unmarshal 64bit immediate", "[disasm][marshal]") {
    compare_unmarshal_marshal(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 0, .imm = 1}, EbpfInst{.imm = 2},
                              EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 0, .imm = 1}, EbpfInst{.imm = 2});
    compare_unmarshal_marshal(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 0, .imm = 1}, EbpfInst{},
                              EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 0, .imm = 1}, EbpfInst{});

    for (uint8_t src = 0; src <= 7; src++) {
        check_unmarshal_fail(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = src}, "0: incomplete lddw\n");
        check_unmarshal_fail(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = src},
                             EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM}, "0: invalid lddw\n");
    }

    // For mode-specific LDDW encodings, next_imm is reserved for src={1,3,4,5}.
    // src=2 (map_value) and src=6 (map_value_by_idx) carry payload in next_imm.
    check_unmarshal_fail(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 1}, EbpfInst{.imm = 1},
                         "0: lddw uses reserved fields\n");
    check_unmarshal_fail(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 3}, EbpfInst{.imm = 1},
                         "0: lddw uses reserved fields\n");
    check_unmarshal_fail(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 4}, EbpfInst{.imm = 1},
                         "0: lddw uses reserved fields\n");
    check_unmarshal_fail(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 5}, EbpfInst{.imm = 1},
                         "0: lddw uses reserved fields\n");

    compare_unmarshal_marshal(
        EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 2, .imm = 7}, EbpfInst{.imm = 11},
        EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 2, .imm = 7}, EbpfInst{.imm = 11});
    compare_unmarshal_marshal(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 2, .imm = 7}, EbpfInst{},
                              EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 2, .imm = 7},
                              EbpfInst{});

    compare_unmarshal_marshal(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 3, .imm = 7}, EbpfInst{},
                              EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 3, .imm = 7},
                              EbpfInst{});
    compare_unmarshal_marshal(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 4, .imm = 7}, EbpfInst{},
                              EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 4, .imm = 7},
                              EbpfInst{});
    compare_unmarshal_marshal(EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 5, .imm = 7}, EbpfInst{},
                              EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 5, .imm = 7},
                              EbpfInst{});
    compare_unmarshal_marshal(
        EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 6, .imm = 7}, EbpfInst{.imm = 11},
        EbpfInst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .dst = 1, .src = 6, .imm = 7}, EbpfInst{.imm = 11});
}

TEST_CASE("unmarshal call-btf-id", "[disasm][marshal]") {
    compare_unmarshal_marshal(EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 17},
                              EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 17});
}

TEST_CASE("unmarshal builtin calls only when relocation-gated", "[disasm][marshal]") {
    REQUIRE(g_ebpf_platform_linux.resolve_builtin_call != nullptr);
    const auto memset_id = g_ebpf_platform_linux.resolve_builtin_call("memset");
    REQUIRE(memset_id.has_value());

    const EbpfInst call_memset{
        .opcode = INST_OP_CALL,
        .src = INST_CALL_STATIC_HELPER,
        .imm = *memset_id,
    };

    const EbpfProgramType type = g_ebpf_platform_linux.get_program_type("unspec", "");
    ProgramInfo info{.platform = &g_ebpf_platform_linux, .type = type};

    const Call ungated = unmarshal_single_call(call_memset, info);
    REQUIRE_FALSE(ungated.is_supported);
    REQUIRE(ungated.unsupported_reason == "helper function is unavailable on this platform");

    info.builtin_call_offsets.insert(0);
    const Call gated = unmarshal_single_call(call_memset, info);
    REQUIRE(gated.is_supported);
    REQUIRE(gated.name == "memset");
    REQUIRE(gated.func == *memset_id);
    REQUIRE(gated.singles.size() == 1);
    REQUIRE(gated.pairs.size() == 1);
    REQUIRE(gated.singles[0] == ArgSingle{ArgSingle::Kind::ANYTHING, false, Reg{2}});
    REQUIRE(gated.pairs[0] == ArgPair{ArgPair::Kind::PTR_TO_WRITABLE_MEM, false, Reg{1}, Reg{3}, false});

    const auto assertions = get_assertions(gated, info, Label{0});
    REQUIRE(has_assertion(assertions, TypeConstraint{Reg{1}, TypeGroup::mem}));
    REQUIRE(has_assertion(assertions, TypeConstraint{Reg{2}, TypeGroup::number}));
    REQUIRE(has_assertion(assertions, TypeConstraint{Reg{3}, TypeGroup::number}));
    REQUIRE(has_assertion(assertions, ValidSize{Reg{3}, false}));
    REQUIRE(has_assertion(assertions, ValidAccess{1, Reg{1}, 0, Value{Reg{3}}, false, AccessType::write}));
}
#define FAIL_UNMARSHAL(dirname, filename, sectionname)                                                       \
    TEST_CASE("Try unmarshalling bad program: " dirname "/" filename " " sectionname, "[unmarshal]") {       \
        thread_local_options = {};                                                                           \
        ElfObject elf{"ebpf-samples/" dirname "/" filename, {}, &g_ebpf_platform_linux};                     \
        const auto& raw_progs = elf.get_programs(sectionname);                                               \
        REQUIRE(raw_progs.size() == 1);                                                                      \
        const RawProgram& raw_prog = raw_progs.back();                                                       \
        std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog, thread_local_options); \
        REQUIRE(std::holds_alternative<std::string>(prog_or_error));                                         \
    }

// Some intentional unmarshal failures
FAIL_UNMARSHAL("invalid", "invalid-lddw.o", ".text")

TEST_CASE("instruction feature handling after unmarshal", "[unmarshal]") {
    constexpr EbpfInst exit{.opcode = INST_OP_EXIT};
    ebpf_platform_t platform = g_ebpf_platform_linux;
    ProgramInfo info{.platform = &platform, .type = platform.get_program_type("unspec", "unspec")};

    SECTION("unknown kfunc btf id") {
        RawProgram raw_prog{
            "", "", 0, "", {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1}, exit}, info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        REQUIRE_THROWS_WITH(
            Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {}),
            Catch::Matchers::ContainsSubstring("not implemented: kfunc prototype lookup failed for BTF id 1") &&
                Catch::Matchers::ContainsSubstring("(at 0)"));
    }

    SECTION("kfunc call by BTF id is accepted when prototype is known") {
        RawProgram raw_prog{
            "", "", 0, "", {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1000}, exit}, info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        const Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {});
        REQUIRE(verify(prog));
    }

    SECTION("kfunc call in local subprogram does not use helper prototype lookup") {
        RawProgram raw_prog{"",
                            "",
                            0,
                            "",
                            {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_LOCAL, .imm = 1}, exit,
                             EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1000}, exit},
                            info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        const Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {});
        REQUIRE(verify(prog));
    }

    SECTION("kfunc in subprogram is not misclassified when BTF id overlaps helper id") {
        RawProgram raw_prog{"",
                            "",
                            0,
                            "",
                            {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_LOCAL, .imm = 1}, exit,
                             EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 12}, exit},
                            info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        const Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {});
        REQUIRE(verify(prog));
    }

    SECTION("kfunc map-value return is lowered to map-lookup call contract") {
        constexpr uint8_t mov64_imm = INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_IMM;
        RawProgram raw_prog{"",
                            "",
                            0,
                            "",
                            {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1005},
                             EbpfInst{.opcode = mov64_imm, .dst = 0, .imm = 0}, exit},
                            info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        const Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {});
        const auto* call = std::get_if<Call>(&prog.instruction_at(Label{0}));
        REQUIRE(call != nullptr);
        REQUIRE(call->is_map_lookup);
        REQUIRE(verify(prog));
    }

    SECTION("kfunc with acquire flag is accepted") {
        RawProgram raw_prog{
            "", "", 0, "", {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1002}, exit}, info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        const Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {});
        const auto* call = std::get_if<Call>(&prog.instruction_at(Label{0}));
        REQUIRE(call != nullptr);
        REQUIRE(call->name == "kfunc_test_acquire_flag");
    }

    SECTION("kfunc with release flag is rejected") {
        RawProgram raw_prog{
            "", "", 0, "", {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1008}, exit}, info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        REQUIRE_THROWS_WITH(Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {}),
                            Catch::Matchers::ContainsSubstring("not implemented: kfunc has unsupported flags") &&
                                Catch::Matchers::ContainsSubstring("(at 0)"));
    }

    SECTION("kfunc program type gating is enforced") {
        RawProgram raw_prog{
            "", "", 0, "", {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1003}, exit}, info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        REQUIRE_THROWS_WITH(
            Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {}),
            Catch::Matchers::ContainsSubstring("not implemented: kfunc is unavailable for program type") &&
                Catch::Matchers::ContainsSubstring("(at 0)"));

        ProgramInfo xdp_info{.platform = &platform, .type = platform.get_program_type("xdp", "xdp")};
        RawProgram xdp_raw_prog{
            "",      "", 0, "", {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1003}, exit},
            xdp_info};
        auto xdp_prog_or_error = unmarshal(xdp_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(xdp_prog_or_error));
        const Program xdp_prog = Program::from_sequence(std::get<InstructionSeq>(xdp_prog_or_error), xdp_info, {});
        REQUIRE(verify(xdp_prog));
    }

    SECTION("kfunc privileged gating is enforced") {
        RawProgram raw_prog{
            "", "", 0, "", {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1004}, exit}, info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        REQUIRE_THROWS_WITH(
            Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {}),
            Catch::Matchers::ContainsSubstring("not implemented: kfunc requires privileged program type") &&
                Catch::Matchers::ContainsSubstring("(at 0)"));

        ProgramInfo kprobe_info{
            .platform = &platform,
            .type = platform.get_program_type("kprobe/test_prog", ""),
        };
        RawProgram kprobe_raw_prog{
            "",         "", 0, "", {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1004}, exit},
            kprobe_info};
        auto kprobe_prog_or_error = unmarshal(kprobe_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(kprobe_prog_or_error));
        const Program kprobe_prog =
            Program::from_sequence(std::get<InstructionSeq>(kprobe_prog_or_error), kprobe_info, {});
        REQUIRE(verify(kprobe_prog));
    }

    SECTION("kfunc argument typing is enforced from prototype table") {
        constexpr uint8_t mov64_imm = INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_IMM;

        RawProgram good_raw_prog{
            "", "", 0, "", {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1001}, exit}, info};
        auto good_prog_or_error = unmarshal(good_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(good_prog_or_error));
        const Program good_prog = Program::from_sequence(std::get<InstructionSeq>(good_prog_or_error), info, {});
        REQUIRE(verify(good_prog));

        RawProgram bad_raw_prog{"",
                                "",
                                0,
                                "",
                                {EbpfInst{.opcode = mov64_imm, .dst = 1, .imm = 0},
                                 EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1001}, exit},
                                info};
        auto bad_prog_or_error = unmarshal(bad_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(bad_prog_or_error));
        const Program bad_prog = Program::from_sequence(std::get<InstructionSeq>(bad_prog_or_error), info, {});
        REQUIRE_FALSE(verify(bad_prog));
    }

    SECTION("kfunc pointer-size argument pairs enforce null and size constraints") {
        constexpr uint8_t mov64_imm = INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_IMM;

        RawProgram good_raw_prog{"",
                                 "",
                                 0,
                                 "",
                                 {EbpfInst{.opcode = mov64_imm, .dst = 1, .imm = 0},
                                  EbpfInst{.opcode = mov64_imm, .dst = 2, .imm = 0},
                                  EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1006}, exit},
                                 info};
        auto good_prog_or_error = unmarshal(good_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(good_prog_or_error));
        const Program good_prog = Program::from_sequence(std::get<InstructionSeq>(good_prog_or_error), info, {});
        REQUIRE(verify(good_prog));

        RawProgram bad_size_raw_prog{"",
                                     "",
                                     0,
                                     "",
                                     {EbpfInst{.opcode = mov64_imm, .dst = 1, .imm = 0},
                                      EbpfInst{.opcode = mov64_imm, .dst = 2, .imm = -1},
                                      EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1006}, exit},
                                     info};
        auto bad_size_prog_or_error = unmarshal(bad_size_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(bad_size_prog_or_error));
        const Program bad_size_prog =
            Program::from_sequence(std::get<InstructionSeq>(bad_size_prog_or_error), info, {});
        REQUIRE_FALSE(verify(bad_size_prog));

        RawProgram bad_nullability_raw_prog{
            "",
            "",
            0,
            "",
            {EbpfInst{.opcode = mov64_imm, .dst = 1, .imm = 1}, EbpfInst{.opcode = mov64_imm, .dst = 2, .imm = 0},
             EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1006}, exit},
            info};
        auto bad_nullability_prog_or_error = unmarshal(bad_nullability_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(bad_nullability_prog_or_error));
        const Program bad_nullability_prog =
            Program::from_sequence(std::get<InstructionSeq>(bad_nullability_prog_or_error), info, {});
        REQUIRE_FALSE(verify(bad_nullability_prog));
    }

    SECTION("kfunc writable-memory argument pairs enforce writeability and strict size") {
        constexpr uint8_t mov64_imm = INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_IMM;
        constexpr uint8_t mov64_reg = INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_REG;
        constexpr uint8_t add64_imm = INST_CLS_ALU64 | INST_ALU_OP_ADD | INST_SRC_IMM;

        RawProgram good_raw_prog{"",
                                 "",
                                 0,
                                 "",
                                 {EbpfInst{.opcode = mov64_reg, .dst = 1, .src = R10_STACK_POINTER},
                                  EbpfInst{.opcode = add64_imm, .dst = 1, .imm = -8},
                                  EbpfInst{.opcode = mov64_imm, .dst = 2, .imm = 4},
                                  EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1007}, exit},
                                 info};
        auto good_prog_or_error = unmarshal(good_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(good_prog_or_error));
        const Program good_prog = Program::from_sequence(std::get<InstructionSeq>(good_prog_or_error), info, {});
        REQUIRE(verify(good_prog));

        RawProgram bad_nullability_raw_prog{
            "",
            "",
            0,
            "",
            {EbpfInst{.opcode = mov64_imm, .dst = 1, .imm = 0}, EbpfInst{.opcode = mov64_imm, .dst = 2, .imm = 4},
             EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1007}, exit},
            info};
        auto bad_nullability_prog_or_error = unmarshal(bad_nullability_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(bad_nullability_prog_or_error));
        const Program bad_nullability_prog =
            Program::from_sequence(std::get<InstructionSeq>(bad_nullability_prog_or_error), info, {});
        REQUIRE_FALSE(verify(bad_nullability_prog));

        RawProgram bad_size_raw_prog{"",
                                     "",
                                     0,
                                     "",
                                     {EbpfInst{.opcode = mov64_reg, .dst = 1, .src = R10_STACK_POINTER},
                                      EbpfInst{.opcode = add64_imm, .dst = 1, .imm = -8},
                                      EbpfInst{.opcode = mov64_imm, .dst = 2, .imm = 0},
                                      EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1007}, exit},
                                     info};
        auto bad_size_prog_or_error = unmarshal(bad_size_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(bad_size_prog_or_error));
        const Program bad_size_prog =
            Program::from_sequence(std::get<InstructionSeq>(bad_size_prog_or_error), info, {});
        REQUIRE_FALSE(verify(bad_size_prog));
    }

    SECTION("lddw variable_addr pseudo") {
        RawProgram raw_prog{
            "",  "", 0, "", {EbpfInst{.opcode = INST_OP_LDDW_IMM, .dst = 1, .src = 3, .imm = 7}, EbpfInst{}, exit},
            info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        const Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {});
        const auto* bin = std::get_if<Bin>(&prog.instruction_at(Label{0}));
        REQUIRE(bin != nullptr);
        REQUIRE(bin->op == Bin::Op::MOV);
        REQUIRE(bin->is64);
        REQUIRE(bin->lddw);
        REQUIRE(bin->dst == Reg{1});
        const auto* imm = std::get_if<Imm>(&bin->v);
        REQUIRE(imm != nullptr);
        REQUIRE(imm->v == 7ULL);
    }

    SECTION("lddw code_addr pseudo via INST_LD_MODE_CODE_ADDR") {
        RawProgram raw_prog{
            "",  "", 0, "", {EbpfInst{.opcode = INST_OP_LDDW_IMM, .dst = 2, .src = 4, .imm = 11}, EbpfInst{}, exit},
            info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        const Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {});
        const auto* pseudo = std::get_if<LoadPseudo>(&prog.instruction_at(Label{0}));
        REQUIRE(pseudo != nullptr);
        REQUIRE(pseudo->dst == Reg{2});
        REQUIRE(pseudo->addr.kind == PseudoAddress::Kind::CODE_ADDR);
        REQUIRE(pseudo->addr.imm == 11);
    }

    SECTION("lddw immediate merges high and low words") {
        RawProgram raw_prog{
            "",
            "",
            0,
            "",
            {EbpfInst{.opcode = INST_OP_LDDW_IMM, .dst = 3, .src = 0, .imm = 1}, EbpfInst{.imm = 2}, exit},
            info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        const Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {});
        const auto* bin = std::get_if<Bin>(&prog.instruction_at(Label{0}));
        REQUIRE(bin != nullptr);
        REQUIRE(bin->op == Bin::Op::MOV);
        REQUIRE(bin->is64);
        REQUIRE(bin->lddw);
        REQUIRE(bin->dst == Reg{3});
        const auto* imm = std::get_if<Imm>(&bin->v);
        REQUIRE(imm != nullptr);
        REQUIRE(imm->v == ((2ULL << 32) | 1ULL));
    }

    SECTION("lddw immediate does not sign-extend low word") {
        RawProgram raw_prog{
            "",
            "",
            0,
            "",
            {EbpfInst{.opcode = INST_OP_LDDW_IMM, .dst = 3, .src = 0, .imm = -1}, EbpfInst{.imm = 0}, exit},
            info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        const Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {});
        const auto* bin = std::get_if<Bin>(&prog.instruction_at(Label{0}));
        REQUIRE(bin != nullptr);
        REQUIRE(bin->op == Bin::Op::MOV);
        REQUIRE(bin->is64);
        REQUIRE(bin->lddw);
        REQUIRE(bin->dst == Reg{3});
        const auto* imm = std::get_if<Imm>(&bin->v);
        REQUIRE(imm != nullptr);
        REQUIRE(imm->v == 0x00000000FFFFFFFFULL);
    }

    SECTION("lddw code_addr pseudo") {
        RawProgram raw_prog{
            "",
            "",
            0,
            "",
            {EbpfInst{.opcode = INST_OP_LDDW_IMM, .dst = 2, .src = INST_LD_MODE_CODE_ADDR, .imm = 7}, EbpfInst{}, exit},
            info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        const Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {});
        const auto* pseudo = std::get_if<LoadPseudo>(&prog.instruction_at(Label{0}));
        REQUIRE(pseudo != nullptr);
        REQUIRE(pseudo->addr.kind == PseudoAddress::Kind::CODE_ADDR);
    }

    SECTION("helper ptr_to_func argument type is accepted for bpf_loop") {
        constexpr uint8_t mov64_imm = INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_IMM;
        RawProgram raw_prog{
            "",
            "",
            0,
            "",
            {EbpfInst{.opcode = INST_OP_LDDW_IMM, .dst = 2, .src = INST_LD_MODE_CODE_ADDR, .imm = 1}, EbpfInst{},
             EbpfInst{.opcode = mov64_imm, .dst = 1, .imm = 1}, EbpfInst{.opcode = mov64_imm, .dst = 3, .imm = 0},
             EbpfInst{.opcode = mov64_imm, .dst = 4, .imm = 0}, EbpfInst{.opcode = INST_OP_CALL, .imm = 181}, exit},
            info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        const Program prog = Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {});
        const auto* call = std::get_if<Call>(&prog.instruction_at(Label{5}));
        REQUIRE(call != nullptr);
        REQUIRE(call->is_supported);
        REQUIRE(std::ranges::any_of(call->singles, [](const ArgSingle& arg) {
            return arg.kind == ArgSingle::Kind::PTR_TO_FUNC && arg.reg == Reg{2};
        }));
    }

    SECTION("ptr_to_func argument enforces function type") {
        constexpr uint8_t mov64_imm = INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_IMM;
        RawProgram good_raw_prog{
            "",
            "",
            0,
            "",
            {EbpfInst{.opcode = INST_OP_LDDW_IMM, .dst = 2, .src = INST_LD_MODE_CODE_ADDR, .imm = 7}, EbpfInst{},
             EbpfInst{.opcode = mov64_imm, .dst = 1, .imm = 1}, EbpfInst{.opcode = mov64_imm, .dst = 3, .imm = 0},
             EbpfInst{.opcode = mov64_imm, .dst = 4, .imm = 0}, EbpfInst{.opcode = INST_OP_CALL, .imm = 181}, exit,
             EbpfInst{.opcode = mov64_imm, .dst = 0, .imm = 0}, exit},
            info};
        auto good_prog_or_error = unmarshal(good_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(good_prog_or_error));
        const Program good_prog = Program::from_sequence(std::get<InstructionSeq>(good_prog_or_error), info, {});
        REQUIRE(verify(good_prog));

        RawProgram bad_raw_prog{
            "",
            "",
            0,
            "",
            {EbpfInst{.opcode = mov64_imm, .dst = 2, .imm = 7}, EbpfInst{.opcode = mov64_imm, .dst = 1, .imm = 1},
             EbpfInst{.opcode = mov64_imm, .dst = 3, .imm = 0}, EbpfInst{.opcode = mov64_imm, .dst = 4, .imm = 0},
             EbpfInst{.opcode = INST_OP_CALL, .imm = 181}, exit},
            info};
        auto bad_prog_or_error = unmarshal(bad_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(bad_prog_or_error));
        const Program bad_prog = Program::from_sequence(std::get<InstructionSeq>(bad_prog_or_error), info, {});
        REQUIRE_FALSE(verify(bad_prog));
    }

    SECTION("ptr_to_func callback target must be a valid instruction label") {
        constexpr uint8_t mov64_imm = INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_IMM;
        RawProgram good_raw_prog{
            "",
            "",
            0,
            "",
            {EbpfInst{.opcode = INST_OP_LDDW_IMM, .dst = 2, .src = INST_LD_MODE_CODE_ADDR, .imm = 7}, EbpfInst{},
             EbpfInst{.opcode = mov64_imm, .dst = 1, .imm = 1}, EbpfInst{.opcode = mov64_imm, .dst = 3, .imm = 0},
             EbpfInst{.opcode = mov64_imm, .dst = 4, .imm = 0}, EbpfInst{.opcode = INST_OP_CALL, .imm = 181}, exit,
             EbpfInst{.opcode = mov64_imm, .dst = 0, .imm = 0}, exit},
            info};
        auto good_prog_or_error = unmarshal(good_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(good_prog_or_error));
        const Program good_prog = Program::from_sequence(std::get<InstructionSeq>(good_prog_or_error), info, {});
        REQUIRE(verify(good_prog));

        RawProgram bad_raw_prog{
            "",
            "",
            0,
            "",
            {EbpfInst{.opcode = INST_OP_LDDW_IMM, .dst = 2, .src = INST_LD_MODE_CODE_ADDR, .imm = 1}, EbpfInst{},
             EbpfInst{.opcode = mov64_imm, .dst = 1, .imm = 1}, EbpfInst{.opcode = mov64_imm, .dst = 3, .imm = 0},
             EbpfInst{.opcode = mov64_imm, .dst = 4, .imm = 0}, EbpfInst{.opcode = INST_OP_CALL, .imm = 181}, exit,
             EbpfInst{.opcode = mov64_imm, .dst = 0, .imm = 0}, exit},
            info};
        auto bad_prog_or_error = unmarshal(bad_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(bad_prog_or_error));
        const Program bad_prog = Program::from_sequence(std::get<InstructionSeq>(bad_prog_or_error), info, {});
        REQUIRE_FALSE(verify(bad_prog));
    }

    SECTION("ptr_to_func callback target must have reachable exit") {
        constexpr uint8_t mov64_imm = INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_IMM;
        RawProgram bad_raw_prog{
            "",
            "",
            0,
            "",
            {EbpfInst{.opcode = INST_OP_LDDW_IMM, .dst = 2, .src = INST_LD_MODE_CODE_ADDR, .imm = 7}, EbpfInst{},
             EbpfInst{.opcode = mov64_imm, .dst = 1, .imm = 1}, EbpfInst{.opcode = mov64_imm, .dst = 3, .imm = 0},
             EbpfInst{.opcode = mov64_imm, .dst = 4, .imm = 0}, EbpfInst{.opcode = INST_OP_CALL, .imm = 181}, exit,
             EbpfInst{.opcode = INST_OP_JA16, .offset = -1}},
            info};
        auto bad_prog_or_error = unmarshal(bad_raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(bad_prog_or_error));
        const Program bad_prog = Program::from_sequence(std::get<InstructionSeq>(bad_prog_or_error), info, {});
        REQUIRE_FALSE(verify(bad_prog));
    }

    SECTION("helper id not usable on platform") {
        RawProgram raw_prog{"", "", 0, "", {EbpfInst{.opcode = INST_OP_CALL, .imm = 0x7fff}, exit}, info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        REQUIRE_THROWS_WITH(
            Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {}),
            Catch::Matchers::ContainsSubstring("rejected: helper function is unavailable on this platform") &&
                Catch::Matchers::ContainsSubstring("(at 0)"));
    }

    SECTION("be64 requires base64 conformance group") {
        ebpf_platform_t p = g_ebpf_platform_linux;
        p.supported_conformance_groups &= ~bpf_conformance_groups_t::base64;
        ProgramInfo pinfo{.platform = &p, .type = p.get_program_type("unspec", "unspec")};
        RawProgram raw_prog{"",
                            "",
                            0,
                            "",
                            {EbpfInst{.opcode = static_cast<uint8_t>(INST_CLS_ALU | INST_ALU_OP_END | INST_END_BE),
                                      .dst = 1,
                                      .imm = 64},
                             exit},
                            pinfo};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        REQUIRE_THROWS_WITH(Program::from_sequence(std::get<InstructionSeq>(prog_or_error), pinfo, {}),
                            Catch::Matchers::ContainsSubstring("rejected: requires conformance group base64") &&
                                Catch::Matchers::ContainsSubstring("(at 0)"));
    }

    SECTION("call btf cannot use register-call opcode form") {
        RawProgram raw_prog{
            "",  "", 0, "", {EbpfInst{.opcode = INST_OP_CALLX, .dst = 0, .src = INST_CALL_BTF_HELPER, .imm = 1}, exit},
            info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<std::string>(prog_or_error));
        REQUIRE_THAT(std::get<std::string>(prog_or_error), Catch::Matchers::ContainsSubstring("bad instruction"));
    }

    SECTION("tail call chain depth above 33 is rejected") {
        std::vector<EbpfInst> insts;
        for (size_t i = 0; i < 34; i++) {
            insts.push_back(EbpfInst{.opcode = INST_OP_CALL, .imm = 12});
        }
        insts.push_back(exit);
        RawProgram raw_prog{"", "", 0, "", std::move(insts), info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        REQUIRE_THROWS_WITH(Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {}),
                            Catch::Matchers::ContainsSubstring("tail call chain depth exceeds 33") &&
                                Catch::Matchers::ContainsSubstring("(at"));
    }

    SECTION("tail call chain depth of exactly 33 is accepted") {
        std::vector<EbpfInst> insts;
        for (size_t i = 0; i < 33; i++) {
            insts.push_back(EbpfInst{.opcode = INST_OP_CALL, .imm = 12});
        }
        insts.push_back(exit);
        RawProgram raw_prog{"", "", 0, "", std::move(insts), info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        REQUIRE_NOTHROW(Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {}));
    }

    SECTION("tail call cycle does not inflate chain depth") {
        // No exit instruction is intentional; this checks SCC-based depth accounting, not termination.
        RawProgram raw_prog{"",
                            "",
                            0,
                            "",
                            {
                                EbpfInst{.opcode = INST_OP_CALL, .imm = 12},
                                EbpfInst{.opcode = INST_OP_JA16, .offset = -2},
                            },
                            info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        REQUIRE_NOTHROW(Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {}));
    }
}

#define TEST_LEGACY(dirname, filename, sectionname)                                                             \
    TEST_CASE("Unsupported instructions: " dirname "/" filename " " sectionname, "[unmarshal]") {               \
        ebpf_platform_t platform = g_ebpf_platform_linux;                                                       \
        platform.supported_conformance_groups &= ~bpf_conformance_groups_t::packet;                             \
        ElfObject elf{"ebpf-samples/" dirname "/" filename, {}, &platform};                                     \
        const auto& raw_progs = elf.get_programs(sectionname);                                                  \
        REQUIRE(raw_progs.size() == 1);                                                                         \
        RawProgram raw_prog = raw_progs.back();                                                                 \
        std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog, {});                      \
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));                                         \
        REQUIRE_THROWS_WITH(Program::from_sequence(std::get<InstructionSeq>(prog_or_error), raw_prog.info, {}), \
                            Catch::Matchers::ContainsSubstring("rejected: requires conformance group packet")); \
    }

TEST_LEGACY("bpf_cilium_test", "bpf_lxc_jit.o", "2/10")
TEST_LEGACY("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "from-container")
TEST_LEGACY("bpf_cilium_test", "bpf_overlay.o", "from-overlay")
TEST_LEGACY("cilium", "bpf_overlay.o", "from-overlay")
TEST_LEGACY("linux", "sockex1_kern.o", "socket1")
TEST_LEGACY("linux", "sockex2_kern.o", "socket2")
TEST_LEGACY("linux", "sockex3_kern.o", "socket/3")
TEST_LEGACY("linux", "sockex3_kern.o", "socket/4")
TEST_LEGACY("linux", "sockex3_kern.o", "socket/1")
TEST_LEGACY("linux", "sockex3_kern.o", "socket/2")
TEST_LEGACY("linux", "sockex3_kern.o", "socket/0")
TEST_LEGACY("linux", "tcbpf1_kern.o", "classifier")
TEST_LEGACY("ovs", "datapath.o", "tail-3")
TEST_LEGACY("ovs", "datapath.o", "tail-32")
TEST_LEGACY("suricata", "bypass_filter.o", "filter")
TEST_LEGACY("suricata", "lb.o", "loadbalancer")
TEST_LEGACY("cilium", "bpf_netdev.o", "from-netdev")
TEST_LEGACY("bpf_cilium_test", "bpf_netdev.o", "from-netdev")
TEST_LEGACY("cilium", "bpf_lxc.o", "2/10")

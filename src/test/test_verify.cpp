// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>
#include <cstddef>
#include <cstdint>
#include <elfio/elfio.hpp>
#include <ranges>
#include <thread>

#include "ebpf_verifier.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"

using namespace prevail;

namespace {
uint16_t read_le16(const char* data, size_t offset) {
    const auto* bytes = reinterpret_cast<const uint8_t*>(data + offset);
    return static_cast<uint16_t>(bytes[0] | (static_cast<uint16_t>(bytes[1]) << 8));
}

uint32_t read_le32(const char* data, size_t offset) {
    const auto* bytes = reinterpret_cast<const uint8_t*>(data + offset);
    return static_cast<uint32_t>(bytes[0] | (static_cast<uint32_t>(bytes[1]) << 8) |
                                 (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24));
}

bool has_nonempty_core_relo_subsection(const std::string& path) {
    // These offsets mirror btf_ext_header_core_t layout in src/elf_loader.cpp.
    constexpr size_t btf_magic_offset = 0;
    constexpr size_t btf_version_offset = 2;
    constexpr size_t btf_hdr_len_offset = 4;
    constexpr size_t btf_ext_header_min_len = 32;
    constexpr size_t btf_core_relo_off_offset = 24;
    constexpr size_t btf_core_relo_len_offset = 28;
    constexpr uint16_t btf_magic = 0xeB9F;
    constexpr uint8_t btf_version = 1;

    ELFIO::elfio reader;
    if (!reader.load(path)) {
        throw std::runtime_error("Failed to load ELF: " + path);
    }

    const auto* btf_ext = reader.sections[".BTF.ext"];
    if (!btf_ext || !btf_ext->get_data()) {
        return false;
    }

    const char* data = btf_ext->get_data();
    const size_t size = btf_ext->get_size();
    if (size < btf_ext_header_min_len) {
        return false;
    }

    if (read_le16(data, btf_magic_offset) != btf_magic || data[btf_version_offset] != btf_version) {
        return false;
    }

    const uint32_t hdr_len = read_le32(data, btf_hdr_len_offset);
    if (hdr_len < btf_ext_header_min_len || hdr_len > size) {
        return false;
    }

    const uint32_t core_relo_off = read_le32(data, btf_core_relo_off_offset);
    const uint32_t core_relo_len = read_le32(data, btf_core_relo_len_offset);
    if (core_relo_len == 0) {
        return false;
    }
    if (core_relo_off > size - hdr_len) {
        return false;
    }

    const size_t core_relo_start = hdr_len + core_relo_off;
    return core_relo_len <= size - core_relo_start;
}
} // namespace

#define FAIL_LOAD_ELF_BASE(test_name, dirname, filename, sectionname)                                    \
    TEST_CASE(test_name, "[elf]") {                                                                      \
        try {                                                                                            \
            thread_local_options = {};                                                                   \
            read_elf("ebpf-samples/" dirname "/" filename, sectionname, "", {}, &g_ebpf_platform_linux); \
            REQUIRE(false);                                                                              \
        } catch (const std::runtime_error&) {                                                            \
        }                                                                                                \
    }

#define FAIL_LOAD_ELF(dirname, filename, sectionname) \
    FAIL_LOAD_ELF_BASE("Try loading nonexisting program: " dirname "/" filename, dirname, filename, sectionname)

// Like FAIL_LOAD_ELF, but includes sectionname in the test name to avoid collisions
// when multiple sections of the same file fail to load.
#define FAIL_LOAD_ELF_SECTION(dirname, filename, sectionname) \
    FAIL_LOAD_ELF_BASE("Try loading bad section: " dirname "/" filename " " sectionname, dirname, filename, sectionname)

// Some intentional failures
FAIL_LOAD_ELF("cilium", "not-found.o", "2/1")
FAIL_LOAD_ELF("cilium", "bpf_lxc.o", "not-found")
FAIL_LOAD_ELF("build", "badrelo.o", ".text")
FAIL_LOAD_ELF("invalid", "badsymsize.o", "xdp_redirect_map")

TEST_CASE("CO-RE relocations are parsed from .BTF.ext core_relo subsection", "[elf][core]") {
    thread_local_options = {};
    constexpr auto fentry_path = "ebpf-samples/cilium-examples/tcprtt_bpf_bpfel.o";
    constexpr auto fentry_section = "fentry/tcp_close";
    REQUIRE(has_nonempty_core_relo_subsection(fentry_path));
    const auto fentry_progs = read_elf(fentry_path, fentry_section, "", {}, &g_ebpf_platform_linux);
    REQUIRE(fentry_progs.size() == 1);
    REQUIRE(fentry_progs[0].core_relocation_count > 0);

    constexpr auto sockops_path = "ebpf-samples/cilium-examples/tcprtt_sockops_bpf_bpfel.o";
    constexpr auto sockops_section = "sockops";
    REQUIRE(has_nonempty_core_relo_subsection(sockops_path));
    const auto sockops_progs = read_elf(sockops_path, sockops_section, "", {}, &g_ebpf_platform_linux);
    REQUIRE(sockops_progs.size() == 1);
    REQUIRE(sockops_progs[0].core_relocation_count > 0);
}

#define FAIL_UNMARSHAL(dirname, filename, sectionname)                                                                \
    TEST_CASE("Try unmarshalling bad program: " dirname "/" filename " " sectionname, "[unmarshal]") {                \
        thread_local_options = {};                                                                                    \
        auto raw_progs = read_elf("ebpf-samples/" dirname "/" filename, sectionname, "", {}, &g_ebpf_platform_linux); \
        REQUIRE(raw_progs.size() == 1);                                                                               \
        const RawProgram& raw_prog = raw_progs.back();                                                                \
        std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog, thread_local_options);          \
        REQUIRE(std::holds_alternative<std::string>(prog_or_error));                                                  \
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

    SECTION("kfunc with unsupported flags is rejected") {
        RawProgram raw_prog{
            "", "", 0, "", {EbpfInst{.opcode = INST_OP_CALL, .src = INST_CALL_BTF_HELPER, .imm = 1002}, exit}, info};
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        REQUIRE_THROWS_WITH(
            Program::from_sequence(std::get<InstructionSeq>(prog_or_error), info, {}),
            Catch::Matchers::ContainsSubstring("not implemented: kfunc flags are unsupported on this platform") &&
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

    SECTION("lddw code_addr pseudo") {
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

// Verify a program in a section that may have multiple programs in it.
#define VERIFY_PROGRAM(dirname, filename, section_name, program_name, _options, platform, should_pass, count) \
    do {                                                                                                      \
        thread_local_options = _options;                                                                      \
        const auto raw_progs =                                                                                \
            read_elf("ebpf-samples/" dirname "/" filename, section_name, "", thread_local_options, platform); \
        REQUIRE(raw_progs.size() == count);                                                                   \
        for (const auto& raw_prog : raw_progs) {                                                              \
            if (count == 1 || raw_prog.function_name == program_name) {                                       \
                const auto prog_or_error = unmarshal(raw_prog, thread_local_options);                         \
                const auto inst_seq = std::get_if<InstructionSeq>(&prog_or_error);                            \
                REQUIRE(inst_seq);                                                                            \
                const Program prog = Program::from_sequence(*inst_seq, raw_prog.info, thread_local_options);  \
                REQUIRE(verify(prog) == should_pass);                                                         \
            }                                                                                                 \
        }                                                                                                     \
    } while (0)

// Verify a section with only one program in it.
#define VERIFY_SECTION(dirname, filename, section_name, _options, platform, should_pass) \
    VERIFY_PROGRAM(dirname, filename, section_name, "", _options, platform, should_pass, 1)

#define TEST_SECTION(project, filename, section)                                      \
    TEST_CASE(project "/" filename " " section, "[verify][samples][" project "]") {   \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, true); \
    }

#define TEST_SECTION_SLOW(project, filename, section)                                     \
    TEST_CASE(project "/" filename " " section, "[verify][samples][slow][" project "]") { \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, true);     \
    }

#define TEST_PROGRAM(project, filename, section_name, program_name, count)                                      \
    TEST_CASE(project "/" filename " " program_name, "[verify][samples][" project "]") {                        \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &g_ebpf_platform_linux, true, count); \
    }

#define TEST_PROGRAM_FAIL(project, filename, section_name, program_name, count)                                 \
    TEST_CASE(project "/" filename " " program_name, "[!shouldfail][verify][samples][" project "]") {           \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &g_ebpf_platform_linux, true, count); \
    }

#define TEST_PROGRAM_REJECT(project, filename, section_name, program_name, count)                                \
    TEST_CASE(project "/" filename " " program_name, "[verify][samples][" project "]") {                         \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &g_ebpf_platform_linux, false, count); \
    }

#define TEST_PROGRAM_REJECT_FAIL(project, filename, section_name, program_name, count)                           \
    TEST_CASE(project "/" filename " " program_name, "[!shouldfail][verify][samples][" project "]") {            \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &g_ebpf_platform_linux, false, count); \
    }

#define TEST_SECTION_REJECT(project, filename, section)                                \
    TEST_CASE(project "/" filename " " section, "[verify][samples][" project "]") {    \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, false); \
    }

#define TEST_SECTION_REJECT_IF_STRICT(project, filename, section)                           \
    TEST_CASE(project "/" filename " " section, "[verify][samples][" project "]") {         \
        ebpf_verifier_options_t options{};                                                  \
        VERIFY_SECTION(project, filename, section, options, &g_ebpf_platform_linux, true);  \
        options.strict = true;                                                              \
        VERIFY_SECTION(project, filename, section, options, &g_ebpf_platform_linux, false); \
    }

#define TEST_SECTION_FAIL(project, filename, section)                                                              \
    TEST_CASE("expect failure " project "/" filename " " section, "[!shouldfail][verify][samples][" project "]") { \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, true);                              \
    }

#define TEST_SECTION_FAIL_SLOW(project, filename, section)                            \
    TEST_CASE("expect failure " project "/" filename " " section,                     \
              "[!shouldfail][verify][samples][slow][" project "]") {                  \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, true); \
    }

#define TEST_SECTION_REJECT_FAIL(project, filename, section)                                                       \
    TEST_CASE("expect failure " project "/" filename " " section, "[!shouldfail][verify][samples][" project "]") { \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, false);                             \
    }

#define TEST_LEGACY(dirname, filename, sectionname)                                                             \
    TEST_CASE("Unsupported instructions: " dirname "/" filename " " sectionname, "[unmarshal]") {               \
        ebpf_platform_t platform = g_ebpf_platform_linux;                                                       \
        platform.supported_conformance_groups &= ~bpf_conformance_groups_t::packet;                             \
        auto raw_progs = read_elf("ebpf-samples/" dirname "/" filename, sectionname, "", {}, &platform);        \
        REQUIRE(raw_progs.size() == 1);                                                                         \
        RawProgram raw_prog = raw_progs.back();                                                                 \
        std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog, {});                      \
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));                                         \
        REQUIRE_THROWS_WITH(Program::from_sequence(std::get<InstructionSeq>(prog_or_error), raw_prog.info, {}), \
                            Catch::Matchers::ContainsSubstring("rejected: requires conformance group packet")); \
    }

#define TEST_SECTION_LEGACY(dirname, filename, sectionname) \
    TEST_SECTION(dirname, filename, sectionname)            \
    TEST_LEGACY(dirname, filename, sectionname)

#define TEST_SECTION_LEGACY_SLOW(dirname, filename, sectionname) \
    TEST_SECTION_SLOW(dirname, filename, sectionname)            \
    TEST_LEGACY(dirname, filename, sectionname)

#define TEST_SECTION_LEGACY_FAIL(dirname, filename, sectionname) \
    TEST_SECTION_FAIL(dirname, filename, sectionname)            \
    TEST_LEGACY(dirname, filename, sectionname)

TEST_SECTION_SLOW("bpf_cilium_test", "bpf_lxc_jit.o", "1/0xdc06")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/6")
TEST_SECTION_SLOW("bpf_cilium_test", "bpf_lxc_jit.o", "2/7")
TEST_SECTION_LEGACY_SLOW("bpf_cilium_test", "bpf_lxc_jit.o", "2/10")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "from-container")

TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "1/0x1010")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/6")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/7")
TEST_SECTION_LEGACY("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "from-container")

TEST_SECTION_SLOW("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "1/0x1010")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/6")
TEST_SECTION_SLOW("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/7")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "from-container")

TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/7")

TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/7")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "3/2")
TEST_SECTION_LEGACY_SLOW("bpf_cilium_test", "bpf_overlay.o", "from-overlay")

TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L3.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L3.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L3.o", "from-netdev")

TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L4.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L4.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L4.o", "from-netdev")

TEST_SECTION("bpf_cilium_test", "bpf_lb-DUNKNOWN.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DUNKNOWN.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DUNKNOWN.o", "from-netdev")

TEST_SECTION("cilium", "bpf_lb.o", "2/1")
TEST_SECTION("cilium", "bpf_lb.o", "from-netdev")

TEST_SECTION("cilium", "bpf_lxc.o", "1/0x1010")
TEST_SECTION("cilium", "bpf_lxc.o", "2/1")
TEST_SECTION("cilium", "bpf_lxc.o", "2/3")
TEST_SECTION("cilium", "bpf_lxc.o", "2/4")
TEST_SECTION("cilium", "bpf_lxc.o", "2/5")
TEST_SECTION("cilium", "bpf_lxc.o", "2/6")
TEST_SECTION("cilium", "bpf_lxc.o", "2/8")
TEST_SECTION("cilium", "bpf_lxc.o", "2/9")
TEST_SECTION("cilium", "bpf_lxc.o", "from-container")

TEST_SECTION("cilium", "bpf_netdev.o", "2/1")
TEST_SECTION("cilium", "bpf_netdev.o", "2/3")
TEST_SECTION("cilium", "bpf_netdev.o", "2/4")
TEST_SECTION("cilium", "bpf_netdev.o", "2/5")
TEST_SECTION("cilium", "bpf_netdev.o", "2/7")

TEST_SECTION("cilium", "bpf_overlay.o", "2/1")
TEST_SECTION("cilium", "bpf_overlay.o", "2/3")
TEST_SECTION("cilium", "bpf_overlay.o", "2/4")
TEST_SECTION("cilium", "bpf_overlay.o", "2/5")
TEST_SECTION("cilium", "bpf_overlay.o", "2/7")
TEST_SECTION_LEGACY("cilium", "bpf_overlay.o", "from-overlay")

TEST_SECTION("cilium", "bpf_xdp.o", "from-netdev")

TEST_SECTION("cilium", "bpf_xdp_dsr_linux_v1_1.o", "from-netdev")
TEST_SECTION("cilium", "bpf_xdp_dsr_linux.o", "2/1")
TEST_SECTION("cilium", "bpf_xdp_dsr_linux.o", "from-netdev")

TEST_SECTION("cilium", "bpf_xdp_snat_linux.o", "2/1")
TEST_SECTION("cilium", "bpf_xdp_snat_linux.o", "from-netdev")

TEST_SECTION("linux", "cpustat_kern.o", "tracepoint/power/cpu_frequency")
TEST_SECTION("linux", "cpustat_kern.o", "tracepoint/power/cpu_idle")
TEST_SECTION("linux", "lathist_kern.o", "kprobe/trace_preempt_off")
TEST_SECTION("linux", "lathist_kern.o", "kprobe/trace_preempt_on")
TEST_SECTION("linux", "lwt_len_hist_kern.o", "len_hist")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_getegid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_geteuid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_getgid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_getpgid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_getppid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_gettid")
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_getuid")
TEST_SECTION("linux", "offwaketime_kern.o", "kprobe/try_to_wake_up")
TEST_SECTION("linux", "offwaketime_kern.o", "tracepoint/sched/sched_switch")
TEST_SECTION("linux", "sampleip_kern.o", "perf_event")
TEST_SECTION("linux", "sock_flags_kern.o", "cgroup/sock1")
TEST_SECTION("linux", "sock_flags_kern.o", "cgroup/sock2")
TEST_SECTION_LEGACY("linux", "sockex1_kern.o", "socket1")
TEST_SECTION_LEGACY("linux", "sockex2_kern.o", "socket2")
TEST_SECTION_LEGACY("linux", "sockex3_kern.o", "socket/3")
TEST_SECTION_LEGACY("linux", "sockex3_kern.o", "socket/4")
TEST_SECTION_LEGACY("linux", "sockex3_kern.o", "socket/1")
TEST_SECTION_LEGACY("linux", "sockex3_kern.o", "socket/2")
TEST_SECTION_LEGACY("linux", "sockex3_kern.o", "socket/0")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/__htab_percpu_map_update_elem")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_lock")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_lock_bh")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_lock_irq")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_lock_irqsave")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_trylock_bh")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_trylock")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_unlock")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_unlock_bh")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/_raw_spin_unlock_irqrestore")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/htab_map_alloc")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/htab_map_update_elem")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/mutex_spin_on_owner")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/rwsem_spin_on_owner")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/spin_lock")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/spin_unlock")
TEST_SECTION("linux", "spintest_kern.o", "kprobe/spin_unlock_irqrestore")
TEST_SECTION("linux", "syscall_tp_kern.o", "tracepoint/syscalls/sys_enter_open")
TEST_SECTION("linux", "syscall_tp_kern.o", "tracepoint/syscalls/sys_exit_open")
TEST_SECTION("linux", "task_fd_query_kern.o", "kprobe/blk_start_request")
TEST_SECTION("linux", "task_fd_query_kern.o", "kretprobe/blk_account_io_completion")
TEST_SECTION("linux", "tc_l2_redirect_kern.o", "drop_non_tun_vip")
TEST_SECTION("linux", "tc_l2_redirect_kern.o", "l2_to_ip6tun_ingress_redirect")
TEST_SECTION("linux", "tc_l2_redirect_kern.o", "l2_to_iptun_ingress_forward")
TEST_SECTION("linux", "tc_l2_redirect_kern.o", "l2_to_iptun_ingress_redirect")
TEST_SECTION("linux", "tcp_basertt_kern.o", "sockops")
TEST_SECTION("linux", "tcp_bufs_kern.o", "sockops")
TEST_SECTION("linux", "tcp_cong_kern.o", "sockops")
TEST_SECTION("linux", "tcp_iw_kern.o", "sockops")
TEST_SECTION_LEGACY("linux", "tcbpf1_kern.o", "classifier")
TEST_SECTION("linux", "tcbpf1_kern.o", "clone_redirect_recv")
TEST_SECTION("linux", "tcbpf1_kern.o", "clone_redirect_xmit")
TEST_SECTION("linux", "tcbpf1_kern.o", "redirect_recv")
TEST_SECTION("linux", "tcbpf1_kern.o", "redirect_xmit")
TEST_SECTION("linux", "tcp_clamp_kern.o", "sockops")
TEST_SECTION("linux", "tcp_rwnd_kern.o", "sockops")
TEST_SECTION("linux", "tcp_synrto_kern.o", "sockops")
TEST_SECTION("linux", "test_cgrp2_tc_kern.o", "filter")
TEST_SECTION("linux", "test_current_task_under_cgroup_kern.o", "kprobe/sys_sync")
TEST_SECTION("linux", "test_overhead_kprobe_kern.o", "kprobe/__set_task_comm")
TEST_SECTION("linux", "test_overhead_kprobe_kern.o", "kprobe/urandom_read")
TEST_SECTION("linux", "test_overhead_raw_tp_kern.o", "raw_tracepoint/task_rename")
TEST_SECTION("linux", "test_overhead_raw_tp_kern.o", "raw_tracepoint/urandom_read")
TEST_SECTION("linux", "test_overhead_tp_kern.o", "tracepoint/random/urandom_read")
TEST_SECTION("linux", "test_overhead_tp_kern.o", "tracepoint/task/task_rename")
TEST_SECTION("linux", "test_probe_write_user_kern.o", "kprobe/sys_connect")
TEST_SECTION("linux", "trace_event_kern.o", "perf_event")
TEST_SECTION("linux", "trace_output_kern.o", "kprobe/sys_write")
TEST_SECTION("linux", "tracex1_kern.o", "kprobe/__netif_receive_skb_core")
TEST_SECTION("linux", "tracex2_kern.o", "kprobe/kfree_skb")
TEST_SECTION("linux", "tracex2_kern.o", "kprobe/sys_write")
TEST_SECTION("linux", "tracex3_kern.o", "kprobe/blk_account_io_completion")
TEST_SECTION("linux", "tracex3_kern.o", "kprobe/blk_start_request")
TEST_SECTION("linux", "tracex4_kern.o", "kprobe/kmem_cache_free")
TEST_SECTION("linux", "tracex4_kern.o", "kretprobe/kmem_cache_alloc_node")
TEST_SECTION("linux", "tracex5_kern.o", "kprobe/__seccomp_filter")
TEST_SECTION("linux", "tracex5_kern.o", "kprobe/0")
TEST_SECTION("linux", "tracex5_kern.o", "kprobe/1")
TEST_SECTION("linux", "tracex5_kern.o", "kprobe/9")
TEST_SECTION("linux", "tracex6_kern.o", "kprobe/htab_map_get_next_key")
TEST_SECTION("linux", "tracex6_kern.o", "kprobe/htab_map_lookup_elem")
TEST_SECTION("linux", "tracex7_kern.o", "kprobe/open_ctree")
TEST_SECTION("linux", "xdp_adjust_tail_kern.o", "xdp_icmp")
TEST_SECTION("linux", "xdp_fwd_kern.o", "xdp_fwd")
TEST_SECTION("linux", "xdp_fwd_kern.o", "xdp_fwd_direct")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_cpumap_enqueue")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_cpumap_kthread")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_devmap_xmit")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_exception")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_err")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_map")
TEST_SECTION("linux", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_map_err")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map0")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map1_touch_data")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map2_round_robin")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map3_proto_separate")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map4_ddos_filter_pktgen")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "xdp_cpu_map5_lb_hash_ip_pairs")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_cpumap_enqueue")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_cpumap_kthread")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_exception")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_redirect_err")
TEST_SECTION("linux", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_redirect_map_err")
TEST_SECTION("linux", "xdp_redirect_kern.o", "xdp_redirect")
TEST_SECTION("linux", "xdp_redirect_kern.o", "xdp_redirect_dummy")
TEST_SECTION("linux", "xdp_redirect_map_kern.o", "xdp_redirect_dummy")
TEST_SECTION("linux", "xdp_redirect_map_kern.o", "xdp_redirect_map")
TEST_SECTION("linux", "xdp_router_ipv4_kern.o", "xdp_router_ipv4")
TEST_SECTION("linux", "xdp_rxq_info_kern.o", "xdp_prog0")
TEST_SECTION("linux", "xdp_sample_pkts_kern.o", "xdp_sample")
TEST_SECTION("linux", "xdp_tx_iptunnel_kern.o", "xdp_tx_iptunnel")
TEST_SECTION("linux", "xdp1_kern.o", "xdp1")
TEST_SECTION("linux", "xdp2_kern.o", "xdp1")
TEST_SECTION("linux", "xdp2skb_meta_kern.o", "tc_mark")
TEST_SECTION("linux", "xdp2skb_meta_kern.o", "xdp_mark")
TEST_SECTION("linux", "xdpsock_kern.o", "xdp_sock")
// Finally passes; still requires double-check
TEST_SECTION("linux", "map_perf_test_kern.o", "kprobe/sys_connect")

TEST_SECTION("prototype-kernel", "napi_monitor_kern.o", "tracepoint/irq/softirq_entry")
TEST_SECTION("prototype-kernel", "napi_monitor_kern.o", "tracepoint/irq/softirq_exit")
TEST_SECTION("prototype-kernel", "napi_monitor_kern.o", "tracepoint/irq/softirq_raise")
TEST_SECTION("prototype-kernel", "napi_monitor_kern.o", "tracepoint/napi/napi_poll")
TEST_SECTION("prototype-kernel", "tc_bench01_redirect_kern.o", "ingress_redirect")
TEST_SECTION("prototype-kernel", "xdp_bench01_mem_access_cost_kern.o", "xdp_bench01")
TEST_SECTION("prototype-kernel", "xdp_bench02_drop_pattern_kern.o", "xdp_bench02")
TEST_SECTION("prototype-kernel", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect")
TEST_SECTION("prototype-kernel", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_err")
TEST_SECTION("prototype-kernel", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_map_err")
TEST_SECTION("prototype-kernel", "xdp_monitor_kern.o", "tracepoint/xdp/xdp_redirect_map")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map0")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map2_round_robin")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_cpumap_enqueue")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_cpumap_kthread")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_exception")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_redirect_err")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "tracepoint/xdp/xdp_redirect_map_err")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map1_touch_data")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map3_proto_separate")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map4_ddos_filter_pktgen")
TEST_SECTION("prototype-kernel", "xdp_redirect_cpu_kern.o", "xdp_cpu_map5_ip_l3_flow_hash")
TEST_SECTION("prototype-kernel", "xdp_redirect_err_kern.o", "xdp_redirect_dummy")
TEST_SECTION("prototype-kernel", "xdp_redirect_err_kern.o", "xdp_redirect_map")
TEST_SECTION("prototype-kernel", "xdp_redirect_err_kern.o", "xdp_redirect_map_rr")
TEST_SECTION("prototype-kernel", "xdp_tcpdump_kern.o", "xdp_tcpdump_to_perf_ring")
TEST_SECTION("prototype-kernel", "xdp_ttl_kern.o", "xdp_ttl")
TEST_SECTION("prototype-kernel", "xdp_vlan01_kern.o", "tc_vlan_push")
TEST_SECTION("prototype-kernel", "xdp_vlan01_kern.o", "xdp_drop_vlan_4011")
TEST_SECTION("prototype-kernel", "xdp_vlan01_kern.o", "xdp_vlan_change")
TEST_SECTION("prototype-kernel", "xdp_vlan01_kern.o", "xdp_vlan_remove_outer")
TEST_SECTION("prototype-kernel", "xdp_vlan01_kern.o", "xdp_vlan_remove_outer2")

TEST_SECTION("ovs", "datapath.o", "tail-0")
TEST_SECTION("ovs", "datapath.o", "tail-1")
TEST_SECTION("ovs", "datapath.o", "tail-2")
TEST_SECTION_LEGACY("ovs", "datapath.o", "tail-3")
TEST_SECTION("ovs", "datapath.o", "tail-4")
TEST_SECTION("ovs", "datapath.o", "tail-5")
TEST_SECTION("ovs", "datapath.o", "tail-7")
TEST_SECTION("ovs", "datapath.o", "tail-8")
TEST_SECTION("ovs", "datapath.o", "tail-11")
TEST_SECTION("ovs", "datapath.o", "tail-12")
TEST_SECTION("ovs", "datapath.o", "tail-13")
TEST_SECTION_LEGACY("ovs", "datapath.o", "tail-32")
TEST_SECTION("ovs", "datapath.o", "tail-33")
TEST_SECTION("ovs", "datapath.o", "tail-35")
TEST_SECTION("ovs", "datapath.o", "af_xdp")
TEST_SECTION("ovs", "datapath.o", "downcall")
TEST_SECTION("ovs", "datapath.o", "egress")
TEST_SECTION("ovs", "datapath.o", "ingress")
TEST_SECTION("ovs", "datapath.o", "xdp")

TEST_SECTION_LEGACY("suricata", "bypass_filter.o", "filter")
TEST_SECTION_LEGACY("suricata", "lb.o", "loadbalancer")
TEST_SECTION("suricata", "filter.o", "filter")
TEST_SECTION("suricata", "vlan_filter.o", "filter")
TEST_SECTION("suricata", "xdp_filter.o", "xdp")

TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_accept4_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_empty")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_pread64_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_preadv64_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_pwrite64_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_single_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_sysdigevent_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/terminate_filler")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/page_fault_kernel")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/page_fault_user")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/sched_switch")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/signal_deliver")

// Test some programs that should pass verification except when the strict flag is set.
TEST_SECTION_REJECT_IF_STRICT("build", "mapoverflow.o", ".text")
TEST_SECTION_REJECT_IF_STRICT("build", "mapunderflow.o", ".text")

TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_access_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_bpf_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_brk_munmap_mmap_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_eventfd_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_execve_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_generic")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_getrlimit_setrlimit_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_getrlimit_setrlrimit_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_mount_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_pagefault_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_procexit_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_single")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_unshare_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/sched_process_exit")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_chmod_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_fchmod_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_fcntl_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_flock_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_prlimit_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_prlimit_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_ptrace_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_quotactl_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_semop_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_send_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_sendfile_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_setns_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_shutdown_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_fchmodat_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_futex_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_lseek_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_mkdirat_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_ptrace_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_quotactl_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_semget_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_signaldeliver_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_symlinkat_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_unlinkat_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_writev_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_llseek_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_pwritev_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_renameat_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_semctl_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sched_switch_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_linkat_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_renameat2_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_sendfile_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_setsockopt_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_getresuid_and_gid_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_mmap_e")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_socket_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/sys_enter")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/sys_exit")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_pipe_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_socketpair_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_creat_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_open_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_openat_x")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/sys_autofill")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/proc_startupdate_3")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/proc_startupdate")
TEST_SECTION("falco", "probe.o", "raw_tracepoint/filler/proc_startupdate_2")

// Falco expected-fail group A (offset lower-bound loss):
// In these sections, a shared-pointer base is incremented by a scalar offset that
// is only upper-bounded by control-flow assumptions. At merge points, the scalar's
// lower bound is lost, so valid_access(..., write) cannot prove offset >= 0.
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_nanosleep_e")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_poll_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_poll_e")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_ppoll_e")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_getsockopt_x")

// Falco expected-fail group B (size lower-bound loss at correlated joins):
// Common pattern:
// 1) branch constrains size_candidate (e.g., assume const > r2)
// 2) alternate branch writes a concrete fallback size
// 3) join loses the branch/value correlation and retains only size <= const
// Then ValidSize for probe_read* cannot prove r2 >= 0.
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_socket_bind_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_recvmsg_x_2")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_sendmsg_e")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_connect_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_sendto_e")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_accept_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_read_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_recv_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_recvmsg_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_send_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_readv_preadv_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_write_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_writev_pwritev_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_sendmsg_x")
TEST_SECTION_FAIL("falco", "probe.o", "raw_tracepoint/filler/sys_recvfrom_x")

TEST_PROGRAM("build", "bpf2bpf.o", ".text", "add1", 2);
TEST_PROGRAM("build", "bpf2bpf.o", ".text", "add2", 2);
TEST_PROGRAM("build", "bpf2bpf.o", "test", "func", 1);

TEST_SECTION("build", "byteswap.o", ".text")
TEST_SECTION("build", "stackok.o", ".text")
TEST_SECTION("build", "packet_start_ok.o", "xdp")
TEST_SECTION("build", "packet_access.o", "xdp")
TEST_SECTION("build", "tail_call.o", "xdp_prog")
TEST_SECTION("build", "map_in_map.o", ".text")
TEST_SECTION("build", "map_in_map_anonymous.o", ".text")
TEST_SECTION("build", "map_in_map_legacy.o", ".text")
TEST_SECTION("build", "store_map_value_in_map.o", ".text")
TEST_SECTION("build", "twomaps.o", ".text");
TEST_SECTION("build", "twostackvars.o", ".text");
TEST_SECTION("build", "twotypes.o", ".text");
TEST_SECTION("build", "global_variable.o", ".text")
TEST_PROGRAM("build", "prog_array.o", ".text", "func", 5);
TEST_PROGRAM("build", "prog_array.o", ".text", "func0", 5);
TEST_PROGRAM("build", "prog_array.o", ".text", "func1", 5);
TEST_PROGRAM("build", "prog_array.o", ".text", "func2", 5);
TEST_PROGRAM("build", "prog_array.o", ".text", "func3", 5);

// Test some programs that ought to fail verification.
TEST_SECTION_REJECT("build", "badmapptr.o", "test")
TEST_SECTION_REJECT("build", "badhelpercall.o", ".text")
TEST_SECTION_REJECT("build", "ctxoffset.o", "sockops")
TEST_SECTION_FAIL("build", "dependent_read.o", "xdp")
TEST_SECTION_REJECT("build", "exposeptr.o", ".text")
TEST_SECTION_REJECT("build", "exposeptr2.o", ".text")
TEST_SECTION_REJECT("build", "mapvalue-overrun.o", ".text")
TEST_SECTION_REJECT("build", "nullmapref.o", "test")
TEST_SECTION_REJECT("build", "packet_overflow.o", "xdp")
TEST_SECTION_REJECT("build", "packet_reallocate.o", "socket_filter")
TEST_SECTION_REJECT("build", "tail_call_bad.o", "xdp_prog")
TEST_SECTION_REJECT("build", "ringbuf_uninit.o", ".text");
// Intentional OOB access in else branch
TEST_SECTION_REJECT("build", "invalid_map_access.o", ".text")

TEST_SECTION("build", "twomaps_btf.o", ".text")
// bpf_loop callback not supported
TEST_SECTION_FAIL("build", "bpf_loop_helper.o", "xdp")
TEST_SECTION("build", "cpumap.o", "xdp")
TEST_SECTION("build", "devmap.o", "xdp")
TEST_SECTION("build", "hash_of_maps.o", ".text")
TEST_SECTION("build", "lpm_trie.o", "xdp")
TEST_SECTION("build", "percpu_array.o", "xdp")
TEST_SECTION("build", "percpu_hash.o", "xdp")
// perf_event_output helper not modeled
TEST_SECTION_FAIL("build", "perf_event_array.o", "xdp")
// queue/stack pop helper not modeled
TEST_SECTION_FAIL("build", "queue_stack.o", ".text")
TEST_SECTION("build", "sockmap.o", "sk_skb/stream_verdict")
TEST_SECTION("build", "global_func.o", "xdp")
// global subprograms verified standalone fail (no calling context)
TEST_PROGRAM_FAIL("build", "global_func.o", ".text", "add_and_store", 2)
TEST_PROGRAM_FAIL("build", "global_func.o", ".text", "process_entry", 2)

// katran
TEST_SECTION("katran", "xdp_root.o", "xdp")

// bcc libbpf-tools
TEST_SECTION_FAIL("bcc", "bashreadline.bpf.o", "uretprobe/readline")
// unresolved extern LINUX_KERNEL_VERSION
FAIL_LOAD_ELF_SECTION("bcc", "capable.bpf.o", "kprobe/cap_capable")
FAIL_LOAD_ELF_SECTION("bcc", "capable.bpf.o", "kretprobe/cap_capable")
TEST_SECTION("bcc", "exitsnoop.bpf.o", "tracepoint/sched/sched_process_exit")
TEST_SECTION_FAIL("bcc", "filelife.bpf.o", "kprobe/vfs_create")
TEST_SECTION_FAIL("bcc", "filelife.bpf.o", "kprobe/vfs_open")
TEST_SECTION_FAIL("bcc", "filelife.bpf.o", "kprobe/security_inode_create")
TEST_SECTION("bcc", "filelife.bpf.o", "kprobe/vfs_unlink")
TEST_SECTION_FAIL("bcc", "filelife.bpf.o", "kretprobe/vfs_unlink")
TEST_SECTION_FAIL("bcc", "oomkill.bpf.o", "kprobe/oom_kill_process")
TEST_SECTION("bcc", "tcpconnect.bpf.o", "kprobe/tcp_v4_connect")
TEST_SECTION_FAIL("bcc", "tcpconnect.bpf.o", "kretprobe/tcp_v4_connect")
TEST_SECTION("bcc", "tcpconnect.bpf.o", "kprobe/tcp_v6_connect")
TEST_SECTION_FAIL("bcc", "tcpconnect.bpf.o", "kretprobe/tcp_v6_connect")

// libbpf-bootstrap
TEST_SECTION_FAIL("libbpf-bootstrap", "bootstrap.bpf.o", "tp/sched/sched_process_exec")
TEST_SECTION_FAIL("libbpf-bootstrap", "bootstrap.bpf.o", "tp/sched/sched_process_exit")
TEST_SECTION_FAIL("libbpf-bootstrap", "bootstrap_legacy.bpf.o", "tp/sched/sched_process_exec")
TEST_SECTION("libbpf-bootstrap", "bootstrap_legacy.bpf.o", "tp/sched/sched_process_exit")
TEST_SECTION_FAIL("libbpf-bootstrap", "fentry.bpf.o", "fentry/do_unlinkat")
TEST_SECTION_FAIL("libbpf-bootstrap", "fentry.bpf.o", "fexit/do_unlinkat")
TEST_SECTION("libbpf-bootstrap", "kprobe.bpf.o", "kprobe/do_unlinkat")
TEST_SECTION("libbpf-bootstrap", "kprobe.bpf.o", "kretprobe/do_unlinkat")
// unresolved extern LINUX_HAS_SYSCALL_WRAPPER
FAIL_LOAD_ELF_SECTION("libbpf-bootstrap", "ksyscall.bpf.o", "ksyscall/tgkill")
FAIL_LOAD_ELF_SECTION("libbpf-bootstrap", "ksyscall.bpf.o", "ksyscall/kill")
TEST_SECTION_FAIL("libbpf-bootstrap", "lsm.bpf.o", "lsm/bpf")
TEST_SECTION("libbpf-bootstrap", "minimal.bpf.o", "tp/syscalls/sys_enter_write")
TEST_SECTION("libbpf-bootstrap", "minimal_legacy.bpf.o", "tp/syscalls/sys_enter_write")
TEST_SECTION("libbpf-bootstrap", "minimal_ns.bpf.o", "tp/syscalls/sys_enter_write")
TEST_SECTION_FAIL("libbpf-bootstrap", "profile.bpf.o", "perf_event")
TEST_SECTION_FAIL("libbpf-bootstrap", "sockfilter.bpf.o", "socket")
TEST_SECTION_FAIL("libbpf-bootstrap", "task_iter.bpf.o", "iter/task")
TEST_SECTION("libbpf-bootstrap", "tc.bpf.o", "tc")
TEST_SECTION("libbpf-bootstrap", "uprobe.bpf.o", "uprobe")
TEST_SECTION("libbpf-bootstrap", "uprobe.bpf.o", "uretprobe")
TEST_SECTION("libbpf-bootstrap", "uprobe.bpf.o", "uprobe//proc/self/exe:uprobed_sub")
TEST_SECTION("libbpf-bootstrap", "uprobe.bpf.o", "uretprobe//proc/self/exe:uprobed_sub")
// unresolved extern LINUX_HAS_BPF_COOKIE
FAIL_LOAD_ELF_SECTION("libbpf-bootstrap", "usdt.bpf.o", "usdt/libc.so.6:libc:setjmp")
FAIL_LOAD_ELF_SECTION("libbpf-bootstrap", "usdt.bpf.o", "usdt")

// linux-selftests
// multi-program section (7 progs)
// TEST_SECTION("linux-selftests", "atomics.o", "raw_tp/sys_enter") -- 7 programs in section
// multi-program section (2 progs)
// TEST_SECTION("linux-selftests", "bloom_filter_map.o", "fentry/__x64_sys_getpgid") -- 2 programs in section
// unresolved extern CONFIG_HZ
FAIL_LOAD_ELF_SECTION("linux-selftests", "bpf_cubic.o", "struct_ops")
// subprogram not found: tcp_reno_cong_avoid (extern kernel function)
FAIL_LOAD_ELF_SECTION("linux-selftests", "bpf_dctcp.o", "struct_ops")
TEST_SECTION("linux-selftests", "fexit_sleep.o", "fentry/__x64_sys_nanosleep")
TEST_SECTION("linux-selftests", "fexit_sleep.o", "fexit/__x64_sys_nanosleep")
TEST_SECTION_FAIL("linux-selftests", "freplace_get_constant.o", "freplace/get_constant")
TEST_SECTION("linux-selftests", "get_cgroup_id_kern.o", "tracepoint/syscalls/sys_enter_nanosleep")
// BTF-typed arguments not modeled
TEST_SECTION_FAIL("linux-selftests", "kfree_skb.o", "tp_btf/kfree_skb")
TEST_SECTION_FAIL("linux-selftests", "kfree_skb.o", "fentry/eth_type_trans")
TEST_SECTION_FAIL("linux-selftests", "kfree_skb.o", "fexit/eth_type_trans")
TEST_SECTION("linux-selftests", "loop1.o", "raw_tracepoint/kfree_skb")
TEST_SECTION("linux-selftests", "loop2.o", "raw_tracepoint/consume_skb")
// loop3 hangs (analysis does not terminate)
// TEST_SECTION("linux-selftests", "loop3.o", "raw_tracepoint/consume_skb")
TEST_SECTION("linux-selftests", "loop4.o", "socket")
TEST_SECTION("linux-selftests", "loop5.o", "socket")
// subprogram not found: bpf_map_sum_elem_count (extern kernel function)
FAIL_LOAD_ELF_SECTION("linux-selftests", "map_ptr_kern.o", "cgroup_skb/egress")
TEST_SECTION_FAIL("linux-selftests", "socket_cookie_prog.o", "cgroup/connect6")
TEST_SECTION_FAIL("linux-selftests", "socket_cookie_prog.o", "sockops")
TEST_SECTION_FAIL("linux-selftests", "socket_cookie_prog.o", "fexit/inet_stream_connect")
TEST_SECTION("linux-selftests", "sockmap_parse_prog.o", "sk_skb1")
TEST_SECTION("linux-selftests", "sockmap_verdict_prog.o", "sk_skb2")
// multi-program tc sections (tailcall programs)
// TEST_SECTION("linux-selftests", "tailcall1.o", "tc") -- 4 programs in section
// TEST_SECTION("linux-selftests", "tailcall2.o", "tc") -- 6 programs in section
// TEST_SECTION("linux-selftests", "tailcall3.o", "tc") -- 2 programs in section
// global subprograms verified standalone fail (no calling context)
TEST_SECTION_FAIL("linux-selftests", "test_global_func1.o", "tc")
TEST_PROGRAM("linux-selftests", "test_global_func1.o", ".text", "f0", 4)
TEST_PROGRAM_FAIL("linux-selftests", "test_global_func1.o", ".text", "f1", 4)
TEST_PROGRAM_FAIL("linux-selftests", "test_global_func1.o", ".text", "f2", 4)
TEST_PROGRAM_FAIL("linux-selftests", "test_global_func1.o", ".text", "f3", 4)
TEST_SECTION("linux-selftests", "test_global_func_args.o", "cgroup_skb/ingress")
TEST_PROGRAM_FAIL("linux-selftests", "test_global_func_args.o", ".text", "foo", 3)
TEST_PROGRAM_FAIL("linux-selftests", "test_global_func_args.o", ".text", "bar", 3)
TEST_PROGRAM("linux-selftests", "test_global_func_args.o", ".text", "baz", 3)
TEST_SECTION_FAIL("linux-selftests", "test_spin_lock.o", "cgroup_skb/ingress")
// multi-program tc section (3 programs)
// TEST_SECTION("linux-selftests", "test_spin_lock.o", "tc") -- 3 programs in section

// cilium-ebpf
TEST_SECTION("cilium-ebpf", "btf_map_init-el.elf", "socket/tail")
TEST_SECTION("cilium-ebpf", "btf_map_init-el.elf", "socket/main")
TEST_SECTION("cilium-ebpf", "constants-el.elf", "sk_lookup/")
// subprogram not found: invalid_kfunc
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "errors-el.elf", "socket")
TEST_SECTION("cilium-ebpf", "fentry_fexit-el.elf", "fentry/target")
TEST_SECTION("cilium-ebpf", "fentry_fexit-el.elf", "fexit/target")
TEST_SECTION("cilium-ebpf", "fentry_fexit-el.elf", "tc")
TEST_SECTION("cilium-ebpf", "freplace-el.elf", "raw_tracepoint/sched_process_exec")
TEST_SECTION("cilium-ebpf", "freplace-el.elf", "freplace/subprog")
// subprogram not found: fwd (forward-declared function)
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "fwd_decl-el.elf", "socket")
// subprogram not found: bpf_kfunc_call_test_mem_len_pass1
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "invalid-kfunc-el.elf", "tc")
TEST_SECTION_FAIL("cilium-ebpf", "invalid_map_static-el.elf", "xdp")
// unresolved extern LINUX_KERNEL_VERSION, CONFIG_HZ, etc.
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "kconfig-el.elf", "socket")
// unresolved extern symbols in tp_btf/task_newtask section
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "kfunc-el.elf", "tc")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "kfunc-el.elf", "fentry/bpf_fentry_test2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "kfunc-el.elf", "tp_btf/task_newtask")
// subprogram not found: bpf_testmod_test_mod_kfunc
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "kfunc-kmod-el.elf", "tc")
// unresolved extern symbols
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "ksym-el.elf", "socket")
// invalid legacy map symbol offset / subprogram not found
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "linked-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "linked1-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "linked2-el.elf", "socket")
// unresolved extern hash_map, hash_map2, MY_CONST
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "static")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "other")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "xdp")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "socket/2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "socket/3")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "socket/4")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "static")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "other")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "xdp")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "socket/2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "socket/3")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "socket/4")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "static")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "other")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "xdp")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "socket/2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "socket/3")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "socket/4")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "static")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "other")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "xdp")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "socket/2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "socket/3")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "socket/4")
// unresolved extern MY_CONST
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "static")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "other")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "xdp")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "socket/2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "socket/3")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "socket/4")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea0")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea1")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea2")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea3")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea4")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea5")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea6")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea7")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea8")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea9")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea10")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea11")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea12")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea13")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea14")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea15")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea16")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea17")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea18")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea19")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea20")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea21")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea22")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea23")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea24")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea25")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea26")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea27")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea28")
TEST_SECTION("cilium-ebpf", "manyprogs-el.elf", "kprobe/sys_execvea29")
TEST_SECTION("cilium-ebpf", "raw_tracepoint-el.elf", "raw_tracepoint/sched_process_exec")
TEST_SECTION("cilium-ebpf", "strings-el.elf", "xdp")
TEST_SECTION("cilium-ebpf", "struct_ops-el.elf", "struct_ops/test_1")
TEST_SECTION_FAIL("cilium-ebpf", "subprog_reloc-el.elf", "xdp")
// multi-program socket section (8 programs)
// TEST_SECTION("cilium-ebpf", "variables-el.elf", "socket") -- 8 programs in section

// The following eBPF programs currently fail verification.
// If the verifier is later updated to accept them, these should
// be changed to TEST_SECTION().

// This fails due to correlated branches not being handled precisely enough,
// Unless the analysis tracks the correlation between shared_offset and the type of another register,
// which is probably arbitrary and brittle.
TEST_SECTION_FAIL("prototype-kernel", "xdp_ddos01_blacklist_kern.o", "xdp_prog")

// Unsupported: ebpf-function
TEST_SECTION_FAIL("prototype-kernel", "xdp_ddos01_blacklist_kern.o", ".text")

// Unsupported: implications are lost in correlated branches
TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/7")

// Failure: 166:168: Upper bound must be at most packet_size (valid_access(r4.offset, width=2) for read)
// This is the result of merging two branches, one with value 0 and another with value -22,
// then checking that the result is != 0. The minor issue is not handling the int32 comparison precisely enough.
// The bigger issue is that the convexity of the numerical domain means that precise handling would still get
// [-22, -1] which is not sufficient (at most -2 is needed)
TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/10")
TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/21")
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_dsr_linux.o", "2/24")

TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_dsr_linux.o", "2/15")

TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/17")

// Failure: trying to access r4 where r4.packet_offset=[0, 255] and packet_size=[54, 65534]
// Root cause: r5.value=[0, 65535] 209: w5 >>= 8; clears r5 instead of yielding [0, 255]
TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/18")
TEST_SECTION_FAIL("cilium", "bpf_xdp_snat_linux.o", "2/10")
TEST_SECTION_FAIL("cilium", "bpf_xdp_snat_linux.o", "2/18")

TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_dsr_linux.o", "2/19")

// Failure: 230: Upper bound must be at most packet_size (valid_access(r3.offset+32, width=8) for write)
// r3.packet_offset=[0, 82] and packet_size=[34, 65534]
// looks like a combination of misunderstanding the value passed to xdp_adjust_tail()
// which is "r7.value=[0, 82]; w7 -= r9;" where r9.value where "r7.value-r9.value<=48"
TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/20")

TEST_SECTION_FAIL("cilium", "bpf_xdp_snat_linux.o", "2/7")
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_snat_linux.o", "2/15")
TEST_SECTION_FAIL("cilium", "bpf_xdp_snat_linux.o", "2/17")
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_snat_linux.o", "2/19")

// Failure (&255): assert r5.type == number; w5 &= 255;
// fails since in one branch (77) r5 is a number but in another (92:93) it is a packet
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_snat_linux.o", "2/24")
// Failure (&255): assert r3.type == number; w3 &= 255;
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_dsr_linux.o", "2/16")
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_snat_linux.o", "2/16")

// False positive, unknown cause
TEST_SECTION_FAIL("linux", "test_map_in_map_kern.o", "kprobe/sys_connect")

TEST_SECTION_LEGACY("cilium", "bpf_netdev.o", "from-netdev")
TEST_SECTION_LEGACY_SLOW("bpf_cilium_test", "bpf_netdev.o", "from-netdev")
TEST_SECTION_SLOW("cilium", "bpf_lxc.o", "2/7")
TEST_SECTION_LEGACY_SLOW("cilium", "bpf_lxc.o", "2/10")
TEST_SECTION_SLOW("cilium", "bpf_lxc.o", "2/11")
TEST_SECTION_SLOW("cilium", "bpf_lxc.o", "2/12")

// cilium-core/bpf_host.o
TEST_PROGRAM_FAIL("cilium-core", "bpf_host.o", "tc/entry", "cil_from_netdev", 5)
TEST_PROGRAM_FAIL("cilium-core", "bpf_host.o", "tc/entry", "cil_from_host", 5)
TEST_PROGRAM_FAIL("cilium-core", "bpf_host.o", "tc/entry", "cil_to_netdev", 5)
// - cil_to_host: unsupported function: skc_lookup_tcp
TEST_PROGRAM_FAIL("cilium-core", "bpf_host.o", "tc/entry", "cil_host_policy", 5)

// cilium-core/bpf_lxc.o
TEST_PROGRAM("cilium-core", "bpf_lxc.o", "tc/entry", "cil_from_container", 4)
TEST_PROGRAM("cilium-core", "bpf_lxc.o", "tc/entry", "cil_lxc_policy", 4)
TEST_PROGRAM("cilium-core", "bpf_lxc.o", "tc/entry", "cil_lxc_policy_egress", 4)
TEST_PROGRAM("cilium-core", "bpf_lxc.o", "tc/entry", "cil_to_container", 4)

// cilium-core/bpf_network.o
TEST_SECTION("cilium-core", "bpf_network.o", "tc/entry")

// cilium-core/bpf_overlay.o
TEST_PROGRAM("cilium-core", "bpf_overlay.o", "tc/entry", "cil_from_overlay", 2)
// - cil_to_overlay: CRAB_ERROR("Bound: inf / inf")

// cilium-core/bpf_sock.o
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/connect4")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/connect6")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/post_bind4")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/post_bind6")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/sendmsg4")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/sendmsg6")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/recvmsg4")
TEST_SECTION_FAIL("cilium-core", "bpf_sock.o", "cgroup/recvmsg6")
// - bpf_sock.o cgroup/sock_release: invalid helper function id 46

// cilium-core/bpf_wireguard.o
TEST_PROGRAM("cilium-core", "bpf_wireguard.o", "tc/entry", "cil_from_wireguard", 2)
TEST_PROGRAM("cilium-core", "bpf_wireguard.o", "tc/entry", "cil_to_wireguard", 2)

// cilium-core/bpf_xdp.o
TEST_SECTION_FAIL("cilium-core", "bpf_xdp.o", "xdp/entry")

// cilium-examples tests
TEST_SECTION("cilium-examples", "cgroup_skb_bpf_bpfel.o", "cgroup_skb/egress")
TEST_SECTION("cilium-examples", "kprobe_bpf_bpfel.o", "kprobe/sys_execve")
TEST_SECTION("cilium-examples", "kprobe_percpu_bpf_bpfel.o", "kprobe/sys_execve")
TEST_SECTION("cilium-examples", "kprobepin_bpf_bpfel.o", "kprobe/sys_execve")
TEST_SECTION("cilium-examples", "tracepoint_in_c_bpf_bpfel.o", "tracepoint/kmem/mm_page_alloc")
TEST_SECTION("cilium-examples", "xdp_bpf_bpfel.o", "xdp")
// This is TEST_SECTION_FAIL, but with a shorter filename to avoid CATCH2 test name limits.
TEST_CASE("expect failure cilium-examples/uretprobe_x86 uretprobe/bash_readline",
          "[!shouldfail][verify][samples][cilium-examples]") {
    VERIFY_SECTION("cilium-examples", "uretprobe_bpf_x86_bpfel.o", "uretprobe/bash_readline", {},
                   &g_ebpf_platform_linux, true);
}

TEST_PROGRAM("cilium-examples", "tcx_bpf_bpfel.o", "tc", "ingress_prog_func", 2)
TEST_PROGRAM("cilium-examples", "tcx_bpf_bpfel.o", "tc", "egress_prog_func", 2)

static void test_analyze_thread(const Program* prog, const ProgramInfo* info, bool* res) {
    thread_local_program_info.set(*info);
    *res = verify(*prog);
}

// Test multithreading
TEST_CASE("multithreading", "[verify][multithreading]") {
    auto raw_progs1 = read_elf("ebpf-samples/bpf_cilium_test/bpf_netdev.o", "2/1", "", {}, &g_ebpf_platform_linux);
    REQUIRE(raw_progs1.size() == 1);
    RawProgram raw_prog1 = raw_progs1.back();
    auto prog_or_error1 = unmarshal(raw_prog1, {});
    auto inst_seq1 = std::get_if<InstructionSeq>(&prog_or_error1);
    REQUIRE(inst_seq1);
    const Program prog1 = Program::from_sequence(*inst_seq1, raw_prog1.info, {});

    auto raw_progs2 = read_elf("ebpf-samples/bpf_cilium_test/bpf_netdev.o", "2/2", "", {}, &g_ebpf_platform_linux);
    REQUIRE(raw_progs2.size() == 1);
    RawProgram raw_prog2 = raw_progs2.back();
    auto prog_or_error2 = unmarshal(raw_prog2, {});
    auto inst_seq2 = std::get_if<InstructionSeq>(&prog_or_error2);
    REQUIRE(inst_seq2);
    const Program prog2 = Program::from_sequence(*inst_seq2, raw_prog2.info, {});

    bool res1, res2;
    std::thread a(test_analyze_thread, &prog1, &raw_prog1.info, &res1);
    std::thread b(test_analyze_thread, &prog2, &raw_prog2.info, &res2);
    a.join();
    b.join();

    REQUIRE(res1);
    REQUIRE(res2);
}

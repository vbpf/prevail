// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "crab_utils/num_safety.hpp"
#include "io/elf_reader.hpp"

namespace prevail {

namespace {

constexpr uint32_t linux_kernel_version(const uint32_t major, const uint32_t minor, const uint32_t patch) {
    return (major << 16U) | (minor << 8U) | patch;
}

} // namespace

std::optional<uint64_t> resolve_known_linux_extern_symbol(const std::string_view symbol_name) {
    if (symbol_name == "LINUX_KERNEL_VERSION") {
        return linux_kernel_version(6, 6, 0);
    }
    if (symbol_name == "LINUX_HAS_SYSCALL_WRAPPER") {
        return 1;
    }
    if (symbol_name == "LINUX_HAS_BPF_COOKIE") {
        return 1;
    }
    if (symbol_name == "CONFIG_HZ") {
        return 250;
    }
    if (symbol_name == "CONFIG_BPF_SYSCALL") {
        return 1;
    }
    if (symbol_name == "CONFIG_DEFAULT_HOSTNAME") {
        // Store first character ('l' from "localhost"), matching common kconfig usage
        // where the program probes CONFIG_DEFAULT_HOSTNAME[0] for non-empty checks.
        return static_cast<uint64_t>('l');
    }
    return std::nullopt;
}

EbpfInst make_mov_reg_nop(const uint8_t reg) {
    return EbpfInst{
        .opcode = static_cast<uint8_t>(INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_REG),
        .dst = reg,
        .src = reg,
        .offset = 0,
        .imm = 0,
    };
}

bool rewrite_extern_constant_load(std::vector<EbpfInst>& instructions, const size_t location, const uint64_t value) {
    if (instructions.size() <= location + 2) {
        return false;
    }

    auto [lo_inst, hi_inst] = validate_and_get_lddw_pair(instructions, location, "external symbol");
    EbpfInst& load_inst = instructions[location + 2];
    if ((load_inst.opcode & INST_CLS_MASK) != INST_CLS_LDX) {
        return false;
    }
    const uint8_t mode = load_inst.opcode & INST_MODE_MASK;
    if (mode != INST_MODE_MEM && mode != INST_MODE_MEMSX) {
        return false;
    }
    if (load_inst.src != lo_inst.get().dst || load_inst.offset != 0) {
        return false;
    }

    const auto width = opcode_to_width(load_inst.opcode);
    uint64_t narrowed_value = value;
    switch (width) {
    case 1: narrowed_value &= 0xffULL; break;
    case 2: narrowed_value &= 0xffffULL; break;
    case 4: narrowed_value &= 0xffffffffULL; break;
    case 8: break;
    default: return false;
    }
    if (mode == INST_MODE_MEMSX && width < 8) {
        const auto shift = gsl::narrow<int>(64U - static_cast<uint32_t>(width * 8));
        narrowed_value = static_cast<uint64_t>((static_cast<int64_t>(narrowed_value << shift)) >> shift);
    }

    // BPF MOV imm has a 32-bit immediate field that is sign-extended to 64 bits
    // by the runtime. Bail out if the value cannot survive the int32 → int64
    // sign-extension round-trip; the caller will fall back to the original
    // LDDW+LDX instruction sequence.
    const auto truncated = static_cast<int32_t>(narrowed_value);
    if (static_cast<uint64_t>(static_cast<int64_t>(truncated)) != narrowed_value) {
        return false;
    }

    // Use mov-imm to materialize the resolved constant in the destination register of
    // the load, and neutralize the preceding LDDW pair.
    const uint8_t mov_opcode = width == 8 || mode == INST_MODE_MEMSX
                                   ? static_cast<uint8_t>(INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_IMM)
                                   : static_cast<uint8_t>(INST_CLS_ALU | INST_ALU_OP_MOV | INST_SRC_IMM);
    load_inst.opcode = mov_opcode;
    load_inst.src = 0;
    load_inst.offset = 0;
    load_inst.imm = truncated;

    lo_inst.get() = make_mov_reg_nop(lo_inst.get().dst);
    hi_inst.get() = make_mov_reg_nop(hi_inst.get().dst);
    return true;
}

bool rewrite_extern_address_load_to_zero(std::vector<EbpfInst>& instructions, const size_t location) {
    if (location + 1 >= instructions.size()) {
        return false;
    }
    if (instructions[location].opcode != INST_OP_LDDW_IMM) {
        return false;
    }

    auto [lo_inst, hi_inst] = validate_and_get_lddw_pair(instructions, location, "external symbol");
    lo_inst.get().imm = 0;
    hi_inst.get().imm = 0;
    return true;
}

bool rewrite_extern_kfunc_call(EbpfInst& instruction, const KsymBtfId& resolved_target) {
    if (instruction.opcode != INST_OP_CALL || instruction.src != INST_CALL_LOCAL || instruction.dst != 0) {
        return false;
    }
    if (instruction.offset != 0) {
        return false;
    }
    if (resolved_target.btf_id <= 0 || resolved_target.module < 0) {
        return false;
    }

    instruction.src = INST_CALL_BTF_HELPER;
    instruction.offset = resolved_target.module;
    instruction.imm = resolved_target.btf_id;
    return true;
}

} // namespace prevail

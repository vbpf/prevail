// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "crab_utils/debug.hpp"
#include "crab_utils/num_safety.hpp"
#include "ir/unmarshal.hpp"
#include "spec/vm_isa.hpp"

using std::string;
using std::vector;

namespace prevail {
int opcode_to_width(const uint8_t opcode) {
    switch (opcode & INST_SIZE_MASK) {
    case INST_SIZE_B: return 1;
    case INST_SIZE_H: return 2;
    case INST_SIZE_W: return 4;
    case INST_SIZE_DW: return 8;
    default: CRAB_ERROR("unexpected opcode", opcode);
    }
}

uint8_t width_to_opcode(const int width) {
    switch (width) {
    case 1: return INST_SIZE_B;
    case 2: return INST_SIZE_H;
    case 4: return INST_SIZE_W;
    case 8: return INST_SIZE_DW;
    default: CRAB_ERROR("unexpected width", width);
    }
}

template <typename T>
void compare(const string& field, T actual, T expected) {
    if (actual != expected) {
        std::cerr << field << ": (actual) " << std::hex << static_cast<int>(actual)
                  << " != " << static_cast<int>(expected) << " (expected)\n";
    }
}

static std::string make_opcode_message(const char* msg, const uint8_t opcode) {
    std::ostringstream oss;
    oss << msg << " op 0x" << std::hex << static_cast<int>(opcode);
    return oss.str();
}

struct InvalidInstruction final : std::invalid_argument {
    size_t pc;
    explicit InvalidInstruction(const size_t pc, const char* what) : std::invalid_argument{what}, pc{pc} {}
    InvalidInstruction(const size_t pc, const std::string& what) : std::invalid_argument{what}, pc{pc} {}
    InvalidInstruction(const size_t pc, const uint8_t opcode)
        : std::invalid_argument{make_opcode_message("bad instruction", opcode)}, pc{pc} {}
};

static auto getMemIsLoad(const uint8_t opcode) -> bool {
    switch (opcode & INST_CLS_MASK) {
    case INST_CLS_LD:
    case INST_CLS_LDX: return true;
    case INST_CLS_ST:
    case INST_CLS_STX: return false;
    default: CRAB_ERROR("unexpected opcode", opcode);
    }
}

static auto getMemWidth(const uint8_t opcode) -> int {
    switch (opcode & INST_SIZE_MASK) {
    case INST_SIZE_B: return 1;
    case INST_SIZE_H: return 2;
    case INST_SIZE_W: return 4;
    case INST_SIZE_DW: return 8;
    default: CRAB_ERROR("unexpected opcode", opcode);
    }
}

static Instruction shift32(const Reg dst, const Bin::Op op) {
    return Bin{.op = op, .dst = dst, .v = Imm{32}, .is64 = true, .lddw = false};
}

struct Unmarshaller {
    vector<vector<string>>& notes;
    const ProgramInfo& info;
    // ReSharper disable once CppMemberFunctionMayBeConst
    void note(const string& what) { notes.back().emplace_back(what); }
    // ReSharper disable once CppMemberFunctionMayBeConst
    void note_next_pc() { notes.emplace_back(); }
    explicit Unmarshaller(vector<vector<string>>& notes, const ProgramInfo& info) : notes{notes}, info{info} {
        note_next_pc();
    }

    auto getAluOp(const size_t pc, const EbpfInst inst) -> std::variant<Bin::Op, Un::Op> {
        // First handle instructions that support a non-zero offset.
        switch (inst.opcode & INST_ALU_OP_MASK) {
        case INST_ALU_OP_DIV:
            switch (inst.offset) {
            case 0: return Bin::Op::UDIV;
            case 1: return Bin::Op::SDIV;
            default: throw InvalidInstruction(pc, make_opcode_message("invalid offset for", inst.opcode));
            }
        case INST_ALU_OP_MOD:
            switch (inst.offset) {
            case 0: return Bin::Op::UMOD;
            case 1: return Bin::Op::SMOD;
            default: throw InvalidInstruction(pc, make_opcode_message("invalid offset for", inst.opcode));
            }
        case INST_ALU_OP_MOV:
            if (inst.offset > 0 && !(inst.opcode & INST_SRC_REG)) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero offset for", inst.opcode));
            }
            switch (inst.offset) {
            case 0: return Bin::Op::MOV;
            case 8: return Bin::Op::MOVSX8;
            case 16: return Bin::Op::MOVSX16;
            case 32: return Bin::Op::MOVSX32;
            default: throw InvalidInstruction(pc, make_opcode_message("invalid offset for", inst.opcode));
            }
        default: break;
        }

        // All the rest require a zero offset.
        if (inst.offset != 0) {
            throw InvalidInstruction(pc, make_opcode_message("nonzero offset for", inst.opcode));
        }

        switch (inst.opcode & INST_ALU_OP_MASK) {
        case INST_ALU_OP_ADD: return Bin::Op::ADD;
        case INST_ALU_OP_SUB: return Bin::Op::SUB;
        case INST_ALU_OP_MUL: return Bin::Op::MUL;
        case INST_ALU_OP_OR: return Bin::Op::OR;
        case INST_ALU_OP_AND: return Bin::Op::AND;
        case INST_ALU_OP_LSH: return Bin::Op::LSH;
        case INST_ALU_OP_RSH: return Bin::Op::RSH;
        case INST_ALU_OP_NEG:
            // Negation is a unary operation. The SRC bit, src, and imm must be all 0.
            if (inst.opcode & INST_SRC_REG) {
                throw InvalidInstruction{pc, inst.opcode};
            }
            if (inst.src != 0) {
                throw InvalidInstruction{pc, inst.opcode};
            }
            if (inst.imm != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero imm for", inst.opcode));
            }
            return Un::Op::NEG;
        case INST_ALU_OP_XOR: return Bin::Op::XOR;
        case INST_ALU_OP_ARSH:
            if ((inst.opcode & INST_CLS_MASK) == INST_CLS_ALU) {
                note("arsh32 is not allowed");
            }
            return Bin::Op::ARSH;
        case INST_ALU_OP_END:
            if (inst.src != 0) {
                throw InvalidInstruction{pc, inst.opcode};
            }
            if ((inst.opcode & INST_CLS_MASK) == INST_CLS_ALU64) {
                if (inst.opcode & INST_END_BE) {
                    throw InvalidInstruction(pc, inst.opcode);
                }
                switch (inst.imm) {
                case 16: return Un::Op::SWAP16;
                case 32: return Un::Op::SWAP32;
                case 64: return Un::Op::SWAP64;
                default: throw InvalidInstruction(pc, "unsupported immediate");
                }
            }
            switch (inst.imm) {
            case 16: return (inst.opcode & INST_END_BE) ? Un::Op::BE16 : Un::Op::LE16;
            case 32: return (inst.opcode & INST_END_BE) ? Un::Op::BE32 : Un::Op::LE32;
            case 64: return (inst.opcode & INST_END_BE) ? Un::Op::BE64 : Un::Op::LE64;
            default: throw InvalidInstruction(pc, "unsupported immediate");
            }
        case 0xe0: throw InvalidInstruction{pc, inst.opcode};
        case 0xf0: throw InvalidInstruction{pc, inst.opcode};
        default: return {};
        }
    }

    static auto getAtomicOp(const size_t pc, const EbpfInst inst) -> Atomic::Op {
        switch (const auto op = gsl::narrow<Atomic::Op>(inst.imm & ~INST_FETCH)) {
        case Atomic::Op::XCHG:
        case Atomic::Op::CMPXCHG:
            if ((inst.imm & INST_FETCH) == 0) {
                throw InvalidInstruction(pc, "unsupported immediate");
            }
        case Atomic::Op::ADD:
        case Atomic::Op::OR:
        case Atomic::Op::AND:
        case Atomic::Op::XOR: return op;
        }
        throw InvalidInstruction(pc, "unsupported immediate");
    }

    static uint64_t sign_extend(const int32_t imm) { return to_unsigned(int64_t{imm}); }

    static uint64_t zero_extend(const int32_t imm) { return uint64_t{to_unsigned(imm)}; }

    static auto getBinValue(const Pc pc, const EbpfInst inst) -> Value {
        if (inst.opcode & INST_SRC_REG) {
            if (inst.imm != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero imm for", inst.opcode));
            }
            return Reg{inst.src};
        }
        if (inst.src != 0) {
            throw InvalidInstruction{pc, inst.opcode};
        }
        // Imm is a signed 32-bit number.  Sign extend it to 64-bits for storage.
        return Imm{sign_extend(inst.imm)};
    }

    static auto getJmpOp(const size_t pc, const uint8_t opcode) -> Condition::Op {
        using Op = Condition::Op;
        switch ((opcode >> 4) & 0xF) {
        case 0x0: return {}; // goto
        case 0x1: return Op::EQ;
        case 0x2: return Op::GT;
        case 0x3: return Op::GE;
        case 0x4: return Op::SET;
        case 0x5: return Op::NE;
        case 0x6: return Op::SGT;
        case 0x7: return Op::SGE;
        case 0x8: return {}; // call
        case 0x9: return {}; // exit
        case 0xa: return Op::LT;
        case 0xb: return Op::LE;
        case 0xc: return Op::SLT;
        case 0xd: return Op::SLE;
        case 0xe: throw InvalidInstruction(pc, opcode);
        case 0xf: throw InvalidInstruction(pc, opcode);
        default: return {};
        }
    }

    auto makeMemOp(const Pc pc, const EbpfInst inst) -> Instruction {
        if (inst.dst > R10_STACK_POINTER || inst.src > R10_STACK_POINTER) {
            throw InvalidInstruction(pc, "bad register");
        }

        const int width = getMemWidth(inst.opcode);
        const bool isLD = (inst.opcode & INST_CLS_MASK) == INST_CLS_LD;
        switch (inst.opcode & INST_MODE_MASK) {
        case INST_MODE_IMM: throw InvalidInstruction(pc, inst.opcode);

        case INST_MODE_ABS:
            if (!isLD || (width == 8)) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            if (inst.dst != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero dst for register", inst.opcode));
            }
            if (inst.src > 0) {
                throw InvalidInstruction(pc, make_opcode_message("bad instruction", inst.opcode));
            }
            if (inst.offset != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero offset for", inst.opcode));
            }
            return Packet{.width = width, .offset = inst.imm, .regoffset = {}};

        case INST_MODE_IND:
            if (!isLD || (width == 8)) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            if (inst.dst != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero dst for register", inst.opcode));
            }
            if (inst.src > R10_STACK_POINTER) {
                throw InvalidInstruction(pc, "bad register");
            }
            if (inst.offset != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero offset for", inst.opcode));
            }
            return Packet{.width = width, .offset = inst.imm, .regoffset = Reg{inst.src}};

        case INST_MODE_MEM: {
            if (isLD) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            const bool isLoad = getMemIsLoad(inst.opcode);
            if (isLoad && inst.dst == R10_STACK_POINTER) {
                throw InvalidInstruction(pc, "cannot modify r10");
            }
            const bool isImm = !(inst.opcode & 1);
            if (isImm && inst.src != 0) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            if (!isImm && inst.imm != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero imm for", inst.opcode));
            }

            assert(!(isLoad && isImm));
            const uint8_t basereg = isLoad ? inst.src : inst.dst;

            if (basereg == R10_STACK_POINTER &&
                (inst.offset + opcode_to_width(inst.opcode) > 0 || inst.offset < -EBPF_TOTAL_STACK_SIZE)) {
                note("Stack access out of bounds");
            }
            auto res = Mem{
                .access =
                    Deref{
                        .width = width,
                        .basereg = Reg{basereg},
                        .offset = inst.offset,
                    },
                .value = isLoad  ? Value{Reg{inst.dst}}
                         : isImm ? Value{Imm{zero_extend(inst.imm)}}
                                 : Value{Reg{inst.src}},
                .is_load = isLoad,
            };
            return res;
        }
        case INST_MODE_MEMSX: {
            // Sign-extending loads are only valid for LDX B/H/W forms.
            if ((inst.opcode & INST_CLS_MASK) != INST_CLS_LDX || width == 8) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            if (inst.dst == R10_STACK_POINTER) {
                throw InvalidInstruction(pc, "cannot modify r10");
            }
            if (inst.imm != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero imm for", inst.opcode));
            }
            return Mem{
                .access =
                    Deref{
                        .width = width,
                        .basereg = Reg{inst.src},
                        .offset = inst.offset,
                    },
                .value = Value{Reg{inst.dst}},
                .is_load = true,
                .is_signed = true,
            };
        }

        case INST_MODE_ATOMIC:
            if (((inst.opcode & INST_CLS_MASK) != INST_CLS_STX) ||
                ((inst.opcode & INST_SIZE_MASK) != INST_SIZE_W && (inst.opcode & INST_SIZE_MASK) != INST_SIZE_DW)) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            return Atomic{
                .op = getAtomicOp(pc, inst),
                .fetch = (inst.imm & INST_FETCH) == INST_FETCH,
                .access =
                    Deref{
                        .width = width,
                        .basereg = Reg{inst.dst},
                        .offset = inst.offset,
                    },
                .valreg = Reg{inst.src},
            };
        default: throw InvalidInstruction(pc, inst.opcode);
        }
    }

    auto makeAluOp(const size_t pc, const EbpfInst inst) -> Instruction {
        const bool is64 = (inst.opcode & INST_CLS_MASK) == INST_CLS_ALU64;
        if (inst.dst == R10_STACK_POINTER) {
            throw InvalidInstruction(pc, "invalid target r10");
        }
        if (inst.dst > R10_STACK_POINTER || inst.src > R10_STACK_POINTER) {
            throw InvalidInstruction(pc, "bad register");
        }
        return std::visit(
            Overloaded{[&](const Un::Op op) -> Instruction { return Un{.op = op, .dst = Reg{inst.dst}, .is64 = is64}; },
                       [&](const Bin::Op op) -> Instruction {
                           Bin res{
                               .op = op,
                               .dst = Reg{inst.dst},
                               .v = getBinValue(pc, inst),
                               .is64 = is64,
                           };
                           if (!thread_local_options.allow_division_by_zero &&
                               (op == Bin::Op::UDIV || op == Bin::Op::UMOD)) {
                               if (const auto pimm = std::get_if<Imm>(&res.v)) {
                                   if (pimm->v == 0) {
                                       note("division by zero");
                                   }
                               }
                           }
                           return res;
                       }},
            getAluOp(pc, inst));
    }

    [[nodiscard]]
    auto makeLddw(const EbpfInst inst, const int32_t next_imm, const vector<EbpfInst>& insts, const Pc pc) const
        -> Instruction {
        if (pc >= insts.size() - 1) {
            throw InvalidInstruction(pc, "incomplete lddw");
        }
        const EbpfInst next = insts[pc + 1];
        if (next.opcode != 0 || next.dst != 0 || next.src != 0 || next.offset != 0) {
            throw InvalidInstruction(pc, "invalid lddw");
        }
        if (inst.src > 6) {
            throw InvalidInstruction(pc, make_opcode_message("bad instruction", inst.opcode));
        }
        if (inst.offset != 0) {
            throw InvalidInstruction(pc, make_opcode_message("nonzero offset for", inst.opcode));
        }
        if (inst.dst > R10_STACK_POINTER) {
            throw InvalidInstruction(pc, "bad register");
        }

        switch (inst.src) {
        case INST_LD_MODE_IMM:
            return Bin{
                .op = Bin::Op::MOV,
                .dst = Reg{inst.dst},
                .v = Imm{merge(inst.imm, next_imm)},
                .is64 = true,
                .lddw = true,
            };
        case INST_LD_MODE_MAP_FD: {
            // magic number, meaning we're a per-process file descriptor defining the map.
            // (for details, look for BPF_PSEUDO_MAP_FD in the kernel)
            if (next.imm != 0) {
                throw InvalidInstruction(pc, "lddw uses reserved fields");
            }
            return LoadMapFd{.dst = Reg{inst.dst}, .mapfd = inst.imm};
        }
        case INST_LD_MODE_MAP_VALUE: return LoadMapAddress{.dst = Reg{inst.dst}, .mapfd = inst.imm, .offset = next_imm};
        case 3:
            return LoadPseudo{.dst = Reg{inst.dst},
                              .addr = PseudoAddress{
                                  .kind = PseudoAddress::Kind::VARIABLE_ADDR, .imm = inst.imm, .next_imm = next_imm}};
        case 4:
            return LoadPseudo{
                .dst = Reg{inst.dst},
                .addr = PseudoAddress{.kind = PseudoAddress::Kind::CODE_ADDR, .imm = inst.imm, .next_imm = next_imm}};
        case 5:
            return LoadPseudo{
                .dst = Reg{inst.dst},
                .addr = PseudoAddress{.kind = PseudoAddress::Kind::MAP_BY_IDX, .imm = inst.imm, .next_imm = next_imm}};
        case 6:
            return LoadPseudo{.dst = Reg{inst.dst},
                              .addr = PseudoAddress{.kind = PseudoAddress::Kind::MAP_VALUE_BY_IDX,
                                                    .imm = inst.imm,
                                                    .next_imm = next_imm}};
        default: throw InvalidInstruction(pc, make_opcode_message("bad instruction", inst.opcode));
        }
    }

    static ArgSingle::Kind toArgSingleKind(const ebpf_argument_type_t t) {
        switch (t) {
        case EBPF_ARGUMENT_TYPE_ANYTHING: return ArgSingle::Kind::ANYTHING;
        case EBPF_ARGUMENT_TYPE_PTR_TO_STACK: return ArgSingle::Kind::PTR_TO_STACK;
        case EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL: return ArgSingle::Kind::PTR_TO_STACK;
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP: return ArgSingle::Kind::MAP_FD;
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS: return ArgSingle::Kind::MAP_FD_PROGRAMS;
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY: return ArgSingle::Kind::PTR_TO_MAP_KEY;
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE: return ArgSingle::Kind::PTR_TO_MAP_VALUE;
        case EBPF_ARGUMENT_TYPE_PTR_TO_CTX: return ArgSingle::Kind::PTR_TO_CTX;
        case EBPF_ARGUMENT_TYPE_PTR_TO_CTX_OR_NULL: return ArgSingle::Kind::PTR_TO_CTX;
        default: break;
        }
        return {};
    }

    static ArgPair::Kind toArgPairKind(const ebpf_argument_type_t t) {
        switch (t) {
        case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
        case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM: return ArgPair::Kind::PTR_TO_READABLE_MEM;
        case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL:
        case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM: return ArgPair::Kind::PTR_TO_WRITABLE_MEM;
        default: break;
        }
        return {};
    }

    [[nodiscard]]
    auto makeCall(const int32_t imm) const -> Call {
        const EbpfHelperPrototype proto = info.platform->get_helper_prototype(imm);
        Call res;
        res.func = imm;
        res.name = proto.name;
        auto mark_unsupported = [&](const std::string& why) -> Call {
            res.is_supported = false;
            res.unsupported_reason = why;
            return res;
        };
        if (proto.return_type == EBPF_RETURN_TYPE_UNSUPPORTED) {
            return mark_unsupported(std::string("helper prototype is unavailable on this platform: ") + proto.name);
        }
        res.reallocate_packet = proto.reallocate_packet;
        res.is_map_lookup = proto.return_type == EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL;
        const std::array<ebpf_argument_type_t, 7> args = {
            {EBPF_ARGUMENT_TYPE_DONTCARE, proto.argument_type[0], proto.argument_type[1], proto.argument_type[2],
             proto.argument_type[3], proto.argument_type[4], EBPF_ARGUMENT_TYPE_DONTCARE}};
        for (size_t i = 1; i < args.size() - 1; i++) {
            switch (args[i]) {
            case EBPF_ARGUMENT_TYPE_UNSUPPORTED:
                return mark_unsupported(std::string("helper argument type is unavailable on this platform: ") +
                                        proto.name);
            case EBPF_ARGUMENT_TYPE_DONTCARE: return res;
            case EBPF_ARGUMENT_TYPE_ANYTHING:
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP:
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS:
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY:
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE:
            case EBPF_ARGUMENT_TYPE_PTR_TO_STACK:
            case EBPF_ARGUMENT_TYPE_PTR_TO_CTX:
                res.singles.push_back({toArgSingleKind(args[i]), false, Reg{gsl::narrow<uint8_t>(i)}});
                break;
            case EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL:
            case EBPF_ARGUMENT_TYPE_PTR_TO_CTX_OR_NULL:
                res.singles.push_back({toArgSingleKind(args[i]), true, Reg{gsl::narrow<uint8_t>(i)}});
                break;
            case EBPF_ARGUMENT_TYPE_CONST_SIZE: {
                // Sanity check: This argument should never be seen in isolation.
                return mark_unsupported(
                    std::string("mismatched EBPF_ARGUMENT_TYPE_PTR_TO* and EBPF_ARGUMENT_TYPE_CONST_SIZE: ") +
                    proto.name);
            }
            case EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: {
                // Sanity check: This argument should never be seen in isolation.
                return mark_unsupported(
                    std::string("mismatched EBPF_ARGUMENT_TYPE_PTR_TO* and EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: ") +
                    proto.name);
            }
            case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
            case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM:
            case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL:
            case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM:
                // Sanity check: This argument must be followed by EBPF_ARGUMENT_TYPE_CONST_SIZE or
                // EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO.
                if (args.size() - i < 2) {
                    return mark_unsupported(
                        std::string(
                            "missing EBPF_ARGUMENT_TYPE_CONST_SIZE or EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: ") +
                        proto.name);
                }
                if (args[i + 1] != EBPF_ARGUMENT_TYPE_CONST_SIZE &&
                    args[i + 1] != EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO) {
                    return mark_unsupported(
                        std::string("Pointer argument not followed by EBPF_ARGUMENT_TYPE_CONST_SIZE or "
                                    "EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: ") +
                        proto.name);
                }
                const bool can_be_zero = (args[i + 1] == EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO);
                const bool or_null = args[i] == EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL ||
                                     args[i] == EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL;
                res.pairs.push_back({toArgPairKind(args[i]), or_null, Reg{gsl::narrow<uint8_t>(i)},
                                     Reg{gsl::narrow<uint8_t>(i + 1)}, can_be_zero});
                i++;
                break;
            }
        }
        return res;
    }

    /// Given a program counter and an offset, get the label of the target instruction.
    static Label getJumpTarget(const int32_t offset, const vector<EbpfInst>& insts, const Pc pc) {
        const Pc new_pc = pc + 1 + offset;
        if (new_pc >= insts.size()) {
            throw InvalidInstruction(pc, "jump out of bounds");
        }
        if (insts[new_pc].opcode == 0) {
            throw InvalidInstruction(pc, "jump to middle of lddw");
        }
        return Label{gsl::narrow<int>(new_pc)};
    }

    static auto makeCallLocal(const EbpfInst inst, const vector<EbpfInst>& insts, const Pc pc) -> CallLocal {
        if (inst.opcode & INST_SRC_REG) {
            throw InvalidInstruction(pc, inst.opcode);
        }
        if (inst.dst != 0) {
            throw InvalidInstruction(pc, make_opcode_message("nonzero dst for register", inst.opcode));
        }
        return CallLocal{.target = getJumpTarget(inst.imm, insts, pc)};
    }

    static auto makeCallx(const EbpfInst inst, const Pc pc) -> Callx {
        // callx puts the register number in the 'dst' field rather than the 'src' field.
        if (inst.dst > R10_STACK_POINTER) {
            throw InvalidInstruction(pc, "bad register");
        }
        if (inst.imm != 0) {
            // Clang prior to v19 put the register number into the 'imm' field.
            if (inst.dst > 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero imm for", inst.opcode));
            }
            if (inst.imm < 0 || inst.imm > R10_STACK_POINTER) {
                throw InvalidInstruction(pc, "bad register");
            }
            return Callx{gsl::narrow<uint8_t>(inst.imm)};
        }
        return Callx{inst.dst};
    }

    [[nodiscard]]
    auto makeJmp(const EbpfInst inst, const vector<EbpfInst>& insts, const Pc pc) const -> Instruction {
        switch ((inst.opcode >> 4) & 0xF) {
        case INST_CALL:
            if ((inst.opcode & INST_CLS_MASK) != INST_CLS_JMP) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            if (inst.src > INST_CALL_BTF_HELPER) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            if (inst.offset != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero offset for", inst.opcode));
            }
            if (inst.src == INST_CALL_LOCAL) {
                return makeCallLocal(inst, insts, pc);
            }
            if (inst.opcode & INST_SRC_REG) {
                // Register-call opcode form is reserved for callx and must not be used for src-based call modes.
                if (inst.src != 0) {
                    throw InvalidInstruction(pc, inst.opcode);
                }
                return makeCallx(inst, pc);
            }
            if (inst.src == INST_CALL_BTF_HELPER) {
                if (inst.dst != 0) {
                    throw InvalidInstruction(pc, make_opcode_message("nonzero dst for register", inst.opcode));
                }
                return CallBtf{.btf_id = inst.imm};
            }
            if (inst.dst != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero dst for register", inst.opcode));
            }
            if (!info.platform->is_helper_usable(inst.imm)) {
                return Call{.func = inst.imm,
                            .name = std::to_string(inst.imm),
                            .is_supported = false,
                            .unsupported_reason = "helper function is unavailable on this platform"};
            }
            return makeCall(inst.imm);
        case INST_EXIT:
            if ((inst.opcode & INST_CLS_MASK) != INST_CLS_JMP || (inst.opcode & INST_SRC_REG)) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            if (inst.src != 0) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            if (inst.dst != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero dst for register", inst.opcode));
            }
            if (inst.imm != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero imm for", inst.opcode));
            }
            if (inst.offset != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero offset for", inst.opcode));
            }
            return Exit{};
        case INST_JA:
            if ((inst.opcode & INST_CLS_MASK) != INST_CLS_JMP && (inst.opcode & INST_CLS_MASK) != INST_CLS_JMP32) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            if (inst.opcode & INST_SRC_REG) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            if ((inst.opcode & INST_CLS_MASK) == INST_CLS_JMP && (inst.imm != 0)) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero imm for", inst.opcode));
            }
            if ((inst.opcode & INST_CLS_MASK) == INST_CLS_JMP32 && (inst.offset != 0)) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero offset for", inst.opcode));
            }
            if (inst.dst != 0) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero dst for register", inst.opcode));
            }
        default: {
            // First validate the opcode, src, and imm.
            const auto op = getJmpOp(pc, inst.opcode);
            if (!(inst.opcode & INST_SRC_REG) && (inst.src != 0)) {
                throw InvalidInstruction(pc, inst.opcode);
            }
            if ((inst.opcode & INST_SRC_REG) && (inst.imm != 0)) {
                throw InvalidInstruction(pc, make_opcode_message("nonzero imm for", inst.opcode));
            }

            const int32_t offset = (inst.opcode == INST_OP_JA32) ? inst.imm : inst.offset;
            const Label target = getJumpTarget(offset, insts, pc);
            if (inst.opcode != INST_OP_JA16 && inst.opcode != INST_OP_JA32) {
                if (inst.dst > R10_STACK_POINTER) {
                    throw InvalidInstruction(pc, "bad register");
                }
                if ((inst.opcode & INST_SRC_REG) && inst.src > R10_STACK_POINTER) {
                    throw InvalidInstruction(pc, "bad register");
                }
            }

            const auto cond = (inst.opcode == INST_OP_JA16 || inst.opcode == INST_OP_JA32)
                                  ? std::optional<Condition>{}
                                  : Condition{.op = op,
                                              .left = Reg{inst.dst},
                                              .right = (inst.opcode & INST_SRC_REG) ? Value{Reg{inst.src}}
                                                                                    : Value{Imm{sign_extend(inst.imm)}},
                                              .is64 = (inst.opcode & INST_CLS_MASK) == INST_CLS_JMP};
            return Jmp{.cond = cond, .target = target};
        }
        }
    }

    vector<LabeledInstruction> unmarshal(vector<EbpfInst> const& insts,
                                         const prevail::ebpf_verifier_options_t& options) {
        vector<LabeledInstruction> prog;
        int exit_count = 0;
        if (insts.empty()) {
            throw std::invalid_argument("Zero length programs are not allowed");
        }
        for (size_t pc = 0; pc < insts.size();) {
            const EbpfInst inst = insts[pc];
            Instruction new_ins;
            bool skip_instruction = false;
            bool fallthrough = true;
            switch (inst.opcode & INST_CLS_MASK) {
            case INST_CLS_LD:
                if (inst.opcode == INST_OP_LDDW_IMM) {
                    const int32_t next_imm = pc < insts.size() - 1 ? insts[pc + 1].imm : 0;
                    new_ins = makeLddw(inst, next_imm, insts, pc);
                    skip_instruction = true;
                    break;
                }
                // fallthrough
            case INST_CLS_LDX:
            case INST_CLS_ST:
            case INST_CLS_STX: new_ins = makeMemOp(pc, inst); break;

            case INST_CLS_ALU:
            case INST_CLS_ALU64: {
                new_ins = makeAluOp(pc, inst);

                // Merge (rX <<= 32; rX >>>= 32) into wX = rX
                //       (rX <<= 32; rX >>= 32)  into rX s32= rX
                if (pc >= insts.size() - 1) {
                    break;
                }
                const EbpfInst next = insts[pc + 1];
                auto dst = Reg{inst.dst};

                if (new_ins != shift32(dst, Bin::Op::LSH)) {
                    break;
                }

                if ((next.opcode & INST_CLS_MASK) != INST_CLS_ALU64) {
                    break;
                }
                auto next_ins = makeAluOp(pc + 1, next);
                if (next_ins == shift32(dst, Bin::Op::RSH)) {
                    new_ins = Bin{.op = Bin::Op::MOV, .dst = dst, .v = dst, .is64 = false};
                    skip_instruction = true;
                } else if (next_ins == shift32(dst, Bin::Op::ARSH)) {
                    new_ins = Bin{.op = Bin::Op::MOVSX32, .dst = dst, .v = dst, .is64 = true};
                    skip_instruction = true;
                }

                break;
            }

            case INST_CLS_JMP32:
            case INST_CLS_JMP: {
                new_ins = makeJmp(inst, insts, pc);
                if (std::holds_alternative<Exit>(new_ins)) {
                    fallthrough = false;
                    exit_count++;
                }
                if (const auto pjmp = std::get_if<Jmp>(&new_ins)) {
                    if (!pjmp->cond) {
                        fallthrough = false;
                    }
                }
                break;
            }
            default: CRAB_ERROR("invalid class: ", inst.opcode & INST_CLS_MASK);
            }
            if (pc == insts.size() - 1 && fallthrough) {
                note("fallthrough in last instruction");
            }

            std::optional<btf_line_info_t> current_line_info = {};

            if (options.verbosity_opts.print_line_info && pc < info.line_info.size()) {
                current_line_info = info.line_info.at(pc);
            }

            prog.emplace_back(Label(gsl::narrow<int>(pc)), new_ins, current_line_info);

            pc++;
            note_next_pc();
            if (skip_instruction) {
                pc++;
                note_next_pc();
            }
        }
        if (exit_count == 0) {
            note("no exit instruction");
        }
        return prog;
    }
};

std::variant<InstructionSeq, std::string> unmarshal(const RawProgram& raw_prog, vector<vector<string>>& notes,
                                                    const prevail::ebpf_verifier_options_t& options) {
    thread_local_program_info = raw_prog.info;
    try {
        return Unmarshaller{notes, raw_prog.info}.unmarshal(raw_prog.prog, options);
    } catch (InvalidInstruction& arg) {
        std::ostringstream ss;
        ss << arg.pc << ": " << arg.what() << "\n";
        return ss.str();
    }
}

std::variant<InstructionSeq, std::string> unmarshal(const RawProgram& raw_prog,
                                                    const prevail::ebpf_verifier_options_t& options) {
    vector<vector<string>> notes;
    return unmarshal(raw_prog, notes, options);
}

Call make_call(const int imm, const ebpf_platform_t& platform) {
    vector<vector<string>> notes;
    const ProgramInfo info{.platform = &platform};
    return Unmarshaller{notes, info}.makeCall(imm);
}
} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cassert>
#include <cinttypes>
#include <utility>
#include <vector>

#include "ir/syntax.hpp"
#include "platform.hpp"

using std::string;
using std::to_string;
using std::vector;

namespace prevail {
class AssertExtractor {
    const ProgramInfo& info;
    const std::optional<Label>& current_label; ///< Pre-simplification label this assert is part of.

    static Imm imm(const Value& v) { return std::get<Imm>(v); }

    static vector<Assertion> zero_offset_ctx(const Reg reg, const bool or_null) {
        vector<Assertion> res;
        res.emplace_back(TypeConstraint{reg, or_null ? TypeGroup::ctx_or_num : TypeGroup::ctx});
        res.emplace_back(ZeroCtxOffset{reg, or_null});
        return res;
    }

    [[nodiscard]]
    ValidAccess make_valid_access(const Reg reg, const int32_t offset = {}, const Value& width = Imm{0},
                                  const bool or_null = {}, const AccessType access_type = {}) const {
        const int depth = current_label.has_value() ? current_label.value().call_stack_depth() : 1;
        return ValidAccess{depth, reg, offset, width, or_null, access_type};
    }

  public:
    explicit AssertExtractor(const ProgramInfo& info, const std::optional<Label>& label)
        : info{info}, current_label{label} {}

    vector<Assertion> operator()(const Undefined&) const {
        // assert(false);
        return {};
    }

    vector<Assertion> operator()(const IncrementLoopCounter& ipc) const { return {{BoundedLoopCount{ipc.name}}}; }

    vector<Assertion> operator()(const LoadMapFd&) const { return {}; }
    vector<Assertion> operator()(const LoadMapAddress&) const { return {}; }
    // Rejected during CFG feature checks; assertion extraction should not receive this.
    vector<Assertion> operator()(const LoadPseudo&) const { return {}; }

    /// Packet access implicitly uses R6, so verify that R6 still has a pointer to the context.
    vector<Assertion> operator()(const Packet&) const { return zero_offset_ctx({6}, false); }

    vector<Assertion> operator()(const Exit&) const {
        vector<Assertion> res;
        if (current_label->stack_frame_prefix.empty()) {
            // Verify that Exit returns a number.
            res.emplace_back(TypeConstraint{Reg{R0_RETURN_VALUE}, TypeGroup::number});
        }
        return res;
    }

    vector<Assertion> operator()(const Call& call) const {
        vector<Assertion> res;
        std::optional<Reg> map_fd_reg;
        res.emplace_back(ValidCall{call.func, call.stack_frame_prefix});
        for (ArgSingle arg : call.singles) {
            switch (arg.kind) {
            case ArgSingle::Kind::ANYTHING:
                // avoid pointer leakage:
                if (!info.type.is_privileged) {
                    res.emplace_back(TypeConstraint{arg.reg, TypeGroup::number});
                }
                break;
            case ArgSingle::Kind::MAP_FD_PROGRAMS:
                res.emplace_back(TypeConstraint{arg.reg, TypeGroup::map_fd_programs});
                // Do not update map_fd_reg
                break;
            case ArgSingle::Kind::MAP_FD:
                res.emplace_back(TypeConstraint{arg.reg, TypeGroup::map_fd});
                map_fd_reg = arg.reg;
                break;
            case ArgSingle::Kind::PTR_TO_MAP_KEY:
            case ArgSingle::Kind::PTR_TO_MAP_VALUE:
                assert(map_fd_reg);
                res.emplace_back(TypeConstraint{arg.reg, TypeGroup::mem});
                res.emplace_back(ValidMapKeyValue{arg.reg, *map_fd_reg, arg.kind == ArgSingle::Kind::PTR_TO_MAP_KEY});
                break;
            case ArgSingle::Kind::PTR_TO_STACK:
                res.emplace_back(TypeConstraint{arg.reg, arg.or_null ? TypeGroup::stack_or_num : TypeGroup::stack});
                // TODO: check 0 when null
                break;
            case ArgSingle::Kind::PTR_TO_CTX:
                for (const Assertion& a : zero_offset_ctx(arg.reg, arg.or_null)) {
                    res.emplace_back(a);
                }
                break;
            }
        }
        for (ArgPair arg : call.pairs) {
            const auto group = arg.or_null ? TypeGroup::mem_or_num : TypeGroup::mem;
            const auto access_type =
                arg.kind == ArgPair::Kind::PTR_TO_READABLE_MEM ? AccessType::read : AccessType::write;
            res.emplace_back(TypeConstraint{arg.size, TypeGroup::number});
            res.emplace_back(ValidSize{arg.size, arg.can_be_zero});
            res.emplace_back(TypeConstraint{arg.mem, group});
            res.emplace_back(make_valid_access(arg.mem, 0, arg.size, arg.or_null, access_type));
            // TODO: reg is constant (or maybe it's not important)
        }
        return res;
    }

    vector<Assertion> operator()(const CallLocal&) const { return {}; }

    vector<Assertion> operator()(const Callx& callx) const {
        vector<Assertion> res;
        res.emplace_back(TypeConstraint{callx.func, TypeGroup::number});
        res.emplace_back(FuncConstraint{callx.func});
        return res;
    }

    // Rejected during CFG feature checks; assertion extraction should not receive this.
    vector<Assertion> operator()(const CallBtf&) const { return {}; }

    [[nodiscard]]
    vector<Assertion> explicate(const Condition& cond) const {
        vector<Assertion> res;
        if (info.type.is_privileged) {
            return res;
        }
        if (const auto pimm = std::get_if<Imm>(&cond.right)) {
            if (pimm->v != 0) {
                // no need to check for valid access, it must be a number
                res.emplace_back(TypeConstraint{cond.left, TypeGroup::number});
            } else {
                bool allow_pointers = false;

                switch (cond.op) {
                case Condition::Op::EQ: allow_pointers = true; break;
                case Condition::Op::NE: allow_pointers = true; break;
                case Condition::Op::SET: allow_pointers = true; break;
                case Condition::Op::NSET: allow_pointers = true; break;
                case Condition::Op::LT: allow_pointers = true; break;
                case Condition::Op::LE: allow_pointers = true; break;
                case Condition::Op::GT: allow_pointers = true; break;
                case Condition::Op::GE: allow_pointers = true; break;
                case Condition::Op::SLT: allow_pointers = false; break;
                case Condition::Op::SLE: allow_pointers = false; break;
                case Condition::Op::SGT: allow_pointers = false; break;
                case Condition::Op::SGE: allow_pointers = false; break;
                default: assert(!"unexpected condition");
                }

                // Only permit pointer comparisons if the operation is 64-bit.
                allow_pointers &= cond.is64;

                if (!allow_pointers) {
                    res.emplace_back(TypeConstraint{cond.left, TypeGroup::number});
                }

                res.emplace_back(make_valid_access(cond.left));
                // OK - map_fd is just another pointer
                // Anything can be compared to 0
            }
        } else {
            const auto reg_right = get<Reg>(cond.right);
            res.emplace_back(make_valid_access(cond.left));
            res.emplace_back(make_valid_access(reg_right));
            if (cond.op != Condition::Op::EQ && cond.op != Condition::Op::NE) {
                res.emplace_back(TypeConstraint{cond.left, TypeGroup::ptr_or_num});
            }
            res.emplace_back(Comparable{.r1 = cond.left, .r2 = reg_right, .or_r2_is_number = false});
        }
        return res;
    }

    vector<Assertion> operator()(const Assume& ins) const {
        if (!ins.is_implicit) {
            return explicate(ins.cond);
        }
        return {};
    }

    vector<Assertion> operator()(const Jmp& ins) const {
        if (!ins.cond) {
            return {};
        }
        return explicate(*ins.cond);
    }

    vector<Assertion> operator()(const Mem& ins) const {
        vector<Assertion> res;
        const Reg basereg = ins.access.basereg;
        Imm width{gsl::narrow<uint32_t>(ins.access.width)};
        const int offset = ins.access.offset;
        if (basereg.v == R10_STACK_POINTER) {
            // We know we are accessing the stack.
            if (offset < -EBPF_SUBPROGRAM_STACK_SIZE || offset + static_cast<int>(width.v) > 0) {
                // This assertion will fail
                res.emplace_back(make_valid_access(basereg, offset, width, false,
                                                   ins.is_load ? AccessType::read : AccessType::write));
            } else if (ins.is_load) {
                // This assertion is not for bound checks but for reading initialized memory.
                // TODO: avoid load assertions: use post-assertion to check that the loaded value is initialized
                // res.emplace_back(make_valid_access(basereg, offset, width, false, AccessType::read));
            }
        } else {
            res.emplace_back(TypeConstraint{basereg, TypeGroup::pointer});
            res.emplace_back(
                make_valid_access(basereg, offset, width, false, ins.is_load ? AccessType::read : AccessType::write));
            if (!info.type.is_privileged && !ins.is_load) {
                if (const auto preg = std::get_if<Reg>(&ins.value)) {
                    if (width.v != 8) {
                        res.emplace_back(TypeConstraint{*preg, TypeGroup::number});
                    } else {
                        res.emplace_back(ValidStore{ins.access.basereg, *preg});
                    }
                }
            }
        }
        return res;
    }

    vector<Assertion> operator()(const Atomic& ins) const {

        return {
            Assertion{TypeConstraint{ins.valreg, TypeGroup::number}},
            Assertion{TypeConstraint{ins.access.basereg, TypeGroup::pointer}},
            Assertion{make_valid_access(ins.access.basereg, ins.access.offset,
                                        Imm{static_cast<uint32_t>(ins.access.width)}, false)},
        };
    }

    vector<Assertion> operator()(const Un& ins) const {
        return {Assertion{TypeConstraint{ins.dst, TypeGroup::number}}};
    }

    vector<Assertion> operator()(const Bin& ins) const {
        switch (ins.op) {
        case Bin::Op::MOV:
            if (const auto src = std::get_if<Reg>(&ins.v)) {
                if (!ins.is64) {
                    return {Assertion{TypeConstraint{*src, TypeGroup::number}}};
                }
            }
            return {};
        case Bin::Op::MOVSX8:
        case Bin::Op::MOVSX16:
        case Bin::Op::MOVSX32:
            if (const auto src = std::get_if<Reg>(&ins.v)) {
                return {Assertion{TypeConstraint{*src, TypeGroup::number}}};
            }
            return {};
        case Bin::Op::ADD: {
            if (const auto src = std::get_if<Reg>(&ins.v)) {
                return {Assertion{TypeConstraint{ins.dst, TypeGroup::ptr_or_num}},
                        Assertion{TypeConstraint{*src, TypeGroup::ptr_or_num}}, Assertion{Addable{*src, ins.dst}},
                        Assertion{Addable{ins.dst, *src}}};
            }
            return {Assertion{TypeConstraint{ins.dst, TypeGroup::ptr_or_num}}};
        }
        case Bin::Op::SUB: {
            if (const auto reg = std::get_if<Reg>(&ins.v)) {
                // disallow map-map since same type does not mean same offset
                // TODO: map identities
                return {TypeConstraint{ins.dst, TypeGroup::ptr_or_num},
                        Comparable{.r1 = ins.dst, .r2 = *reg, .or_r2_is_number = true}};
            }
            return {Assertion{TypeConstraint{ins.dst, TypeGroup::ptr_or_num}}};
        }
        case Bin::Op::UDIV:
        case Bin::Op::UMOD:
        case Bin::Op::SDIV:
        case Bin::Op::SMOD: {
            if (const auto src = std::get_if<Reg>(&ins.v)) {
                const bool is_signed = (ins.op == Bin::Op::SDIV || ins.op == Bin::Op::SMOD);
                return {Assertion{TypeConstraint{ins.dst, TypeGroup::number}},
                        Assertion{ValidDivisor{*src, is_signed}}};
            }
            return {Assertion{TypeConstraint{ins.dst, TypeGroup::number}}};
        }
            // For all other binary operations, the destination register must be a number and the source must either be
            // an immediate or a number.
        default:
            if (const auto src = std::get_if<Reg>(&ins.v)) {
                return {Assertion{TypeConstraint{ins.dst, TypeGroup::number}},
                        Assertion{TypeConstraint{*src, TypeGroup::number}}};
            } else {
                return {Assertion{TypeConstraint{ins.dst, TypeGroup::number}}};
            }
        }
        assert(false);
    }
};

/// Annotate the CFG by adding explicit assertions for all the preconditions
/// of any instruction. For example, jump instructions are asserted not to
/// compare numbers and pointers, or pointers to potentially distinct memory
/// regions. The verifier will use these assertions to treat the program as
/// unsafe unless it can prove that the assertions can never fail.
vector<Assertion> get_assertions(const Instruction& ins, const ProgramInfo& info, const std::optional<Label>& label) {
    return std::visit(AssertExtractor{info, label}, ins);
}
} // namespace prevail

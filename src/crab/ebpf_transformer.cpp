// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.

#include <bitset>
#include <cassert>
#include <optional>
#include <utility>
#include <vector>

#include "boost/endian/conversion.hpp"

#include "arith/dsl_syntax.hpp"
#include "config.hpp"
#include "crab/array_domain.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/var_registry.hpp"
#include "crab_utils/num_safety.hpp"
#include "ir/unmarshal.hpp"
#include "platform.hpp"
#include "string_constraints.hpp"

namespace prevail {
class EbpfTransformer final {
    EbpfDomain& dom;
    // shorthands:
    ArrayDomain& stack;

  public:
    explicit EbpfTransformer(EbpfDomain& _dom) : dom(_dom), stack(_dom.stack) {}

    // abstract transformers
    void operator()(const Assume&);

    void operator()(const Atomic&);

    void operator()(const Bin&);

    void operator()(const Call&);

    void operator()(const CallLocal&);

    void operator()(const Callx&);
    void operator()(const CallBtf&);

    void operator()(const Exit&);

    void operator()(const IncrementLoopCounter&);

    void operator()(const Jmp&) const;

    void operator()(const LoadMapFd&);

    void operator()(const LoadMapAddress&);
    void operator()(const LoadPseudo&);

    void operator()(const Mem&);

    void operator()(const Packet&);

    void operator()(const Un&);

    void operator()(const Undefined&);

    void initialize_loop_counter(const Label& label);

  private:
    /// Forget everything about all offset variables for a given register.
    void scratch_caller_saved_registers();

    void save_callee_saved_registers(const std::string& prefix);

    void restore_callee_saved_registers(const std::string& prefix);

    void havoc_subprogram_stack(const std::string& prefix);

    void forget_packet_pointers();

    void do_load_mapfd(const Reg& dst_reg, int mapfd, bool maybe_null);

    void do_load_map_address(const Reg& dst_reg, int mapfd, int32_t offset);

    void assign_valid_ptr(const Reg& dst_reg, bool maybe_null);

    static void recompute_stack_numeric_size(TypeToNumDomain& state, ArrayDomain& stack, const Reg& reg);

    static void recompute_stack_numeric_size(TypeToNumDomain& state, const ArrayDomain& stack, Variable type_variable);

    static void do_load_stack(TypeToNumDomain& state, ArrayDomain& stack, const Reg& target_reg,
                              const LinearExpression& addr, int width, const Reg& src_reg);

    void do_load(const Mem& b, const Reg& target_reg);

    static void do_store_stack(TypeToNumDomain& state, ArrayDomain& stack, const LinearExpression& symb_addr,
                               int exact_width, const LinearExpression& val_svalue, const LinearExpression& val_uvalue,
                               const std::optional<Reg>& opt_val_reg);

    void do_mem_store(const Mem& b, const LinearExpression& val_svalue, const LinearExpression& val_uvalue,
                      const std::optional<Reg>& opt_val_reg);

    void add(const Reg& dst_reg, int imm, int finite_width);

    void shl(const Reg& dst_reg, int imm, int finite_width);

    void lshr(const Reg& dst_reg, int imm, int finite_width);

    void ashr(const Reg& dst_reg, const LinearExpression& right_svalue, int finite_width);
}; // end EbpfDomain

void ebpf_domain_transform(EbpfDomain& inv, const Instruction& ins) {
    if (inv.is_bottom()) {
        return;
    }
    const auto pre = inv;
    std::visit(EbpfTransformer{inv}, ins);
    if (inv.is_bottom() && !std::holds_alternative<Assume>(ins)) {
        // Fail. raise an exception to stop the analysis.
        std::stringstream msg;
        msg << "Bug! pre-invariant:\n"
            << pre << "\n followed by instruction: " << ins << "\n"
            << "leads to bottom";
        throw std::logic_error(msg.str());
    }
}

void EbpfTransformer::scratch_caller_saved_registers() {
    for (uint8_t i = R1_ARG; i <= R5_ARG; i++) {
        dom.state.havoc_register(Reg{i});
    }
}

/// Create variables specific to the new call stack frame that store
/// copies of the states of r6 through r9.
void EbpfTransformer::save_callee_saved_registers(const std::string& prefix) {
    // TODO: define location `stack_frame_var`, and pass to dom.state.assign().
    //       Similarly in restore_callee_saved_registers
    for (const Reg r : {Reg{R6}, Reg{R7}, Reg{R8}, Reg{R9}}) {
        if (dom.state.is_initialized(r)) {
            const Variable type_var = variable_registry->type_reg(r.v);
            dom.state.assign_type(variable_registry->stack_frame_var(DataKind::types, r.v, prefix), type_var);
            for (const TypeEncoding type : dom.state.iterate_types(r)) {
                auto kinds = type_to_kinds.at(type);
                kinds.push_back(DataKind::uvalues);
                kinds.push_back(DataKind::svalues);
                for (const DataKind kind : kinds) {
                    const Variable src_var = variable_registry->reg(kind, r.v);
                    const Variable dst_var = variable_registry->stack_frame_var(kind, r.v, prefix);
                    if (!dom.state.values.eval_interval(src_var).is_top()) {
                        dom.state.values.assign(dst_var, src_var);
                    }
                }
            }
        }
    }
}

void EbpfTransformer::restore_callee_saved_registers(const std::string& prefix) {
    for (uint8_t r = R6; r <= R9; r++) {
        Reg reg{r};
        const Variable type_var = variable_registry->stack_frame_var(DataKind::types, r, prefix);
        if (dom.state.is_initialized(type_var)) {
            dom.state.assign_type(reg, type_var);
            for (const TypeEncoding type : dom.state.iterate_types(reg)) {
                auto kinds = type_to_kinds.at(type);
                kinds.push_back(DataKind::uvalues);
                kinds.push_back(DataKind::svalues);
                for (const DataKind kind : kinds) {
                    const Variable src_var = variable_registry->stack_frame_var(kind, r, prefix);
                    const Variable dst_var = variable_registry->reg(kind, r);
                    if (!dom.state.values.eval_interval(src_var).is_top()) {
                        dom.state.values.assign(dst_var, src_var);
                    } else {
                        dom.state.values.havoc(dst_var);
                    }
                    dom.state.values.havoc(src_var);
                }
            }
        }
        dom.state.havoc_type(type_var);
    }
}

void EbpfTransformer::havoc_subprogram_stack(const std::string& prefix) {
    const Variable r10_stack_offset = reg_pack(R10_STACK_POINTER).stack_offset;
    const auto intv = dom.state.values.eval_interval(r10_stack_offset);
    if (!intv.is_singleton()) {
        return;
    }
    const int64_t stack_start = intv.singleton()->cast_to<int64_t>() - EBPF_SUBPROGRAM_STACK_SIZE;
    stack.havoc_type(dom.state.types, Interval{stack_start}, Interval{EBPF_SUBPROGRAM_STACK_SIZE});
    for (const DataKind kind : iterate_kinds()) {
        stack.havoc(dom.state.values, kind, Interval{stack_start}, Interval{EBPF_SUBPROGRAM_STACK_SIZE});
    }
}

void EbpfTransformer::forget_packet_pointers() {
    dom.state.havoc_all_locations_having_type(T_PACKET);
    dom.initialize_packet();
}

/** Linear constraint for a pointer comparison.
 */
static LinearConstraint assume_cst_offsets_reg(const Condition::Op op, const Variable dst_offset,
                                               const Variable src_offset) {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return eq(dst_offset, src_offset);
    case Op::NE: return neq(dst_offset, src_offset);
    case Op::GE: return dst_offset >= src_offset;
    case Op::SGE: return dst_offset >= src_offset; // pointer comparison is unsigned
    case Op::LE: return dst_offset <= src_offset;
    case Op::SLE: return dst_offset <= src_offset; // pointer comparison is unsigned
    case Op::GT: return dst_offset > src_offset;
    case Op::SGT: return dst_offset > src_offset; // pointer comparison is unsigned
    case Op::SLT: return src_offset > dst_offset;
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return src_offset > dst_offset; // FIX unsigned
    default: return dst_offset - dst_offset == 0;
    }
}

void EbpfTransformer::operator()(const Assume& s) {
    if (dom.is_bottom()) {
        return;
    }
    const Condition cond = s.cond;
    const auto dst = reg_pack(cond.left);
    if (const auto psrc_reg = std::get_if<Reg>(&cond.right)) {
        const auto src_reg = *psrc_reg;
        const auto src = reg_pack(src_reg);
        if (dom.state.same_type(cond.left, src_reg)) {
            dom.state = dom.state.join_over_types(cond.left, [&](TypeToNumDomain& state, const TypeEncoding type) {
                if (type == T_NUM) {
                    for (const LinearConstraint& cst : state.values->assume_cst_reg(
                             cond.op, cond.is64, dst.svalue, dst.uvalue, src.svalue, src.uvalue)) {
                        state.values.add_constraint(cst);
                    }
                } else {
                    // Either pointers to a singleton region,
                    // or an equality comparison on map descriptors/pointers to non-singleton locations
                    if (const auto dst_offset = get_type_offset_variable(cond.left, type)) {
                        if (const auto src_offset = get_type_offset_variable(src_reg, type)) {
                            state.values.add_constraint(
                                assume_cst_offsets_reg(cond.op, dst_offset.value(), src_offset.value()));
                        }
                    }
                }
            });
        } else if (dom.state.entail_type(reg_type(src_reg), T_NUM)) {
            // Different types but src is a number — apply only numeric constraints.
            // This does not split dst by concrete type via join_over_types: the numeric
            // constraints are applied to the global state across all type possibilities.
            // This is sound (pointer registers carry meaningful svalue/uvalue bounds)
            // but less precise than a type-split approach for non-numeric type paths.
            for (const LinearConstraint& cst :
                 dom.state.values->assume_cst_reg(cond.op, cond.is64, dst.svalue, dst.uvalue, src.svalue, src.uvalue)) {
                dom.state.values.add_constraint(cst);
            }
        } else {
            // Different types and src is not a number.
            // The checker may not have seen this Assume (e.g., implicit Assume or CFG-split edge),
            // so go to bottom conservatively.
            dom.state.set_to_bottom();
        }
    } else {
        const int64_t imm = gsl::narrow_cast<int64_t>(std::get<Imm>(cond.right).v);
        for (const LinearConstraint& cst :
             dom.state.values->assume_cst_imm(cond.op, cond.is64, dst.svalue, dst.uvalue, imm)) {
            dom.state.values.add_constraint(cst);
        }
    }
}

void EbpfTransformer::operator()(const Undefined& a) {}

// Rejected before abstract interpretation by cfg_builder::check_instruction_feature_support.
void EbpfTransformer::operator()(const CallBtf&) {
    assert(false && "CallBtf should be rejected before abstract transformation");
}

static uint64_t merge_imm32_to_u64(const int32_t lo, const int32_t hi) {
    return static_cast<uint64_t>(static_cast<uint32_t>(lo)) | (static_cast<uint64_t>(static_cast<uint32_t>(hi)) << 32);
}

void EbpfTransformer::operator()(const LoadPseudo& pseudo) {
    switch (pseudo.addr.kind) {
    case PseudoAddress::Kind::CODE_ADDR: {
        const auto dst = reg_pack(pseudo.dst);
        const uint64_t imm64 = merge_imm32_to_u64(pseudo.addr.imm, pseudo.addr.next_imm);
        dom.state.values.assign(dst.svalue, to_signed(imm64));
        dom.state.values.assign(dst.uvalue, imm64);
        dom.state.values->overflow_bounds(dst.uvalue, 64, false);
        dom.state.assign_type(pseudo.dst, T_FUNC);
        dom.state.havoc_offsets(pseudo.dst);
        return;
    }
    case PseudoAddress::Kind::VARIABLE_ADDR:
    case PseudoAddress::Kind::MAP_BY_IDX:
    case PseudoAddress::Kind::MAP_VALUE_BY_IDX:
        assert(false && "unexpected LoadPseudo kind during abstract transformation");
        return;
    }
}

// Simple truncation function usable with swap_endianness().
template <class T>
constexpr T truncate(T x) noexcept {
    return x;
}

void EbpfTransformer::operator()(const Un& stmt) {
    if (dom.is_bottom()) {
        return;
    }
    const auto dst = reg_pack(stmt.dst);
    auto swap_endianness = [&](const Variable v, auto be_or_le) {
        if (dom.state.is_in_group(stmt.dst, TS_NUM)) {
            if (const auto n = dom.state.values.eval_interval(v).singleton()) {
                if (n->fits_cast_to<int64_t>()) {
                    dom.state.values.set(v, Interval{be_or_le(n->cast_to<int64_t>())});
                    return;
                }
            }
        }
        dom.state.values.havoc(v);
        dom.state.havoc_offsets(stmt.dst);
    };
    // Swap bytes if needed.  For 64-bit types we need the weights to fit in a
    // signed int64, but for smaller types we don't want sign extension,
    // so we use unsigned which still fits in a signed int64.
    switch (stmt.op) {
    case Un::Op::BE16:
        if (!thread_local_options.big_endian) {
            swap_endianness(dst.svalue, boost::endian::endian_reverse<uint16_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint16_t>);
        } else {
            swap_endianness(dst.svalue, truncate<uint16_t>);
            swap_endianness(dst.uvalue, truncate<uint16_t>);
        }
        break;
    case Un::Op::BE32:
        if (!thread_local_options.big_endian) {
            swap_endianness(dst.svalue, boost::endian::endian_reverse<uint32_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint32_t>);
        } else {
            swap_endianness(dst.svalue, truncate<uint32_t>);
            swap_endianness(dst.uvalue, truncate<uint32_t>);
        }
        break;
    case Un::Op::BE64:
        if (!thread_local_options.big_endian) {
            swap_endianness(dst.svalue, boost::endian::endian_reverse<int64_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint64_t>);
        }
        break;
    case Un::Op::LE16:
        if (thread_local_options.big_endian) {
            swap_endianness(dst.svalue, boost::endian::endian_reverse<uint16_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint16_t>);
        } else {
            swap_endianness(dst.svalue, truncate<uint16_t>);
            swap_endianness(dst.uvalue, truncate<uint16_t>);
        }
        break;
    case Un::Op::LE32:
        if (thread_local_options.big_endian) {
            swap_endianness(dst.svalue, boost::endian::endian_reverse<uint32_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint32_t>);
        } else {
            swap_endianness(dst.svalue, truncate<uint32_t>);
            swap_endianness(dst.uvalue, truncate<uint32_t>);
        }
        break;
    case Un::Op::LE64:
        if (thread_local_options.big_endian) {
            swap_endianness(dst.svalue, boost::endian::endian_reverse<int64_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint64_t>);
        }
        break;
    case Un::Op::SWAP16:
        swap_endianness(dst.svalue, boost::endian::endian_reverse<uint16_t>);
        swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint16_t>);
        break;
    case Un::Op::SWAP32:
        swap_endianness(dst.svalue, boost::endian::endian_reverse<uint32_t>);
        swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint32_t>);
        break;
    case Un::Op::SWAP64:
        swap_endianness(dst.svalue, boost::endian::endian_reverse<int64_t>);
        swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint64_t>);
        break;
    case Un::Op::NEG:
        dom.state.values->neg(dst.svalue, dst.uvalue, stmt.is64 ? 64 : 32);
        dom.state.havoc_offsets(stmt.dst);
        break;
    }
}

void EbpfTransformer::operator()(const Exit& a) {
    if (dom.is_bottom()) {
        return;
    }
    // Clean up any state for the current stack frame.
    const std::string prefix = a.stack_frame_prefix;
    if (prefix.empty()) {
        return;
    }
    havoc_subprogram_stack(prefix);
    restore_callee_saved_registers(prefix);

    // Restore r10.
    constexpr Reg r10_reg{R10_STACK_POINTER};
    add(r10_reg, EBPF_SUBPROGRAM_STACK_SIZE, 64);

    // Scratch r1-r5: the callee may have clobbered them (caller-saved per BPF ABI).
    scratch_caller_saved_registers();
}

void EbpfTransformer::operator()(const Jmp&) const {
    // This is a NOP. It only exists to hold the jump preconditions.
}

void EbpfTransformer::operator()(const Packet& a) {
    if (dom.is_bottom()) {
        return;
    }
    constexpr Reg r0_reg{R0_RETURN_VALUE};
    dom.state.havoc_register_except_type(r0_reg);
    dom.state.assign_type(r0_reg, T_NUM);
    scratch_caller_saved_registers();
}

void EbpfTransformer::do_load_stack(TypeToNumDomain& state, ArrayDomain& stack, const Reg& target_reg,
                                    const LinearExpression& symb_addr, const int width, const Reg& src_reg) {
    const Interval addr = state.values.eval_interval(symb_addr);
    using namespace dsl_syntax;
    if (state.values.entail(width <= reg_pack(src_reg).stack_numeric_size)) {
        state.assign_type(target_reg, T_NUM);
    } else {
        state.assign_type(target_reg, stack.load_type(addr, width));
        if (!state.is_initialized(target_reg)) {
            // We don't know what we loaded, so just havoc the destination register.
            state.havoc_register(target_reg);
            return;
        }
    }

    const RegPack& target = reg_pack(target_reg);
    if (width == 1 || width == 2 || width == 4 || width == 8) {
        // Use the addr before we havoc the destination register since we might be getting the
        // addr from that same register.
        const std::optional<LinearExpression> sresult = stack.load(state.values, DataKind::svalues, addr, width);
        const std::optional<LinearExpression> uresult = stack.load(state.values, DataKind::uvalues, addr, width);
        state.havoc_register_except_type(target_reg);
        state.values.assign(target.svalue, sresult);
        state.values.assign(target.uvalue, uresult);
        for (const TypeEncoding type : state.iterate_types(target_reg)) {
            for (const auto& kind : type_to_kinds.at(type)) {
                const Variable dst_var = variable_registry->reg(kind, target_reg.v);
                state.values.assign(dst_var, stack.load(state.values, kind, addr, width));
            }
        }
    } else {
        state.havoc_register_except_type(target_reg);
    }
}

static void do_load_ctx(TypeToNumDomain& state, const Reg& target_reg, const LinearExpression& addr_vague,
                        const int width) {
    using namespace dsl_syntax;
    if (state.values.is_bottom()) {
        return;
    }

    const ebpf_context_descriptor_t* desc = thread_local_program_info->type.context_descriptor;

    const RegPack& target = reg_pack(target_reg);

    if (desc->end < 0) {
        state.havoc_register(target_reg);
        state.assign_type(target_reg, T_NUM);
        return;
    }

    const Interval interval = state.values.eval_interval(addr_vague);
    const std::optional<Number> maybe_addr = interval.singleton();
    state.havoc_register(target_reg);

    const bool may_touch_ptr =
        interval.contains(desc->data) || interval.contains(desc->meta) || interval.contains(desc->end);

    if (!maybe_addr) {
        if (may_touch_ptr) {
            state.havoc_type(target_reg);
        } else {
            state.assign_type(target_reg, T_NUM);
        }
        return;
    }

    const Number& addr = *maybe_addr;

    // We use offsets for packet data, data_end, and meta during verification,
    // but at runtime they will be 64-bit pointers.  We can use the offset values
    // for verification like we use map_fd's as a proxy for maps which
    // at runtime are actually 64-bit memory pointers.
    const int offset_width = desc->end - desc->data;
    if (addr == desc->data) {
        if (width == offset_width) {
            state.values.assign(target.packet_offset, 0);
        }
    } else if (addr == desc->end) {
        if (width == offset_width) {
            state.values.assign(target.packet_offset, variable_registry->packet_size());
            // EXPERIMENTAL: Explicit upper bound since packet_size is min_only.
            // This preserves the relational constraint (packet_offset <= packet_size)
            // while ensuring comparison checks have a concrete upper bound.
            state.values.add_constraint(target.packet_offset < MAX_PACKET_SIZE);
        }
    } else if (addr == desc->meta) {
        if (width == offset_width) {
            state.values.assign(target.packet_offset, variable_registry->meta_offset());
        }
    } else {
        if (may_touch_ptr) {
            state.havoc_type(target_reg);
        } else {
            state.assign_type(target_reg, T_NUM);
        }
        return;
    }
    if (width == offset_width) {
        state.assign_type(target_reg, T_PACKET);
        state.values.add_constraint(4098 <= target.svalue);
        state.values.add_constraint(target.svalue <= PTR_MAX);
    }
}

static void do_load_packet_or_shared(TypeToNumDomain& state, const Reg& target_reg, const int width,
                                     const bool is_signed) {
    if (state.values.is_bottom()) {
        return;
    }
    const RegPack& target = reg_pack(target_reg);

    state.havoc_register(target_reg);
    state.assign_type(target_reg, T_NUM);

    // Small copies can be range-limited and useful for later arithmetic.
    if (is_signed && (width == 1 || width == 2 || width == 4)) {
        state.values.set(target.svalue, Interval::signed_int(width * 8));
        state.values.set(target.uvalue, Interval::unsigned_int(width * 8));
    } else if (width == 1 || width == 2) {
        const Interval full = Interval::unsigned_int(width * 8);
        state.values.set(target.svalue, full);
        state.values.set(target.uvalue, full);
    }
}

void EbpfTransformer::do_load(const Mem& b, const Reg& target_reg) {
    using namespace dsl_syntax;

    const auto mem_reg = reg_pack(b.access.basereg);
    const int width = b.access.width;
    const int offset = b.access.offset;

    if (b.access.basereg.v == R10_STACK_POINTER) {
        const LinearExpression addr = mem_reg.stack_offset + offset;
        do_load_stack(dom.state, stack, target_reg, addr, width, b.access.basereg);
        return;
    }
    dom.state = dom.state.join_over_types(b.access.basereg, [&](TypeToNumDomain& state, TypeEncoding type) {
        switch (type) {
        case T_UNINIT: return;
        case T_MAP: return;
        case T_MAP_PROGRAMS: return;
        case T_NUM: return;
        case T_FUNC: return;
        case T_CTX: {
            LinearExpression addr = mem_reg.ctx_offset + offset;
            do_load_ctx(state, target_reg, addr, width);
            break;
        }
        case T_STACK: {
            LinearExpression addr = mem_reg.stack_offset + offset;
            do_load_stack(state, stack, target_reg, addr, width, b.access.basereg);
            break;
        }
        case T_PACKET: {
            LinearExpression addr = mem_reg.packet_offset + offset;
            do_load_packet_or_shared(state, target_reg, width, b.is_signed);
            break;
        }
        case T_SHARED: {
            LinearExpression addr = mem_reg.shared_offset + offset;
            do_load_packet_or_shared(state, target_reg, width, b.is_signed);
            break;
        }
        case T_SOCKET:
        case T_BTF_ID:
        case T_ALLOC_MEM: {
            // TODO: implement proper load semantics for these pointer types.
            // For now, treat like packet/shared (havoc the result).
            do_load_packet_or_shared(state, target_reg, width, b.is_signed);
            break;
        }
        }
    });
}

void EbpfTransformer::do_store_stack(TypeToNumDomain& state, ArrayDomain& stack, const LinearExpression& symb_addr,
                                     const int exact_width, const LinearExpression& val_svalue,
                                     const LinearExpression& val_uvalue, const std::optional<Reg>& opt_val_reg) {
    const Interval addr = state.values.eval_interval(symb_addr);
    const Interval width{exact_width};
    // no aliasing of val - we don't move from stack to stack, so we can just havoc first
    stack.havoc_type(state.types, addr, width);
    for (const DataKind kind : iterate_kinds()) {
        if (kind == DataKind::svalues || kind == DataKind::uvalues) {
            continue;
        }
        stack.havoc(state.values, kind, addr, width);
    }
    bool must_be_num = false;
    if (opt_val_reg && !state.is_initialized(*opt_val_reg)) {
        stack.havoc(state.values, DataKind::svalues, addr, width);
        stack.havoc(state.values, DataKind::uvalues, addr, width);
    } else {
        // opt_val_reg is unset when storing an immediate value.
        must_be_num = !opt_val_reg || state.is_in_group(*opt_val_reg, TS_NUM);
        const LinearExpression val_type =
            must_be_num ? LinearExpression{T_NUM} : variable_registry->type_reg(opt_val_reg->v);
        state.assign_type(stack.store_type(state.types, addr, width, must_be_num), val_type);

        if (exact_width == 8) {
            stack.havoc(state.values, DataKind::svalues, addr, width);
            stack.havoc(state.values, DataKind::uvalues, addr, width);
            state.values.assign(stack.store(state.values, DataKind::svalues, addr, width), val_svalue);
            state.values.assign(stack.store(state.values, DataKind::uvalues, addr, width), val_uvalue);

            if (!must_be_num) {
                for (TypeEncoding type : state.iterate_types(*opt_val_reg)) {
                    for (const DataKind kind : type_to_kinds.at(type)) {
                        const Variable src_var = variable_registry->reg(kind, opt_val_reg->v);
                        state.values.assign(stack.store(state.values, kind, addr, width), src_var);
                    }
                }
            }
        } else if ((exact_width == 1 || exact_width == 2 || exact_width == 4) && must_be_num) {
            // Keep track of numbers on the stack that might be used as array indices.
            if (const auto stack_svalue = stack.store(state.values, DataKind::svalues, addr, width)) {
                state.values.assign(stack_svalue, val_svalue);
                state.values->overflow_bounds(*stack_svalue, exact_width * 8, true);
            } else {
                stack.havoc(state.values, DataKind::svalues, addr, width);
            }
            if (const auto stack_uvalue = stack.store(state.values, DataKind::uvalues, addr, width)) {
                state.values.assign(stack_uvalue, val_uvalue);
                state.values->overflow_bounds(*stack_uvalue, exact_width * 8, false);
            } else {
                stack.havoc(state.values, DataKind::uvalues, addr, width);
            }
        } else {
            stack.havoc(state.values, DataKind::svalues, addr, width);
            stack.havoc(state.values, DataKind::uvalues, addr, width);
        }
    }

    // Update stack_numeric_size for any stack type variables.
    // stack_numeric_size holds the number of continuous bytes starting from stack_offset that are known to be numeric.
    for (const Variable type_variable : variable_registry->get_type_variables()) {
        if (!state.is_initialized(type_variable) || !state.may_have_type(type_variable, T_STACK)) {
            continue;
        }
        const Variable stack_offset_variable = variable_registry->kind_var(DataKind::stack_offsets, type_variable);
        const Variable stack_numeric_size_variable =
            variable_registry->kind_var(DataKind::stack_numeric_sizes, type_variable);

        using namespace dsl_syntax;
        // See if the variable's numeric interval overlaps with changed bytes.
        if (state.values.intersect(
                dsl_syntax::operator<=(symb_addr, stack_offset_variable + stack_numeric_size_variable)) &&
            state.values.intersect(dsl_syntax::operator>=(symb_addr + exact_width, stack_offset_variable))) {
            if (!must_be_num) {
                state.values.havoc(stack_numeric_size_variable);
            }
            recompute_stack_numeric_size(state, stack, type_variable);
        }
    }
}

void EbpfTransformer::operator()(const Mem& b) {
    if (dom.is_bottom()) {
        return;
    }
    if (const auto preg = std::get_if<Reg>(&b.value)) {
        if (b.is_load) {
            do_load(b, *preg);
            if (b.is_signed) {
                Bin::Op op{};
                // MEMSX decode only allows widths 1/2/4. Programmatic Mem construction paths
                // (for example from Atomic lowering) do not set is_signed=true.
                switch (b.access.width) {
                case 1: op = Bin::Op::MOVSX8; break;
                case 2: op = Bin::Op::MOVSX16; break;
                case 4: op = Bin::Op::MOVSX32; break;
                default: CRAB_ERROR("unexpected MEMSX width", b.access.width);
                }
                (*this)(Bin{.op = op, .dst = *preg, .v = *preg, .is64 = true, .lddw = false});
            }
        } else {
            const auto data_reg = reg_pack(*preg);
            do_mem_store(b, data_reg.svalue, data_reg.uvalue, *preg);
        }
    } else {
        const uint64_t imm = std::get<Imm>(b.value).v;
        do_mem_store(b, to_signed(imm), imm, {});
    }
}

void EbpfTransformer::do_mem_store(const Mem& b, const LinearExpression& val_svalue, const LinearExpression& val_uvalue,
                                   const std::optional<Reg>& opt_val_reg) {
    if (dom.is_bottom()) {
        return;
    }
    const int width = b.access.width;
    const Number offset{b.access.offset};
    if (b.access.basereg.v == R10_STACK_POINTER) {
        const auto r10_stack_offset = reg_pack(b.access.basereg).stack_offset;
        const auto r10_interval = dom.state.values.eval_interval(r10_stack_offset);
        if (r10_interval.is_singleton()) {
            const int32_t stack_offset = r10_interval.singleton()->cast_to<int32_t>();
            const Number base_addr{stack_offset};
            do_store_stack(dom.state, stack, base_addr + offset, width, val_svalue, val_uvalue, opt_val_reg);
            return;
        }
    }
    dom.state = dom.state.join_over_types(b.access.basereg, [&](TypeToNumDomain& state, const TypeEncoding type) {
        if (type == T_STACK) {
            const auto base_addr = LinearExpression(reg_pack(b.access.basereg).stack_offset);
            do_store_stack(state, stack, dsl_syntax::operator+(base_addr, offset), width, val_svalue, val_uvalue,
                           opt_val_reg);
        }
        // do nothing for any other type
    });
}

// Construct a Bin operation that does the main operation that a given Atomic operation does atomically.
static Bin atomic_to_bin(const Atomic& a) {
    Bin bin{.dst = Reg{R11_ATOMIC_SCRATCH}, .v = a.valreg, .is64 = a.access.width == sizeof(uint64_t), .lddw = false};
    switch (a.op) {
    case Atomic::Op::ADD: bin.op = Bin::Op::ADD; break;
    case Atomic::Op::OR: bin.op = Bin::Op::OR; break;
    case Atomic::Op::AND: bin.op = Bin::Op::AND; break;
    case Atomic::Op::XOR: bin.op = Bin::Op::XOR; break;
    case Atomic::Op::XCHG:
    case Atomic::Op::CMPXCHG: bin.op = Bin::Op::MOV; break;
    default: throw std::exception();
    }
    return bin;
}

void EbpfTransformer::operator()(const Atomic& a) {
    if (dom.is_bottom()) {
        return;
    }
    if (!dom.state.is_in_group(a.access.basereg, TS_POINTER) || !dom.state.is_in_group(a.valreg, TS_NUM)) {
        return;
    }
    if (!dom.state.may_have_type(a.access.basereg, T_STACK)) {
        // Shared memory regions are volatile so we can just havoc
        // any register that will be updated.
        if (a.op == Atomic::Op::CMPXCHG) {
            dom.state.havoc_register_except_type(Reg{R0_RETURN_VALUE});
        } else if (a.fetch) {
            dom.state.havoc_register_except_type(a.valreg);
        }
        return;
    }

    // Fetch the current value into the R11 pseudo-register.
    constexpr Reg r11{R11_ATOMIC_SCRATCH};
    (*this)(Mem{.access = a.access, .value = r11, .is_load = true});

    // Compute the new value in R11.
    (*this)(atomic_to_bin(a));

    if (a.op == Atomic::Op::CMPXCHG) {
        // For CMPXCHG, store the original value in r0.
        (*this)(Mem{.access = a.access, .value = Reg{R0_RETURN_VALUE}, .is_load = true});

        // For the destination, there are 3 possibilities:
        // 1) dst.value == r0.value : set R11 to valreg
        // 2) dst.value != r0.value : don't modify R11
        // 3) dst.value may or may not == r0.value : set R11 to the union of R11 and valreg
        // For now we just havoc the value of R11.
        dom.state.havoc_register_except_type(r11);
    } else if (a.fetch) {
        // For other FETCH operations, store the original value in the src register.
        (*this)(Mem{.access = a.access, .value = a.valreg, .is_load = true});
    }

    // Store the new value back in the original shared memory location.
    // Note that do_mem_store() currently doesn't track shared memory values,
    // but stack memory values are tracked and are legal here.
    (*this)(Mem{.access = a.access, .value = r11, .is_load = false});

    // Clear the R11 pseudo-register.
    dom.state.havoc_register(r11);
}

void EbpfTransformer::operator()(const Call& call) {
    using namespace dsl_syntax;
    if (dom.is_bottom()) {
        return;
    }
    std::optional<Reg> maybe_fd_reg{};
    for (ArgSingle param : call.singles) {
        switch (param.kind) {
        case ArgSingle::Kind::MAP_FD: maybe_fd_reg = param.reg; break;
        case ArgSingle::Kind::ANYTHING:
        case ArgSingle::Kind::MAP_FD_PROGRAMS:
        case ArgSingle::Kind::PTR_TO_MAP_KEY:
        case ArgSingle::Kind::PTR_TO_MAP_VALUE:
        case ArgSingle::Kind::PTR_TO_FUNC:
        case ArgSingle::Kind::PTR_TO_CTX:
        case ArgSingle::Kind::PTR_TO_SOCKET:
        case ArgSingle::Kind::PTR_TO_BTF_ID:
        case ArgSingle::Kind::PTR_TO_ALLOC_MEM:
        case ArgSingle::Kind::PTR_TO_SPIN_LOCK:
        case ArgSingle::Kind::PTR_TO_TIMER:
        case ArgSingle::Kind::CONST_SIZE_OR_ZERO:
            // Do nothing. We don't track the content of relevant memory regions.
            break;
        case ArgSingle::Kind::PTR_TO_STACK:
            // Do nothing; the stack is passed as context, not to be modified.
            break;
        case ArgSingle::Kind::PTR_TO_WRITABLE_LONG:
        case ArgSingle::Kind::PTR_TO_WRITABLE_INT: {
            // Fixed-width writable pointer: the helper may store a number at the pointed-to location.
            const int width = param.kind == ArgSingle::Kind::PTR_TO_WRITABLE_LONG ? 8 : 4;
            Interval w{width};
            dom.state = dom.state.join_over_types(param.reg, [&](TypeToNumDomain& state, const TypeEncoding type) {
                // Branch over possible pointer *types* for this register. This is separate from
                // uncertainty over regions/offsets within one type (e.g., many shared regions).
                if (type == T_STACK) {
                    const auto offset = get_type_offset_variable(param.reg, type);
                    if (!offset.has_value()) {
                        return;
                    }
                    const Interval addr = state.values.eval_interval(*offset);
                    for (const DataKind kind : iterate_kinds()) {
                        stack.havoc(state.values, kind, addr, w);
                    }
                    // Keep this scoped to stack-typed pointers only.
                    stack.store_numbers(addr, w);
                }
            });
            break;
        }
        }
    }
    for (ArgPair param : call.pairs) {
        switch (param.kind) {
        case ArgPair::Kind::PTR_TO_READABLE_MEM:
            // Do nothing. No side effect allowed.
            break;

        case ArgPair::Kind::PTR_TO_WRITABLE_MEM: {
            bool store_numbers = true;
            auto variable = dom.state.get_type_offset_variable(param.mem);
            if (!variable.has_value()) {
                // checked by the checker
                break;
            }
            Interval addr = dom.state.values.eval_interval(variable.value());
            Interval width = dom.state.values.eval_interval(reg_pack(param.size).svalue);

            dom.state = dom.state.join_over_types(param.mem, [&](TypeToNumDomain& state, const TypeEncoding type) {
                if (type == T_STACK) {
                    // Pointer to a memory region that the called function may change,
                    // so we must havoc.
                    for (const DataKind kind : iterate_kinds()) {
                        stack.havoc(state.values, kind, addr, width);
                    }
                } else {
                    store_numbers = false;
                }
            });
            if (store_numbers) {
                // Functions are not allowed to write sensitive data,
                // and initialization is guaranteed
                stack.store_numbers(addr, width);
            }
        }
        }
    }

    constexpr Reg r0_reg{R0_RETURN_VALUE};
    const auto r0_pack = reg_pack(r0_reg);
    dom.state.values.havoc(r0_pack.stack_numeric_size);
    // Set r0 as a nullable T_SHARED pointer at offset 0.
    // If region_size is known, constrain it; otherwise havoc to prevent stale values.
    auto assign_shared_map_value = [&](const std::optional<Interval>& region_size) {
        assign_valid_ptr(r0_reg, true);
        dom.state.values.assign(r0_pack.shared_offset, 0);
        if (region_size) {
            dom.state.values.set(r0_pack.shared_region_size, *region_size);
        } else {
            dom.state.values.havoc(r0_pack.shared_region_size);
        }
        dom.state.assign_type(r0_reg, T_SHARED);
    };
    auto resolve_map_lookup = [&] {
        // Map lookup is the only way to get a null pointer.
        if (!maybe_fd_reg) {
            assign_shared_map_value(std::nullopt);
            return;
        }
        const auto map_type = dom.get_map_type(*maybe_fd_reg);
        if (!map_type) {
            assign_shared_map_value(std::nullopt);
            return;
        }
        if (thread_local_program_info->platform->get_map_type(*map_type).value_type == EbpfMapValueType::MAP) {
            // Map-of-maps: r0 is an inner map fd if known, otherwise an opaque shared pointer.
            if (const auto inner_map_fd = dom.get_map_inner_map_fd(*maybe_fd_reg)) {
                do_load_mapfd(r0_reg, to_signed(*inner_map_fd), true);
            } else {
                assign_shared_map_value(std::nullopt);
            }
            return;
        }
        // Regular map: r0 is a shared pointer with known value size.
        assign_shared_map_value(dom.get_map_value_size(*maybe_fd_reg));
    };
    if (call.is_map_lookup) {
        resolve_map_lookup();
    } else if (call.return_ptr_type.has_value()) {
        assign_valid_ptr(r0_reg, call.return_nullable);
        dom.state.assign_type(r0_reg, *call.return_ptr_type);
        if (*call.return_ptr_type == T_ALLOC_MEM && call.alloc_size_reg.has_value()) {
            // Propagate allocation bounds: offset starts at 0, size is the allocation size argument.
            dom.state.values.assign(r0_pack.alloc_mem_offset, 0);
            const auto size_value = dom.state.values.eval_interval(reg_pack(*call.alloc_size_reg).uvalue);
            dom.state.values.set(r0_pack.alloc_mem_size, size_value);
        } else {
            dom.state.havoc_offsets(r0_reg);
        }
    } else {
        dom.state.havoc_register_except_type(r0_reg);
        dom.state.assign_type(r0_reg, T_NUM);
        // dom.state.values.add_constraint(r0_pack.value < 0); for INTEGER_OR_NO_RETURN_IF_SUCCEED.
    }
    scratch_caller_saved_registers();
    if (call.reallocate_packet) {
        forget_packet_pointers();
    }
}

void EbpfTransformer::operator()(const CallLocal& call) {
    using namespace dsl_syntax;
    if (dom.is_bottom()) {
        return;
    }
    save_callee_saved_registers(call.stack_frame_prefix);

    // Update r10.
    constexpr Reg r10_reg{R10_STACK_POINTER};
    add(r10_reg, -EBPF_SUBPROGRAM_STACK_SIZE, 64);
}

void EbpfTransformer::operator()(const Callx& callx) {
    using namespace dsl_syntax;
    if (dom.is_bottom()) {
        return;
    }

    // Look up the helper function id.
    const RegPack& reg = reg_pack(callx.func);
    const auto src_interval = dom.state.values.eval_interval(reg.svalue);
    if (const auto sn = src_interval.singleton()) {
        if (sn->fits<int32_t>()) {
            // We can now process it as if the id was immediate.
            const int32_t imm = sn->cast_to<int32_t>();
            if (!thread_local_program_info->platform->is_helper_usable(imm)) {
                return;
            }
            const Call call = make_call(imm, *thread_local_program_info->platform);
            (*this)(call);
        }
    }
}

void EbpfTransformer::do_load_mapfd(const Reg& dst_reg, const int mapfd, const bool maybe_null) {
    const EbpfMapDescriptor& desc = thread_local_program_info->platform->get_map_descriptor(mapfd);
    const EbpfMapType& type = thread_local_program_info->platform->get_map_type(desc.type);
    const RegPack& dst = reg_pack(dst_reg);
    if (type.value_type == EbpfMapValueType::PROGRAM) {
        dom.state.assign_type(dst_reg, T_MAP_PROGRAMS);
        dom.state.values.assign(dst.map_fd_programs, mapfd);
    } else {
        dom.state.assign_type(dst_reg, T_MAP);
        dom.state.values.assign(dst.map_fd, mapfd);
    }
    assign_valid_ptr(dst_reg, maybe_null);
}

void EbpfTransformer::operator()(const LoadMapFd& ins) {
    if (dom.is_bottom()) {
        return;
    }
    do_load_mapfd(ins.dst, ins.mapfd, false);
}

void EbpfTransformer::do_load_map_address(const Reg& dst_reg, const int mapfd, const int32_t offset) {
    const EbpfMapDescriptor& desc = thread_local_program_info->platform->get_map_descriptor(mapfd);
    const EbpfMapType& type = thread_local_program_info->platform->get_map_type(desc.type);

    if (type.value_type == EbpfMapValueType::PROGRAM) {
        throw std::invalid_argument("Cannot load address of program map type - only data maps are supported");
    }

    // Set the shared region size and offset for the map.
    dom.state.assign_type(dst_reg, T_SHARED);
    const RegPack& dst = reg_pack(dst_reg);
    dom.state.values.assign(dst.shared_offset, offset);
    dom.state.values.assign(dst.shared_region_size, desc.value_size);
    assign_valid_ptr(dst_reg, false);
}

void EbpfTransformer::operator()(const LoadMapAddress& ins) {
    if (dom.is_bottom()) {
        return;
    }
    do_load_map_address(ins.dst, ins.mapfd, ins.offset);
}

void EbpfTransformer::assign_valid_ptr(const Reg& dst_reg, const bool maybe_null) {
    using namespace dsl_syntax;
    const RegPack& reg = reg_pack(dst_reg);
    dom.state.values.havoc(reg.svalue);
    dom.state.values.havoc(reg.uvalue);
    if (maybe_null) {
        dom.state.values.add_constraint(0 <= reg.svalue);
    } else {
        dom.state.values.add_constraint(0 < reg.svalue);
    }
    dom.state.values.add_constraint(reg.svalue <= PTR_MAX);
    dom.state.values.assign(reg.uvalue, reg.svalue);
}

// If nothing is known of the stack_numeric_size,
// try to recompute the stack_numeric_size.
void EbpfTransformer::recompute_stack_numeric_size(TypeToNumDomain& state, const ArrayDomain& stack,
                                                   const Variable type_variable) {
    const Variable stack_numeric_size_variable =
        variable_registry->kind_var(DataKind::stack_numeric_sizes, type_variable);

    if (state.may_have_type(type_variable, T_STACK)) {
        const int numeric_size =
            stack.min_all_num_size(state.values, variable_registry->kind_var(DataKind::stack_offsets, type_variable));
        if (numeric_size > 0) {
            state.values.assign(stack_numeric_size_variable, numeric_size);
        }
    }
}

void EbpfTransformer::recompute_stack_numeric_size(TypeToNumDomain& state, ArrayDomain& stack, const Reg& reg) {
    recompute_stack_numeric_size(state, stack, reg_type(reg));
}

void EbpfTransformer::add(const Reg& dst_reg, const int imm, const int finite_width) {
    const auto dst = reg_pack(dst_reg);
    dom.state.values->add_overflow(dst.svalue, dst.uvalue, imm, finite_width);
    if (const auto offset = dom.state.get_type_offset_variable(dst_reg)) {
        dom.state.values->add(*offset, imm);
        if (imm > 0) {
            // Since the start offset is increasing but
            // the end offset is not, the numeric size decreases.
            dom.state.values->sub(dst.stack_numeric_size, imm);
        } else if (imm < 0) {
            dom.state.values.havoc(dst.stack_numeric_size);
        }
        recompute_stack_numeric_size(dom.state, stack, dst_reg);
    }
}

void EbpfTransformer::shl(const Reg& dst_reg, int imm, const int finite_width) {
    dom.state.havoc_offsets(dst_reg);

    // The BPF ISA requires masking the imm.
    imm &= finite_width - 1;
    const RegPack dst = reg_pack(dst_reg);
    if (dom.state.is_in_group(dst_reg, TS_NUM)) {
        dom.state.values->shl(dst.svalue, dst.uvalue, imm, finite_width);
    } else {
        dom.state.values.havoc(dst.svalue);
        dom.state.values.havoc(dst.uvalue);
    }
}

void EbpfTransformer::lshr(const Reg& dst_reg, int imm, int finite_width) {
    dom.state.havoc_offsets(dst_reg);

    // The BPF ISA requires masking the imm.
    imm &= finite_width - 1;
    const RegPack dst = reg_pack(dst_reg);
    if (dom.state.is_in_group(dst_reg, TS_NUM)) {
        dom.state.values->lshr(dst.svalue, dst.uvalue, imm, finite_width);
    } else {
        dom.state.values.havoc(dst.svalue);
        dom.state.values.havoc(dst.uvalue);
    }
}

void EbpfTransformer::ashr(const Reg& dst_reg, const LinearExpression& right_svalue, const int finite_width) {
    dom.state.havoc_offsets(dst_reg);

    const RegPack dst = reg_pack(dst_reg);
    if (dom.state.is_in_group(dst_reg, TS_NUM)) {
        dom.state.values->ashr(dst.svalue, dst.uvalue, right_svalue, finite_width);
    } else {
        dom.state.values.havoc(dst.svalue);
        dom.state.values.havoc(dst.uvalue);
    }
}

static int _movsx_bits(const Bin::Op op) {
    switch (op) {
    case Bin::Op::MOVSX8: return 8;
    case Bin::Op::MOVSX16: return 16;
    case Bin::Op::MOVSX32: return 32;
    default: throw std::exception();
    }
}

void EbpfTransformer::operator()(const Bin& bin) {
    if (dom.is_bottom()) {
        return;
    }
    using namespace dsl_syntax;

    auto dst = reg_pack(bin.dst);
    int finite_width = bin.is64 ? 64 : 32;

    // TODO: Unusable states and values should be better handled.
    //       Probably by propagating an error state.
    if (!dom.state.is_initialized(bin.dst) &&
        !std::set{Bin::Op::MOV, Bin::Op::MOVSX8, Bin::Op::MOVSX16, Bin::Op::MOVSX32}.contains(bin.op)) {
        dom.state.havoc_register(bin.dst);
        return;
    }
    if (auto pimm = std::get_if<Imm>(&bin.v)) {
        // dst += K
        int64_t imm;
        if (bin.is64) {
            // Use the full signed value.
            imm = to_signed(pimm->v);
        } else {
            // Use only the low 32 bits of the value.
            imm = gsl::narrow_cast<int32_t>(pimm->v);
            // If this is a 32-bit operation and the destination is not proven a number, forget the register.
            if (dom.state.is_in_group(bin.dst, TS_NUM)) {
                // Safe to zero-extend the low 32 bits; even if it's also bin.src, only the 32-bit value is used.
                dom.state.values->bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
            } else {
                dom.state.havoc_register(bin.dst);
            }
        }
        switch (bin.op) {
        case Bin::Op::MOV:
            dom.state.values.assign(dst.svalue, imm);
            dom.state.values.assign(dst.uvalue, imm);
            dom.state.values->overflow_bounds(dst.uvalue, bin.is64 ? 64 : 32, false);
            dom.state.assign_type(bin.dst, T_NUM);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::MOVSX8:
        case Bin::Op::MOVSX16:
        case Bin::Op::MOVSX32: CRAB_ERROR("Unsupported operation");
        case Bin::Op::ADD:
            if (imm == 0) {
                return;
            }
            add(bin.dst, gsl::narrow<int>(imm), finite_width);
            break;
        case Bin::Op::SUB:
            if (imm == 0) {
                return;
            }
            add(bin.dst, gsl::narrow<int>(-imm), finite_width);
            break;
        case Bin::Op::MUL:
            dom.state.values->mul(dst.svalue, dst.uvalue, imm, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::UDIV:
            dom.state.values->udiv(dst.svalue, dst.uvalue, imm, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::UMOD:
            dom.state.values->urem(dst.svalue, dst.uvalue, imm, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::SDIV:
            dom.state.values->sdiv(dst.svalue, dst.uvalue, imm, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::SMOD:
            dom.state.values->srem(dst.svalue, dst.uvalue, imm, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::OR:
            dom.state.values->bitwise_or(dst.svalue, dst.uvalue, imm);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::AND:
            // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
            dom.state.values->bitwise_and(dst.svalue, dst.uvalue, imm);
            if (gsl::narrow<int32_t>(imm) > 0) {
                // AND with immediate is only a 32-bit operation so svalue and uvalue are the same.
                dom.state.values.add_constraint(dst.svalue <= imm);
                dom.state.values.add_constraint(dst.uvalue <= imm);
                dom.state.values.add_constraint(0 <= dst.svalue);
                dom.state.values.add_constraint(0 <= dst.uvalue);
            }
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::LSH: shl(bin.dst, gsl::narrow<int32_t>(imm), finite_width); break;
        case Bin::Op::RSH: lshr(bin.dst, gsl::narrow<int32_t>(imm), finite_width); break;
        case Bin::Op::ARSH: ashr(bin.dst, gsl::narrow<int32_t>(imm), finite_width); break;
        case Bin::Op::XOR:
            dom.state.values->bitwise_xor(dst.svalue, dst.uvalue, imm);
            dom.state.havoc_offsets(bin.dst);
            break;
        }
    } else {
        // dst op= src
        auto src_reg = std::get<Reg>(bin.v);
        auto src = reg_pack(src_reg);
        if (!dom.state.is_initialized(src_reg)) {
            dom.state.havoc_register(bin.dst);
            return;
        }
        switch (bin.op) {
        case Bin::Op::ADD: {
            if (dom.state.same_type(bin.dst, std::get<Reg>(bin.v))) {
                // both must have been checked to be numbers
                dom.state.values->add_overflow(dst.svalue, dst.uvalue, src.svalue, finite_width);
            } else {
                // Here we're not sure that lhs and rhs are the same type; they might be.
                // But previous assertions should fail unless we know that exactly one of lhs or rhs is a pointer.
                dom.state =
                    dom.state.join_over_types(bin.dst, [&](TypeToNumDomain& state, const TypeEncoding dst_type) {
                        state =
                            state.join_over_types(src_reg, [&](TypeToNumDomain& state, const TypeEncoding src_type) {
                                if (dst_type == T_NUM && src_type != T_NUM) {
                                    // num += ptr
                                    state.assign_type(bin.dst, src_type);
                                    if (const auto dst_offset = get_type_offset_variable(bin.dst, src_type)) {
                                        state.values->apply(ArithBinOp::ADD, dst_offset.value(), dst.svalue,
                                                            get_type_offset_variable(src_reg, src_type).value());
                                    }
                                    if (src_type == T_SHARED) {
                                        state.values.assign(dst.shared_region_size, src.shared_region_size);
                                    }
                                } else if (dst_type != T_NUM && src_type == T_NUM) {
                                    // ptr += num
                                    state.assign_type(bin.dst, dst_type);
                                    if (const auto dst_offset = get_type_offset_variable(bin.dst, dst_type)) {
                                        state.values->apply(ArithBinOp::ADD, dst_offset.value(), dst_offset.value(),
                                                            src.svalue);
                                        if (dst_type == T_STACK) {
                                            // Reduce the numeric size.
                                            using namespace dsl_syntax;
                                            if (state.values.intersect(src.svalue < 0)) {
                                                state.values.havoc(dst.stack_numeric_size);
                                                recompute_stack_numeric_size(state, stack, bin.dst);
                                            } else {
                                                state.values->apply_signed(ArithBinOp::SUB, dst.stack_numeric_size,
                                                                           dst.stack_numeric_size,
                                                                           dst.stack_numeric_size, src.svalue, 0);
                                            }
                                        }
                                    }
                                } else if (dst_type == T_NUM && src_type == T_NUM) {
                                    // dst and src don't necessarily have the same type, but among the possibilities
                                    // enumerated is the case where they are both numbers.
                                    state.values->apply_signed(ArithBinOp::ADD, dst.svalue, dst.uvalue, dst.svalue,
                                                               src.svalue, finite_width);
                                } else {
                                    // We ignore the cases here that do not match the assumption described
                                    // above.  Joining bottom with another result will leave the other
                                    // results unchanged.
                                    state.values.set_to_bottom();
                                }
                            });
                    });
                // careful: change dst.value only after dealing with offset
                dom.state.values->apply_signed(ArithBinOp::ADD, dst.svalue, dst.uvalue, dst.svalue, src.svalue,
                                               finite_width);
            }
            break;
        }
        case Bin::Op::SUB: {
            if (dom.state.same_type(bin.dst, std::get<Reg>(bin.v))) {
                // src and dest have the same type.
                TypeDomain tmp_m_type_inv = dom.state.types;
                dom.state = dom.state.join_over_types(bin.dst, [&](TypeToNumDomain& state, const TypeEncoding type) {
                    switch (type) {
                    case T_NUM:
                        // This is: sub_overflow(inv, dst.value, src.value, finite_width);
                        state.values->apply_signed(ArithBinOp::SUB, dst.svalue, dst.uvalue, dst.svalue, src.svalue,
                                                   finite_width);
                        state.assign_type(bin.dst, T_NUM);
                        state.havoc_offsets(bin.dst);
                        break;
                    default:
                        // ptr -= ptr
                        // Assertions should make sure we only perform this on non-shared pointers.
                        if (const auto dst_offset = get_type_offset_variable(bin.dst, type)) {
                            state.values->apply_signed(ArithBinOp::SUB, dst.svalue, dst.uvalue, dst_offset.value(),
                                                       get_type_offset_variable(src_reg, type).value(), finite_width);
                            state.values.havoc(dst_offset.value());
                        }
                        state.havoc_offsets(bin.dst);
                        state.assign_type(bin.dst, T_NUM);
                        break;
                    }
                });
            } else {
                // We're not sure that lhs and rhs are the same type.
                // Either they're different, or at least one is not a singleton.
                if (dom.state.is_in_group(std::get<Reg>(bin.v), TS_NUM)) {
                    dom.state.values->sub_overflow(dst.svalue, dst.uvalue, src.svalue, finite_width);
                    if (auto dst_offset = dom.state.get_type_offset_variable(bin.dst)) {
                        dom.state.values->sub(dst_offset.value(), src.svalue);
                        if (dom.state.may_have_type(bin.dst, T_STACK)) {
                            // Reduce the numeric size.
                            using namespace dsl_syntax;
                            if (dom.state.values.intersect(src.svalue > 0)) {
                                dom.state.values.havoc(dst.stack_numeric_size);
                                recompute_stack_numeric_size(dom.state, stack, bin.dst);
                            } else {
                                dom.state.values->apply(ArithBinOp::ADD, dst.stack_numeric_size, dst.stack_numeric_size,
                                                        src.svalue);
                            }
                        }
                    }
                } else {
                    dom.state.havoc_register(bin.dst);
                }
            }
            break;
        }
        case Bin::Op::MUL:
            dom.state.values->mul(dst.svalue, dst.uvalue, src.svalue, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::UDIV:
            dom.state.values->udiv(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::UMOD:
            dom.state.values->urem(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::SDIV:
            dom.state.values->sdiv(dst.svalue, dst.uvalue, src.svalue, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::SMOD:
            dom.state.values->srem(dst.svalue, dst.uvalue, src.svalue, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::OR:
            dom.state.values->bitwise_or(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::AND:
            dom.state.values->bitwise_and(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::LSH:
            if (dom.state.is_in_group(src_reg, TS_NUM)) {
                auto src_interval = dom.state.values.eval_interval(src.uvalue);
                if (std::optional<Number> sn = src_interval.singleton()) {
                    // truncate to uint64?
                    uint64_t imm = sn->cast_to<uint64_t>() & (bin.is64 ? 63 : 31);
                    if (imm <= std::numeric_limits<int32_t>::max()) {
                        if (!bin.is64) {
                            // Use only the low 32 bits of the value.
                            dom.state.values->bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
                        }
                        shl(bin.dst, gsl::narrow_cast<int32_t>(imm), finite_width);
                        break;
                    }
                }
            }
            dom.state.values->shl_overflow(dst.svalue, dst.uvalue, src.uvalue);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::RSH:
            if (dom.state.is_in_group(src_reg, TS_NUM)) {
                auto src_interval = dom.state.values.eval_interval(src.uvalue);
                if (std::optional<Number> sn = src_interval.singleton()) {
                    uint64_t imm = sn->cast_to<uint64_t>() & (bin.is64 ? 63 : 31);
                    if (imm <= std::numeric_limits<int32_t>::max()) {
                        if (!bin.is64) {
                            // Use only the low 32 bits of the value.
                            dom.state.values->bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
                        }
                        lshr(bin.dst, gsl::narrow_cast<int32_t>(imm), finite_width);
                        break;
                    }
                }
            }
            dom.state.havoc_register_except_type(bin.dst);
            break;
        case Bin::Op::ARSH:
            if (dom.state.is_in_group(src_reg, TS_NUM)) {
                ashr(bin.dst, src.svalue, finite_width);
                break;
            }
            dom.state.havoc_register_except_type(bin.dst);
            break;
        case Bin::Op::XOR:
            dom.state.values->bitwise_xor(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            dom.state.havoc_offsets(bin.dst);
            break;
        case Bin::Op::MOVSX8:
        case Bin::Op::MOVSX16:
        case Bin::Op::MOVSX32: {
            const int source_width = _movsx_bits(bin.op);
            // Keep relational information if operation is a no-op.
            if (dst.svalue == src.svalue &&
                dom.state.values.eval_interval(dst.svalue) <= Interval::signed_int(source_width)) {
                return;
            }
            if (dom.state.is_in_group(src_reg, TS_NUM)) {
                dom.state.havoc_offsets(bin.dst);
                dom.state.assign_type(bin.dst, T_NUM);
                dom.state.values->sign_extend(dst.svalue, dst.uvalue, src.svalue, finite_width, source_width);
                break;
            }
            dom.state.havoc_register(bin.dst);
            break;
        }
        case Bin::Op::MOV:
            // Keep relational information if operation is a no-op.
            if (bin.is64 || dom.state.is_in_group(src_reg, TS_NUM)) {
                if (bin.dst != src_reg) {
                    // the 32bit case is handled below
                    dom.state.assign(bin.dst, src_reg);
                }
            } else {
                // If src is not a number, we don't know how to truncate a pointer.
                dom.state.havoc_register(bin.dst);
            }
            break;
        }
    }
    if (!bin.is64) {
        dom.state.values->bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
    }
}

void EbpfTransformer::initialize_loop_counter(const Label& label) {
    dom.state.values.assign(variable_registry->loop_counter(to_string(label)), 0);
}

void EbpfTransformer::operator()(const IncrementLoopCounter& ins) {
    if (dom.is_bottom()) {
        return;
    }
    const auto counter = variable_registry->loop_counter(to_string(ins.name));
    dom.state.values->add(counter, 1);
}

void ebpf_domain_initialize_loop_counter(EbpfDomain& dom, const Label& label) {
    EbpfTransformer{dom}.initialize_loop_counter(label);
}
} // namespace prevail

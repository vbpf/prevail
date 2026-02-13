// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.

#include <bitset>
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

    static void recompute_stack_numeric_size(TypeToNumDomain& rcp, ArrayDomain& stack, const Reg& reg);

    static void recompute_stack_numeric_size(TypeToNumDomain& rcp, ArrayDomain& stack, Variable type_variable);

    static void do_load_stack(TypeToNumDomain& rcp, ArrayDomain& stack, const Reg& target_reg,
                              const LinearExpression& addr, int width, const Reg& src_reg);

    void do_load(const Mem& b, const Reg& target_reg);

    static void do_store_stack(TypeToNumDomain& rcp, ArrayDomain& stack, const LinearExpression& symb_addr,
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
        dom.rcp.havoc_register(Reg{i});
    }
}

/// Create variables specific to the new call stack frame that store
/// copies of the states of r6 through r9.
void EbpfTransformer::save_callee_saved_registers(const std::string& prefix) {
    // TODO: define location `stack_frame_var`, and pass to dom.rcp.assign().
    //       Similarly in restore_callee_saved_registers
    for (uint8_t r = R6; r <= R9; r++) {
        if (dom.rcp.types.is_initialized(Reg{r})) {
            const Variable type_var = variable_registry->type_reg(r);
            dom.rcp.assign_type(variable_registry->stack_frame_var(DataKind::types, r, prefix), type_var);
            for (const TypeEncoding type : dom.rcp.types.iterate_types(Reg{r})) {
                auto kinds = type_to_kinds.at(type);
                kinds.push_back(DataKind::uvalues);
                kinds.push_back(DataKind::svalues);
                for (const DataKind kind : kinds) {
                    const Variable src_var = variable_registry->reg(kind, r);
                    const Variable dst_var = variable_registry->stack_frame_var(kind, r, prefix);
                    if (!dom.rcp.values.eval_interval(src_var).is_top()) {
                        dom.rcp.values.assign(dst_var, src_var);
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
        if (dom.rcp.types.is_initialized(type_var)) {
            dom.rcp.assign_type(reg, type_var);
            for (const TypeEncoding type : dom.rcp.types.iterate_types(reg)) {
                auto kinds = type_to_kinds.at(type);
                kinds.push_back(DataKind::uvalues);
                kinds.push_back(DataKind::svalues);
                for (const DataKind kind : kinds) {
                    const Variable src_var = variable_registry->stack_frame_var(kind, r, prefix);
                    const Variable dst_var = variable_registry->reg(kind, r);
                    if (!dom.rcp.values.eval_interval(src_var).is_top()) {
                        dom.rcp.values.assign(dst_var, src_var);
                    } else {
                        dom.rcp.values.havoc(dst_var);
                    }
                    dom.rcp.values.havoc(src_var);
                }
            }
        }
        dom.rcp.types.havoc_type(type_var);
    }
}

void EbpfTransformer::havoc_subprogram_stack(const std::string& prefix) {
    const Variable r10_stack_offset = reg_pack(R10_STACK_POINTER).stack_offset;
    const auto intv = dom.rcp.values.eval_interval(r10_stack_offset);
    if (!intv.is_singleton()) {
        return;
    }
    const int64_t stack_start = intv.singleton()->cast_to<int64_t>() - EBPF_SUBPROGRAM_STACK_SIZE;
    stack.havoc_type(dom.rcp.types, Interval{stack_start}, Interval{EBPF_SUBPROGRAM_STACK_SIZE});
    for (const DataKind kind : iterate_kinds()) {
        stack.havoc(dom.rcp.values, kind, Interval{stack_start}, Interval{EBPF_SUBPROGRAM_STACK_SIZE});
    }
}

void EbpfTransformer::forget_packet_pointers() {
    dom.rcp.havoc_all_locations_having_type(T_PACKET);
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
        // This should have been checked by EbpfChecker
        assert(dom.rcp.types.same_type(cond.left, std::get<Reg>(cond.right)));
        dom.rcp = dom.rcp.join_over_types(cond.left, [&](TypeToNumDomain& rcp, const TypeEncoding type) {
            if (type == T_NUM) {
                for (const LinearConstraint& cst :
                     rcp.values->assume_cst_reg(cond.op, cond.is64, dst.svalue, dst.uvalue, src.svalue, src.uvalue)) {
                    rcp.values.add_constraint(cst);
                }
            } else {
                // Either pointers to a singleton region,
                // or an equality comparison on map descriptors/pointers to non-singleton locations
                if (const auto dst_offset = get_type_offset_variable(cond.left, type)) {
                    if (const auto src_offset = get_type_offset_variable(src_reg, type)) {
                        rcp.values.add_constraint(
                            assume_cst_offsets_reg(cond.op, dst_offset.value(), src_offset.value()));
                    }
                }
            }
        });
    } else {
        const int64_t imm = gsl::narrow_cast<int64_t>(std::get<Imm>(cond.right).v);
        for (const LinearConstraint& cst :
             dom.rcp.values->assume_cst_imm(cond.op, cond.is64, dst.svalue, dst.uvalue, imm)) {
            dom.rcp.values.add_constraint(cst);
        }
    }
}

void EbpfTransformer::operator()(const Undefined& a) {}

// Rejected during CFG feature checks; transformer should not receive this.
void EbpfTransformer::operator()(const CallBtf&) {}

// Rejected during CFG feature checks; transformer should not receive this.
void EbpfTransformer::operator()(const LoadPseudo&) {}

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
        if (dom.rcp.types.type_is_number(stmt.dst)) {
            if (const auto n = dom.rcp.values.eval_interval(v).singleton()) {
                if (n->fits_cast_to<int64_t>()) {
                    dom.rcp.values.set(v, Interval{be_or_le(n->cast_to<int64_t>())});
                    return;
                }
            }
        }
        dom.rcp.values.havoc(v);
        dom.rcp.havoc_offsets(stmt.dst);
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
        dom.rcp.values->neg(dst.svalue, dst.uvalue, stmt.is64 ? 64 : 32);
        dom.rcp.havoc_offsets(stmt.dst);
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
}

void EbpfTransformer::operator()(const Jmp&) const {
    // This is a NOP. It only exists to hold the jump preconditions.
}

void EbpfTransformer::operator()(const Packet& a) {
    if (dom.is_bottom()) {
        return;
    }
    constexpr Reg r0_reg{R0_RETURN_VALUE};
    dom.rcp.havoc_register_except_type(r0_reg);
    dom.rcp.assign_type(r0_reg, T_NUM);
    scratch_caller_saved_registers();
}

void EbpfTransformer::do_load_stack(TypeToNumDomain& rcp, ArrayDomain& stack, const Reg& target_reg,
                                    const LinearExpression& symb_addr, const int width, const Reg& src_reg) {
    const Interval addr = rcp.values.eval_interval(symb_addr);
    using namespace dsl_syntax;
    if (rcp.values.entail(width <= reg_pack(src_reg).stack_numeric_size)) {
        rcp.assign_type(target_reg, T_NUM);
    } else {
        rcp.assign_type(target_reg, stack.load_type(addr, width));
        if (!rcp.types.is_initialized(target_reg)) {
            // We don't know what we loaded, so just havoc the destination register.
            rcp.havoc_register(target_reg);
            return;
        }
    }

    const RegPack& target = reg_pack(target_reg);
    if (width == 1 || width == 2 || width == 4 || width == 8) {
        // Use the addr before we havoc the destination register since we might be getting the
        // addr from that same register.
        const std::optional<LinearExpression> sresult = stack.load(rcp.values, DataKind::svalues, addr, width);
        const std::optional<LinearExpression> uresult = stack.load(rcp.values, DataKind::uvalues, addr, width);
        rcp.havoc_register_except_type(target_reg);
        rcp.values.assign(target.svalue, sresult);
        rcp.values.assign(target.uvalue, uresult);
        for (const TypeEncoding type : rcp.types.iterate_types(target_reg)) {
            for (const auto& kind : type_to_kinds.at(type)) {
                const Variable dst_var = variable_registry->reg(kind, target_reg.v);
                rcp.values.assign(dst_var, stack.load(rcp.values, kind, addr, width));
            }
        }
    } else {
        rcp.havoc_register_except_type(target_reg);
    }
}

static void do_load_ctx(TypeToNumDomain& rcp, const Reg& target_reg, const LinearExpression& addr_vague,
                        const int width) {
    using namespace dsl_syntax;
    if (rcp.values.is_bottom()) {
        return;
    }

    const ebpf_context_descriptor_t* desc = thread_local_program_info->type.context_descriptor;

    const RegPack& target = reg_pack(target_reg);

    if (desc->end < 0) {
        rcp.havoc_register(target_reg);
        rcp.assign_type(target_reg, T_NUM);
        return;
    }

    const Interval interval = rcp.values.eval_interval(addr_vague);
    const std::optional<Number> maybe_addr = interval.singleton();
    rcp.havoc_register(target_reg);

    const bool may_touch_ptr =
        interval.contains(desc->data) || interval.contains(desc->meta) || interval.contains(desc->end);

    if (!maybe_addr) {
        if (may_touch_ptr) {
            rcp.types.havoc_type(target_reg);
        } else {
            rcp.assign_type(target_reg, T_NUM);
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
            rcp.values.assign(target.packet_offset, 0);
        }
    } else if (addr == desc->end) {
        if (width == offset_width) {
            rcp.values.assign(target.packet_offset, variable_registry->packet_size());
            // EXPERIMENTAL: Explicit upper bound since packet_size is min_only.
            // This preserves the relational constraint (packet_offset <= packet_size)
            // while ensuring comparison checks have a concrete upper bound.
            rcp.values.add_constraint(target.packet_offset < MAX_PACKET_SIZE);
        }
    } else if (addr == desc->meta) {
        if (width == offset_width) {
            rcp.values.assign(target.packet_offset, variable_registry->meta_offset());
        }
    } else {
        if (may_touch_ptr) {
            rcp.types.havoc_type(target_reg);
        } else {
            rcp.assign_type(target_reg, T_NUM);
        }
        return;
    }
    if (width == offset_width) {
        rcp.assign_type(target_reg, T_PACKET);
        rcp.values.add_constraint(4098 <= target.svalue);
        rcp.values.add_constraint(target.svalue <= PTR_MAX);
    }
}

static void do_load_packet_or_shared(TypeToNumDomain& rcp, const Reg& target_reg, const int width) {
    if (rcp.values.is_bottom()) {
        return;
    }
    const RegPack& target = reg_pack(target_reg);

    rcp.havoc_register(target_reg);
    rcp.assign_type(target_reg, T_NUM);

    // A 1 or 2 byte copy results in a limited range of values that may be used as array indices.
    if (width == 1 || width == 2) {
        const Interval full = Interval::unsigned_int(width * 8);
        rcp.values.set(target.svalue, full);
        rcp.values.set(target.uvalue, full);
    }
}

void EbpfTransformer::do_load(const Mem& b, const Reg& target_reg) {
    using namespace dsl_syntax;

    const auto mem_reg = reg_pack(b.access.basereg);
    const int width = b.access.width;
    const int offset = b.access.offset;

    if (b.access.basereg.v == R10_STACK_POINTER) {
        const LinearExpression addr = mem_reg.stack_offset + offset;
        do_load_stack(dom.rcp, stack, target_reg, addr, width, b.access.basereg);
        return;
    }
    dom.rcp = dom.rcp.join_over_types(b.access.basereg, [&](TypeToNumDomain& rcp, TypeEncoding type) {
        switch (type) {
        case T_UNINIT: return;
        case T_MAP: return;
        case T_MAP_PROGRAMS: return;
        case T_NUM: return;
        case T_CTX: {
            LinearExpression addr = mem_reg.ctx_offset + offset;
            do_load_ctx(rcp, target_reg, addr, width);
            break;
        }
        case T_STACK: {
            LinearExpression addr = mem_reg.stack_offset + offset;
            do_load_stack(rcp, stack, target_reg, addr, width, b.access.basereg);
            break;
        }
        case T_PACKET: {
            LinearExpression addr = mem_reg.packet_offset + offset;
            do_load_packet_or_shared(rcp, target_reg, width);
            break;
        }
        case T_SHARED: {
            LinearExpression addr = mem_reg.shared_offset + offset;
            do_load_packet_or_shared(rcp, target_reg, width);
            break;
        }
        }
    });
}

void EbpfTransformer::do_store_stack(TypeToNumDomain& rcp, ArrayDomain& stack, const LinearExpression& symb_addr,
                                     const int exact_width, const LinearExpression& val_svalue,
                                     const LinearExpression& val_uvalue, const std::optional<Reg>& opt_val_reg) {
    const Interval addr = rcp.values.eval_interval(symb_addr);
    const Interval width{exact_width};
    // no aliasing of val - we don't move from stack to stack, so we can just havoc first
    stack.havoc_type(rcp.types, addr, width);
    for (const DataKind kind : iterate_kinds()) {
        if (kind == DataKind::svalues || kind == DataKind::uvalues) {
            continue;
        }
        stack.havoc(rcp.values, kind, addr, width);
    }
    bool must_be_num = false;
    if (opt_val_reg && !rcp.types.is_initialized(*opt_val_reg)) {
        stack.havoc(rcp.values, DataKind::svalues, addr, width);
        stack.havoc(rcp.values, DataKind::uvalues, addr, width);
    } else {
        // opt_val_reg is unset when storing an immediate value.
        must_be_num = !opt_val_reg || rcp.types.type_is_number(*opt_val_reg);
        const LinearExpression val_type =
            must_be_num ? LinearExpression{T_NUM} : variable_registry->type_reg(opt_val_reg->v);
        rcp.assign_type(stack.store_type(rcp.types, addr, width, must_be_num), val_type);

        if (exact_width == 8) {
            stack.havoc(rcp.values, DataKind::svalues, addr, width);
            stack.havoc(rcp.values, DataKind::uvalues, addr, width);
            rcp.values.assign(stack.store(rcp.values, DataKind::svalues, addr, width), val_svalue);
            rcp.values.assign(stack.store(rcp.values, DataKind::uvalues, addr, width), val_uvalue);

            if (!must_be_num) {
                for (TypeEncoding type : rcp.types.iterate_types(*opt_val_reg)) {
                    for (const DataKind kind : type_to_kinds.at(type)) {
                        const Variable src_var = variable_registry->reg(kind, opt_val_reg->v);
                        rcp.values.assign(stack.store(rcp.values, kind, addr, width), src_var);
                    }
                }
            }
        } else if ((exact_width == 1 || exact_width == 2 || exact_width == 4) && must_be_num) {
            // Keep track of numbers on the stack that might be used as array indices.
            if (const auto stack_svalue = stack.store(rcp.values, DataKind::svalues, addr, width)) {
                rcp.values.assign(stack_svalue, val_svalue);
                rcp.values->overflow_bounds(*stack_svalue, exact_width * 8, true);
            } else {
                stack.havoc(rcp.values, DataKind::svalues, addr, width);
            }
            if (const auto stack_uvalue = stack.store(rcp.values, DataKind::uvalues, addr, width)) {
                rcp.values.assign(stack_uvalue, val_uvalue);
                rcp.values->overflow_bounds(*stack_uvalue, exact_width * 8, false);
            } else {
                stack.havoc(rcp.values, DataKind::uvalues, addr, width);
            }
        } else {
            stack.havoc(rcp.values, DataKind::svalues, addr, width);
            stack.havoc(rcp.values, DataKind::uvalues, addr, width);
        }
    }

    // Update stack_numeric_size for any stack type variables.
    // stack_numeric_size holds the number of continuous bytes starting from stack_offset that are known to be numeric.
    for (const Variable type_variable : variable_registry->get_type_variables()) {
        if (!rcp.types.is_initialized(type_variable) || !rcp.types.may_have_type(type_variable, T_STACK)) {
            continue;
        }
        const Variable stack_offset_variable = variable_registry->kind_var(DataKind::stack_offsets, type_variable);
        const Variable stack_numeric_size_variable =
            variable_registry->kind_var(DataKind::stack_numeric_sizes, type_variable);

        using namespace dsl_syntax;
        // See if the variable's numeric interval overlaps with changed bytes.
        if (rcp.values.intersect(
                dsl_syntax::operator<=(symb_addr, stack_offset_variable + stack_numeric_size_variable)) &&
            rcp.values.intersect(dsl_syntax::operator>=(symb_addr + exact_width, stack_offset_variable))) {
            if (!must_be_num) {
                rcp.values.havoc(stack_numeric_size_variable);
            }
            recompute_stack_numeric_size(rcp, stack, type_variable);
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
        const auto r10_interval = dom.rcp.values.eval_interval(r10_stack_offset);
        if (r10_interval.is_singleton()) {
            const int32_t stack_offset = r10_interval.singleton()->cast_to<int32_t>();
            const Number base_addr{stack_offset};
            do_store_stack(dom.rcp, stack, base_addr + offset, width, val_svalue, val_uvalue, opt_val_reg);
            return;
        }
    }
    dom.rcp = dom.rcp.join_over_types(b.access.basereg, [&](TypeToNumDomain& rcp, const TypeEncoding type) {
        if (type == T_STACK) {
            const auto base_addr = LinearExpression(reg_pack(b.access.basereg).stack_offset);
            do_store_stack(rcp, stack, dsl_syntax::operator+(base_addr, offset), width, val_svalue, val_uvalue,
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
    if (!dom.rcp.types.type_is_pointer(a.access.basereg) || !dom.rcp.types.type_is_number(a.valreg)) {
        return;
    }
    if (dom.rcp.types.type_is_not_stack(a.access.basereg)) {
        // Shared memory regions are volatile so we can just havoc
        // any register that will be updated.
        if (a.op == Atomic::Op::CMPXCHG) {
            dom.rcp.havoc_register_except_type(Reg{R0_RETURN_VALUE});
        } else if (a.fetch) {
            dom.rcp.havoc_register_except_type(a.valreg);
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
        dom.rcp.havoc_register_except_type(r11);
    } else if (a.fetch) {
        // For other FETCH operations, store the original value in the src register.
        (*this)(Mem{.access = a.access, .value = a.valreg, .is_load = true});
    }

    // Store the new value back in the original shared memory location.
    // Note that do_mem_store() currently doesn't track shared memory values,
    // but stack memory values are tracked and are legal here.
    (*this)(Mem{.access = a.access, .value = r11, .is_load = false});

    // Clear the R11 pseudo-register.
    dom.rcp.havoc_register(r11);
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
        case ArgSingle::Kind::PTR_TO_CTX:
            // Do nothing. We don't track the content of relevant memory regions
            break;
        case ArgSingle::Kind::PTR_TO_STACK:
            // Do nothing; the stack is passed as context, not to be modified.
            break;
        }
    }
    for (ArgPair param : call.pairs) {
        switch (param.kind) {
        case ArgPair::Kind::PTR_TO_READABLE_MEM:
            // Do nothing. No side effect allowed.
            break;

        case ArgPair::Kind::PTR_TO_WRITABLE_MEM: {
            bool store_numbers = true;
            auto variable = dom.rcp.get_type_offset_variable(param.mem);
            if (!variable.has_value()) {
                // checked by the checker
                break;
            }
            Interval addr = dom.rcp.values.eval_interval(variable.value());
            Interval width = dom.rcp.values.eval_interval(reg_pack(param.size).svalue);

            dom.rcp = dom.rcp.join_over_types(param.mem, [&](TypeToNumDomain& rcp, const TypeEncoding type) {
                if (type == T_STACK) {
                    // Pointer to a memory region that the called function may change,
                    // so we must havoc.
                    for (const DataKind kind : iterate_kinds()) {
                        stack.havoc(rcp.values, kind, addr, width);
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
    dom.rcp.values.havoc(r0_pack.stack_numeric_size);
    if (call.is_map_lookup) {
        // This is the only way to get a null pointer
        if (maybe_fd_reg) {
            if (const auto map_type = dom.get_map_type(*maybe_fd_reg)) {
                if (thread_local_program_info->platform->get_map_type(*map_type).value_type == EbpfMapValueType::MAP) {
                    if (const auto inner_map_fd = dom.get_map_inner_map_fd(*maybe_fd_reg)) {
                        do_load_mapfd(r0_reg, to_signed(*inner_map_fd), true);
                        goto out;
                    }
                } else {
                    assign_valid_ptr(r0_reg, true);
                    dom.rcp.values.assign(r0_pack.shared_offset, 0);
                    dom.rcp.values.set(r0_pack.shared_region_size, dom.get_map_value_size(*maybe_fd_reg));
                    dom.rcp.assign_type(r0_reg, T_SHARED);
                }
            }
        }
        assign_valid_ptr(r0_reg, true);
        dom.rcp.values.assign(r0_pack.shared_offset, 0);
        dom.rcp.assign_type(r0_reg, T_SHARED);
    } else {
        dom.rcp.havoc_register_except_type(r0_reg);
        dom.rcp.assign_type(r0_reg, T_NUM);
        // dom.rcp.values.add_constraint(r0_pack.value < 0); for INTEGER_OR_NO_RETURN_IF_SUCCEED.
    }
out:
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
    const auto src_interval = dom.rcp.values.eval_interval(reg.svalue);
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
        dom.rcp.assign_type(dst_reg, T_MAP_PROGRAMS);
        dom.rcp.values.assign(dst.map_fd_programs, mapfd);
    } else {
        dom.rcp.assign_type(dst_reg, T_MAP);
        dom.rcp.values.assign(dst.map_fd, mapfd);
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
    dom.rcp.assign_type(dst_reg, T_SHARED);
    const RegPack& dst = reg_pack(dst_reg);
    dom.rcp.values.assign(dst.shared_offset, offset);
    dom.rcp.values.assign(dst.shared_region_size, desc.value_size);
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
    dom.rcp.values.havoc(reg.svalue);
    dom.rcp.values.havoc(reg.uvalue);
    if (maybe_null) {
        dom.rcp.values.add_constraint(0 <= reg.svalue);
    } else {
        dom.rcp.values.add_constraint(0 < reg.svalue);
    }
    dom.rcp.values.add_constraint(reg.svalue <= PTR_MAX);
    dom.rcp.values.assign(reg.uvalue, reg.svalue);
}

// If nothing is known of the stack_numeric_size,
// try to recompute the stack_numeric_size.
void EbpfTransformer::recompute_stack_numeric_size(TypeToNumDomain& rcp, ArrayDomain& stack,
                                                   const Variable type_variable) {
    const Variable stack_numeric_size_variable =
        variable_registry->kind_var(DataKind::stack_numeric_sizes, type_variable);

    if (rcp.types.may_have_type(type_variable, T_STACK)) {
        const int numeric_size =
            stack.min_all_num_size(rcp.values, variable_registry->kind_var(DataKind::stack_offsets, type_variable));
        if (numeric_size > 0) {
            rcp.values.assign(stack_numeric_size_variable, numeric_size);
        }
    }
}

void EbpfTransformer::recompute_stack_numeric_size(TypeToNumDomain& rcp, ArrayDomain& stack, const Reg& reg) {
    recompute_stack_numeric_size(rcp, stack, reg_type(reg));
}

void EbpfTransformer::add(const Reg& dst_reg, const int imm, const int finite_width) {
    const auto dst = reg_pack(dst_reg);
    dom.rcp.values->add_overflow(dst.svalue, dst.uvalue, imm, finite_width);
    if (const auto offset = dom.rcp.get_type_offset_variable(dst_reg)) {
        dom.rcp.values->add(*offset, imm);
        if (imm > 0) {
            // Since the start offset is increasing but
            // the end offset is not, the numeric size decreases.
            dom.rcp.values->sub(dst.stack_numeric_size, imm);
        } else if (imm < 0) {
            dom.rcp.values.havoc(dst.stack_numeric_size);
        }
        recompute_stack_numeric_size(dom.rcp, stack, dst_reg);
    }
}

void EbpfTransformer::shl(const Reg& dst_reg, int imm, const int finite_width) {
    dom.rcp.havoc_offsets(dst_reg);

    // The BPF ISA requires masking the imm.
    imm &= finite_width - 1;
    const RegPack dst = reg_pack(dst_reg);
    if (dom.rcp.types.type_is_number(dst_reg)) {
        dom.rcp.values->shl(dst.svalue, dst.uvalue, imm, finite_width);
    } else {
        dom.rcp.values.havoc(dst.svalue);
        dom.rcp.values.havoc(dst.uvalue);
    }
}

void EbpfTransformer::lshr(const Reg& dst_reg, int imm, int finite_width) {
    dom.rcp.havoc_offsets(dst_reg);

    // The BPF ISA requires masking the imm.
    imm &= finite_width - 1;
    const RegPack dst = reg_pack(dst_reg);
    if (dom.rcp.types.type_is_number(dst_reg)) {
        dom.rcp.values->lshr(dst.svalue, dst.uvalue, imm, finite_width);
    } else {
        dom.rcp.values.havoc(dst.svalue);
        dom.rcp.values.havoc(dst.uvalue);
    }
}

void EbpfTransformer::ashr(const Reg& dst_reg, const LinearExpression& right_svalue, const int finite_width) {
    dom.rcp.havoc_offsets(dst_reg);

    const RegPack dst = reg_pack(dst_reg);
    if (dom.rcp.types.type_is_number(dst_reg)) {
        dom.rcp.values->ashr(dst.svalue, dst.uvalue, right_svalue, finite_width);
    } else {
        dom.rcp.values.havoc(dst.svalue);
        dom.rcp.values.havoc(dst.uvalue);
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
    if (!dom.rcp.types.is_initialized(bin.dst) &&
        !std::set{Bin::Op::MOV, Bin::Op::MOVSX8, Bin::Op::MOVSX16, Bin::Op::MOVSX32}.contains(bin.op)) {
        dom.rcp.havoc_register(bin.dst);
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
            if (dom.rcp.types.type_is_number(bin.dst)) {
                // Safe to zero-extend the low 32 bits; even if it's also bin.src, only the 32-bit value is used.
                dom.rcp.values->bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
            } else {
                dom.rcp.havoc_register(bin.dst);
            }
        }
        switch (bin.op) {
        case Bin::Op::MOV:
            dom.rcp.values.assign(dst.svalue, imm);
            dom.rcp.values.assign(dst.uvalue, imm);
            dom.rcp.values->overflow_bounds(dst.uvalue, bin.is64 ? 64 : 32, false);
            dom.rcp.assign_type(bin.dst, T_NUM);
            dom.rcp.havoc_offsets(bin.dst);
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
            dom.rcp.values->mul(dst.svalue, dst.uvalue, imm, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::UDIV:
            dom.rcp.values->udiv(dst.svalue, dst.uvalue, imm, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::UMOD:
            dom.rcp.values->urem(dst.svalue, dst.uvalue, imm, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::SDIV:
            dom.rcp.values->sdiv(dst.svalue, dst.uvalue, imm, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::SMOD:
            dom.rcp.values->srem(dst.svalue, dst.uvalue, imm, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::OR:
            dom.rcp.values->bitwise_or(dst.svalue, dst.uvalue, imm);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::AND:
            // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
            dom.rcp.values->bitwise_and(dst.svalue, dst.uvalue, imm);
            if (gsl::narrow<int32_t>(imm) > 0) {
                // AND with immediate is only a 32-bit operation so svalue and uvalue are the same.
                dom.rcp.values.add_constraint(dst.svalue <= imm);
                dom.rcp.values.add_constraint(dst.uvalue <= imm);
                dom.rcp.values.add_constraint(0 <= dst.svalue);
                dom.rcp.values.add_constraint(0 <= dst.uvalue);
            }
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::LSH: shl(bin.dst, gsl::narrow<int32_t>(imm), finite_width); break;
        case Bin::Op::RSH: lshr(bin.dst, gsl::narrow<int32_t>(imm), finite_width); break;
        case Bin::Op::ARSH: ashr(bin.dst, gsl::narrow<int32_t>(imm), finite_width); break;
        case Bin::Op::XOR:
            dom.rcp.values->bitwise_xor(dst.svalue, dst.uvalue, imm);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        }
    } else {
        // dst op= src
        auto src_reg = std::get<Reg>(bin.v);
        auto src = reg_pack(src_reg);
        if (!dom.rcp.types.is_initialized(src_reg)) {
            dom.rcp.havoc_register(bin.dst);
            return;
        }
        switch (bin.op) {
        case Bin::Op::ADD: {
            if (dom.rcp.types.same_type(bin.dst, std::get<Reg>(bin.v))) {
                // both must have been checked to be numbers
                dom.rcp.values->add_overflow(dst.svalue, dst.uvalue, src.svalue, finite_width);
            } else {
                // Here we're not sure that lhs and rhs are the same type; they might be.
                // But previous assertions should fail unless we know that exactly one of lhs or rhs is a pointer.
                dom.rcp = dom.rcp.join_over_types(bin.dst, [&](TypeToNumDomain& rcp, const TypeEncoding dst_type) {
                    rcp = rcp.join_over_types(src_reg, [&](TypeToNumDomain& rcp, const TypeEncoding src_type) {
                        if (dst_type == T_NUM && src_type != T_NUM) {
                            // num += ptr
                            rcp.assign_type(bin.dst, src_type);
                            if (const auto dst_offset = get_type_offset_variable(bin.dst, src_type)) {
                                rcp.values->apply(ArithBinOp::ADD, dst_offset.value(), dst.svalue,
                                                  get_type_offset_variable(src_reg, src_type).value());
                            }
                            if (src_type == T_SHARED) {
                                rcp.values.assign(dst.shared_region_size, src.shared_region_size);
                            }
                        } else if (dst_type != T_NUM && src_type == T_NUM) {
                            // ptr += num
                            rcp.assign_type(bin.dst, dst_type);
                            if (const auto dst_offset = get_type_offset_variable(bin.dst, dst_type)) {
                                rcp.values->apply(ArithBinOp::ADD, dst_offset.value(), dst_offset.value(), src.svalue);
                                if (dst_type == T_STACK) {
                                    // Reduce the numeric size.
                                    using namespace dsl_syntax;
                                    if (rcp.values.intersect(src.svalue < 0)) {
                                        rcp.values.havoc(dst.stack_numeric_size);
                                        recompute_stack_numeric_size(rcp, stack, bin.dst);
                                    } else {
                                        rcp.values->apply_signed(ArithBinOp::SUB, dst.stack_numeric_size,
                                                                 dst.stack_numeric_size, dst.stack_numeric_size,
                                                                 src.svalue, 0);
                                    }
                                }
                            }
                        } else if (dst_type == T_NUM && src_type == T_NUM) {
                            // dst and src don't necessarily have the same type, but among the possibilities
                            // enumerated is the case where they are both numbers.
                            rcp.values->apply_signed(ArithBinOp::ADD, dst.svalue, dst.uvalue, dst.svalue, src.svalue,
                                                     finite_width);
                        } else {
                            // We ignore the cases here that do not match the assumption described
                            // above.  Joining bottom with another result will leave the other
                            // results unchanged.
                            rcp.values.set_to_bottom();
                        }
                    });
                });
                // careful: change dst.value only after dealing with offset
                dom.rcp.values->apply_signed(ArithBinOp::ADD, dst.svalue, dst.uvalue, dst.svalue, src.svalue,
                                             finite_width);
            }
            break;
        }
        case Bin::Op::SUB: {
            if (dom.rcp.types.same_type(bin.dst, std::get<Reg>(bin.v))) {
                // src and dest have the same type.
                TypeDomain tmp_m_type_inv = dom.rcp.types;
                dom.rcp = dom.rcp.join_over_types(bin.dst, [&](TypeToNumDomain& rcp, const TypeEncoding type) {
                    switch (type) {
                    case T_NUM:
                        // This is: sub_overflow(inv, dst.value, src.value, finite_width);
                        rcp.values->apply_signed(ArithBinOp::SUB, dst.svalue, dst.uvalue, dst.svalue, src.svalue,
                                                 finite_width);
                        rcp.assign_type(bin.dst, T_NUM);
                        rcp.havoc_offsets(bin.dst);
                        break;
                    default:
                        // ptr -= ptr
                        // Assertions should make sure we only perform this on non-shared pointers.
                        if (const auto dst_offset = get_type_offset_variable(bin.dst, type)) {
                            rcp.values->apply_signed(ArithBinOp::SUB, dst.svalue, dst.uvalue, dst_offset.value(),
                                                     get_type_offset_variable(src_reg, type).value(), finite_width);
                            rcp.values.havoc(dst_offset.value());
                        }
                        rcp.havoc_offsets(bin.dst);
                        rcp.assign_type(bin.dst, T_NUM);
                        break;
                    }
                });
            } else {
                // We're not sure that lhs and rhs are the same type.
                // Either they're different, or at least one is not a singleton.
                if (dom.rcp.types.type_is_number(std::get<Reg>(bin.v))) {
                    dom.rcp.values->sub_overflow(dst.svalue, dst.uvalue, src.svalue, finite_width);
                    if (auto dst_offset = dom.rcp.get_type_offset_variable(bin.dst)) {
                        dom.rcp.values->sub(dst_offset.value(), src.svalue);
                        if (dom.rcp.types.may_have_type(bin.dst, T_STACK)) {
                            // Reduce the numeric size.
                            using namespace dsl_syntax;
                            if (dom.rcp.values.intersect(src.svalue > 0)) {
                                dom.rcp.values.havoc(dst.stack_numeric_size);
                                recompute_stack_numeric_size(dom.rcp, stack, bin.dst);
                            } else {
                                dom.rcp.values->apply(ArithBinOp::ADD, dst.stack_numeric_size, dst.stack_numeric_size,
                                                      src.svalue);
                            }
                        }
                    }
                } else {
                    dom.rcp.havoc_register(bin.dst);
                }
            }
            break;
        }
        case Bin::Op::MUL:
            dom.rcp.values->mul(dst.svalue, dst.uvalue, src.svalue, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::UDIV:
            dom.rcp.values->udiv(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::UMOD:
            dom.rcp.values->urem(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::SDIV:
            dom.rcp.values->sdiv(dst.svalue, dst.uvalue, src.svalue, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::SMOD:
            dom.rcp.values->srem(dst.svalue, dst.uvalue, src.svalue, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::OR:
            dom.rcp.values->bitwise_or(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::AND:
            dom.rcp.values->bitwise_and(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::LSH:
            if (dom.rcp.types.type_is_number(src_reg)) {
                auto src_interval = dom.rcp.values.eval_interval(src.uvalue);
                if (std::optional<Number> sn = src_interval.singleton()) {
                    // truncate to uint64?
                    uint64_t imm = sn->cast_to<uint64_t>() & (bin.is64 ? 63 : 31);
                    if (imm <= std::numeric_limits<int32_t>::max()) {
                        if (!bin.is64) {
                            // Use only the low 32 bits of the value.
                            dom.rcp.values->bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
                        }
                        shl(bin.dst, gsl::narrow_cast<int32_t>(imm), finite_width);
                        break;
                    }
                }
            }
            dom.rcp.values->shl_overflow(dst.svalue, dst.uvalue, src.uvalue);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::RSH:
            if (dom.rcp.types.type_is_number(src_reg)) {
                auto src_interval = dom.rcp.values.eval_interval(src.uvalue);
                if (std::optional<Number> sn = src_interval.singleton()) {
                    uint64_t imm = sn->cast_to<uint64_t>() & (bin.is64 ? 63 : 31);
                    if (imm <= std::numeric_limits<int32_t>::max()) {
                        if (!bin.is64) {
                            // Use only the low 32 bits of the value.
                            dom.rcp.values->bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
                        }
                        lshr(bin.dst, gsl::narrow_cast<int32_t>(imm), finite_width);
                        break;
                    }
                }
            }
            dom.rcp.havoc_register_except_type(bin.dst);
            break;
        case Bin::Op::ARSH:
            if (dom.rcp.types.type_is_number(src_reg)) {
                ashr(bin.dst, src.svalue, finite_width);
                break;
            }
            dom.rcp.havoc_register_except_type(bin.dst);
            break;
        case Bin::Op::XOR:
            dom.rcp.values->bitwise_xor(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            dom.rcp.havoc_offsets(bin.dst);
            break;
        case Bin::Op::MOVSX8:
        case Bin::Op::MOVSX16:
        case Bin::Op::MOVSX32: {
            const int source_width = _movsx_bits(bin.op);
            // Keep relational information if operation is a no-op.
            if (dst.svalue == src.svalue &&
                dom.rcp.values.eval_interval(dst.svalue) <= Interval::signed_int(source_width)) {
                return;
            }
            if (dom.rcp.types.type_is_number(src_reg)) {
                dom.rcp.havoc_offsets(bin.dst);
                dom.rcp.assign_type(bin.dst, T_NUM);
                dom.rcp.values->sign_extend(dst.svalue, dst.uvalue, src.svalue, finite_width, source_width);
                break;
            }
            dom.rcp.havoc_register(bin.dst);
            break;
        }
        case Bin::Op::MOV:
            // Keep relational information if operation is a no-op.
            if (bin.is64 || dom.rcp.types.type_is_number(src_reg)) {
                if (bin.dst != src_reg) {
                    // the 32bit case is handled below
                    dom.rcp.assign(bin.dst, src_reg);
                }
            } else {
                // If src is not a number, we don't know how to truncate a pointer.
                dom.rcp.havoc_register(bin.dst);
            }
            break;
        }
    }
    if (!bin.is64) {
        dom.rcp.values->bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
    }
}

void EbpfTransformer::initialize_loop_counter(const Label& label) {
    dom.rcp.values.assign(variable_registry->loop_counter(to_string(label)), 0);
}

void EbpfTransformer::operator()(const IncrementLoopCounter& ins) {
    if (dom.is_bottom()) {
        return;
    }
    const auto counter = variable_registry->loop_counter(to_string(ins.name));
    dom.rcp.values->add(counter, 1);
}

void ebpf_domain_initialize_loop_counter(EbpfDomain& dom, const Label& label) {
    EbpfTransformer{dom}.initialize_loop_counter(label);
}
} // namespace prevail

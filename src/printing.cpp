// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <variant>
#include <vector>

#include "arith/num_big.hpp"
#include "arith/variable.hpp"
#include "cfg/cfg.hpp"
#include "crab/interval.hpp"
#include "crab/type_encoding.hpp"
#include "crab/var_registry.hpp"
#include "ir/syntax.hpp"
#include "platform.hpp"
#include "spec/function_prototypes.hpp"
#include "verifier.hpp"

using std::optional;
using std::string;
using std::vector;

namespace prevail {

std::ostream& operator<<(std::ostream& o, const Interval& interval) {
    if (interval.is_bottom()) {
        o << "_|_";
    } else {
        o << "[" << interval._lb << ", " << interval._ub << "]";
    }
    return o;
}
static std::string int128_to_string(Int128 n) {
    if (n == 0) {
        return "0";
    }
    bool negative = false;
    if (n < 0) {
        negative = true;
        // Handle kInt128Min: negate via unsigned to avoid overflow.
        if (n == kInt128Min) {
            // kInt128Min == -170141183460469231731687303715884105728
            // Build the string for the absolute value via unsigned arithmetic.
            auto u = static_cast<UInt128>(n);
            // Two's complement: UInt128(kInt128Min) is the correct magnitude.
            std::string result;
            while (u != 0) {
                result += static_cast<char>('0' + static_cast<int>(u % 10));
                u /= 10;
            }
            result += '-';
            std::ranges::reverse(result);
            return result;
        }
        n = -n;
    }
    std::string result;
    while (n > 0) {
        result += static_cast<char>('0' + static_cast<int>(n % 10));
        n /= 10;
    }
    if (negative) {
        result += '-';
    }
    std::ranges::reverse(result);
    return result;
}

std::ostream& operator<<(std::ostream& o, const Number& z) { return o << z.to_string(); }

std::string Number::to_string() const { return int128_to_string(_n); }

std::string Interval::to_string() const {
    std::ostringstream s;
    s << *this;
    return s.str();
}

std::ostream& operator<<(std::ostream& os, const Label& label) {
    if (label == Label::entry) {
        return os << "entry";
    }
    if (label == Label::exit) {
        return os << "exit";
    }
    if (!label.stack_frame_prefix.empty()) {
        os << label.stack_frame_prefix << STACK_FRAME_DELIMITER;
    }
    os << label.from;
    if (label.to != -1) {
        os << ":" << label.to;
    }
    if (!label.special_label.empty()) {
        os << " (" << label.special_label << ")";
    }
    return os;
}

string to_string(Label const& label) {
    std::stringstream str;
    str << label;
    return str.str();
}

struct LineInfoPrinter {
    std::ostream& os;
    std::string previous_source_line;

    void print_line_info(const Label& label) {
        if (thread_local_options.verbosity_opts.print_line_info) {
            const auto& line_info_map = thread_local_program_info.get().line_info;
            const auto& line_info = line_info_map.find(label.from);
            // Print line info only once.
            if (line_info != line_info_map.end() && line_info->second.source_line != previous_source_line) {
                os << "\n" << line_info->second << "\n";
                previous_source_line = line_info->second.source_line;
            }
        }
    }
};

struct DetailedPrinter : LineInfoPrinter {
    const Program& prog;

    DetailedPrinter(std::ostream& os, const Program& prog) : LineInfoPrinter{os}, prog(prog) {}

    void print_labels(const std::string& direction, const std::set<Label>& labels) {
        auto [it, et] = std::pair{labels.begin(), labels.end()};
        if (it != et) {
            os << "  " << direction << " ";
            while (it != et) {
                os << *it;
                ++it;
                if (it == et) {
                    os << ";";
                } else {
                    os << ",";
                }
            }
        }
        os << "\n";
    }

    void print_jump(const std::string& direction, const Label& label) {
        print_labels(direction, direction == "from" ? prog.cfg().parents_of(label) : prog.cfg().children_of(label));
    }

    void print_instruction(const Program& prog, const Label& label) {
        for (const auto& pre : prog.assertions_at(label)) {
            os << "  " << "assert " << pre << ";\n";
        }
        os << "  " << prog.instruction_at(label) << ";\n";
    }
};

void print_program(const Program& prog, std::ostream& os, const bool simplify) {
    DetailedPrinter printer{os, prog};
    for (const BasicBlock& bb : BasicBlock::collect_basic_blocks(prog.cfg(), simplify)) {
        printer.print_jump("from", bb.first_label());
        os << bb.first_label() << ":\n";
        for (const Label& label : bb) {
            printer.print_line_info(label);
            printer.print_instruction(prog, label);
        }
        printer.print_jump("goto", bb.last_label());
    }
    os << "\n";
}

void print_invariants(std::ostream& os, const Program& prog, const bool simplify, const AnalysisResult& result) {
    DetailedPrinter printer{os, prog};
    for (const BasicBlock& bb : BasicBlock::collect_basic_blocks(prog.cfg(), simplify)) {
        if (result.invariants.at(bb.first_label()).pre.is_bottom()) {
            continue;
        }
        os << "\nPre-invariant : " << result.invariants.at(bb.first_label()).pre << "\n";
        printer.print_jump("from", bb.first_label());
        os << bb.first_label() << ":\n";
        Label last_label = bb.first_label();
        for (const Label& label : bb) {
            printer.print_line_info(label);
            printer.print_instruction(prog, label);
            last_label = label;

            const auto& current = result.invariants.at(last_label);
            if (current.error) {
                os << "\nVerification error:\n";
                if (label != bb.last_label()) {
                    os << "After " << current.pre << "\n";
                }
                print_error(os, *current.error);
                os << "\n";
                return;
            }
        }
        const auto& current = result.invariants.at(last_label);
        if (!current.post.is_bottom()) {
            printer.print_jump("goto", last_label);
            os << "\nPost-invariant : " << current.post << "\n";
        }
    }
    os << "\n";
}

void print_dot(const Program& prog, std::ostream& out) {
    out << "digraph program {\n";
    out << "    node [shape = rectangle];\n";
    for (const auto& label : prog.labels()) {
        out << "    \"" << label << "\"[xlabel=\"" << label << "\",label=\"";

        for (const auto& pre : prog.assertions_at(label)) {
            out << "assert " << pre << "\\l";
        }
        out << prog.instruction_at(label) << "\\l";

        out << "\"];\n";
        for (const Label& next : prog.cfg().children_of(label)) {
            out << "    \"" << label << "\" -> \"" << next << "\";\n";
        }
        out << "\n";
    }
    out << "}\n";
}

void print_dot(const Program& prog, const std::string& outfile) {
    std::ofstream out{outfile};
    if (out.fail()) {
        throw std::runtime_error(std::string("Could not open file ") + outfile);
    }
    print_dot(prog, out);
}

void print_unreachable(std::ostream& os, const Program& prog, const AnalysisResult& result) {
    for (const auto& [label, notes] : result.find_unreachable(prog)) {
        for (const auto& msg : notes) {
            os << label << ": " << msg << "\n";
        }
    }
    os << "\n";
}

std::string to_string(const VerificationError& error) {
    std::stringstream ss;
    if (const auto& label = error.where) {
        ss << *label << ": ";
    }
    ss << error.what();
    return ss.str();
}

void print_error(std::ostream& os, const VerificationError& error) {
    LineInfoPrinter printer{os};
    if (const auto& label = error.where) {
        printer.print_line_info(*label);
        os << *label << ": ";
    }
    os << error.what() << "\n";
    os << "\n";
}

std::ostream& operator<<(std::ostream& os, const ArgSingle::Kind kind) {
    switch (kind) {
    case ArgSingle::Kind::ANYTHING: return os << "uint64_t";
    case ArgSingle::Kind::PTR_TO_CTX: return os << "ctx";
    case ArgSingle::Kind::PTR_TO_STACK: return os << "stack";
    case ArgSingle::Kind::MAP_FD: return os << "map_fd";
    case ArgSingle::Kind::MAP_FD_PROGRAMS: return os << "map_fd_programs";
    case ArgSingle::Kind::PTR_TO_MAP_KEY: return os << "map_key";
    case ArgSingle::Kind::PTR_TO_MAP_VALUE: return os << "map_value";
    }
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, const ArgPair::Kind kind) {
    switch (kind) {
    case ArgPair::Kind::PTR_TO_READABLE_MEM: return os << "mem";
    case ArgPair::Kind::PTR_TO_WRITABLE_MEM: return os << "out";
    }
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, const ArgSingle arg) {
    os << arg.kind;
    if (arg.or_null) {
        os << "?";
    }
    os << " " << arg.reg;
    return os;
}

std::ostream& operator<<(std::ostream& os, const ArgPair arg) {
    os << arg.kind;
    if (arg.or_null) {
        os << "?";
    }
    os << " " << arg.mem << "[" << arg.size;
    if (arg.can_be_zero) {
        os << "?";
    }
    os << "], uint64_t " << arg.size;
    return os;
}

std::ostream& operator<<(std::ostream& os, const Bin::Op op) {
    using Op = Bin::Op;
    switch (op) {
    case Op::MOV: return os;
    case Op::MOVSX8: return os << "s8";
    case Op::MOVSX16: return os << "s16";
    case Op::MOVSX32: return os << "s32";
    case Op::ADD: return os << "+";
    case Op::SUB: return os << "-";
    case Op::MUL: return os << "*";
    case Op::UDIV: return os << "/";
    case Op::SDIV: return os << "s/";
    case Op::UMOD: return os << "%";
    case Op::SMOD: return os << "s%";
    case Op::OR: return os << "|";
    case Op::AND: return os << "&";
    case Op::LSH: return os << "<<";
    case Op::RSH: return os << ">>";
    case Op::ARSH: return os << ">>>";
    case Op::XOR: return os << "^";
    }
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, const Condition::Op op) {
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return os << "==";
    case Op::NE: return os << "!=";
    case Op::SET: return os << "&==";
    case Op::NSET: return os << "&!="; // not in ebpf
    case Op::LT: return os << "<";     // TODO: os << "u<";
    case Op::LE: return os << "<=";    // TODO: os << "u<=";
    case Op::GT: return os << ">";     // TODO: os << "u>";
    case Op::GE: return os << ">=";    // TODO: os << "u>=";
    case Op::SLT: return os << "s<";
    case Op::SLE: return os << "s<=";
    case Op::SGT: return os << "s>";
    case Op::SGE: return os << "s>=";
    }
    assert(false);
    return os;
}

static string size(const int w, const bool is_signed = false) {
    return string(is_signed ? "s" : "u") + std::to_string(w * 8);
}

// ReSharper disable CppMemberFunctionMayBeConst
struct AssertionPrinterVisitor {
    std::ostream& _os;

    void operator()(ValidStore const& a) {
        _os << a.mem << ".type != stack -> " << TypeConstraint{a.val, TypeGroup::number};
    }

    void operator()(ValidAccess const& a) {
        if (a.or_null) {
            _os << "(" << TypeConstraint{a.reg, TypeGroup::number} << " and " << a.reg << ".value == 0) or ";
        }
        _os << "valid_access(" << a.reg << ".offset";
        if (a.offset > 0) {
            _os << "+" << a.offset;
        } else if (a.offset < 0) {
            _os << a.offset;
        }

        if (a.width == Value{Imm{0}}) {
            // a.width == 0, meaning we only care it's an in-bound pointer,
            // so it can be compared with another pointer to the same region.
            _os << ") for comparison/subtraction";
        } else {
            _os << ", width=" << a.width << ") for ";
            if (a.access_type == AccessType::read) {
                _os << "read";
            } else {
                _os << "write";
            }
        }
    }

    void operator()(const BoundedLoopCount& a) {
        _os << variable_registry->loop_counter(to_string(a.name)) << " < " << BoundedLoopCount::limit;
    }

    void operator()(ValidSize const& a) {
        const auto op = a.can_be_zero ? " >= " : " > ";
        _os << a.reg << ".value" << op << 0;
    }

    void operator()(ValidCall const& a) {
        const EbpfHelperPrototype proto = thread_local_program_info->platform->get_helper_prototype(a.func);
        _os << "valid call(" << proto.name << ")";
    }

    void operator()(ValidMapKeyValue const& a) {
        _os << "within(" << a.access_reg << ":" << (a.key ? "key_size" : "value_size") << "(" << a.map_fd_reg << "))";
    }

    void operator()(ZeroCtxOffset const& a) {
        _os << variable_registry->reg(DataKind::ctx_offsets, a.reg.v) << " == 0";
    }

    void operator()(Comparable const& a) {
        if (a.or_r2_is_number) {
            _os << TypeConstraint{a.r2, TypeGroup::number} << " or ";
        }
        _os << variable_registry->type_reg(a.r1.v) << " == " << variable_registry->type_reg(a.r2.v) << " in "
            << TypeGroup::singleton_ptr;
    }

    void operator()(Addable const& a) {
        _os << TypeConstraint{a.ptr, TypeGroup::pointer} << " -> " << TypeConstraint{a.num, TypeGroup::number};
    }

    void operator()(ValidDivisor const& a) { _os << a.reg << " != 0"; }

    void operator()(TypeConstraint const& tc) {
        const string cmp_op = is_singleton_type(tc.types) ? "==" : "in";
        _os << variable_registry->type_reg(tc.reg.v) << " " << cmp_op << " " << tc.types;
    }

    void operator()(FuncConstraint const& fc) { _os << variable_registry->type_reg(fc.reg.v) << " is helper"; }
};

// ReSharper disable CppMemberFunctionMayBeConst
struct CommandPrinterVisitor {
    std::ostream& os_;

    void visit(const auto& item) { std::visit(*this, item); }

    void operator()(Undefined const& a) { os_ << "Undefined{" << a.opcode << "}"; }

    void operator()(LoadMapFd const& b) { os_ << b.dst << " = map_fd " << b.mapfd; }

    void operator()(LoadMapAddress const& b) { os_ << b.dst << " = map_val(" << b.mapfd << ") + " << b.offset; }

    void operator()(LoadPseudo const& b) {
        os_ << b.dst << " = ";
        switch (b.addr.kind) {
        case PseudoAddress::Kind::VARIABLE_ADDR: os_ << "variable_addr(" << b.addr.imm << ")"; break;
        case PseudoAddress::Kind::CODE_ADDR: os_ << "code_addr(" << b.addr.imm << ")"; break;
        case PseudoAddress::Kind::MAP_BY_IDX: os_ << "map_by_idx(" << b.addr.imm << ")"; break;
        case PseudoAddress::Kind::MAP_VALUE_BY_IDX:
            os_ << "mva(map_by_idx(" << b.addr.imm << ")) + " << b.addr.next_imm;
            break;
        }
    }

    // llvm-objdump uses "w<number>" for 32-bit operations and "r<number>" for 64-bit operations.
    // We use the same convention here for consistency.
    static std::string reg_name(Reg const& a, const bool is64) { return ((is64) ? "r" : "w") + std::to_string(a.v); }

    void operator()(Bin const& b) {
        os_ << reg_name(b.dst, b.is64) << " " << b.op << "= " << b.v;
        if (b.lddw) {
            os_ << " ll";
        }
    }

    void operator()(Un const& b) {
        os_ << b.dst << " = ";
        switch (b.op) {
        case Un::Op::BE16: os_ << "be16 "; break;
        case Un::Op::BE32: os_ << "be32 "; break;
        case Un::Op::BE64: os_ << "be64 "; break;
        case Un::Op::LE16: os_ << "le16 "; break;
        case Un::Op::LE32: os_ << "le32 "; break;
        case Un::Op::LE64: os_ << "le64 "; break;
        case Un::Op::SWAP16: os_ << "swap16 "; break;
        case Un::Op::SWAP32: os_ << "swap32 "; break;
        case Un::Op::SWAP64: os_ << "swap64 "; break;
        case Un::Op::NEG: os_ << "-"; break;
        }
        os_ << b.dst;
    }

    void operator()(Call const& call) {
        os_ << "r0 = " << call.name << ":" << call.func << "(";
        for (uint8_t r = 1; r <= 5; r++) {
            // Look for a singleton.
            auto single = std::ranges::find_if(call.singles, [r](const ArgSingle arg) { return arg.reg.v == r; });
            if (single != call.singles.end()) {
                if (r > 1) {
                    os_ << ", ";
                }
                os_ << *single;
                continue;
            }

            // Look for the start of a pair.
            auto pair = std::ranges::find_if(call.pairs, [r](const ArgPair arg) { return arg.mem.v == r; });
            if (pair != call.pairs.end()) {
                if (r > 1) {
                    os_ << ", ";
                }
                os_ << *pair;
                r++;
                continue;
            }

            // Not found.
            break;
        }
        os_ << ")";
    }

    void operator()(CallLocal const& call) { os_ << "call <" << to_string(call.target) << ">"; }

    void operator()(Callx const& callx) { os_ << "callx " << callx.func; }

    void operator()(CallBtf const& call) { os_ << "call_btf " << call.btf_id; }

    void operator()(Exit const& b) { os_ << "exit"; }

    void operator()(Jmp const& b) {
        // A "standalone" jump Instruction.
        // Print the label without offset calculations.
        if (b.cond) {
            os_ << "if ";
            print(*b.cond);
            os_ << " ";
        }
        os_ << "goto label <" << to_string(b.target) << ">";
    }

    void operator()(Jmp const& b, const int offset) {
        const string sign = offset > 0 ? "+" : "";
        const string target = sign + std::to_string(offset) + " <" + to_string(b.target) + ">";

        if (b.cond) {
            os_ << "if ";
            print(*b.cond);
            os_ << " ";
        }
        os_ << "goto " << target;
    }

    void operator()(Packet const& b) {
        /* Direct packet access, R0 = *(uint *) (skb->data + imm32) */
        /* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */
        const string s = size(b.width);
        os_ << "r0 = ";
        os_ << "*(" << s << " *)skb[";
        if (b.regoffset) {
            os_ << *b.regoffset;
        }
        if (b.offset != 0) {
            if (b.regoffset) {
                os_ << " + ";
            }
            os_ << b.offset;
        }
        os_ << "]";
    }

    void print(Deref const& access) {
        const string sign = access.offset < 0 ? " - " : " + ";
        const int offset = std::abs(access.offset); // what about INT_MIN?
        os_ << "*(" << size(access.width) << " *)";
        os_ << "(" << access.basereg << sign << offset << ")";
    }

    void print(Condition const& cond) {
        os_ << cond.left << " " << ((!cond.is64) ? "w" : "") << cond.op << " " << cond.right;
    }

    void operator()(Mem const& b) {
        if (b.is_load) {
            os_ << b.value << " = ";
        }
        if (b.is_load && b.is_signed) {
            const string sign = b.access.offset < 0 ? " - " : " + ";
            const int offset = std::abs(b.access.offset);
            os_ << "*(" << size(b.access.width, true) << " *)";
            os_ << "(" << b.access.basereg << sign << offset << ")";
        } else {
            print(b.access);
        }
        if (!b.is_load) {
            os_ << " = " << b.value;
        }
    }

    void operator()(Atomic const& b) {
        os_ << "lock ";
        print(b.access);
        os_ << " ";
        bool showfetch = true;
        switch (b.op) {
        case Atomic::Op::ADD: os_ << "+"; break;
        case Atomic::Op::OR: os_ << "|"; break;
        case Atomic::Op::AND: os_ << "&"; break;
        case Atomic::Op::XOR: os_ << "^"; break;
        case Atomic::Op::XCHG:
            os_ << "x";
            showfetch = false;
            break;
        case Atomic::Op::CMPXCHG:
            os_ << "cx";
            showfetch = false;
            break;
        }
        os_ << "= " << b.valreg;

        if (showfetch && b.fetch) {
            os_ << " fetch";
        }
    }

    void operator()(Assume const& b) {
        os_ << "assume ";
        print(b.cond);
    }

    void operator()(IncrementLoopCounter const& a) {
        os_ << variable_registry->loop_counter(to_string(a.name)) << "++";
    }
};
// ReSharper restore CppMemberFunctionMayBeConst

std::ostream& operator<<(std::ostream& os, Instruction const& ins) {
    std::visit(CommandPrinterVisitor{os}, ins);
    return os;
}

string to_string(Instruction const& ins) {
    std::stringstream str;
    str << ins;
    return str.str();
}

std::ostream& operator<<(std::ostream& os, const Assertion& a) {
    std::visit(AssertionPrinterVisitor{os}, a);
    return os;
}

string to_string(Assertion const& constraint) {
    std::stringstream str;
    str << constraint;
    return str.str();
}

auto get_labels(const InstructionSeq& insts) {
    Pc pc = 0;
    std::map<Label, Pc> pc_of_label;
    for (const auto& [label, inst, _] : insts) {
        pc_of_label[label] = pc;
        pc += size(inst);
    }
    return pc_of_label;
}

void print(const InstructionSeq& insts, std::ostream& out, const std::optional<const Label>& label_to_print,
           const bool print_line_info) {
    const auto pc_of_label = get_labels(insts);
    Pc pc = 0;
    std::string previous_source;
    CommandPrinterVisitor visitor{out};
    for (const LabeledInstruction& labeled_inst : insts) {
        const auto& [label, ins, line_info] = labeled_inst;
        if (!label_to_print.has_value() || label == label_to_print) {
            if (line_info.has_value() && print_line_info) {
                auto& [file, source, line, column] = line_info.value();
                // Only decorate the first instruction associated with a source line.
                if (source != previous_source) {
                    out << line_info.value();
                    previous_source = source;
                }
            }
            if (label.isjump()) {
                out << "\n";
                out << label << ":\n";
            }
            if (label_to_print.has_value()) {
                out << pc << ": ";
            } else {
                out << std::setw(8) << pc << ":\t";
            }
            if (const auto jmp = std::get_if<Jmp>(&ins)) {
                if (!pc_of_label.contains(jmp->target)) {
                    throw std::runtime_error(string("Cannot find label ") + to_string(jmp->target));
                }
                const Pc target_pc = pc_of_label.at(jmp->target);
                visitor(*jmp, gsl::narrow<int>(target_pc) - static_cast<int>(pc) - 1);
            } else {
                std::visit(visitor, ins);
            }
            out << "\n";
        }
        pc += size(ins);
    }
}

std::ostream& operator<<(std::ostream& o, const EbpfMapDescriptor& desc) {
    return o << "(" << "original_fd = " << desc.original_fd << ", " << "inner_map_fd = " << desc.inner_map_fd << ", "
             << "type = " << desc.type << ", " << "max_entries = " << desc.max_entries << ", "
             << "value_size = " << desc.value_size << ", " << "key_size = " << desc.key_size << ")";
}

void print_map_descriptors(const std::vector<EbpfMapDescriptor>& descriptors, std::ostream& o) {
    int i = 0;
    for (const auto& desc : descriptors) {
        o << "map " << i << ":" << desc << "\n";
        i++;
    }
}

std::ostream& operator<<(std::ostream& os, const btf_line_info_t& line_info) {
    os << "; " << line_info.file_name << ":" << line_info.line_number << "\n";
    os << "; " << line_info.source_line << "\n";
    return os;
}

void print_invariants_filtered(std::ostream& os, const Program& prog, const bool simplify, const AnalysisResult& result,
                               const std::set<Label>& filter, const bool compact,
                               const std::map<Label, RelevantState>* relevance) {
    DetailedPrinter printer{os, prog};
    const auto basic_blocks = BasicBlock::collect_basic_blocks(prog.cfg(), simplify);

    // Build a mapping from each label in a basic block to the block's first label.
    // Needed to look up post-invariants for mid-block predecessor labels at join points.
    std::map<Label, Label> label_to_block_leader;
    for (const BasicBlock& bb : basic_blocks) {
        for (const Label& label : bb) {
            label_to_block_leader.insert({label, bb.first_label()});
        }
    }

    // Helper to look up the post-invariant for a predecessor label.
    // Mid-block labels don't have direct invariant entries, so we map
    // through the block leader to find the containing block's post-state.
    // Note: when simplify=true, the block leader's post represents the
    // entire collapsed block, which is correct for the last instruction
    // but approximate for mid-block predecessors. Failure slicing defaults
    // to simplify=false, so this approximation is rarely triggered.
    auto get_parent_post_invariant = [&](const Label& parent) -> const EbpfDomain* {
        const auto leader_it = label_to_block_leader.find(parent);
        const Label& lookup_label = (leader_it != label_to_block_leader.end()) ? leader_it->second : parent;
        const auto inv_it = result.invariants.find(lookup_label);
        if (inv_it != result.invariants.end() && !inv_it->second.post.is_bottom()) {
            return &inv_it->second.post;
        }
        return nullptr;
    };

    for (const BasicBlock& bb : basic_blocks) {
        // Check if any label in this basic block is in the filter
        bool bb_has_filtered_label = false;
        for (const Label& label : bb) {
            if (filter.contains(label)) {
                bb_has_filtered_label = true;
                break;
            }
        }
        if (!bb_has_filtered_label) {
            continue;
        }

        // Find the first filtered label in this block to use as the block header
        Label first_filtered_label = bb.first_label();
        for (const Label& label : bb) {
            if (filter.contains(label)) {
                first_filtered_label = label;
                break;
            }
        }

        // Use bb.first_label() for reachability check: if the block's entry is unreachable,
        // skip the entire block. The filtered label's pre-invariant is printed below.
        if (result.invariants.at(bb.first_label()).pre.is_bottom()) {
            continue;
        }

        // Print pre-invariant for first filtered label in block (unless compact)
        if (!compact) {
            // Set invariant filter if we have relevance info for this label
            const auto* label_relevance =
                relevance ? (relevance->contains(first_filtered_label) ? &relevance->at(first_filtered_label) : nullptr)
                          : nullptr;
            os << invariant_filter(label_relevance);
            os << "\nPre-invariant : " << result.invariants.at(first_filtered_label).pre << "\n";
            os << invariant_filter(nullptr); // Clear filter
        }

        // Print the jump and block header anchored to the basic block entry label
        // for correct CFG structure representation.
        printer.print_jump("from", bb.first_label());
        os << bb.first_label() << ":\n";

        // R3: Show per-predecessor invariants at join points.
        // When multiple predecessors exist and at least 2 are in the slice,
        // show what each incoming edge contributed to help diagnose lost correlations.
        if (!compact && relevance) {
            const auto parents = prog.cfg().parents_of(bb.first_label());
            std::vector<Label> in_slice_parents;
            for (const auto& parent : parents) {
                if (filter.contains(parent)) {
                    in_slice_parents.push_back(parent);
                }
            }
            if (in_slice_parents.size() >= 2) {
                // Build the union of relevant registers from this label and all in-slice parents
                RelevantState join_relevance;
                if (relevance->contains(first_filtered_label)) {
                    const auto& fl = relevance->at(first_filtered_label);
                    join_relevance.registers.insert(fl.registers.begin(), fl.registers.end());
                    join_relevance.stack_offsets.insert(fl.stack_offsets.begin(), fl.stack_offsets.end());
                }
                for (const auto& parent : in_slice_parents) {
                    if (relevance->contains(parent)) {
                        const auto& pr = relevance->at(parent);
                        join_relevance.registers.insert(pr.registers.begin(), pr.registers.end());
                        join_relevance.stack_offsets.insert(pr.stack_offsets.begin(), pr.stack_offsets.end());
                    }
                }

                os << "  --- join point: per-predecessor state ---\n";
                for (const auto& parent : in_slice_parents) {
                    const auto* post = get_parent_post_invariant(parent);
                    if (post) {
                        os << invariant_filter(&join_relevance);
                        os << "  from " << parent << ": " << *post << "\n";
                        os << invariant_filter(nullptr);
                    }
                }
                os << "  --- end join point ---\n";
            }
        }

        if (first_filtered_label != bb.first_label()) {
            // Indicate that some labels/instructions were skipped due to filtering.
            os << "  ... skipped ...\n";
        }

        Label last_label = bb.first_label();
        Label prev_filtered_label = bb.first_label();
        bool has_prev_filtered = false;
        for (const Label& label : bb) {
            if (!filter.contains(label)) {
                continue;
            }

            // If there was a gap since the previous filtered label in this block,
            // close the previous label's output and show a skip indicator.
            if (has_prev_filtered && prev_filtered_label != label) {
                // Print post-invariant and goto for the previous filtered label
                if (!compact) {
                    const auto& prev_current = result.invariants.at(prev_filtered_label);
                    if (!prev_current.post.is_bottom()) {
                        const auto* prev_label_relevance =
                            relevance ? (relevance->contains(prev_filtered_label) ? &relevance->at(prev_filtered_label)
                                                                                  : nullptr)
                                      : nullptr;
                        os << invariant_filter(prev_label_relevance);
                        printer.print_jump("goto", prev_filtered_label);
                        os << "\nPost-invariant : " << prev_current.post << "\n";
                        os << invariant_filter(nullptr);
                    }
                }
                // Check if there are skipped labels between prev and current
                bool has_gap = false;
                for (const Label& mid : bb) {
                    if (mid <= prev_filtered_label) {
                        continue;
                    }
                    if (mid >= label) {
                        break;
                    }
                    has_gap = true;
                    break;
                }
                if (has_gap) {
                    os << "  ... skipped ...\n";
                }
                // Print pre-invariant for this label
                if (!compact) {
                    const auto* label_rel =
                        relevance ? (relevance->contains(label) ? &relevance->at(label) : nullptr) : nullptr;
                    os << invariant_filter(label_rel);
                    os << "\nPre-invariant : " << result.invariants.at(label).pre << "\n";
                    os << invariant_filter(nullptr);
                    printer.print_jump("from", label);
                }
            }

            printer.print_line_info(label);

            // Print assertions, filtered by relevance if provided
            const auto* label_relevance =
                relevance ? (relevance->contains(label) ? &relevance->at(label) : nullptr) : nullptr;
            for (const auto& assertion : prog.assertions_at(label)) {
                // If we have relevance info, only print assertions involving relevant registers.
                // Assertions with no register deps (e.g., ValidCall, BoundedLoopCount) are always
                // printed to avoid hiding the failing assertion from the slice output.
                if (label_relevance) {
                    auto assertion_regs = extract_assertion_registers(assertion);
                    if (!assertion_regs.empty()) {
                        bool is_relevant = false;
                        for (const auto& reg : assertion_regs) {
                            if (label_relevance->registers.contains(reg)) {
                                is_relevant = true;
                                break;
                            }
                        }
                        if (!is_relevant) {
                            continue; // Skip this assertion
                        }
                    }
                }
                os << "  assert " << assertion << ";\n";
            }
            os << "  " << prog.instruction_at(label) << ";\n";

            last_label = label;
            prev_filtered_label = label;
            has_prev_filtered = true;

            const auto& current = result.invariants.at(label);
            if (current.error) {
                os << "\nVerification error:\n";
                print_error(os, *current.error);
                os << "\n";
            }
        }

        // Print post-invariant (unless compact)
        if (!compact) {
            const auto& current = result.invariants.at(last_label);
            if (!current.post.is_bottom()) {
                // Set invariant filter for post-invariant
                const auto* label_relevance =
                    relevance ? (relevance->contains(last_label) ? &relevance->at(last_label) : nullptr) : nullptr;
                os << invariant_filter(label_relevance);
                printer.print_jump("goto", last_label);
                os << "\nPost-invariant : " << current.post << "\n";
                os << invariant_filter(nullptr); // Clear filter
            }
        }
    }
    os << "\n";
}

void print_failure_slices(std::ostream& os, const Program& prog, const bool simplify, const AnalysisResult& result,
                          const std::vector<FailureSlice>& slices, const bool compact) {
    if (slices.empty()) {
        os << "No verification failures found.\n";
        return;
    }

    for (size_t i = 0; i < slices.size(); ++i) {
        const auto& slice = slices[i];

        os << "=== Failure Slice " << (i + 1) << " of " << slices.size() << " ===\n\n";

        // Print error summary
        os << "[ERROR] " << slice.error.what() << "\n";
        os << "[LOCATION] " << slice.failing_label << "\n";

        // Print relevant registers at failure point
        const auto it = slice.relevance.find(slice.failing_label);
        if (it != slice.relevance.end()) {
            os << "[RELEVANT REGISTERS] ";
            bool first = true;
            for (const auto& reg : it->second.registers) {
                if (!first) {
                    os << ", ";
                }
                os << "r" << static_cast<int>(reg.v);
                first = false;
            }
            if (!it->second.stack_offsets.empty()) {
                for (const auto& offset : it->second.stack_offsets) {
                    if (!first) {
                        os << ", ";
                    }
                    os << "stack[" << offset << "]";
                    first = false;
                }
            }
            os << "\n";
        }

        os << "[SLICE SIZE] " << slice.relevance.size() << " program points\n\n";

        // Print a compact control-flow summary showing the branch-path skeleton
        // through the slice. Lists labels in order with Assume/Jmp annotations.
        // At join points (labels with ≥2 in-slice predecessors), the converging
        // predecessors are grouped as {pred1 | pred2} → join_label.
        {
            os << "[CONTROL FLOW] ";
            // Collect and sort impacted labels
            auto labels = slice.impacted_labels();

            // Build a map: join_label → set of in-slice predecessors
            // Also collect which labels are convergence predecessors (to skip them in linear output)
            std::map<Label, std::vector<Label>> join_predecessors;
            for (const auto& lbl : labels) {
                const auto& parents = prog.cfg().parents_of(lbl);
                std::vector<Label> in_slice_parents;
                for (const auto& p : parents) {
                    if (labels.contains(p)) {
                        in_slice_parents.push_back(p);
                    }
                }
                if (in_slice_parents.size() >= 2) {
                    join_predecessors[lbl] = in_slice_parents;
                }
            }
            // Labels consumed by a {..|..} group are skipped in linear output,
            // unless they are themselves join points (nested joins).
            std::set<Label> convergence_members;
            for (const auto& [join_lbl, preds] : join_predecessors) {
                for (const auto& p : preds) {
                    if (!join_predecessors.contains(p)) {
                        convergence_members.insert(p);
                    }
                }
            }

            // Helper to annotate a label with its instruction type
            auto annotate_label = [&](const Label& lbl) {
                os << lbl;
                const auto& ins = prog.instruction_at(lbl);
                if (const auto* assume = std::get_if<Assume>(&ins)) {
                    os << " (assume " << assume->cond.left << " " << assume->cond.op << " " << assume->cond.right
                       << ")";
                } else if (const auto* jmp = std::get_if<Jmp>(&ins)) {
                    if (jmp->cond) {
                        os << " (if " << jmp->cond->left << " " << jmp->cond->op << " " << jmp->cond->right << ")";
                    }
                }
            };

            bool first_cf = true;
            for (const auto& lbl : labels) {
                // Skip labels that are part of a convergence group (printed with their join)
                if (convergence_members.contains(lbl)) {
                    continue;
                }

                if (!first_cf) {
                    os << ", ";
                }
                first_cf = false;

                // If this label is a join point, print {pred1 | pred2} → lbl
                if (join_predecessors.contains(lbl)) {
                    os << "{";
                    bool first_pred = true;
                    for (const auto& pred : join_predecessors.at(lbl)) {
                        if (!first_pred) {
                            os << " | ";
                        }
                        first_pred = false;
                        annotate_label(pred);
                    }
                    os << "} -> ";
                }

                annotate_label(lbl);
            }
            if (labels.contains(slice.failing_label)) {
                os << " FAIL";
            }
            os << "\n\n";
        }

        // Print the filtered CFG with assertion filtering based on relevance
        os << "[CAUSAL TRACE]\n";
        print_invariants_filtered(os, prog, simplify, result, slice.impacted_labels(), compact, &slice.relevance);

        if (i + 1 < slices.size()) {
            os << "\n";
        }
    }
}

} // namespace prevail

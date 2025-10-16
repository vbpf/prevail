// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <fstream>
#include <iomanip>
#include <iostream>
#include <variant>
#include <vector>

#include "arith/num_big.hpp"
#include "arith/variable.hpp"
#include "asm_syntax.hpp"
#include "cfg/cfg.hpp"
#include "crab/fwd_analyzer.hpp"
#include "crab/interval.hpp"
#include "crab/type_encoding.hpp"
#include "crab/var_registry.hpp"
#include "crab_verifier.hpp"
#include "helpers.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"

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
std::ostream& operator<<(std::ostream& o, const Number& z) { return o << z._n.str(); }

std::string Number::to_string() const { return _n.str(); }

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

void print_jump(std::ostream& o, const std::string& direction, const std::set<Label>& labels) {
    auto [it, et] = std::pair{labels.begin(), labels.end()};
    if (it != et) {
        o << "  " << direction << " ";
        while (it != et) {
            o << *it;
            ++it;
            if (it == et) {
                o << ";";
            } else {
                o << ",";
            }
        }
    }
    o << "\n";
}

void print_program(const Program& prog, std::ostream& os, const bool simplify, const printfunc& prefunc,
                   const printfunc& postfunc) {
    LineInfoPrinter printer{os};
    for (const BasicBlock& bb : BasicBlock::collect_basic_blocks(prog.cfg(), simplify)) {
        prefunc(os, bb.first_label());
        print_jump(os, "from", prog.cfg().parents_of(bb.first_label()));
        os << bb.first_label() << ":\n";
        for (const Label& label : bb) {
            printer.print_line_info(label);
            for (const auto& pre : prog.assertions_at(label)) {
                os << "  " << "assert " << pre << ";\n";
            }
            os << "  " << prog.instruction_at(label) << ";\n";
        }
        print_jump(os, "goto", prog.cfg().children_of(bb.last_label()));
        postfunc(os, bb.last_label());
    }
    os << "\n";
}

static void nop(std::ostream&, const Label&) {}

void print_program(const Program& prog, std::ostream& os, const bool simplify) {
    print_program(prog, os, simplify, nop, nop);
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

void print_reachability(std::ostream& os, const Report& report) {
    for (const auto& [label, notes] : report.reachability) {
        for (const auto& msg : notes) {
            os << label << ": " << msg << "\n";
        }
    }
    os << "\n";
}

void print_warnings(std::ostream& os, const Report& report) {
    LineInfoPrinter printer{os};
    for (const auto& [label, warnings] : report.warnings) {
        for (const auto& msg : warnings) {
            printer.print_line_info(label);
            os << label << ": " << msg << "\n";
        }
    }
    os << "\n";
}

void print_all_messages(std::ostream& os, const Report& report) {
    print_reachability(os, report);
    print_warnings(os, report);
}

void print_invariants(std::ostream& os, const Program& prog, const bool simplify, const Invariants& invariants) {
    print_program(
        prog, os, simplify,
        [&](std::ostream& os, const Label& label) -> void {
            os << "\nPre-invariant : " << invariants.invariants.at(label).pre << "\n";
        },
        [&](std::ostream& os, const Label& label) -> void {
            os << "\nPost-invariant : " << invariants.invariants.at(label).post << "\n";
        });
}

std::ostream& operator<<(std::ostream& os, const ArgSingle::Kind kind) {
    switch (kind) {
    case ArgSingle::Kind::ANYTHING: return os << "uint64_t";
    case ArgSingle::Kind::PTR_TO_CTX: return os << "ctx";
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
    os << arg.kind << " " << arg.reg;
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

static string size(const int w) { return string("u") + std::to_string(w * 8); }

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
        _os << variable_registry->loop_counter(to_string(a.name)) << " < " << a.limit;
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
        _os << "within stack(" << a.access_reg << ":" << (a.key ? "key_size" : "value_size") << "(" << a.map_fd_reg
            << "))";
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
        print(b.access);
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
                visitor(*jmp, target_pc - static_cast<int>(pc) - 1);
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
} // namespace prevail
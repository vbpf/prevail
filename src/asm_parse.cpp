// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <map>
#include <regex>
#include <sstream>
#include <string>

#include <boost/lexical_cast.hpp>

#include "arith/dsl_syntax.hpp"
#include "arith/linear_constraint.hpp"
#include "asm_parse.hpp"
#include "asm_unmarshal.hpp"
#include "crab/type_encoding.hpp"
#include "crab/var_registry.hpp"
#include "platform.hpp"
#include "string_constraints.hpp"

using std::regex;
using std::regex_match;

namespace prevail {
#define REG R"_(\s*(r\d\d?)\s*)_"
#define WREG R"_(\s*([wr]\d\d?)\s*)_"
#define IMM R"_(\s*\[?([-+]?(?:0x)?[0-9a-f]+)\]?\s*)_"
#define REG_OR_IMM R"_(\s*([+-]?(?:0x)?[0-9a-f]+|r\d\d?)\s*)_"

#define FUNC IMM
#define OPASSIGN R"_(\s*(\S*)=\s*)_"
#define ASSIGN R"_(\s*=\s*)_"
#define LONGLONG R"_(\s*(ll|)\s*)_"
#define UNOP R"_((-|be16|be32|be64|le16|le32|le64|swap16|swap32|swap64))_"
#define ATOMICOP R"_((\+|\||&|\^|x|cx)=)_"

#define PLUSMINUS R"_((\s*[+-])\s*)_"
#define LPAREN R"_(\s*\(\s*)_"
#define RPAREN R"_(\s*\)\s*)_"

#define PAREN(x) LPAREN x RPAREN
#define STAR R"_(\s*\*\s*)_"
#define DEREF STAR PAREN("u(\\d+)" STAR)

#define IN R"_(\s*in\s*)_"
#define TYPE_SET R"_(\s*\{\s*([^}]*)\s*\}\s*)_"

#define CMPOP R"_(\s*(&?[=!]=|s?[<>]=?)\s*)_"
#define LABEL R"_((<\w[a-zA-Z_0-9]*>))_"
#define WRAPPED_LABEL "\\s*" LABEL "\\s*"

#define SPECIAL_VAR R"_(\s*(packet_size|meta_offset)\s*)_"
#define KIND \
    R"_(\s*(svalue|uvalue|ctx_offset|map_fd|map_fd_programs|packet_offset|shared_offset|stack_offset|shared_region_size|stack_numeric_size)\s*)_"
#define INTERVAL R"_(\s*\[([-+]?\d+),\s*([-+]?\d+)\]?\s*)_"
#define ARRAY_RANGE R"_(\s*\[([-+]?\d+)\.\.\.\s*([-+]?\d+)\]?\s*)_"

#define DOT "[.]"
#define TYPE R"_(\s*(shared|number|packet|stack|ctx|map_fd|map_fd_programs)\s*)_"

// Match map_val(fd) + offset
#define MAP_VAL R"_(\s*map_val\((\d+)\)\s*\+\s*(\d+)\s*)_"

// Match map_fd fd
#define MAP_FD R"_(\s*map_fd\s+(\d+)\s*)_"

// Match map_fd fd
#define MAP_FD_PROGRAMS R"_(\s*map_fd_programs\s+(\d+)\s*)_"

static const std::map<std::string, Bin::Op> str_to_binop = {
    {"", Bin::Op::MOV},        {"+", Bin::Op::ADD},   {"-", Bin::Op::SUB},     {"*", Bin::Op::MUL},
    {"/", Bin::Op::UDIV},      {"%", Bin::Op::UMOD},  {"|", Bin::Op::OR},      {"&", Bin::Op::AND},
    {"<<", Bin::Op::LSH},      {">>", Bin::Op::RSH},  {"s>>", Bin::Op::ARSH},  {"^", Bin::Op::XOR},
    {"s/", Bin::Op::SDIV},     {"s%", Bin::Op::SMOD}, {"s8", Bin::Op::MOVSX8}, {"s16", Bin::Op::MOVSX16},
    {"s32", Bin::Op::MOVSX32},
};

static const std::map<std::string, Un::Op> str_to_unop = {
    {"be16", Un::Op::BE16},     {"be32", Un::Op::BE32}, {"be64", Un::Op::BE64},     {"le16", Un::Op::LE16},
    {"le32", Un::Op::LE32},     {"le64", Un::Op::LE64}, {"swap16", Un::Op::SWAP16}, {"swap32", Un::Op::SWAP32},
    {"swap64", Un::Op::SWAP64}, {"-", Un::Op::NEG},
};

static const std::map<std::string, Condition::Op> str_to_cmpop = {
    {"==", Condition::Op::EQ},  {"!=", Condition::Op::NE},   {"&==", Condition::Op::SET}, {"&!=", Condition::Op::NSET},
    {"<", Condition::Op::LT},   {"<=", Condition::Op::LE},   {">", Condition::Op::GT},    {">=", Condition::Op::GE},
    {"s<", Condition::Op::SLT}, {"s<=", Condition::Op::SLE}, {"s>", Condition::Op::SGT},  {"s>=", Condition::Op::SGE},
};

static const std::map<std::string, Atomic::Op> str_to_atomicop = {{"+", Atomic::Op::ADD},  {"|", Atomic::Op::OR},
                                                                  {"&", Atomic::Op::AND},  {"^", Atomic::Op::XOR},
                                                                  {"x", Atomic::Op::XCHG}, {"cx", Atomic::Op::CMPXCHG}};

static const std::map<std::string, int> str_to_width = {
    {"8", 1},
    {"16", 2},
    {"32", 4},
    {"64", 8},
};

static bool is64_reg(const std::string& s) { return s.at(0) == 'r'; }

static Reg reg(const std::string& s) {
    assert(s.at(0) == 'r' || s.at(0) == 'w');
    const uint8_t res = static_cast<uint8_t>(boost::lexical_cast<uint16_t>(s.substr(1)));
    return Reg{res};
}

static Imm imm(const std::string& s, const bool lddw) {
    const int base = s.find("0x") != std::string::npos ? 16 : 10;

    if (lddw) {
        if (s.at(0) == '-') {
            return Imm{static_cast<uint64_t>(std::stoll(s, nullptr, base))};
        } else {
            return Imm{std::stoull(s, nullptr, base)};
        }
    } else {
        if (s.at(0) == '-') {
            return Imm{static_cast<uint64_t>(std::stol(s, nullptr, base))};
        } else {
            return Imm{static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(std::stoul(s, nullptr, base))))};
        }
    }
}

static Number signed_number(const std::string& s) { return std::stoll(s); }

static Number unsigned_number(const std::string& s) { return std::stoull(s); }

static Value reg_or_imm(const std::string& s) {
    if (s.at(0) == 'w' || s.at(0) == 'r') {
        return reg(s);
    } else {
        return imm(s, false);
    }
}

static Deref deref(const std::string& width, const std::string& basereg, const std::string& sign,
                   const std::string& _offset) {
    const int offset = boost::lexical_cast<int>(_offset);
    return Deref{
        .width = str_to_width.at(width),
        .basereg = reg(basereg),
        .offset = (sign == "-" ? -offset : +offset),
    };
}

Instruction parse_instruction(const std::string& line, const std::map<std::string, Label>& label_name_to_label) {
    // treat ";" as a comment
    std::string text = line.substr(0, line.find(';'));
    const size_t end = text.find_last_not_of(' ');
    if (end != std::string::npos) {
        text = text.substr(0, end + 1);
    }
    std::smatch m;
    if (regex_match(text, m, regex("exit"))) {
        return Exit{};
    }
    if (regex_match(text, m, regex("call " FUNC))) {
        const int func = boost::lexical_cast<int>(m[1]);
        return make_call(func, g_ebpf_platform_linux);
    }
    if (regex_match(text, m, regex("call " WRAPPED_LABEL))) {
        return CallLocal{.target = label_name_to_label.at(m[1])};
    }
    if (regex_match(text, m, regex("callx " REG))) {
        return Callx{reg(m[1])};
    }
    if (regex_match(text, m, regex(WREG OPASSIGN WREG))) {
        const std::string r = m[1];
        return Bin{.op = str_to_binop.at(m[2]), .dst = reg(r), .v = reg(m[3]), .is64 = is64_reg(r), .lddw = false};
    }
    if (regex_match(text, m, regex(WREG ASSIGN UNOP WREG))) {
        if (m[1] != m[3]) {
            throw std::invalid_argument(std::string("Invalid unary operation: ") + text);
        }
        return Un{.op = str_to_unop.at(m[2]), .dst = reg(m[1]), .is64 = is64_reg(m[1])};
    }
    if (regex_match(text, m, regex(WREG ASSIGN MAP_VAL))) {
        return LoadMapAddress{
            .dst = reg(m[1]), .mapfd = boost::lexical_cast<int>(m[2]), .offset = boost::lexical_cast<int>(m[3])};
    }
    if (regex_match(text, m, regex(WREG ASSIGN MAP_FD_PROGRAMS))) {
        return LoadMapFd{.dst = reg(m[1]), .mapfd = boost::lexical_cast<int>(m[2])};
    }
    if (regex_match(text, m, regex(WREG ASSIGN MAP_FD))) {
        return LoadMapFd{.dst = reg(m[1]), .mapfd = boost::lexical_cast<int>(m[2])};
    }
    if (regex_match(text, m, regex(WREG OPASSIGN IMM LONGLONG))) {
        const std::string r = m[1];
        const bool lddw = !m[4].str().empty();
        return Bin{.op = str_to_binop.at(m[2]), .dst = reg(r), .v = imm(m[3], lddw), .is64 = is64_reg(r), .lddw = lddw};
    }
    if (regex_match(text, m, regex(REG ASSIGN DEREF PAREN(REG PLUSMINUS IMM)))) {
        return Mem{
            .access = deref(m[2], m[3], m[4], m[5]),
            .value = reg(m[1]),
            .is_load = true,
        };
    }
    if (regex_match(text, m, regex(DEREF PAREN(REG PLUSMINUS IMM) ASSIGN REG_OR_IMM))) {
        return Mem{
            .access = deref(m[1], m[2], m[3], m[4]),
            .value = reg_or_imm(m[5]),
            .is_load = false,
        };
    }
    if (regex_match(text, m, regex("lock " DEREF PAREN(REG PLUSMINUS IMM) " " ATOMICOP " " REG "( fetch)?"))) {
        const Atomic::Op op = str_to_atomicop.at(m[5]);
        return Atomic{.op = op,
                      .fetch = m[7].matched || op == Atomic::Op::XCHG || op == Atomic::Op::CMPXCHG,
                      .access = deref(m[1], m[2], m[3], m[4]),
                      .valreg = reg(m[6])};
    }
    if (regex_match(text, m, regex("r0 = " DEREF "skb\\[(.*)\\]"))) {
        const auto width = str_to_width.at(m[1]);
        const std::string access = m[2].str();
        if (regex_match(access, m, regex(REG))) {
            return Packet{.width = width, .offset = 0, .regoffset = reg(m[1])};
        }
        if (regex_match(access, m, regex(IMM))) {
            return Packet{.width = width, .offset = static_cast<int32_t>(imm(m[1], false).v), .regoffset = {}};
        }
        if (regex_match(access, m, regex(REG PLUSMINUS REG))) {
            return Packet{.width = width, .offset = 0 /* ? */, .regoffset = reg(m[2])};
        }
        if (regex_match(access, m, regex(REG PLUSMINUS IMM))) {
            return Packet{.width = width, .offset = static_cast<int32_t>(imm(m[2], false).v), .regoffset = reg(m[1])};
        }
        return Undefined{0};
    }
    if (regex_match(text, m, regex("assume " WREG CMPOP REG_OR_IMM))) {
        Assume res{
            .cond =
                Condition{
                    .op = str_to_cmpop.at(m[2]), .left = reg(m[1]), .right = reg_or_imm(m[3]), .is64 = is64_reg(m[1])},
            .is_implicit = false,
        };
        return res;
    }
    if (regex_match(text, m, regex("(?:if " WREG CMPOP REG_OR_IMM " )?goto\\s+(?:" IMM ")?" WRAPPED_LABEL))) {
        // We ignore second IMM
        Jmp res{.cond = {}, .target = label_name_to_label.at(m[5])};
        if (m[1].matched) {
            res.cond = Condition{
                .op = str_to_cmpop.at(m[2]), .left = reg(m[1]), .right = reg_or_imm(m[3]), .is64 = is64_reg(m[1])};
        }
        return res;
    }
    return Undefined{0};
}

[[maybe_unused]]
static InstructionSeq parse_program(std::istream& is) {
    std::string line;
    std::vector<Label> pc_to_label;
    InstructionSeq labeled_insts;
    const std::set<Label> seen_labels;
    std::optional<Label> next_label;
    while (std::getline(is, line)) {
        std::smatch m;
        if (regex_search(line, m, regex(LABEL ":"))) {
            next_label = Label(boost::lexical_cast<int>(m[1]));
            if (seen_labels.contains(*next_label)) {
                throw std::invalid_argument("duplicate labels");
            }
            line = m.suffix();
        }
        if (regex_search(line, m, regex(R"(^\s*(\d+:)?\s*)"))) {
            line = m.suffix();
        }
        if (line.empty()) {
            continue;
        }
        Instruction ins = parse_instruction(line, {});
        if (std::holds_alternative<Undefined>(ins)) {
            continue;
        }

        if (!next_label) {
            next_label = Label(static_cast<int>(labeled_insts.size()));
        }
        labeled_insts.emplace_back(*next_label, ins, std::optional<btf_line_info_t>());
        next_label = {};
    }
    return labeled_insts;
}

static uint8_t regnum(const std::string& s) { return static_cast<uint8_t>(boost::lexical_cast<uint16_t>(s.substr(1))); }

static Variable special_var(const std::string& s) {
    if (s == "packet_size") {
        return variable_registry->packet_size();
    }
    if (s == "meta_offset") {
        return variable_registry->meta_offset();
    }
    throw std::runtime_error(std::string() + "Bad special variable: " + s);
}

std::tuple<std::vector<LinearConstraint>, std::vector<LinearConstraint>>
parse_linear_constraints(const std::set<std::string>& constraints, std::vector<Interval>& numeric_ranges) {
    using namespace dsl_syntax;

    std::vector<LinearConstraint> value_csts;
    std::vector<LinearConstraint> type_csts;
    for (const std::string& cst_text : constraints) {
        std::smatch m;
        if (regex_match(cst_text, m, regex(SPECIAL_VAR "=" IMM))) {
            value_csts.push_back(special_var(m[1]) == signed_number(m[2]));
        } else if (regex_match(cst_text, m, regex(SPECIAL_VAR "=" INTERVAL))) {
            Variable d = special_var(m[1]);
            Number lb{signed_number(m[2])};
            Number ub{signed_number(m[3])};
            value_csts.push_back(lb <= d);
            value_csts.push_back(d <= ub);
        } else if (regex_match(cst_text, m, regex(SPECIAL_VAR "=" REG DOT KIND))) {
            LinearExpression d = special_var(m[1]);
            LinearExpression s = variable_registry->reg(regkind(m[3]), regnum(m[2]));
            value_csts.push_back(d == s);
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" SPECIAL_VAR))) {
            LinearExpression d = variable_registry->reg(regkind(m[2]), regnum(m[1]));
            LinearExpression s = special_var(m[3]);
            value_csts.push_back(d == s);
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" REG DOT KIND))) {
            LinearExpression d = variable_registry->reg(regkind(m[2]), regnum(m[1]));
            LinearExpression s = variable_registry->reg(regkind(m[4]), regnum(m[3]));
            value_csts.push_back(d == s);
        } else if (regex_match(cst_text, m,
                               regex(REG DOT "type"
                                             "=" REG DOT "type"))) {
            LinearExpression d = variable_registry->reg(DataKind::types, regnum(m[1]));
            LinearExpression s = variable_registry->reg(DataKind::types, regnum(m[2]));
            type_csts.push_back(d == s);
        } else if (regex_match(cst_text, m,
                               regex(REG DOT "type"
                                             "=" TYPE))) {
            Variable d = variable_registry->reg(DataKind::types, regnum(m[1]));
            type_csts.push_back(d == string_to_type_encoding(m[2]));
        } else if (regex_match(cst_text, m, regex(REG DOT "type" IN TYPE_SET))) {
            Variable d = variable_registry->reg(DataKind::types, regnum(m[1]));
            const std::string inside = m[2]; // everything between the braces

            // Tokenize items inside {...} using the existing TYPE regex.
            static const regex type_tok_regex(TYPE);

            bool any = false;
            Number lb = 0, ub = 0; // initialize once we see the first item

            for (std::sregex_iterator it(inside.begin(), inside.end(), type_tok_regex), end; it != end; ++it) {
                // TYPE has a single capturing group with the symbolic token
                const auto sym = (*it)[1].str();
                const auto enc = string_to_type_encoding(sym);

                // Convert to Number for the DSL constraints
                const Number n = static_cast<int>(enc);
                if (!any) {
                    lb = ub = n;
                    any = true;
                } else {
                    if (n < lb) {
                        lb = n;
                    }
                    if (n > ub) {
                        ub = n;
                    }
                }
            }

            if (!any) {
                throw std::runtime_error("Empty type set in 'in { ... }' constraint: " + cst_text);
            }

            // Emit interval over-approx: lb <= d <= ub
            type_csts.push_back(lb <= d);
            type_csts.push_back(d <= ub);
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" IMM))) {
            Variable d = variable_registry->reg(regkind(m[2]), regnum(m[1]));
            Number value;
            if (m[2] == "uvalue") {
                value = unsigned_number(m[3]);
            } else {
                value = signed_number(m[3]);
            }
            value_csts.push_back(d == value);
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" INTERVAL))) {
            Variable d = variable_registry->reg(regkind(m[2]), regnum(m[1]));
            Number lb, ub;
            if (m[2] == "uvalue") {
                lb = unsigned_number(m[3]);
                ub = unsigned_number(m[4]);
            } else {
                lb = signed_number(m[3]);
                ub = signed_number(m[4]);
            }
            value_csts.push_back(lb <= d);
            value_csts.push_back(d <= ub);
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "-" REG DOT KIND "<=" IMM))) {
            Variable d = variable_registry->reg(regkind(m[2]), regnum(m[1]));
            Variable s = variable_registry->reg(regkind(m[4]), regnum(m[3]));
            Number diff = signed_number(m[5]);
            value_csts.push_back(d - s <= diff);
        } else if (regex_match(cst_text, m,
                               regex("s" ARRAY_RANGE DOT "type"
                                     "=" TYPE))) {
            TypeEncoding type = string_to_type_encoding(m[3]);
            if (type == T_NUM) {
                numeric_ranges.emplace_back(signed_number(m[1]), signed_number(m[2]));
            } else {
                Number lb = signed_number(m[1]);
                Number ub = signed_number(m[2]);
                Variable d = variable_registry->cell_var(DataKind::types, lb, ub - lb + 1);
                type_csts.push_back(d == type);
            }
        } else if (regex_match(cst_text, m,
                               regex("s" ARRAY_RANGE DOT "svalue"
                                     "=" IMM))) {
            Number lb = signed_number(m[1]);
            Number ub = signed_number(m[2]);
            Variable d = variable_registry->cell_var(DataKind::svalues, lb, ub - lb + 1);
            value_csts.push_back(d == signed_number(m[3]));
        } else if (regex_match(cst_text, m,
                               regex("s" ARRAY_RANGE DOT "uvalue"
                                     "=" IMM))) {
            Number lb = signed_number(m[1]);
            Number ub = signed_number(m[2]);
            Variable d = variable_registry->cell_var(DataKind::uvalues, lb, ub - lb + 1);
            value_csts.push_back(d == unsigned_number(m[3]));
        } else {
            throw std::runtime_error(std::string("Unknown constraint: ") + cst_text);
        }
    }
    return {type_csts, value_csts};
}

// return a-b, taking account potential optional-none
StringInvariant StringInvariant::operator-(const StringInvariant& b) const {
    if (this->is_bottom()) {
        return bottom();
    }
    StringInvariant res = top();
    for (const std::string& cst : this->value()) {
        if (b.is_bottom() || !b.contains(cst)) {
            res.maybe_inv->insert(cst);
        }
    }
    return res;
}

// return a+b, taking account potential optional-none
StringInvariant StringInvariant::operator+(const StringInvariant& b) const {
    if (this->is_bottom()) {
        return b;
    }
    StringInvariant res = *this;
    for (const std::string& cst : b.value()) {
        if (res.is_bottom() || !res.contains(cst)) {
            res.maybe_inv->insert(cst);
        }
    }
    return res;
}

std::ostream& operator<<(std::ostream& o, const StringInvariant& inv) {
    if (inv.is_bottom()) {
        return o << "_|_";
    }
    // Intervals
    bool first = true;
    o << "[";
    auto& set = inv.maybe_inv.value();
    std::string lastbase;
    for (const auto& item : set) {
        if (first) {
            first = false;
        } else {
            o << ", ";
        }
        const size_t pos = item.find_first_of(".=[");
        std::string base = item.substr(0, pos);
        if (base != lastbase) {
            o << "\n    ";
            lastbase = base;
        }
        o << item;
    }
    o << "]";
    return o;
}
} // namespace prevail

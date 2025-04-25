// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <map>
#include <vector>

#include "asm_syntax.hpp"
#include "cfg/cfg.hpp"
#include "cfg/label.hpp"
#include "config.hpp"
#include "crab_utils/debug.hpp"

namespace prevail {
class Program {
    friend struct CfgBuilder;

    std::map<Label, Instruction> m_instructions{{Label::entry, Undefined{}}, {Label::exit, Undefined{}}};

    // This is a cache. The assertions can also be computed on the fly.
    std::map<Label, std::vector<Assertion>> m_assertions{{Label::entry, {}}, {Label::exit, {}}};
    Cfg m_cfg;

    // TODO: add ProgramInfo field

  public:
    const Cfg& cfg() const { return m_cfg; }

    //! return a view of the labels, including entry and exit
    [[nodiscard]]
    auto labels() const {
        return m_cfg.labels();
    }

    const Instruction& instruction_at(const Label& label) const {
        if (!m_instructions.contains(label)) {
            CRAB_ERROR("Label ", to_string(label), " not found in the CFG: ");
        }
        return m_instructions.at(label);
    }

    Instruction& instruction_at(const Label& label) {
        if (!m_instructions.contains(label)) {
            CRAB_ERROR("Label ", to_string(label), " not found in the CFG: ");
        }
        return m_instructions.at(label);
    }

    std::vector<Assertion> assertions_at(const Label& label) const {
        if (!m_assertions.contains(label)) {
            CRAB_ERROR("Label ", to_string(label), " not found in the CFG: ");
        }
        return m_assertions.at(label);
    }

    static Program from_sequence(const InstructionSeq& inst_seq, const ProgramInfo& info,
                                 const ebpf_verifier_options_t& options);
};

class InvalidControlFlow final : public std::runtime_error {
  public:
    explicit InvalidControlFlow(const std::string& what) : std::runtime_error(what) {}
};

std::vector<Assertion> get_assertions(Instruction ins, const ProgramInfo& info, const std::optional<Label>& label);

std::vector<std::string> stats_headers();
std::map<std::string, int> collect_stats(const Program& prog);

using printfunc = std::function<void(std::ostream&, const Label& label)>;
void print_program(const Program& prog, std::ostream& os, bool simplify, const printfunc& prefunc,
                   const printfunc& postfunc);
void print_program(const Program& prog, std::ostream& os, bool simplify);
void print_dot(const Program& prog, const std::string& outfile);
} // namespace prevail

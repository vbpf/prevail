// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <map>
#include <vector>

#include "crab/cfg.hpp"
#include "crab/label.hpp"
#include "crab_utils/debug.hpp"

#include "asm_syntax.hpp"

class Program {
    friend struct cfg_builder_t;

    std::map<label_t, Instruction> m_instructions{{label_t::entry, Undefined{}}, {label_t::exit, Undefined{}}};

    // This is a cache. The assertions can also be computed on the fly.
    std::map<label_t, std::vector<Assertion>> m_assertions{{label_t::entry, {}}, {label_t::exit, {}}};
    prevail::cfg_t m_cfg;

    // TODO: add program_info field

  public:
    const prevail::cfg_t& cfg() const { return m_cfg; }

    //! return a view of the labels, including entry and exit
    [[nodiscard]]
    auto labels() const {
        return m_cfg.labels();
    }

    const Instruction& instruction_at(const label_t& label) const {
        if (!m_instructions.contains(label)) {
            CRAB_ERROR("Label ", to_string(label), " not found in the CFG: ");
        }
        return m_instructions.at(label);
    }

    Instruction& instruction_at(const label_t& label) {
        if (!m_instructions.contains(label)) {
            CRAB_ERROR("Label ", to_string(label), " not found in the CFG: ");
        }
        return m_instructions.at(label);
    }

    std::vector<Assertion> assertions_at(const label_t& label) const {
        if (!m_assertions.contains(label)) {
            CRAB_ERROR("Label ", to_string(label), " not found in the CFG: ");
        }
        return m_assertions.at(label);
    }

    static Program from_sequence(const InstructionSeq& inst_seq, const program_info& info,
                                 const ebpf_verifier_options_t& options);
};

class InvalidControlFlow final : public std::runtime_error {
  public:
    explicit InvalidControlFlow(const std::string& what) : std::runtime_error(what) {}
};

std::vector<Assertion> get_assertions(Instruction ins, const program_info& info, const std::optional<label_t>& label);

std::vector<std::string> stats_headers();
std::map<std::string, int> collect_stats(const Program& prog);

using printfunc = std::function<void(std::ostream&, const label_t& label)>;
void print_program(const Program& prog, std::ostream& os, bool simplify, const printfunc& prefunc,
                   const printfunc& postfunc);
void print_program(const Program& prog, std::ostream& os, bool simplify);
void print_dot(const Program& prog, const std::string& outfile);

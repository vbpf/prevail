// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <map>
#include <set>
#include <vector>

#include "cfg/cfg.hpp"
#include "cfg/label.hpp"
#include "config.hpp"
#include "crab_utils/debug.hpp"          // CRAB_ERROR (used by inline methods below)
#include "crab_utils/prevail_errors.hpp" // RuntimeInputError base for InvalidControlFlow
#include "ir/syntax.hpp"
#include "spec/type_descriptors.hpp"

namespace prevail {
class Program {
    friend struct CfgBuilder;

    std::map<Label, Instruction> m_instructions{{Label::entry, Undefined{}}, {Label::exit, Undefined{}}};

    // This is a cache. The assertions can also be computed on the fly.
    std::map<Label, std::vector<Assertion>> m_assertions{{Label::entry, {}}, {Label::exit, {}}};
    Cfg m_cfg;

    ProgramInfo m_info;

    // Derived from the CFG by Program::from_sequence. Lives on Program rather than in
    // ProgramInfo because ProgramInfo holds loader output; these sets are analysis-prep.
    std::set<int32_t> m_callback_target_labels;
    std::set<int32_t> m_callback_targets_with_exit;

  public:
    const Cfg& cfg() const { return m_cfg; }
    const ProgramInfo& info() const { return m_info; }

    // Top-level instruction labels eligible as PTR_TO_FUNC callback targets.
    const std::set<int32_t>& callback_target_labels() const { return m_callback_target_labels; }
    // Subset whose body can reach a top-level Exit in the CFG.
    const std::set<int32_t>& callback_targets_with_exit() const { return m_callback_targets_with_exit; }

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
                                 const VerifierOptions& options);
};

class InvalidControlFlow final : public RuntimeInputError {
  public:
    explicit InvalidControlFlow(const std::string& what) : RuntimeInputError(what) {}
};

std::vector<Assertion> get_assertions(const Instruction& ins, const ProgramInfo& info, const RuntimeConfig& runtime,
                                      const std::optional<Label>& label);

void print_program(const Program& prog, std::ostream& os, const VerbosityOptions& verbosity);
void print_dot(const Program& prog, const std::string& outfile);
} // namespace prevail

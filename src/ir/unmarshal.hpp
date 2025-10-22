// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <string>
#include <variant>
#include <vector>

#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "ir/syntax.hpp"

namespace prevail {

/** Translate a sequence of eBPF instructions (elf binary format) to a sequence
 *  of Instructions.
 *
 *  \param raw_prog is the input program to parse.
 *  \param[out] notes is a vector for storing errors and warnings.
 *  \return a sequence of instructions if successful, an error string otherwise.
 */
std::variant<InstructionSeq, std::string> unmarshal(const RawProgram& raw_prog,
                                                    std::vector<std::vector<std::string>>& notes);
std::variant<InstructionSeq, std::string> unmarshal(const RawProgram& raw_prog);

Call make_call(int imm, const ebpf_platform_t& platform);
} // namespace prevail

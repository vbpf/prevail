// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <expected>
#include <string>
#include <vector>

#include "ir/syntax.hpp"
#include "platform.hpp"
#include "spec/type_descriptors.hpp"

namespace prevail {

/** Translate a sequence of eBPF instructions (elf binary format) to a sequence
 *  of Instructions.
 *
 *  \param raw_prog is the input program to parse.
 *  \param[out] notes is a vector for storing errors and warnings.
 *  \param options unmarshalling options
 *  \return a sequence of instructions if successful, an error string otherwise.
 */
std::expected<InstructionSeq, std::string> unmarshal(const RawProgram& raw_prog,
                                                     std::vector<std::vector<std::string>>& notes,
                                                     const ebpf_verifier_options_t& options);
std::expected<InstructionSeq, std::string> unmarshal(const RawProgram& raw_prog,
                                                     const ebpf_verifier_options_t& options);

Call make_call(int imm, const ebpf_platform_t& platform);
} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <istream>
#include <stdexcept>
#include <string>
#include <vector>

#include "platform.hpp"
#include "program.hpp"
namespace prevail {

class UnmarshalError final : public std::runtime_error {
  public:
    explicit UnmarshalError(const std::string& what) : std::runtime_error(what) {}
};

/// Read an ELF file and return the programs in the desired section.
/// @param input_stream The input stream to read the ELF file from.
/// @param path The path to the ELF file (for error messages).
/// @param desired_section The section to read programs from.
/// @param options Verifier options (control verbosity, platform behavior, etc.).
/// @param platform pointer handling platform-specific behavior.
/// @return a vector of parsed and relocated RawProgram structs.
std::vector<RawProgram> read_elf(std::istream& input_stream, const std::string& path,
                                 const std::string& desired_section, const ebpf_verifier_options_t& options,
                                 const ebpf_platform_t* platform);

std::vector<RawProgram> read_elf(const std::string& path, const std::string& desired_section,
                                 const ebpf_verifier_options_t& options, const ebpf_platform_t* platform);

} // namespace prevail

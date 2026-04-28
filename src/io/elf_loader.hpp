// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "crab_utils/prevail_errors.hpp"
#include "ir/program.hpp"
#include "platform.hpp"

namespace prevail {

class UnmarshalError : public RuntimeInputError {
  public:
    explicit UnmarshalError(const std::string& what) : RuntimeInputError(what) {}
};

struct ElfProgramInfo {
    std::string section_name;
    std::string function_name;
    uint32_t section_offset{};
    bool invalid{};
    std::string invalid_reason;
};

/// @note Not thread-safe. Callers must synchronize externally.
class ElfObject {
  public:
    ElfObject(std::string path, VerifierOptions options, const ebpf_platform_t* platform);
    ~ElfObject();
    ElfObject(ElfObject&&) noexcept;
    ElfObject& operator=(ElfObject&&) noexcept;

    const std::string& path() const noexcept;
    const std::vector<ElfProgramInfo>& list_programs();
    const std::vector<RawProgram>& get_programs(const std::string& desired_section = {},
                                                const std::string& desired_program = {});
    static bool is_valid(const ElfProgramInfo& program) noexcept { return !program.invalid; }

  private:
    struct ElfObjectState;
    std::unique_ptr<ElfObjectState> state_;
};

} // namespace prevail

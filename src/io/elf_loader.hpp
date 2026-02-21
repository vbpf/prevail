// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "ir/program.hpp"
#include "platform.hpp"

namespace prevail {

class UnmarshalError : public std::runtime_error {
  public:
    explicit UnmarshalError(const std::string& what) : std::runtime_error(what) {}
};

class MalformedElf final : public UnmarshalError {
  public:
    explicit MalformedElf(const std::string& what) : UnmarshalError(what) {}
};

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
                    ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);

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
    ElfObject(std::string path, ebpf_verifier_options_t options, const ebpf_platform_t* platform);
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

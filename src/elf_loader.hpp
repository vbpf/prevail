// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <istream>
#include <stdexcept>
#include <string>
#include <unordered_map>
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

class ElfObject {
    struct QueryKey {
        std::string section;
        std::string program;

        bool operator==(const QueryKey&) const = default;
    };

    struct SectionCacheEntry {
        bool loaded{};
        bool valid{};
        std::string error;
        std::vector<RawProgram> programs;
    };

    struct QueryKeyHash {
        size_t operator()(const QueryKey& key) const noexcept;
    };

  public:
    ElfObject(std::string path, ebpf_verifier_options_t options, const ebpf_platform_t* platform);

    const std::string& path() const noexcept;
    const std::vector<ElfProgramInfo>& list_programs();
    const std::vector<RawProgram>& get_programs(const std::string& desired_section = {},
                                                const std::string& desired_program = {});
    static bool is_valid(const ElfProgramInfo& program) noexcept { return !program.invalid; }

  private:
    void discover_programs();
    void load_section(const std::string& section_name);
    std::vector<RawProgram> filter_section_programs(const std::vector<RawProgram>& programs,
                                                    const std::string& desired_program) const;
    void mark_section_validity(const std::string& section_name, bool valid, const std::string& reason);

    std::string path_;
    ebpf_verifier_options_t options_;
    const ebpf_platform_t* platform_;

    bool catalog_loaded_{};
    std::vector<ElfProgramInfo> programs_;
    std::vector<std::string> section_order_;
    std::unordered_map<std::string, std::vector<size_t>> section_program_indices_;
    std::unordered_map<std::string, SectionCacheEntry> section_cache_;
    std::unordered_map<QueryKey, std::vector<RawProgram>, QueryKeyHash> query_cache_;
};

} // namespace prevail

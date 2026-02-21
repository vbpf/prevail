// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cerrno>
#include <cstring>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <vector>

#include <elfio/elfio.hpp>

#include "crab_utils/num_safety.hpp"
#include "io/elf_reader.hpp"

namespace prevail {

// ---------------------------------------------------------------------------
// ElfObject::ElfObjectState — private state hidden behind the PIMPL wall
// ---------------------------------------------------------------------------

struct QueryKey {
    std::string section;
    std::string program;

    bool operator==(const QueryKey&) const = default;
};

struct QueryKeyHash {
    size_t operator()(const QueryKey& key) const noexcept {
        size_t seed = std::hash<std::string>{}(key.section);
        seed ^= std::hash<std::string>{}(key.program) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
        return seed;
    }
};

struct SectionCacheEntry {
    bool loaded{};
    bool valid{};
    std::string error;
    std::vector<RawProgram> programs;
};

struct ElfObject::ElfObjectState {
    std::string path;
    ebpf_verifier_options_t options;
    const ebpf_platform_t* platform;

    bool catalog_loaded{};
    std::vector<ElfProgramInfo> programs;
    std::vector<std::string> section_order;
    std::unordered_map<std::string, std::vector<size_t>> section_program_indices;
    std::unordered_map<std::string, SectionCacheEntry> section_cache;
    std::unordered_map<QueryKey, std::vector<RawProgram>, QueryKeyHash> query_cache;

    // Cached ELF reader and symbol accessor — parsed once in discover_programs(),
    // reused by load_section() to avoid re-parsing the file.
    std::optional<ELFIO::elfio> reader;
    std::optional<ELFIO::const_symbol_section_accessor> symbols;

    ElfObjectState(std::string p, ebpf_verifier_options_t opts, const ebpf_platform_t* plat)
        : path(std::move(p)), options(std::move(opts)), platform(plat) {}

    void discover_programs();
    void load_section(const std::string& section_name);
    void mark_section_validity(const std::string& section_name, bool valid, const std::string& reason);
    std::vector<RawProgram> filter_section_programs(const std::vector<RawProgram>& programs,
                                                    const std::string& desired_program) const;
};

// ---------------------------------------------------------------------------
// ElfObjectState methods
// ---------------------------------------------------------------------------

void ElfObject::ElfObjectState::discover_programs() {
    if (catalog_loaded) {
        return;
    }

    if (std::ifstream stream{path, std::ios::in | std::ios::binary}) {
        reader.emplace(load_elf(stream, path));
        symbols.emplace(read_and_validate_symbol_section(*reader, path));

        for (const auto& section : reader->sections) {
            if (!(section->get_flags() & ELFIO::SHF_EXECINSTR) || !section->get_size() || !section->get_data()) {
                continue;
            }

            const std::string section_name = section->get_name();
            if (!section_cache.contains(section_name)) {
                section_order.push_back(section_name);
                section_cache.emplace(section_name, SectionCacheEntry{});
            }

            for (ELFIO::Elf_Xword offset = 0; offset < section->get_size();) {
                auto [function_name, size] = get_program_name_and_size(*section, offset, *symbols);
                programs.push_back(ElfProgramInfo{
                    .section_name = section_name,
                    .function_name = function_name,
                    .section_offset = gsl::narrow<uint32_t>(offset),
                });
                section_program_indices[section_name].push_back(programs.size() - 1);
                offset += size;
            }
        }

        catalog_loaded = true;
        if (programs.empty()) {
            throw UnmarshalError("No executable sections");
        }
        return;
    }

    struct stat st; // NOLINT(*-pro-type-member-init)
    if (stat(path.c_str(), &st)) {
        throw UnmarshalError(std::string(strerror(errno)) + " opening " + path);
    }
    throw UnmarshalError("Can't process ELF file " + path);
}

void ElfObject::ElfObjectState::mark_section_validity(const std::string& section_name, const bool valid,
                                                      const std::string& reason) {
    if (!section_program_indices.contains(section_name)) {
        return;
    }
    for (const size_t index : section_program_indices.at(section_name)) {
        programs[index].invalid = !valid;
        programs[index].invalid_reason = valid ? std::string{} : reason;
    }
}

void ElfObject::ElfObjectState::load_section(const std::string& section_name) {
    discover_programs();
    auto section_it = section_cache.find(section_name);
    if (section_it == section_cache.end()) {
        throw UnmarshalError("Section not found");
    }

    SectionCacheEntry& cache_entry = section_it->second;
    if (cache_entry.loaded) {
        return;
    }

    cache_entry.loaded = true;
    try {
        // Use the cached reader/symbols to construct ProgramReader directly,
        // avoiding re-opening and re-parsing the ELF file.
        parse_params_t params{path, options, platform, section_name};
        auto global = extract_global_data(params, *reader, *symbols);
        ProgramReader program_reader{params, *reader, *symbols, global};
        program_reader.read_programs();
        cache_entry.programs = std::move(program_reader.raw_programs);
        cache_entry.valid = true;
        cache_entry.error.clear();
        mark_section_validity(section_name, true, "");
    } catch (const std::runtime_error& e) {
        cache_entry.valid = false;
        cache_entry.error = e.what();
        cache_entry.programs.clear();
        mark_section_validity(section_name, false, cache_entry.error);
    }
}

std::vector<RawProgram> ElfObject::ElfObjectState::filter_section_programs(const std::vector<RawProgram>& programs_vec,
                                                                           const std::string& desired_program) const {
    if (desired_program.empty()) {
        return programs_vec;
    }

    std::vector<RawProgram> selected;
    for (const RawProgram& program : programs_vec) {
        if (program.function_name == desired_program) {
            selected.push_back(program);
        }
    }
    return selected;
}

// ---------------------------------------------------------------------------
// ElfObject facade (delegates to ElfObjectState)
// ---------------------------------------------------------------------------

ElfObject::ElfObject(std::string path, ebpf_verifier_options_t options, const ebpf_platform_t* platform)
    : state_(std::make_unique<ElfObjectState>(std::move(path), std::move(options), platform)) {}

ElfObject::~ElfObject() = default;
ElfObject::ElfObject(ElfObject&&) noexcept = default;
ElfObject& ElfObject::operator=(ElfObject&&) noexcept = default;

const std::string& ElfObject::path() const noexcept { return state_->path; }

const std::vector<ElfProgramInfo>& ElfObject::list_programs() {
    state_->discover_programs();
    for (const auto& section_name : state_->section_order) {
        state_->load_section(section_name);
    }
    return state_->programs;
}

const std::vector<RawProgram>& ElfObject::get_programs(const std::string& desired_section,
                                                       const std::string& desired_program) {
    state_->discover_programs();
    QueryKey key{.section = desired_section, .program = desired_program};
    if (const auto cached = state_->query_cache.find(key); cached != state_->query_cache.end()) {
        return cached->second;
    }

    if (!desired_section.empty()) {
        state_->load_section(desired_section);
        const auto section_it = state_->section_cache.find(desired_section);
        if (section_it == state_->section_cache.end()) {
            throw UnmarshalError("Section not found");
        }
        if (!section_it->second.valid) {
            throw UnmarshalError(section_it->second.error);
        }
        auto selected = state_->filter_section_programs(section_it->second.programs, desired_program);
        if (!desired_program.empty()) {
            if (selected.empty()) {
                throw UnmarshalError("Program not found in section '" + desired_section + "': " + desired_program);
            }
            if (selected.size() > 1) {
                throw UnmarshalError("Program name is ambiguous in section '" + desired_section +
                                     "': " + desired_program);
            }
        }
        auto [it, _] = state_->query_cache.emplace(std::move(key), std::move(selected));
        return it->second;
    }

    std::vector<RawProgram> all_programs;
    for (const auto& section_name : state_->section_order) {
        state_->load_section(section_name);
        const auto& cache_entry = state_->section_cache.at(section_name);
        if (cache_entry.valid) {
            all_programs.insert(all_programs.end(), cache_entry.programs.begin(), cache_entry.programs.end());
        }
    }
    if (all_programs.empty()) {
        throw UnmarshalError("No executable sections");
    }

    auto selected = state_->filter_section_programs(all_programs, desired_program);
    if (!desired_program.empty()) {
        if (selected.empty()) {
            throw UnmarshalError("Program not found: " + desired_program);
        }
        if (selected.size() > 1) {
            throw UnmarshalError("Program name is ambiguous across sections: " + desired_program +
                                 "; please specify a section");
        }
    }
    auto [it, _] = state_->query_cache.emplace(std::move(key), std::move(selected));
    return it->second;
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

int create_map_crab(const EbpfMapType& map_type, const uint32_t key_size, const uint32_t value_size,
                    const uint32_t max_entries, ebpf_verifier_options_t) {
    const EquivalenceKey equiv{map_type.value_type, key_size, value_size, map_type.is_array ? max_entries : 0};
    if (!thread_local_program_info->cache.contains(equiv)) {
        // +1 so 0 is the null FD
        thread_local_program_info->cache[equiv] = gsl::narrow<int>(thread_local_program_info->cache.size()) + 1;
    }
    return thread_local_program_info->cache.at(equiv);
}

EbpfMapDescriptor* find_map_descriptor(const int map_fd) {
    for (EbpfMapDescriptor& map : thread_local_program_info->map_descriptors) {
        if (map.original_fd == map_fd) {
            return &map;
        }
    }
    return nullptr;
}

} // namespace prevail

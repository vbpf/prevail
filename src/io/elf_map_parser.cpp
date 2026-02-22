// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <cassert>
#include <iostream>
#include <map>
#include <ranges>
#include <set>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include <elfio/elfio.hpp>
#include <libbtf/btf_json.h>
#include <libbtf/btf_map.h>
#include <libbtf/btf_parse.h>

#include "crab_utils/num_safety.hpp"
#include "io/elf_reader.hpp"

namespace prevail {

namespace {

constexpr int DEFAULT_MAP_FD = -1;

void dump_btf_types(const libbtf::btf_type_data& btf_data, const std::string& path) {
    std::stringstream output;
    std::cout << "Dumping BTF data for " << path << std::endl;
    btf_data.to_json(output);
    std::cout << libbtf::pretty_print_json(output.str()) << std::endl;
}

std::map<int, int> map_typeid_to_fd(const std::vector<EbpfMapDescriptor>& map_descriptors) {
    std::map<int, int> type_id_to_fd_map;
    int pseudo_fd = 1;
    for (const auto& map_descriptor : map_descriptors) {
        if (!type_id_to_fd_map.contains(map_descriptor.original_fd)) {
            type_id_to_fd_map[map_descriptor.original_fd] = pseudo_fd++;
        }
    }
    return type_id_to_fd_map;
}

/// @brief Add implicit map descriptors for global variable sections.
void add_global_variable_maps(const ELFIO::elfio& reader, ElfGlobalData& global, MapOffsets& map_offsets) {
    for (const auto section : global_sections(reader)) {
        map_offsets[section->get_name()] = global.map_descriptors.size();

        global.map_descriptors.push_back(EbpfMapDescriptor{
            .original_fd = gsl::narrow<int>(global.map_descriptors.size() + 1),
            .type = 0,
            .key_size = sizeof(uint32_t),
            .value_size = gsl::narrow<uint32_t>(section->get_size()),
            .max_entries = 1,
            .inner_map_fd = DEFAULT_MAP_FD,
        });

        global.variable_section_indices.insert(section->get_index());
    }
}

ElfGlobalData parse_btf_section(const parse_params_t& parse_params, const ELFIO::elfio& reader) {
    const auto btf_section = reader.sections[".BTF"];
    if (!btf_section) {
        return {};
    }

    std::optional<libbtf::btf_type_data> btf_data;
    try {
        btf_data.emplace(vector_of<std::byte>(*btf_section));
    } catch (const std::exception& e) {
        throw UnmarshalError(std::string("Unsupported or invalid BTF data: ") + e.what());
    }
    if (parse_params.options.verbosity_opts.dump_btf_types_json) {
        dump_btf_types(*btf_data, parse_params.path);
    }

    ElfGlobalData global;
    MapOffsets map_offsets;

    // Parse BTF-defined maps from the .maps DATASEC
    try {
        for (const auto& map : parse_btf_map_section(*btf_data)) {
            map_offsets.emplace(map.name, global.map_descriptors.size());
            global.map_descriptors.push_back(EbpfMapDescriptor{
                .original_fd = gsl::narrow<int>(map.type_id), // Temporary: stores BTF type ID
                .type = map.map_type,
                .key_size = map.key_size,
                .value_size = map.value_size,
                .max_entries = map.max_entries,
                .inner_map_fd = map.inner_map_type_id == 0 ? DEFAULT_MAP_FD : gsl::narrow<int>(map.inner_map_type_id),
            });
        }
    } catch (const std::exception& e) {
        throw UnmarshalError(std::string("Unsupported or invalid BTF map metadata: ") + e.what());
    }

    // Remap BTF type IDs to pseudo file descriptors
    const auto type_id_to_fd_map = map_typeid_to_fd(global.map_descriptors);
    for (auto& desc : global.map_descriptors) {
        if (auto it = type_id_to_fd_map.find(desc.original_fd); it != type_id_to_fd_map.end()) {
            desc.original_fd = it->second;
        } else {
            throw UnmarshalError("Unknown map type ID in BTF: " + std::to_string(desc.original_fd));
        }

        if (desc.inner_map_fd != DEFAULT_MAP_FD) {
            auto inner_it = type_id_to_fd_map.find(desc.inner_map_fd);
            if (inner_it == type_id_to_fd_map.end()) {
                throw UnmarshalError("Unknown inner map type ID in BTF: " + std::to_string(desc.inner_map_fd));
            }
            desc.inner_map_fd = inner_it->second;
        }
    }

    if (const auto maps_section = reader.sections[".maps"]) {
        global.map_section_indices.insert(maps_section->get_index());
    }

    add_global_variable_maps(reader, global, map_offsets);

    global.map_record_size_or_map_offsets = std::move(map_offsets);
    return global;
}

ElfGlobalData create_global_variable_maps(const ELFIO::elfio& reader) {
    ElfGlobalData global;
    MapOffsets offsets;

    for (const auto section : global_sections(reader)) {
        offsets[section->get_name()] = global.map_descriptors.size();

        global.map_descriptors.push_back(EbpfMapDescriptor{
            .original_fd = gsl::narrow<int>(global.map_descriptors.size() + 1),
            .type = 0,
            .key_size = sizeof(uint32_t),
            .value_size = gsl::narrow<uint32_t>(section->get_size()),
            .max_entries = 1,
            .inner_map_fd = DEFAULT_MAP_FD,
        });

        global.variable_section_indices.insert(section->get_index());
    }

    global.map_record_size_or_map_offsets = std::move(offsets);
    return global;
}

ElfGlobalData parse_map_sections(const parse_params_t& parse_params, const ELFIO::elfio& reader,
                                 const ELFIO::const_symbol_section_accessor& symbols) {
    ElfGlobalData global;
    std::map<ELFIO::Elf_Half, size_t> section_record_sizes;
    std::map<ELFIO::Elf_Half, size_t> section_base_index;

    for (ELFIO::Elf_Half i = 0; i < reader.sections.size(); ++i) {
        const auto s = reader.sections[i];
        assert(s);
        if (!is_map_section(s->get_name())) {
            continue;
        }

        std::vector<symbol_details_t> map_symbols;
        for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); ++index) {
            const auto symbol_details = get_symbol_details(symbols, index);
            if (symbol_details.section_index == i && !symbol_details.name.empty()) {
                map_symbols.push_back(symbol_details);
            }
        }

        global.map_section_indices.insert(s->get_index());

        if (map_symbols.empty()) {
            continue;
        }

        const size_t base_index = global.map_descriptors.size();
        if (s->get_data() == nullptr) {
            throw UnmarshalError("Malformed legacy maps section: " + s->get_name());
        }

        size_t map_record_size = 0;
        for (const auto& symbol : map_symbols) {
            if (symbol.size == 0) {
                continue;
            }
            const auto symbol_size = gsl::narrow<size_t>(symbol.size);
            map_record_size = map_record_size == 0 ? symbol_size : std::min(map_record_size, symbol_size);
        }
        if (map_record_size == 0) {
            map_record_size = parse_params.platform->map_record_size;
        }

        if (map_record_size < 4 * sizeof(uint32_t) || map_record_size % sizeof(uint32_t) != 0) {
            throw UnmarshalError("Malformed legacy maps section: " + s->get_name());
        }
        if (s->get_size() < map_record_size) {
            throw UnmarshalError("Malformed legacy maps section: " + s->get_name());
        }

        size_t map_count = s->get_size() / map_record_size;
        if (map_count == 0) {
            throw UnmarshalError("Malformed legacy maps section: " + s->get_name());
        }
        if (s->get_size() % map_record_size != 0) {
            size_t max_record_end = 0;
            for (const auto& symbol : map_symbols) {
                const size_t symbol_offset = gsl::narrow<size_t>(symbol.value);
                if (symbol_offset >= s->get_size()) {
                    throw UnmarshalError("Malformed legacy maps section: " + s->get_name());
                }
                max_record_end = std::max(max_record_end, symbol_offset + map_record_size);
            }
            if (max_record_end > s->get_size()) {
                throw UnmarshalError("Malformed legacy maps section: " + s->get_name());
            }
            map_count = (max_record_end + map_record_size - 1) / map_record_size;
        }

        section_record_sizes[i] = map_record_size;
        section_base_index[i] = base_index;

        parse_params.platform->parse_maps_section(global.map_descriptors, s->get_data(), map_record_size,
                                                  gsl::narrow<int>(map_count), parse_params.platform,
                                                  parse_params.options);
    }

    parse_params.platform->resolve_inner_map_references(global.map_descriptors);

    MapOffsets map_offsets;
    for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); ++index) {
        const auto sym_details = get_symbol_details(symbols, index);

        if (!global.map_section_indices.contains(sym_details.section_index) || sym_details.name.empty()) {
            continue;
        }

        const auto record_size_it = section_record_sizes.find(sym_details.section_index);
        const auto base_index_it = section_base_index.find(sym_details.section_index);
        if (record_size_it == section_record_sizes.end() || base_index_it == section_base_index.end()) {
            continue;
        }

        const auto* section = reader.sections[sym_details.section_index];
        assert(section);
        const size_t record_size = record_size_it->second;

        if (sym_details.value % record_size != 0 || sym_details.value >= section->get_size()) {
            throw UnmarshalError("Legacy map symbol '" + sym_details.name + "' has invalid offset: not aligned to " +
                                 std::to_string(record_size) + "-byte boundary or out of section bounds");
        }

        const size_t local_index = sym_details.value / record_size;
        const size_t descriptor_index = base_index_it->second + local_index;

        if (descriptor_index >= global.map_descriptors.size()) {
            throw UnmarshalError("Legacy map symbol index out of range for: " + sym_details.name);
        }

        map_offsets[sym_details.name] = descriptor_index;
    }

    for (const auto section : global_sections(reader)) {
        map_offsets[section->get_name()] = global.map_descriptors.size();
        global.map_descriptors.push_back(EbpfMapDescriptor{
            .original_fd = gsl::narrow<int>(global.map_descriptors.size() + 1),
            .type = 0,
            .key_size = sizeof(uint32_t),
            .value_size = gsl::narrow<uint32_t>(section->get_size()),
            .max_entries = 1,
            .inner_map_fd = DEFAULT_MAP_FD,
        });
        global.variable_section_indices.insert(section->get_index());
    }

    global.map_record_size_or_map_offsets = std::move(map_offsets);
    return global;
}

} // namespace

ElfGlobalData extract_global_data(const parse_params_t& params, const ELFIO::elfio& reader,
                                  const ELFIO::const_symbol_section_accessor& symbols) {
    const bool has_btf_maps = reader.sections[".BTF"] != nullptr && reader.sections[".maps"] != nullptr;
    if (has_btf_maps) {
        try {
            return parse_btf_section(params, reader);
        } catch (const UnmarshalError&) {
            // If BTF-defined maps can't be decoded, fall back to section-based map descriptors.
        }
        return parse_map_sections(params, reader, symbols);
    }

    const bool has_legacy_maps =
        std::ranges::any_of(reader.sections, [](const auto& s) { return is_map_section(s->get_name()); });
    if (has_legacy_maps) {
        return parse_map_sections(params, reader, symbols);
    }

    if (reader.sections[".BTF"]) {
        return parse_btf_section(params, reader);
    }

    return create_global_variable_maps(reader);
}

void update_line_info(std::vector<RawProgram>& raw_programs, const ELFIO::section* btf_section,
                      const ELFIO::section* btf_ext) {
    auto visitor = [&raw_programs](const std::string& section, const uint32_t instruction_offset,
                                   const std::string& file_name, const std::string& source, const uint32_t line_number,
                                   const uint32_t column_number) {
        for (auto& program : raw_programs) {
            if (program.section_name == section && instruction_offset >= program.insn_off &&
                instruction_offset < program.insn_off + program.prog.size() * sizeof(EbpfInst)) {
                const size_t inst_index = (instruction_offset - program.insn_off) / sizeof(EbpfInst);
                if (inst_index >= program.prog.size()) {
                    throw UnmarshalError("Invalid BTF data");
                }
                program.info.line_info.insert_or_assign(inst_index,
                                                        btf_line_info_t{file_name, source, line_number, column_number});
            }
        }
    };
    libbtf::btf_parse_line_information(vector_of<std::byte>(*btf_section), vector_of<std::byte>(*btf_ext), visitor);
    for (auto& program : raw_programs) {
        std::optional<btf_line_info_t> last;
        for (size_t i = 0; i < program.prog.size(); ++i) {
            auto it = program.info.line_info.find(i);
            if (it != program.info.line_info.end()) {
                if (it->second.line_number != 0) {
                    last = it->second;
                }
            } else if (last) {
                program.info.line_info[i] = *last;
            }
        }
    }
}

} // namespace prevail

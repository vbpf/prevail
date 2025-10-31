// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <variant>
#include <vector>

#include "elfio/elfio.hpp"
#include "libbtf/btf_c_type.h"
#include "libbtf/btf_json.h"
#include "libbtf/btf_map.h"
#include "libbtf/btf_parse.h"

#include "crab_utils/num_safety.hpp"
#include "elf_loader.hpp"
#include "ir/program.hpp"
#include "platform.hpp"

/// @brief ELF file parser for BPF programs with support for legacy and BTF-based formats.
///
/// This file implements a complete BPF ELF loader that handles:
/// - Legacy map definitions (struct bpf_elf_map in "maps" sections)
/// - BTF-based map definitions (parsed from .BTF section metadata)
/// - Global variables in .data/.rodata/.bss sections (as implicit array maps)
/// - CO-RE (Compile Once - Run Everywhere) relocations
/// - Subprogram linking and function call relocations
/// - Mixed-mode files (BTF metadata + legacy map sections)
///
/// The loader performs ELF parsing, symbol resolution, relocation processing,
/// and produces fully-linked RawProgram objects ready for verification.

namespace prevail {

namespace {

/// @brief Validate and return a LDDW instruction pair for relocation.
///
/// LDDW (Load Double Word) is a two-slot instruction used for 64-bit immediate loads.
/// Encoding: first slot has opcode 0x18, second slot has opcode 0x00.
///
/// @param instructions Instruction vector
/// @param location Index of the first instruction
/// @param context Description for error messages (e.g., "global variable 'foo'")
/// @return Pair of references to the low and high instruction slots
/// @throws UnmarshalError if validation fails
std::pair<std::reference_wrapper<EbpfInst>, std::reference_wrapper<EbpfInst>>
validate_and_get_lddw_pair(std::vector<EbpfInst>& instructions, size_t location, const std::string& context) {
    constexpr uint8_t BPF_LDDW = 0x18;
    constexpr uint8_t BPF_LDDW_HI = 0x00;

    if (instructions.size() <= location + 1) {
        throw UnmarshalError("Invalid relocation: " + std::string(context) + " reference at instruction boundary");
    }

    auto& lo_inst = instructions[location];
    auto& hi_inst = instructions[location + 1];

    if (lo_inst.opcode != BPF_LDDW) {
        throw UnmarshalError("Invalid relocation: expected LDDW first slot (opcode 0x18) for " + std::string(context) +
                             ", found opcode 0x" + std::to_string(static_cast<int>(lo_inst.opcode)));
    }
    if (hi_inst.opcode != BPF_LDDW_HI) {
        throw UnmarshalError("Invalid relocation: expected LDDW second slot (opcode 0x00) for " + std::string(context) +
                             ", found opcode 0x" + std::to_string(static_cast<int>(hi_inst.opcode)));
    }

    return {std::ref(lo_inst), std::ref(hi_inst)};
}

template <typename T>
    requires std::is_trivially_copyable_v<T>
std::vector<T> vector_of(const char* data, ELFIO::Elf_Xword size) {
    if (!data || size % sizeof(T) != 0 || size > std::numeric_limits<uint32_t>::max()) {
        throw UnmarshalError("Invalid argument to vector_of");
    }
    const size_t n = size / sizeof(T);
    std::vector<T> v(n);
    std::memcpy(v.data(), data, n * sizeof(T));
    return v;
}

template <typename T>
    requires std::is_trivially_copyable_v<T>
std::vector<T> vector_of(const ELFIO::section& sec) {
    return vector_of<T>(sec.get_data(), sec.get_size());
}

bool is_map_section(const std::string& name) {
    const std::string maps_prefix = "maps/";
    return name == "maps" || (name.length() > 5 && name.compare(0, maps_prefix.length(), maps_prefix) == 0);
}

bool is_global_section(const std::string& name) {
    return name == ".data" || name == ".rodata" || name == ".bss" || name.starts_with(".data.") ||
           name.starts_with(".rodata.") || name.starts_with(".bss.");
}

struct symbol_details_t {
    std::string name;
    ELFIO::Elf64_Addr value{};
    ELFIO::Elf_Xword size{};
    unsigned char bind{};
    unsigned char type{};
    ELFIO::Elf_Half section_index{};
    unsigned char other{};
};

symbol_details_t get_symbol_details(const ELFIO::const_symbol_section_accessor& symbols, const ELFIO::Elf_Xword index) {
    symbol_details_t details;
    symbols.get_symbol(index, details.name, details.value, details.size, details.bind, details.type,
                       details.section_index, details.other);
    return details;
}

struct parse_params_t {
    const std::string& path;
    const ebpf_verifier_options_t& options;
    const ebpf_platform_t* platform;
    const std::string desired_section;
};

std::tuple<std::string, ELFIO::Elf_Xword>
get_program_name_and_size(const ELFIO::section& sec, const ELFIO::Elf_Xword start,
                          const ELFIO::const_symbol_section_accessor& symbols) {
    const ELFIO::Elf_Xword symbol_count = symbols.get_symbols_num();
    const ELFIO::Elf_Half section_index = sec.get_index();
    std::string program_name = sec.get_name();
    ELFIO::Elf_Xword size = sec.get_size() - start;
    for (ELFIO::Elf_Xword index = 0; index < symbol_count; index++) {
        auto symbol_details = get_symbol_details(symbols, index);
        if (symbol_details.section_index == section_index && !symbol_details.name.empty()) {
            if (symbol_details.type != ELFIO::STT_FUNC) {
                continue;
            }
            const auto relocation_offset = symbol_details.value;
            if (relocation_offset == start) {
                program_name = symbol_details.name;
            } else if (relocation_offset > start && relocation_offset < start + size) {
                size = relocation_offset - start;
            }
        }
    }
    return {program_name, size};
}

std::string bad_reloc_value(const size_t reloc_value) {
    return "Bad reloc value (" + std::to_string(reloc_value) + "). " + "Make sure to compile with -O2.";
}

struct FunctionRelocation {
    size_t prog_index{};
    ELFIO::Elf_Xword source_offset{};
    ELFIO::Elf_Xword relocation_entry_index{};
    std::string target_function_name;
};

RawProgram* find_subprogram(std::vector<RawProgram>& programs, const ELFIO::section& subprogram_section,
                            const std::string& symbol_name) {
    for (auto& subprog : programs) {
        if (subprog.section_name == subprogram_section.get_name() && subprog.function_name == symbol_name) {
            return &subprog;
        }
    }
    return nullptr;
}

using MapOffsets = std::map<std::string, size_t>;

/// @brief EBPF-Global data extracted from an ELF file during parsing.
///
/// This structure aggregates all map descriptors and metadata about sections
/// containing maps and global variables. It uses a variant to support both
/// legacy and BTF-based map resolution strategies.
struct ElfGlobalData {
    /// Section indices containing map definitions (e.g., "maps", "maps/xyz")
    std::set<ELFIO::Elf_Half> map_section_indices;

    /// All map descriptors extracted from the file
    std::vector<EbpfMapDescriptor> map_descriptors;

    /// Strategy for resolving map symbols to descriptors:
    /// - size_t: Legacy mode - fixed record size, use offset/size arithmetic
    /// - MapOffsets: BTF mode - name-based lookup from map name to descriptor index
    std::variant<size_t, MapOffsets> map_record_size_or_map_offsets;

    /// Section indices containing global variables (.data, .rodata, .bss)
    std::set<ELFIO::Elf_Half> variable_section_indices;
};

/// @brief Collect all global variable sections from the ELF file.
///
/// @param reader The ELF file reader
/// @return Vector of pointers to global variable sections (can be empty)
std::vector<ELFIO::section*> global_sections(const ELFIO::elfio& reader) {
    std::vector<ELFIO::section*> result;
    for (auto& section : reader.sections) {
        if (!section || !is_global_section(section->get_name())) {
            continue;
        }

        const auto type = section->get_type();

        // Global variables in eBPF are stored in special sections:
        // - .data, .data.*     -> initialized read-write globals (SHT_PROGBITS)
        // - .rodata, .rodata.* -> constants (SHT_PROGBITS)
        // - .bss, .bss.*       -> uninitialized globals (SHT_NOBITS, zero-initialized at load)
        // .bss sections have type SHT_NOBITS and contain no file data, but still
        // have a non-zero size representing the memory allocation needed at runtime.
        if (type == ELFIO::SHT_NOBITS || (type == ELFIO::SHT_PROGBITS && section->get_size() != 0)) {
            result.push_back(section.get());
        }
    }
    return result;
}

constexpr int DEFAULT_MAP_FD = -1;

/// @brief Add implicit map descriptors for global variable sections.
///
/// Creates single-entry array maps for .data/.rodata/.bss sections.
/// Each section becomes a map where the entire section content is the map value.
///
/// @param reader ELF file reader
/// @param global Global data to populate with map descriptors
/// @param map_offsets Map name to descriptor index mapping
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

ELFIO::const_symbol_section_accessor read_and_validate_symbol_section(const ELFIO::elfio& reader,
                                                                      const std::string& path) {
    const ELFIO::section* symbol_section = reader.sections[".symtab"];
    if (!symbol_section) {
        throw UnmarshalError("No symbol section found in ELF file " + path);
    }
    const auto expected_entry_size =
        reader.get_class() == ELFIO::ELFCLASS32 ? sizeof(ELFIO::Elf32_Sym) : sizeof(ELFIO::Elf64_Sym);
    if (symbol_section->get_entry_size() != expected_entry_size) {
        throw UnmarshalError("Invalid symbol section in ELF file " + path);
    }
    return ELFIO::const_symbol_section_accessor{reader, symbol_section};
}

ELFIO::elfio load_elf(std::istream& input_stream, const std::string& path) {
    ELFIO::elfio reader;
    if (!reader.load(input_stream)) {
        throw UnmarshalError("Can't process ELF file " + path);
    }
    return reader;
}

void dump_btf_types(const libbtf::btf_type_data& btf_data, const std::string& path) {
    std::stringstream output;
    std::cout << "Dumping BTF data for " << path << std::endl;
    btf_data.to_json(output);
    std::cout << libbtf::pretty_print_json(output.str()) << std::endl;
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

ElfGlobalData parse_btf_section(const parse_params_t& parse_params, const ELFIO::elfio& reader) {
    const auto btf_section = reader.sections[".BTF"];
    if (!btf_section) {
        return {};
    }

    const libbtf::btf_type_data btf_data(vector_of<std::byte>(*btf_section), false);
    if (parse_params.options.verbosity_opts.dump_btf_types_json) {
        dump_btf_types(btf_data, parse_params.path);
    }

    ElfGlobalData global;
    MapOffsets map_offsets;

    // Parse BTF-defined maps from the .maps DATASEC
    for (const auto& map : parse_btf_map_section(btf_data)) {
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

    // Remap BTF type IDs to pseudo file descriptors
    // Only remap values that are actually set (not the sentinel)
    const auto type_id_to_fd_map = map_typeid_to_fd(global.map_descriptors);
    for (auto& desc : global.map_descriptors) {
        // Remap the outer map's type ID to a pseudo-FD
        if (auto it = type_id_to_fd_map.find(desc.original_fd); it != type_id_to_fd_map.end()) {
            desc.original_fd = it->second;
        } else {
            throw UnmarshalError("Unknown map type ID in BTF: " + std::to_string(desc.original_fd));
        }

        // Only remap inner_map_fd if it's not the sentinel value
        if (desc.inner_map_fd != DEFAULT_MAP_FD) {
            auto inner_it = type_id_to_fd_map.find(desc.inner_map_fd);
            if (inner_it == type_id_to_fd_map.end()) {
                throw UnmarshalError("Unknown inner map type ID in BTF: " + std::to_string(desc.inner_map_fd));
            }
            desc.inner_map_fd = inner_it->second;
        }
    }

    // Remember the .maps section index if present (used for relocation classification)
    if (const auto maps_section = reader.sections[".maps"]) {
        global.map_section_indices.insert(maps_section->get_index());
    }

    // Create implicit maps for all global variable sections
    add_global_variable_maps(reader, global, map_offsets);

    global.map_record_size_or_map_offsets = std::move(map_offsets);
    return global;
}

/// @brief Create implicit map descriptors for global variable sections.
///
/// In eBPF, global variables are implemented as single-entry array maps:
/// - .data section -> read-write array map (initialized globals)
/// - .rodata section -> read-only array map (constants)
/// - .bss section -> zero-initialized array map (uninitialized globals)
///
/// Each section becomes a map descriptor with:
/// - key_size = 4 (uint32_t index, always 0)
/// - value_size = section size (entire section is the map value)
/// - max_entries = 1 (single entry containing all variables)
///
/// Access pattern: `r0 = *(type *)(map_value_ptr + offset_within_section)`
///
/// @param reader ELF file reader
/// @return Global data with map descriptors for each non-empty variable section
ElfGlobalData create_global_variable_maps(const ELFIO::elfio& reader) {
    ElfGlobalData global;
    MapOffsets offsets;

    // For legacy (non-BTF) files without map sections, create implicit map descriptors
    // for global variable sections only
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

/// @brief Parse legacy map sections with per-section validation.
///
/// Legacy BPF ELF files define maps using struct bpf_elf_map in "maps" or "maps/*"
/// sections. This function:
/// 1. Identifies all legacy map sections
/// 2. Calculates the per-section record size (section_size / symbol_count)
/// 3. Validates symbol offsets are aligned and within bounds
/// 4. Builds a name-to-descriptor mapping for relocation resolution
///
/// Note: Different map sections may have different record sizes, so validation
/// must be done per-section, not globally.
///
/// @param parse_params Parsing parameters including platform callbacks
/// @param reader The ELF file reader
/// @param symbols Symbol table accessor
/// @return Global data structure with map descriptors and metadata
ElfGlobalData parse_map_sections(const parse_params_t& parse_params, const ELFIO::elfio& reader,
                                 const ELFIO::const_symbol_section_accessor& symbols) {
    ElfGlobalData global;
    std::map<ELFIO::Elf_Half, size_t> section_record_sizes; // Per-section record size
    std::map<ELFIO::Elf_Half, size_t> section_base_index;   // Starting descriptor index per section

    // Parse each legacy map section
    for (ELFIO::Elf_Half i = 0; i < reader.sections.size(); ++i) {
        const auto s = reader.sections[i];
        if (!s || !is_map_section(s->get_name())) {
            continue;
        }

        // Count map symbols in this section
        int map_count = 0;
        for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); ++index) {
            const auto symbol_details = get_symbol_details(symbols, index);
            if (symbol_details.section_index == i && !symbol_details.name.empty()) {
                map_count++;
            }
        }

        // Track this as a map section even if empty
        global.map_section_indices.insert(s->get_index());

        if (map_count <= 0) {
            continue;
        }

        const size_t base_index = global.map_descriptors.size();
        const size_t map_record_size = s->get_size() / map_count;

        // Validate section structure
        if (s->get_data() == nullptr || map_record_size == 0 || s->get_size() % map_record_size != 0) {
            throw UnmarshalError("Malformed legacy maps section: " + s->get_name());
        }

        section_record_sizes[i] = map_record_size;
        section_base_index[i] = base_index;

        // Platform-specific parsing of map definitions
        parse_params.platform->parse_maps_section(global.map_descriptors, s->get_data(), map_record_size, map_count,
                                                  parse_params.platform, parse_params.options);
    }

    // Resolve inner map references (platform-specific logic)
    parse_params.platform->resolve_inner_map_references(global.map_descriptors);

    // Build name-to-index mapping with per-section validation
    MapOffsets map_offsets;
    for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); ++index) {
        const auto sym_details = get_symbol_details(symbols, index);

        // Skip symbols not in map sections or without names
        if (!global.map_section_indices.contains(sym_details.section_index) || sym_details.name.empty()) {
            continue;
        }

        // Look up the per-section metadata
        const auto record_size_it = section_record_sizes.find(sym_details.section_index);
        const auto base_index_it = section_base_index.find(sym_details.section_index);
        if (record_size_it == section_record_sizes.end() || base_index_it == section_base_index.end()) {
            continue; // Section was not parsed (empty)
        }

        const auto* section = reader.sections[sym_details.section_index];
        const size_t record_size = record_size_it->second;
        if (!section) {
            continue;
        }

        // Validate alignment and bounds before calculating index.
        // A malformed ELF could have symbol offsets that don't align to record boundaries
        // or that exceed the section size, leading to incorrect descriptor lookups
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

    // Add implicit maps for global variable sections
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

/// @brief Extract maps and global variable metadata from an ELF file.
///
/// This function determines the appropriate parsing strategy based on the file's format:
/// 1. **Legacy maps** (priority): If a "maps" section exists, use struct bpf_elf_map parsing
///    - The .BTF section (if present) contains only type information, not map definitions
/// 2. **BTF-only**: If no legacy maps but .BTF exists, parse map definitions from BTF
///    - Modern format where maps are defined as BTF VAR types in a DATASEC
/// 3. **No maps**: If neither exists, create implicit maps for global variable sections only
///
/// @param params Parsing parameters including path, options, and platform
/// @param reader The loaded ELF file reader
/// @param symbols Symbol table accessor for the ELF file
/// @return Global data structure containing all extracted metadata
ElfGlobalData extract_global_data(const parse_params_t& params, const ELFIO::elfio& reader,
                                  const ELFIO::const_symbol_section_accessor& symbols) {
    const bool has_legacy_maps =
        std::ranges::any_of(reader.sections, [](const auto& s) { return is_map_section(s->get_name()); });
    // If we have legacy maps section, always use legacy parser regardless of BTF.
    // The BTF in these files is just for type info, not map definitions
    if (has_legacy_maps) {
        return parse_map_sections(params, reader, symbols);
    }

    // Only use BTF for maps if there's no legacy maps section
    if (reader.sections[".BTF"]) {
        return parse_btf_section(params, reader);
    }

    // No maps or BTF, but might still have global variables
    return create_global_variable_maps(reader);
}

enum bpf_core_relo_kind {
    BPF_CORE_FIELD_BYTE_OFFSET = 0,
    BPF_CORE_FIELD_BYTE_SIZE = 1,
    BPF_CORE_FIELD_EXISTS = 2,
    BPF_CORE_FIELD_SIGNED = 3,
    BPF_CORE_FIELD_LSHIFT_U64 = 4,
    BPF_CORE_FIELD_RSHIFT_U64 = 5,
    BPF_CORE_TYPE_ID_LOCAL = 6,
    BPF_CORE_TYPE_ID_TARGET = 7,
    BPF_CORE_TYPE_EXISTS = 8,
    BPF_CORE_TYPE_SIZE = 9,
    BPF_CORE_ENUMVAL_EXISTS = 10,
    BPF_CORE_ENUMVAL_VALUE = 11,
    BPF_CORE_TYPE_MATCHES = 12,
};

struct bpf_core_relo {
    uint32_t insn_off;
    uint32_t type_id;
    uint32_t access_str_off;
    bpf_core_relo_kind kind;
};

std::vector<uint32_t> parse_core_access_string(const std::string& s) {
    std::vector<uint32_t> indices;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ':')) {
        if (!item.empty()) {
            try {
                indices.push_back(std::stoul(item));
            } catch (const std::exception&) {
                throw UnmarshalError("Invalid CO-RE access string: " + s);
            }
        }
    }
    return indices;
}

class ProgramReader {
    const parse_params_t& parse_params;
    const ELFIO::elfio& reader;
    const ELFIO::const_symbol_section_accessor& symbols;
    const ElfGlobalData& global;
    std::vector<FunctionRelocation> function_relocations;
    std::vector<std::string> unresolved_symbol_errors;
    std::map<uint32_t, std::string> external_function_relocations;

    // loop detection for recursive subprogram resolution
    std::map<const RawProgram*, bool> resolved_subprograms;
    std::set<const RawProgram*> currently_visiting;

    /// @brief Apply a single CO-RE relocation to an instruction.
    ///
    /// CO-RE (Compile Once - Run Everywhere) relocations allow BPF programs to access
    /// kernel data structures in a portable way. The loader resolves these relocations
    /// by traversing the BTF type graph to calculate field offsets, type sizes, etc.
    ///
    /// Supported relocation kinds:
    /// - FIELD_BYTE_OFFSET: Calculate offset of a struct field (with nested access)
    /// - TYPE_ID_LOCAL/TARGET: Replace with type ID
    /// - TYPE_SIZE: Replace with sizeof(type)
    ///
    /// @param prog Program containing the instruction to relocate
    /// @param relo CO-RE relocation descriptor (from .BTF.ext section)
    /// @param btf_data BTF type information for offset calculations
    /// @throws UnmarshalError if relocation is invalid or unsupported
    void apply_core_relocation(RawProgram& prog, const bpf_core_relo& relo,
                               const libbtf::btf_type_data& btf_data) const;
    void process_core_relocations(const libbtf::btf_type_data& btf_data);

  public:
    std::vector<RawProgram> raw_programs;

    ProgramReader(const parse_params_t& p, const ELFIO::elfio& r, const ELFIO::const_symbol_section_accessor& s,
                  const ElfGlobalData& g)
        : parse_params{p}, reader{r}, symbols{s}, global{g} {}

    std::string append_subprograms(RawProgram& prog);
    [[nodiscard]]
    int relocate_map(const std::string& name, ELFIO::Elf_Word index) const;
    [[nodiscard]]
    int relocate_global_variable(const std::string& name) const;

    /// @brief Attempt to relocate a symbol reference in an instruction.
    ///
    /// Handles multiple relocation types:
    /// - **Function calls**: Queue for later resolution when all programs are loaded
    /// - **Map references**: Resolve to map file descriptor
    /// - **Global variables**: Resolve to implicit map FD + offset within section
    /// - **Config symbols**: Zero out (compile-time configuration)
    ///
    /// Global variable relocations MUST be applied to LDDW instruction pairs
    /// (opcode 0x18 followed by opcode 0x00). This function validates the instruction
    /// structure before patching to prevent corruption of non-LDDW instructions.
    ///
    /// @param symbol_name Name of the symbol (maybe empty for unnamed relocations)
    /// @param symbol_section_index Section containing the symbol
    /// @param instructions Instruction vector to modify
    /// @param location Instruction index to relocate
    /// @param index Symbol table index for additional lookup
    /// @param addend Additional offset to apply
    /// @return true if relocation succeeded or should be skipped, false if unresolved
    bool try_reloc(const std::string& symbol_name, ELFIO::Elf_Half symbol_section_index,
                   std::vector<EbpfInst>& instructions, size_t location, ELFIO::Elf_Word index,
                   ELFIO::Elf_Sxword addend);
    void process_relocations(std::vector<EbpfInst>& instructions, const ELFIO::const_relocation_section_accessor& reloc,
                             const std::string& section_name, ELFIO::Elf_Xword program_offset, size_t program_size);
    [[nodiscard]]
    const ELFIO::section* get_relocation_section(const std::string& name) const;
    void read_programs();
};

void ProgramReader::apply_core_relocation(RawProgram& prog, const bpf_core_relo& relo,
                                          const libbtf::btf_type_data& btf_data) const {
    const size_t inst_idx = (relo.insn_off - prog.insn_off) / sizeof(EbpfInst);
    if (inst_idx >= prog.prog.size()) {
        throw UnmarshalError("CO-RE relocation offset out of bounds");
    }
    EbpfInst& inst = prog.prog[inst_idx];

    switch (relo.kind) {
    case BPF_CORE_FIELD_BYTE_OFFSET: {
        const auto* btf_section = reader.sections[".BTF"];
        const auto* hdr = reinterpret_cast<const btf_header_t*>(btf_section->get_data());
        const char* base = btf_section->get_data() + hdr->hdr_len;
        const char* str_base = base + hdr->str_off;
        const std::string access_string(str_base + relo.access_str_off);

        const auto indices = parse_core_access_string(access_string);
        uint32_t current_type_id = relo.type_id;
        uint32_t final_offset_bits = 0;

        for (const uint32_t index : indices) {
            int depth = 0;
            while (true) {
                if (++depth > 255) {
                    throw UnmarshalError("CO-RE type resolution exceeded depth limit (possible corrupt BTF)");
                }
                const auto kind_index = btf_data.get_kind_index(current_type_id);
                if (kind_index == libbtf::BTF_KIND_TYPEDEF) {
                    current_type_id = btf_data.get_kind_type<libbtf::btf_kind_typedef>(current_type_id).type;
                } else if (kind_index == libbtf::BTF_KIND_CONST) {
                    current_type_id = btf_data.get_kind_type<libbtf::btf_kind_const>(current_type_id).type;
                } else if (kind_index == libbtf::BTF_KIND_VOLATILE) {
                    current_type_id = btf_data.get_kind_type<libbtf::btf_kind_volatile>(current_type_id).type;
                } else if (kind_index == libbtf::BTF_KIND_RESTRICT) {
                    current_type_id = btf_data.get_kind_type<libbtf::btf_kind_restrict>(current_type_id).type;
                } else {
                    break;
                }
            }
            const auto kind_index = btf_data.get_kind_index(current_type_id);
            if (kind_index == libbtf::BTF_KIND_STRUCT) {
                auto s = btf_data.get_kind_type<libbtf::btf_kind_struct>(current_type_id);
                if (index < s.members.size()) {
                    final_offset_bits += s.members[index].offset_from_start_in_bits;
                    current_type_id = s.members[index].type;
                } else {
                    throw UnmarshalError("CO-RE: member index out of bounds");
                }
            } else if (kind_index == libbtf::BTF_KIND_ARRAY) {
                const auto a = btf_data.get_kind_type<libbtf::btf_kind_array>(current_type_id);
                final_offset_bits += index * btf_data.get_size(a.element_type) * 8;
                current_type_id = a.element_type;
            } else {
                throw UnmarshalError("CO-RE: indexing into non-aggregate type");
            }
        }
        inst.imm = gsl::narrow<int32_t>(final_offset_bits) / 8;
        break;
    }
    case BPF_CORE_TYPE_ID_LOCAL:
    case BPF_CORE_TYPE_ID_TARGET: inst.imm = gsl::narrow<int>(relo.type_id); break;
    case BPF_CORE_TYPE_SIZE: inst.imm = gsl::narrow<int>(btf_data.get_size(relo.type_id)); break;
    default: throw UnmarshalError("Unsupported CO-RE relocation kind: " + std::to_string(relo.kind));
    }
}

void ProgramReader::process_core_relocations(const libbtf::btf_type_data& btf_data) {
    const ELFIO::section* relo_sec = reader.sections[".rel.BTF"];
    if (!relo_sec) {
        relo_sec = reader.sections[".rela.BTF"];
    }
    if (!relo_sec) {
        return;
    }

    const ELFIO::section* btf_ext_sec = reader.sections[".BTF.ext"];
    if (!btf_ext_sec) {
        throw UnmarshalError(".BTF.ext section missing for CO-RE relocations");
    }

    const char* btf_ext_data = btf_ext_sec->get_data();
    const ELFIO::const_relocation_section_accessor relocs(reader, relo_sec);

    // R_BPF_64_NODYLD32 from the kernel UAPI (linux/bpf.h)
    // This relocation type is specifically for CO-RE field access relocations.
    // The value 19 is stable across kernel versions as part of the BPF ELF ABI.
    constexpr unsigned int R_BPF_64_NODYLD32 = 19;

    for (ELFIO::Elf_Xword i = 0; i < relocs.get_entries_num(); i++) {
        ELFIO::Elf64_Addr offset{};
        ELFIO::Elf_Word sym_idx{};
        unsigned type{};
        ELFIO::Elf_Sxword addend{};
        if (relocs.get_entry(i, offset, sym_idx, type, addend)) {
            // Only process relocations that are specifically for CO-RE.
            // Ignore other relocation types like function calls (308).
            if (type != R_BPF_64_NODYLD32) {
                continue;
            }

            const auto sym = get_symbol_details(symbols, sym_idx);
            if (sym.value + sizeof(bpf_core_relo) > btf_ext_sec->get_size()) {
                throw UnmarshalError("CO-RE relocation offset out of BTF.ext bounds");
            }
            const auto* relo = reinterpret_cast<const bpf_core_relo*>(btf_ext_data + sym.value);
            bool applied = false;

            for (auto& prog : raw_programs) {
                // Find the right program based on the instruction offset from the CO-RE struct.
                if (relo->insn_off >= prog.insn_off &&
                    relo->insn_off < prog.insn_off + prog.prog.size() * sizeof(EbpfInst)) {
                    apply_core_relocation(prog, *relo, btf_data);
                    applied = true;
                    break;
                }
            }

            if (!applied) {
                throw UnmarshalError("Failed to find program for CO-RE relocation at instruction offset " +
                                     std::to_string(relo->insn_off));
            }
        }
    }
}

/// @brief Recursively append subprograms to a main program.
///
/// BPF programs can call local functions (subprograms). The linker must:
/// 1. Identify all CallLocal instructions in the program
/// 2. Find the target subprogram by name
/// 3. Append the subprogram's instructions to the caller
/// 4. Update the CallLocal immediate with the correct PC-relative offset
/// 5. Recursively process any subprograms called by the subprogram
///
/// Note: Recursive calls are detected and rejected.
///
/// @param prog Program to process
/// @return Empty string on success, error message on failure
std::string ProgramReader::append_subprograms(RawProgram& prog) {
    if (resolved_subprograms[&prog]) {
        return {};
    }

    if (currently_visiting.contains(&prog)) {
        throw UnmarshalError("Mutual recursion in subprogram calls");
    }
    currently_visiting.insert(&prog);

    std::map<std::string, ELFIO::Elf_Xword> subprogram_offsets;
    for (const auto& reloc : function_relocations) {
        if (reloc.prog_index >= raw_programs.size() ||
            raw_programs[reloc.prog_index].function_name != prog.function_name) {
            continue;
        }
        if (!subprogram_offsets.contains(reloc.target_function_name)) {
            subprogram_offsets[reloc.target_function_name] = prog.prog.size();
            auto sym = get_symbol_details(symbols, reloc.relocation_entry_index);
            if (sym.section_index >= reader.sections.size()) {
                throw UnmarshalError("Invalid section index");
            }
            const auto& sub_sec = *reader.sections[sym.section_index];
            if (const auto sub = find_subprogram(raw_programs, sub_sec, sym.name)) {
                if (sub == &prog) {
                    throw UnmarshalError("Recursive subprogram call");
                }
                const std::string err = append_subprograms(*sub);
                if (!err.empty()) {
                    return err;
                }
                const size_t base = subprogram_offsets[reloc.target_function_name];
                prog.prog.insert(prog.prog.end(), sub->prog.begin(), sub->prog.end());
                for (const auto& [k, info] : sub->info.line_info) {
                    prog.info.line_info[base + k] = info;
                }
            } else {
                return "Subprogram not found: " + sym.name;
            }
        }
        // BPF uses signed 32-bit immediates: offset = target - (source + 1)
        const auto target_offset = gsl::narrow<int64_t>(subprogram_offsets[reloc.target_function_name]);
        const auto source_offset = gsl::narrow<int64_t>(reloc.source_offset);
        prog.prog[reloc.source_offset].imm = gsl::narrow<int32_t>(target_offset - source_offset - 1);
    }
    currently_visiting.erase(&prog);
    resolved_subprograms[&prog] = true;
    return {};
}

int ProgramReader::relocate_map(const std::string& name, const ELFIO::Elf_Word index) const {
    size_t val{};
    if (const auto* record_size = std::get_if<size_t>(&global.map_record_size_or_map_offsets)) {
        // Legacy path: map symbol value is byte offset into maps section
        // Divide by struct size to get descriptor index
        const auto symbol_value = get_symbol_details(symbols, index).value;
        if (symbol_value % *record_size != 0) {
            throw UnmarshalError("Map symbol offset " + std::to_string(symbol_value) +
                                 " is not aligned to record size " + std::to_string(*record_size));
        }

        val = symbol_value / *record_size;
    } else {
        // BTF path: use map name to look up descriptor index
        const auto& offsets = std::get<MapOffsets>(global.map_record_size_or_map_offsets);
        const auto it = offsets.find(name);
        if (it == offsets.end()) {
            throw UnmarshalError("Map descriptor not found: " + name);
        }
        val = it->second;
    }
    if (val >= global.map_descriptors.size()) {
        throw UnmarshalError(bad_reloc_value(val));
    }
    return global.map_descriptors.at(val).original_fd;
}

int ProgramReader::relocate_global_variable(const std::string& name) const {
    const auto* offsets = std::get_if<MapOffsets>(&global.map_record_size_or_map_offsets);
    if (!offsets) {
        throw UnmarshalError("Invalid map offsets");
    }
    const auto it = offsets->find(name);
    if (it == offsets->end()) {
        throw UnmarshalError("Map descriptor not found: " + name);
    }
    const size_t val = it->second;
    if (val >= global.map_descriptors.size()) {
        throw UnmarshalError(bad_reloc_value(val));
    }
    return global.map_descriptors.at(val).original_fd;
}

bool ProgramReader::try_reloc(const std::string& symbol_name, const ELFIO::Elf_Half symbol_section_index,
                              std::vector<EbpfInst>& instructions, const size_t location, const ELFIO::Elf_Word index,
                              const ELFIO::Elf_Sxword addend) {
    // Handle empty symbol names for global variable sections
    // These occur in legacy ELF files where relocations reference
    // section symbols rather than named variable symbols
    if (symbol_name.empty()) {
        if (global.variable_section_indices.contains(symbol_section_index)) {
            if (!std::holds_alternative<MapOffsets>(global.map_record_size_or_map_offsets)) {
                return false; // Legacy path without MapOffsets; let caller handle
            }

            auto [lo_inst, hi_inst] = validate_and_get_lddw_pair(instructions, location, "global variable");

            const auto symbol_details = get_symbol_details(symbols, index);
            hi_inst.get().imm = gsl::narrow<int32_t>(symbol_details.value);
            lo_inst.get().src = INST_LD_MODE_MAP_VALUE;

            const std::string section_name = reader.sections[symbol_section_index]->get_name();
            lo_inst.get().imm = relocate_global_variable(section_name);
            return true;
        }
        // Empty symbol name in non-variable section - skip it
        return true;
    }

    EbpfInst& instruction_to_relocate = instructions[location];

    // Calls to external helper functions are flagged as local calls with an undefined section index (0).
    if (instruction_to_relocate.opcode == INST_OP_CALL && instruction_to_relocate.src == INST_CALL_LOCAL &&
        symbol_section_index == 0) {
        // To prevent the eBPF verifier from attempting to resolve this as a local function,
        // change the instruction to a call to a static helper and add it to the external function map.
        instruction_to_relocate.src = INST_CALL_STATIC_HELPER;
        external_function_relocations[location] = symbol_name;
        return true;
    }

    // Handle local function calls - queue for post-processing
    if (instruction_to_relocate.opcode == INST_OP_CALL && instruction_to_relocate.src == INST_CALL_LOCAL) {
        function_relocations.emplace_back(FunctionRelocation{raw_programs.size(), location, index, symbol_name});
        return true;
    }

    // Only LD-class instructions can be map/global loads
    if ((instruction_to_relocate.opcode & INST_CLS_MASK) != INST_CLS_LD) {
        return false;
    }

    // Handle map relocations (BTF or legacy)
    if (global.map_section_indices.contains(symbol_section_index)) {
        instruction_to_relocate.src = INST_LD_MODE_MAP_FD;
        instruction_to_relocate.imm = relocate_map(symbol_name, index);
        return true;
    }

    // Handle named global variables (including __config_* symbols in .rodata.config)
    if (global.variable_section_indices.contains(symbol_section_index)) {
        auto [lo_inst, hi_inst] =
            validate_and_get_lddw_pair(instructions, location, "global variable '" + symbol_name + "'");

        const int32_t offset = addend != 0 ? gsl::narrow<int32_t>(addend) : lo_inst.get().imm;
        hi_inst.get().imm = offset;
        lo_inst.get().src = INST_LD_MODE_MAP_VALUE;
        lo_inst.get().imm = relocate_global_variable(reader.sections[symbol_section_index]->get_name());
        return true;
    }

    // Legacy fallback: zero out __config_* symbols not in a variable section
    // (for compatibility with older toolchains)
    if (symbol_name.rfind("__config_", 0) == 0) {
        instruction_to_relocate.imm = 0;
        return true;
    }

    return false;
}

void ProgramReader::process_relocations(std::vector<EbpfInst>& instructions,
                                        const ELFIO::const_relocation_section_accessor& reloc,
                                        const std::string& section_name, const ELFIO::Elf_Xword program_offset,
                                        const size_t program_size) {
    for (ELFIO::Elf_Xword i = 0; i < reloc.get_entries_num(); i++) {
        ELFIO::Elf64_Addr o{};
        ELFIO::Elf_Word idx{};
        unsigned type{};
        ELFIO::Elf_Sxword addend{};
        if (reloc.get_entry(i, o, idx, type, addend)) {
            if (o < program_offset || o >= program_offset + program_size) {
                continue;
            }
            o -= program_offset;

            if (o % sizeof(EbpfInst) != 0) {
                throw UnmarshalError("Unaligned relocation offset");
            }
            const auto loc = o / sizeof(EbpfInst);
            if (loc >= instructions.size()) {
                throw UnmarshalError("Invalid relocation");
            }
            auto sym = get_symbol_details(symbols, idx);

            if (!try_reloc(sym.name, sym.section_index, instructions, loc, idx, addend)) {
                unresolved_symbol_errors.push_back("Unresolved external symbol " + sym.name + " in section " +
                                                   section_name + " at location " + std::to_string(loc));
            }
        }
    }
}

const ELFIO::section* ProgramReader::get_relocation_section(const std::string& name) const {
    if (name == ".BTF") {
        return nullptr;
    }
    const auto* relocs = reader.sections[".rel" + name];
    if (!relocs) {
        relocs = reader.sections[".rela" + name];
    }
    if (!relocs || !relocs->get_data()) {
        return nullptr;
    }
    return relocs;
}

void ProgramReader::read_programs() {
    // Clear cycle detection state for this batch
    resolved_subprograms.clear();

    for (const auto& sec : reader.sections) {
        if (!(sec->get_flags() & ELFIO::SHF_EXECINSTR) || !sec->get_size() || !sec->get_data()) {
            continue;
        }
        const auto& sec_name = sec->get_name();
        const auto prog_type = parse_params.platform->get_program_type(sec_name, parse_params.path);
        for (ELFIO::Elf_Xword offset = 0; offset < sec->get_size();) {
            auto [name, size] = get_program_name_and_size(*sec, offset, symbols);
            auto instructions = vector_of<EbpfInst>(sec->get_data() + offset, size);
            if (const auto reloc_sec = get_relocation_section(sec_name)) {
                process_relocations(instructions, ELFIO::const_relocation_section_accessor{reader, reloc_sec}, sec_name,
                                    offset, size);
            }

            raw_programs.emplace_back(RawProgram{
                parse_params.path,
                sec_name,
                gsl::narrow<uint32_t>(offset),
                name,
                std::move(instructions),
                {parse_params.platform, global.map_descriptors, prog_type},
                external_function_relocations,
            });
            external_function_relocations.clear();
            offset += size;
        }
    }

    if (const auto btf_sec = reader.sections[".BTF"]) {
        process_core_relocations({vector_of<std::byte>(*btf_sec), false});
    }

    if (!unresolved_symbol_errors.empty()) {
        for (const auto& err : unresolved_symbol_errors) {
            std::cerr << err << std::endl;
        }
        throw UnmarshalError("Unresolved symbols found.");
    }

    if (const auto btf_sec = reader.sections[".BTF"]) {
        if (const auto btf_ext = reader.sections[".BTF.ext"]) {
            update_line_info(raw_programs, btf_sec, btf_ext);
        }
    }

    for (auto& prog : raw_programs) {
        const auto err = append_subprograms(prog);
        if (!err.empty() && prog.section_name == parse_params.desired_section) {
            throw UnmarshalError(err);
        }
    }

    if (!parse_params.desired_section.empty()) {
        std::erase_if(raw_programs, [&](const auto& p) { return p.section_name != parse_params.desired_section; });
    }

    if (raw_programs.empty()) {
        throw UnmarshalError(parse_params.desired_section.empty() ? "No executable sections" : "Section not found");
    }
}
} // namespace

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

std::vector<RawProgram> read_elf(std::istream& input_stream, const std::string& path,
                                 const std::string& desired_section, const ebpf_verifier_options_t& options,
                                 const ebpf_platform_t* platform) {
    parse_params_t params{path, options, platform, desired_section};
    auto reader = load_elf(input_stream, path);
    auto symbols = read_and_validate_symbol_section(reader, path);
    auto global = extract_global_data(params, reader, symbols);
    ProgramReader program_reader{params, reader, symbols, global};
    program_reader.read_programs();
    return std::move(program_reader.raw_programs);
}

std::vector<RawProgram> read_elf(const std::string& path, const std::string& desired_section,
                                 const ebpf_verifier_options_t& options, const ebpf_platform_t* platform) {
    if (std::ifstream stream{path, std::ios::in | std::ios::binary}) {
        return read_elf(stream, path, desired_section, options, platform);
    }
    struct stat st; // NOLINT(*-pro-type-member-init)
    if (stat(path.c_str(), &st)) {
        throw UnmarshalError(std::string(strerror(errno)) + " opening " + path);
    }
    throw UnmarshalError("Can't process ELF file " + path);
}

} // namespace prevail

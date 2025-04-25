// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "elfio/elfio.hpp"
#include "libbtf/btf_json.h"
#include "libbtf/btf_map.h"
#include "libbtf/btf_parse.h"

#include "asm_files.hpp"
#include "crab_utils/num_safety.hpp"
#include "platform.hpp"

namespace prevail {

template <typename T>
    requires std::is_trivially_copyable_v<T>
static std::vector<T> vector_of(const char* data, const ELFIO::Elf_Xword size) {
    if (size % sizeof(T) != 0 || size > std::numeric_limits<uint32_t>::max() || !data) {
        throw UnmarshalError("Invalid argument to vector_of");
    }
    return {reinterpret_cast<const T*>(data), reinterpret_cast<const T*>(data + size)};
}

template <typename T>
    requires std::is_trivially_copyable_v<T>
static std::vector<T> vector_of(const ELFIO::section& sec) {
    return vector_of<T>(sec.get_data(), sec.get_size());
}

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

// Maps sections are identified as any section called "maps", or matching "maps/<map-name>".
static bool is_map_section(const std::string& name) {
    const std::string maps_prefix = "maps/";
    return name == "maps" || (name.length() > 5 && name.compare(0, maps_prefix.length(), maps_prefix) == 0);
}

struct symbol_details_t {
    std::string name;
    ELFIO::Elf64_Addr value{}; // also relocation offset
    ELFIO::Elf_Xword size{};
    unsigned char bind{};
    unsigned char type{};
    ELFIO::Elf_Half section_index{};
    unsigned char other{};
};

static symbol_details_t get_symbol_details(const ELFIO::const_symbol_section_accessor& symbols,
                                           const ELFIO::Elf_Xword index) {
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

std::vector<RawProgram> read_elf(const std::string& path, const std::string& desired_section,
                                 const ebpf_verifier_options_t& options, const ebpf_platform_t* platform) {
    if (std::ifstream stream{path, std::ios::in | std::ios::binary}) {
        return read_elf(stream, path, desired_section, options, platform);
    }
    struct stat st;
    if (stat(path.c_str(), &st)) {
        throw UnmarshalError(std::string(strerror(errno)) + " opening " + path);
    }
    throw UnmarshalError("Can't process ELF file " + path);
}

static std::tuple<std::string, ELFIO::Elf_Xword>
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
                // We found the program name for this program.
                program_name = symbol_details.name;
            } else if (relocation_offset > start && relocation_offset < start + size) {
                // We found another program that follows, so truncate the size of this program.
                size = relocation_offset - start;
            }
        }
    }
    return {program_name, size};
}

static std::string bad_reloc_value(const size_t reloc_value) {
    return "Bad reloc value (" + std::to_string(reloc_value) + "). " + "Make sure to compile with -O2.";
}

// Structure used to keep track of subprogram relocation data until any subprograms
// are loaded and can be appended to the calling program.
struct FunctionRelocation {
    size_t prog_index{};              // Index of source program in std::vector of raw programs.
    ELFIO::Elf_Xword source_offset{}; // Instruction offset in source section of source instruction.
    ELFIO::Elf_Xword relocation_entry_index{};
    std::string target_function_name;
};

static RawProgram* find_subprogram(std::vector<RawProgram>& programs, const ELFIO::section& subprogram_section,
                                   const std::string& symbol_name) {
    // Find subprogram by name.
    for (auto& subprog : programs) {
        if (subprog.section_name == subprogram_section.get_name() && subprog.function_name == symbol_name) {
            return &subprog;
        }
    }
    return nullptr;
}

using MapOffsets = std::map<std::string, size_t>;

struct elf_global_data {
    std::set<ELFIO::Elf_Half> map_section_indices;
    std::vector<EbpfMapDescriptor> map_descriptors;
    std::variant<size_t, MapOffsets> map_record_size_or_map_offsets;
    std::set<ELFIO::Elf_Half> variable_section_indices;
};

static std::map<int, int> map_typeid_to_fd(const std::vector<EbpfMapDescriptor>& map_descriptors) {
    std::map<int, int> type_id_to_fd_map;
    int pseudo_fd = 1;
    // Gather the typeids for each map and assign a pseudo-fd to each map.
    for (const auto& map_descriptor : map_descriptors) {
        if (!type_id_to_fd_map.contains(map_descriptor.original_fd)) {
            type_id_to_fd_map[map_descriptor.original_fd] = pseudo_fd++;
        }
    }
    return type_id_to_fd_map;
}

static ELFIO::const_symbol_section_accessor read_and_validate_symbol_section(const ELFIO::elfio& reader,
                                                                             const std::string& path) {
    const ELFIO::section* symbol_section = reader.sections[".symtab"];
    if (!symbol_section) {
        throw UnmarshalError("No symbol section found in ELF file " + path);
    }

    // Make sure the ELFIO library will be able to parse the symbol section correctly.
    const auto expected_entry_size =
        reader.get_class() == ELFIO::ELFCLASS32 ? sizeof(ELFIO::Elf32_Sym) : sizeof(ELFIO::Elf64_Sym);

    if (symbol_section->get_entry_size() != expected_entry_size) {
        throw UnmarshalError("Invalid symbol section found in ELF file " + path);
    }
    return ELFIO::const_symbol_section_accessor{reader, symbol_section};
}

static ELFIO::elfio load_elf(std::istream& input_stream, const std::string& path) {
    ELFIO::elfio reader;
    if (!reader.load(input_stream)) {
        throw UnmarshalError("Can't process ELF file " + path);
    }
    return reader;
}

static void dump_btf_types(const libbtf::btf_type_data& btf_data, const std::string& path) {
    std::stringstream output;
    std::cout << "Dumping BTF data for" << path << std::endl;
    // Dump the BTF data to stdout for debugging purposes.
    btf_data.to_json(output);
    std::cout << libbtf::pretty_print_json(output.str()) << std::endl;
    std::cout << std::endl;
}

static void update_line_info(std::vector<RawProgram>& raw_programs, const ELFIO::section* btf_section,
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

    // BTF doesn't include line info for every instruction, only on the first instruction per source line.
    for (auto& program : raw_programs) {
        for (size_t i = 1; i < program.prog.size(); i++) {
            // If the previous PC has line info, copy it.
            if (program.info.line_info[i].line_number == 0 && program.info.line_info[i - 1].line_number != 0) {
                program.info.line_info[i] = program.info.line_info[i - 1];
            }
        }
    }
}

static elf_global_data parse_btf_section(const parse_params_t& parse_params, const ELFIO::elfio& reader) {
    const auto btf_section = reader.sections[".BTF"];
    if (!btf_section) {
        return {};
    }
    const libbtf::btf_type_data btf_data = vector_of<std::byte>(*btf_section);
    if (parse_params.options.verbosity_opts.dump_btf_types_json) {
        dump_btf_types(btf_data, parse_params.path);
    }

    elf_global_data global;

    {
        MapOffsets map_offsets;
        for (const auto& map : parse_btf_map_section(btf_data)) {
            map_offsets.emplace(map.name, global.map_descriptors.size());
            global.map_descriptors.push_back({
                .original_fd = gsl::narrow_cast<int>(map.type_id),
                .type = map.map_type,
                .key_size = map.key_size,
                .value_size = map.value_size,
                .max_entries = map.max_entries,
                .inner_map_fd = map.inner_map_type_id != 0 ? map.inner_map_type_id : DEFAULT_MAP_FD,
            });
        }
        global.map_record_size_or_map_offsets = std::move(map_offsets);
    }

    {
        // Prevail requires:
        // Map fds are sequential starting from 1.
        // Map fds are assigned in the order of the maps in the ELF file.
        const std::map<int, int> type_id_to_fd_map = map_typeid_to_fd(global.map_descriptors);
        for (auto& map_descriptor : global.map_descriptors) {
            map_descriptor.original_fd = type_id_to_fd_map.at(map_descriptor.original_fd);
            if (map_descriptor.inner_map_fd != DEFAULT_MAP_FD) {
                map_descriptor.inner_map_fd = type_id_to_fd_map.at(map_descriptor.inner_map_fd);
            }
        }
    }

    if (const auto maps_section = reader.sections[".maps"]) {
        global.map_section_indices.insert(maps_section->get_index());
    }

    for (const auto section_name : {".rodata", ".data", ".bss"}) {
        if (const auto section = reader.sections[section_name]) {
            if (section->get_size() != 0) {
                global.variable_section_indices.insert(section->get_index());
            }
        }
    }
    return global;
}

// parse_maps_sections processes all maps sections in the provided ELF file by calling the platform-specific maps'
// parser. The section index of each maps section is inserted into map_section_indices.
static elf_global_data parse_map_sections(const parse_params_t& parse_params, const ELFIO::elfio& reader,
                                          const ELFIO::const_symbol_section_accessor& symbols) {
    elf_global_data global;
    size_t map_record_size = parse_params.platform->map_record_size;
    for (ELFIO::Elf_Half i = 0; i < reader.sections.size(); ++i) {
        const auto s = reader.sections[i];
        if (!is_map_section(s->get_name())) {
            continue;
        }

        // Count the number of symbols that point into this maps section.
        int map_count = 0;
        for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); index++) {
            const auto symbol_details = get_symbol_details(symbols, index);
            if (symbol_details.section_index == i && !symbol_details.name.empty()) {
                map_count++;
            }
        }

        if (map_count > 0) {
            map_record_size = s->get_size() / map_count;
            if (s->get_data() == nullptr || map_record_size == 0) {
                throw UnmarshalError("bad maps section");
            }
            if (s->get_size() % map_record_size != 0) {
                throw UnmarshalError("bad maps section size");
            }
            parse_params.platform->parse_maps_section(global.map_descriptors, s->get_data(), map_record_size, map_count,
                                                      parse_params.platform, parse_params.options);
        }
        global.map_section_indices.insert(s->get_index());
    }
    parse_params.platform->resolve_inner_map_references(global.map_descriptors);
    global.map_record_size_or_map_offsets = map_record_size;
    return global;
}

static elf_global_data extract_global_data(const parse_params_t& parse_params, const ELFIO::elfio& reader,
                                           const ELFIO::const_symbol_section_accessor& symbols) {
    if (std::ranges::any_of(reader.sections, [](const auto& section) { return is_map_section(section->get_name()); })) {
        return parse_map_sections(parse_params, reader, symbols);
    }
    return parse_btf_section(parse_params, reader);
}

class ProgramReader {
    const parse_params_t& parse_params;
    const ELFIO::elfio& reader;
    const ELFIO::const_symbol_section_accessor& symbols;
    const elf_global_data& global;

    std::vector<FunctionRelocation> function_relocations;
    std::vector<std::string> unresolved_symbol_errors;
    std::map<const RawProgram*, bool> resolved_subprograms;

  public:
    std::vector<RawProgram> raw_programs;

    ProgramReader(const parse_params_t& parse_params, const ELFIO::elfio& reader,
                  const ELFIO::const_symbol_section_accessor& symbols, const elf_global_data& global)
        : parse_params{parse_params}, reader{reader}, symbols{symbols}, global{global} {}

    // Returns an error message, or empty string on success.
    std::string append_subprograms(RawProgram& prog) {
        if (resolved_subprograms[&prog]) {
            // We've already appended any relevant subprograms.
            return {};
        }
        resolved_subprograms[&prog] = true;

        // Perform function relocations and fill in the inst.imm values of CallLocal instructions.
        std::map<std::string, ELFIO::Elf_Xword> subprogram_offsets;
        for (const auto& reloc : function_relocations) {
            if (reloc.prog_index >= raw_programs.size()) {
                continue;
            }
            if (raw_programs[reloc.prog_index].function_name != prog.function_name) {
                continue;
            }

            // Check whether we already appended the target program, and append it if not.
            if (!subprogram_offsets.contains(reloc.target_function_name)) {
                subprogram_offsets[reloc.target_function_name] = prog.prog.size();

                const auto symbol_details = get_symbol_details(symbols, reloc.relocation_entry_index);
                if (symbol_details.section_index >= reader.sections.size()) {
                    throw UnmarshalError("Invalid section index " + std::to_string(symbol_details.section_index) +
                                         " at source offset " + std::to_string(reloc.source_offset));
                }
                const ELFIO::section& subprogram_section = *reader.sections[symbol_details.section_index];

                if (const auto subprogram = find_subprogram(raw_programs, subprogram_section, symbol_details.name)) {
                    // Don't permit recursive subprograms.
                    if (subprogram == &prog) {
                        throw UnmarshalError("Subprogram '" + symbol_details.name +
                                             "' is the same as the calling program");
                    }

                    // Make sure subprogram has already had any subprograms of its own appended.
                    std::string error = append_subprograms(*subprogram);
                    if (!error.empty()) {
                        return error;
                    }

                    // Append subprogram to program.
                    prog.prog.insert(prog.prog.end(), subprogram->prog.begin(), subprogram->prog.end());
                    for (size_t i = 0; i < subprogram->info.line_info.size(); i++) {
                        prog.info.line_info[prog.info.line_info.size()] = subprogram->info.line_info[i];
                    }
                } else {
                    // The program will be invalid, but continue rather than throwing an exception
                    // since we might be verifying a different program in the file.
                    return std::string("Subprogram '" + symbol_details.name + "' not found in section '" +
                                       subprogram_section.get_name() + "'");
                }
            }

            // Fill in the PC offset into the imm field of the CallLocal instruction.
            const int64_t target_offset = gsl::narrow_cast<int64_t>(subprogram_offsets[reloc.target_function_name]);
            const auto offset_diff = target_offset - gsl::narrow<int64_t>(reloc.source_offset) - 1;
            if (offset_diff < std::numeric_limits<int32_t>::min() ||
                offset_diff > std::numeric_limits<int32_t>::max()) {
                throw UnmarshalError("Offset difference out of int32_t range for instruction at source offset " +
                                     std::to_string(reloc.source_offset));
            }
            prog.prog[reloc.source_offset].imm = gsl::narrow_cast<int32_t>(offset_diff);
        }
        return {};
    }

    int relocate_map(const std::string& symbol_name, const ELFIO::Elf_Word index) const {
        // Relocation value is an offset into the "maps" or ".maps" section.
        size_t reloc_value{};
        if (const auto* map_record_size = std::get_if<size_t>(&global.map_record_size_or_map_offsets)) {
            // The older maps section format uses a single map_record_size value,
            // so we can calculate the map descriptor index directly.
            const auto symbol_details = get_symbol_details(symbols, index);
            const auto relocation_offset = symbol_details.value;
            reloc_value = relocation_offset / *map_record_size;
        } else {
            // The newer .maps section format uses a variable-length map descriptor array,
            // so we need to look up the map descriptor index in a map.
            const auto& map_descriptors_offsets = std::get<MapOffsets>(global.map_record_size_or_map_offsets);
            const auto it = map_descriptors_offsets.find(symbol_name);
            if (it == map_descriptors_offsets.end()) {
                throw UnmarshalError("Map descriptor not found for symbol " + symbol_name);
            }
            reloc_value = it->second;
        }
        if (reloc_value >= global.map_descriptors.size()) {
            throw UnmarshalError(bad_reloc_value(reloc_value));
        }
        return global.map_descriptors.at(reloc_value).original_fd;
    }

    int relocate_global_variable(const std::string& symbol_name) const {
        const auto map_descriptors_offsets = std::get_if<MapOffsets>(&global.map_record_size_or_map_offsets);
        if (!map_descriptors_offsets) {
            throw UnmarshalError("Invalid map_offsets");
        }
        const auto it = map_descriptors_offsets->find(symbol_name);
        if (it == map_descriptors_offsets->end()) {
            throw UnmarshalError("Map descriptor not found for symbol " + symbol_name);
        }
        const size_t reloc_value = it->second;
        if (reloc_value >= global.map_descriptors.size()) {
            throw UnmarshalError(bad_reloc_value(reloc_value));
        }
        return global.map_descriptors.at(reloc_value).original_fd;
    }

    bool try_reloc(const std::string& symbol_name, const ELFIO::Elf_Half symbol_section_index,
                   std::vector<EbpfInst>& instructions, const size_t location, const ELFIO::Elf_Word index) {
        EbpfInst& instruction_to_relocate = instructions[location];

        // Queue up relocation for function symbols.
        if (instruction_to_relocate.opcode == INST_OP_CALL && instruction_to_relocate.src == INST_CALL_LOCAL) {
            function_relocations.emplace_back(FunctionRelocation{
                .prog_index = raw_programs.size(),
                .source_offset = location,
                .relocation_entry_index = index,
                .target_function_name = symbol_name,
            });
            return true;
        }

        // Verify that this is a map or global variable relocation.
        if ((instruction_to_relocate.opcode & INST_CLS_MASK) != INST_CLS_LD) {
            throw UnmarshalError("Illegal operation on symbol " + symbol_name + " at location " +
                                 std::to_string(location));
        }

        // Perform relocation for symbols located in the maps section.
        if (global.map_section_indices.contains(symbol_section_index)) {
            instruction_to_relocate.src = INST_LD_MODE_MAP_FD;
            instruction_to_relocate.imm = relocate_map(symbol_name, index);
            return true;
        }

        if (global.variable_section_indices.contains(symbol_section_index)) {
            // Load instructions are two instructions long, so we need to check the next instruction.
            if (instructions.size() <= location + 1) {
                throw UnmarshalError("Invalid relocation data");
            }
            // Copy the immediate value to the next instruction.
            instructions[location + 1].imm = instruction_to_relocate.imm;
            instruction_to_relocate.src = INST_LD_MODE_MAP_VALUE;
            instruction_to_relocate.imm = relocate_global_variable(reader.sections[symbol_section_index]->get_name());
            return true;
        }
        return false;
    }

    void process_relocations(std::vector<EbpfInst>& instructions, const ELFIO::const_relocation_section_accessor& reloc,
                             const std::string& section_name, const ELFIO::Elf_Xword program_offset,
                             const size_t program_size) {
        for (ELFIO::Elf_Xword i = 0; i < reloc.get_entries_num(); i++) {
            ELFIO::Elf64_Addr offset{};
            ELFIO::Elf_Word index{};
            unsigned type{};
            ELFIO::Elf_Sxword addend{};
            if (reloc.get_entry(i, offset, index, type, addend)) {
                if (offset < program_offset || offset >= program_offset + program_size) {
                    // Relocation is not for this program.
                    continue;
                }
                offset -= program_offset;
                const unsigned long location = offset / sizeof(EbpfInst);
                if (location >= instructions.size()) {
                    throw UnmarshalError("Invalid relocation data");
                }

                const auto symbol_details = get_symbol_details(symbols, index);
                if (!try_reloc(symbol_details.name, symbol_details.section_index, instructions, location, index)) {
                    unresolved_symbol_errors.push_back("Unresolved external symbol " + symbol_details.name +
                                                       " in section " + section_name + " at location " +
                                                       std::to_string(location));
                }
            }
        }
    }

    const ELFIO::section* get_relocation_section(const std::string& section_name) const {
        const ELFIO::section* prelocs = reader.sections[".rel" + section_name];
        if (!prelocs) {
            prelocs = reader.sections[".rela" + section_name];
        }
        if (!prelocs) {
            return nullptr;
        }
        if (!prelocs->get_data()) {
            throw UnmarshalError("Malformed relocation data");
        }
        return prelocs;
    }

    void read_programs() {
        for (const auto& section : reader.sections) {
            if (!(section->get_flags() & ELFIO::SHF_EXECINSTR)) {
                // Section does not contain executable instructions.
                continue;
            }
            const auto section_size = section->get_size();
            if (section_size == 0) {
                continue;
            }
            const auto section_data = section->get_data();
            if (section_data == nullptr) {
                continue;
            }
            const std::string section_name = section->get_name();
            const EbpfProgramType program_type =
                parse_params.platform->get_program_type(section_name, parse_params.path);

            for (ELFIO::Elf_Xword program_offset = 0; program_offset < section_size;) {
                auto [program_name, program_size] = get_program_name_and_size(*section, program_offset, symbols);
                std::vector<EbpfInst> instructions = vector_of<EbpfInst>(section_data + program_offset, program_size);

                if (const ELFIO::section* reloc_section = get_relocation_section(section_name)) {
                    const ELFIO::const_relocation_section_accessor reloc{reader, reloc_section};
                    process_relocations(instructions, reloc, section_name, program_offset, program_size);
                }

                raw_programs.emplace_back(RawProgram{
                    parse_params.path,
                    section_name,
                    gsl::narrow_cast<uint32_t>(program_offset),
                    program_name,
                    std::move(instructions),
                    ProgramInfo{
                        .platform = parse_params.platform,
                        .map_descriptors = global.map_descriptors,
                        .type = program_type,
                    },
                });
                program_offset += program_size;
            }
        }

        // Below, only relocations of symbols located in the maps sections are allowed,
        // so if there are relocations there needs to be a maps section.
        if (!unresolved_symbol_errors.empty()) {
            for (const auto& unresolved_symbol : unresolved_symbol_errors) {
                std::cerr << unresolved_symbol << std::endl;
            }
            throw UnmarshalError("There are relocations in section but no maps sections in file " + parse_params.path +
                                 "\nMake sure to inline all function calls.");
        }

        if (const auto btf_section = reader.sections[".BTF"]) {
            if (const auto btf_ext = reader.sections[".BTF.ext"]) {
                update_line_info(raw_programs, btf_section, btf_ext);
            }
        }

        // Now that we have all programs in the list, we can recursively append any subprograms
        // to the calling programs.  We have to keep them as programs themselves in case the caller
        // wants to verify them separately, but we also have to append them if used as subprograms to
        // allow the caller to be fully verified since inst.imm can only point into the same program.
        for (auto& prog : raw_programs) {
            std::string error = append_subprograms(prog);
            if (!error.empty()) {
                if (prog.section_name == parse_params.desired_section) {
                    throw UnmarshalError(error);
                }
            }
        }

        // Now that we've incorporated any subprograms from other sections, we can narrow the list
        // to return to just those programs in the desired section, if any.
        if (!parse_params.desired_section.empty() && !raw_programs.empty()) {
            for (int index = raw_programs.size() - 1; index >= 0; index--) {
                if (raw_programs[index].section_name != parse_params.desired_section) {
                    raw_programs.erase(raw_programs.begin() + index);
                }
            }
        }

        if (raw_programs.empty()) {
            if (parse_params.desired_section.empty()) {
                throw UnmarshalError("Can't find any non-empty TEXT sections in file " + parse_params.path);
            }
            throw UnmarshalError("Can't find section " + parse_params.desired_section + " in file " +
                                 parse_params.path);
        }
    }
};

std::vector<RawProgram> read_elf(std::istream& input_stream, const std::string& path,
                                 const std::string& desired_section, const ebpf_verifier_options_t& options,
                                 const ebpf_platform_t* platform) {
    const parse_params_t parse_params{
        .path = path, .options = options, .platform = platform, .desired_section = desired_section};
    const ELFIO::elfio reader = load_elf(input_stream, path);
    const ELFIO::const_symbol_section_accessor symbols = read_and_validate_symbol_section(reader, path);
    const elf_global_data global = extract_global_data(parse_params, reader, symbols);
    ProgramReader program_reader{parse_params, reader, symbols, global};
    program_reader.read_programs();
    return std::move(program_reader.raw_programs);
}
} // namespace prevail

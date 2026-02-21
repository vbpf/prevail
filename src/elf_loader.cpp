// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <deque>
#include <filesystem>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <variant>
#include <vector>

#include <elfio/elfio.hpp>
#include <libbtf/btf_c_type.h>
#include <libbtf/btf_json.h>
#include <libbtf/btf_map.h>
#include <libbtf/btf_parse.h>

#include "crab_utils/num_safety.hpp"
#include "elf_loader.hpp"
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

constexpr uint32_t linux_kernel_version(const uint32_t major, const uint32_t minor, const uint32_t patch) {
    return (major << 16U) | (minor << 8U) | patch;
}

std::optional<uint64_t> resolve_known_linux_extern_symbol(const std::string_view symbol_name) {
    if (symbol_name == "LINUX_KERNEL_VERSION") {
        return linux_kernel_version(6, 6, 0);
    }
    if (symbol_name == "LINUX_HAS_SYSCALL_WRAPPER") {
        return 1;
    }
    if (symbol_name == "LINUX_HAS_BPF_COOKIE") {
        return 1;
    }
    if (symbol_name == "CONFIG_HZ") {
        return 250;
    }
    if (symbol_name == "CONFIG_BPF_SYSCALL") {
        return 1;
    }
    if (symbol_name == "CONFIG_DEFAULT_HOSTNAME") {
        // Store first character ('l' from "localhost"), matching common kconfig usage
        // where the program probes CONFIG_DEFAULT_HOSTNAME[0] for non-empty checks.
        return static_cast<uint64_t>('l');
    }
    return std::nullopt;
}

EbpfInst make_mov_reg_nop(const uint8_t reg) {
    return EbpfInst{
        .opcode = static_cast<uint8_t>(INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_REG),
        .dst = reg,
        .src = reg,
        .offset = 0,
        .imm = 0,
    };
}

bool rewrite_extern_constant_load(std::vector<EbpfInst>& instructions, const size_t location, const uint64_t value) {
    if (instructions.size() <= location + 2) {
        return false;
    }

    auto [lo_inst, hi_inst] = validate_and_get_lddw_pair(instructions, location, "external symbol");
    EbpfInst& load_inst = instructions[location + 2];
    if ((load_inst.opcode & INST_CLS_MASK) != INST_CLS_LDX) {
        return false;
    }
    const uint8_t mode = load_inst.opcode & INST_MODE_MASK;
    if (mode != INST_MODE_MEM && mode != INST_MODE_MEMSX) {
        return false;
    }
    if (load_inst.src != lo_inst.get().dst || load_inst.offset != 0) {
        return false;
    }

    const auto width = opcode_to_width(load_inst.opcode);
    uint64_t narrowed_value = value;
    switch (width) {
    case 1: narrowed_value &= 0xffULL; break;
    case 2: narrowed_value &= 0xffffULL; break;
    case 4: narrowed_value &= 0xffffffffULL; break;
    case 8: break;
    default: return false;
    }
    if (mode == INST_MODE_MEMSX && width < 8) {
        const auto shift = gsl::narrow<int>(64U - static_cast<uint32_t>(width * 8));
        narrowed_value = static_cast<uint64_t>((static_cast<int64_t>(narrowed_value << shift)) >> shift);
    }

    // Use mov-imm to materialize the resolved constant in the destination register of
    // the load, and neutralize the preceding LDDW pair.
    const uint8_t mov_opcode = width == 8 || mode == INST_MODE_MEMSX
                                   ? static_cast<uint8_t>(INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_IMM)
                                   : static_cast<uint8_t>(INST_CLS_ALU | INST_ALU_OP_MOV | INST_SRC_IMM);
    load_inst.opcode = mov_opcode;
    load_inst.src = 0;
    load_inst.offset = 0;
    load_inst.imm = gsl::narrow<int32_t>(narrowed_value);

    lo_inst.get() = make_mov_reg_nop(lo_inst.get().dst);
    hi_inst.get() = make_mov_reg_nop(hi_inst.get().dst);
    return true;
}

bool rewrite_extern_address_load_to_zero(std::vector<EbpfInst>& instructions, const size_t location) {
    if (location + 1 >= instructions.size()) {
        return false;
    }
    if (instructions[location].opcode != INST_OP_LDDW_IMM) {
        return false;
    }

    auto [lo_inst, hi_inst] = validate_and_get_lddw_pair(instructions, location, "external symbol");
    lo_inst.get().imm = 0;
    hi_inst.get().imm = 0;
    return true;
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

constexpr unsigned R_BPF_NONE_TYPE = 0;
constexpr unsigned R_BPF_64_64_TYPE = 1;
constexpr unsigned R_BPF_64_32_TYPE = 10;

bool is_supported_bpf_relocation_type(const unsigned type) {
    return type == R_BPF_NONE_TYPE || type == R_BPF_64_64_TYPE || type == R_BPF_64_32_TYPE;
}

symbol_details_t get_symbol_details(const ELFIO::const_symbol_section_accessor& symbols, const ELFIO::Elf_Xword index) {
    symbol_details_t details;
    if (!symbols.get_symbol(index, details.name, details.value, details.size, details.bind, details.type,
                            details.section_index, details.other)) {
        throw MalformedElf("Invalid symbol index in ELF symbol table: " + std::to_string(index));
    }
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

std::optional<std::string> find_function_symbol_at_offset(const ELFIO::const_symbol_section_accessor& symbols,
                                                          const ELFIO::Elf_Half section_index,
                                                          const ELFIO::Elf_Xword offset) {
    const ELFIO::Elf_Xword symbol_count = symbols.get_symbols_num();
    for (ELFIO::Elf_Xword index = 0; index < symbol_count; index++) {
        const auto symbol = get_symbol_details(symbols, index);
        if (symbol.section_index != section_index || symbol.type != ELFIO::STT_FUNC || symbol.name.empty()) {
            continue;
        }
        if (symbol.value == offset) {
            return symbol.name;
        }
    }
    return std::nullopt;
}

ELFIO::Elf_Xword compute_reachable_program_span(const std::vector<EbpfInst>& section_instructions,
                                                const ELFIO::Elf_Xword program_offset,
                                                const ELFIO::Elf_Xword initial_size) {
    if (section_instructions.empty()) {
        return initial_size;
    }

    const size_t total = section_instructions.size();
    const size_t start = program_offset / sizeof(EbpfInst);
    size_t initial_end = (program_offset + initial_size) / sizeof(EbpfInst);
    if (start >= total || initial_end <= start) {
        return initial_size;
    }
    initial_end = std::min(initial_end, total);

    auto mark = [&](const int64_t index, std::vector<bool>& seen, std::deque<size_t>& work) {
        if (index < 0 || index >= gsl::narrow<int64_t>(total)) {
            return;
        }
        const size_t idx = gsl::narrow<size_t>(index);
        if (seen[idx]) {
            return;
        }
        seen[idx] = true;
        work.push_back(idx);
    };

    std::vector<bool> seen(total, false);
    std::deque<size_t> work;
    mark(gsl::narrow<int64_t>(start), seen, work);

    size_t max_reachable = initial_end - 1;
    while (!work.empty()) {
        const size_t pc = work.front();
        work.pop_front();
        max_reachable = std::max(max_reachable, pc);

        const EbpfInst& inst = section_instructions[pc];
        const bool is_lddw = inst.opcode == INST_OP_LDDW_IMM;
        const size_t fallthrough = pc + (is_lddw ? 2 : 1);

        // LDDW is a two-slot instruction, so keep the high slot in range.
        if (is_lddw && pc + 1 < total) {
            mark(gsl::narrow<int64_t>(pc + 1), seen, work);
            max_reachable = std::max(max_reachable, pc + 1);
        }

        const uint8_t cls = inst.opcode & INST_CLS_MASK;
        if (cls == INST_CLS_JMP || cls == INST_CLS_JMP32) {
            const uint8_t op = (inst.opcode >> 4) & 0xF;
            if (op == INST_EXIT) {
                continue;
            }
            if (op == INST_CALL) {
                if (inst.opcode == INST_OP_CALL && inst.src == INST_CALL_LOCAL) {
                    const int64_t target = gsl::narrow<int64_t>(pc) + 1 + inst.imm;
                    mark(target, seen, work);
                }
                mark(gsl::narrow<int64_t>(fallthrough), seen, work);
                continue;
            }

            const int64_t target = gsl::narrow<int64_t>(pc) + 1 + inst.offset;
            mark(target, seen, work);
            if (op != INST_JA) {
                mark(gsl::narrow<int64_t>(fallthrough), seen, work);
            }
            continue;
        }

        mark(gsl::narrow<int64_t>(fallthrough), seen, work);
    }

    const size_t span_end = std::max(initial_end, max_reachable + 1);
    return gsl::narrow<ELFIO::Elf_Xword>((span_end - start) * sizeof(EbpfInst));
}

std::string bad_reloc_value(const size_t reloc_value) {
    return "Bad reloc value (" + std::to_string(reloc_value) + "). " + "Make sure to compile with -O2.";
}

struct FunctionRelocation {
    size_t prog_index{};
    ELFIO::Elf_Xword source_offset{};
    std::optional<ELFIO::Elf_Xword> relocation_entry_index;
    ELFIO::Elf_Half target_section_index{};
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
        throw MalformedElf("No symbol section found in ELF file " + path);
    }
    const auto expected_entry_size =
        reader.get_class() == ELFIO::ELFCLASS32 ? sizeof(ELFIO::Elf32_Sym) : sizeof(ELFIO::Elf64_Sym);
    if (symbol_section->get_entry_size() != expected_entry_size || symbol_section->get_entry_size() == 0 ||
        symbol_section->get_data() == nullptr || symbol_section->get_size() % symbol_section->get_entry_size() != 0) {
        throw MalformedElf("Invalid symbol section in ELF file " + path);
    }

    const auto linked_strtab_index = symbol_section->get_link();
    if (linked_strtab_index >= reader.sections.size() || reader.sections[linked_strtab_index] == nullptr ||
        reader.sections[linked_strtab_index]->get_data() == nullptr) {
        throw MalformedElf("Invalid symbol string table link in ELF file " + path);
    }
    return ELFIO::const_symbol_section_accessor{reader, symbol_section};
}

ELFIO::elfio load_elf(std::istream& input_stream, const std::string& path) {
    ELFIO::elfio reader;
    if (!reader.load(input_stream)) {
        throw MalformedElf("Can't process ELF file " + path);
    }

    // Accept EM_NONE for compatibility with older toolchains that emit eBPF
    // objects without setting e_machine, but reject all non-BPF architectures.
    if (reader.get_machine() != ELFIO::EM_BPF && reader.get_machine() != ELFIO::EM_NONE) {
        throw MalformedElf("Unsupported ELF machine in file " + path + ": expected EM_BPF");
    }

    std::error_code ec;
    const std::uintmax_t file_size = std::filesystem::file_size(path, ec);
    if (!ec) {
        for (const auto& section : reader.sections) {
            if (!section || section->get_type() == ELFIO::SHT_NOBITS) {
                continue;
            }

            const std::uintmax_t offset = section->get_offset();
            const std::uintmax_t size = section->get_size();
            if (offset > file_size || size > file_size - offset) {
                throw MalformedElf("ELF section '" + section->get_name() + "' has out-of-bounds file range");
            }
        }
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

        std::vector<symbol_details_t> map_symbols;
        for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); ++index) {
            const auto symbol_details = get_symbol_details(symbols, index);
            if (symbol_details.section_index == i && !symbol_details.name.empty()) {
                map_symbols.push_back(symbol_details);
            }
        }

        // Track this as a map section even if empty
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

        // Validate section structure
        // Legacy map records must contain at least the required base fields
        // (type/key_size/value_size/max_entries) and keep 32-bit field alignment.
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

        // Platform-specific parsing of map definitions
        parse_params.platform->parse_maps_section(global.map_descriptors, s->get_data(), map_record_size,
                                                  gsl::narrow<int>(map_count), parse_params.platform,
                                                  parse_params.options);
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
/// 1. **BTF maps** (priority): If both .BTF and .maps are present, parse map definitions from BTF
///    - Modern format where map metadata is anchored in BTF DATASEC records
/// 2. **Legacy maps**: If any "maps" section exists, use struct bpf_elf_map parsing
/// 3. **BTF-only**: If no legacy maps but .BTF exists, parse map definitions from BTF
///    - Modern format where maps are defined as BTF VAR types in a DATASEC
/// 4. **No maps**: If neither exists, create implicit maps for global variable sections only
///
/// @param params Parsing parameters including path, options, and platform
/// @param reader The loaded ELF file reader
/// @param symbols Symbol table accessor for the ELF file
/// @return Global data structure containing all extracted metadata
ElfGlobalData extract_global_data(const parse_params_t& params, const ELFIO::elfio& reader,
                                  const ELFIO::const_symbol_section_accessor& symbols) {
    const bool has_btf_maps = reader.sections[".BTF"] != nullptr && reader.sections[".maps"] != nullptr;
    if (has_btf_maps) {
        return parse_btf_section(params, reader);
    }

    const bool has_legacy_maps =
        std::ranges::any_of(reader.sections, [](const auto& s) { return is_map_section(s->get_name()); });
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

// This type is used only for offsetof() lookups of core_relo fields in
// extended BTF.ext headers; it is never instantiated.
struct btf_ext_header_core_t {
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t hdr_len;
    uint32_t func_info_off;
    uint32_t func_info_len;
    uint32_t line_info_off;
    uint32_t line_info_len;
    uint32_t core_relo_off;
    uint32_t core_relo_len;
};

static_assert(sizeof(btf_ext_header_core_t) == 32);

// TODO(issue #943): These BTF/BTF.ext parsing helpers are generic and should
// move into libbtf once a shared CO-RE relocation parser API is available.
struct btf_string_table_view_t {
    const char* base;
    size_t size;
};

struct core_field_resolution_t {
    uint32_t type_id;
    uint64_t offset_bits;
    std::optional<uint32_t> member_offset_encoding;
};

template <typename T>
    requires std::is_trivially_copyable_v<T>
T read_struct_at(const char* data, size_t data_size, size_t offset, const std::string& context) {
    if (offset > data_size || data_size - offset < sizeof(T)) {
        throw UnmarshalError(context + " out of bounds");
    }
    T value;
    std::memcpy(&value, data + offset, sizeof(T));
    return value;
}

size_t checked_add(size_t start, size_t length, size_t limit, const std::string& context) {
    if (start > limit || length > limit - start) {
        throw UnmarshalError(context + " out of bounds");
    }
    return start + length;
}

btf_string_table_view_t parse_btf_string_table(const ELFIO::section& btf_section) {
    if (!btf_section.get_data()) {
        throw UnmarshalError(".BTF section has no data");
    }
    const char* btf_data = btf_section.get_data();
    const size_t btf_size = btf_section.get_size();
    const auto hdr = read_struct_at<btf_header_t>(btf_data, btf_size, 0, "BTF header");
    if (hdr.magic != BTF_HEADER_MAGIC || hdr.version != BTF_HEADER_VERSION) {
        throw UnmarshalError("Invalid .BTF header");
    }
    if (hdr.hdr_len < sizeof(btf_header_t) || hdr.hdr_len > btf_size) {
        throw UnmarshalError("Invalid .BTF header length");
    }

    const size_t str_start = checked_add(hdr.hdr_len, hdr.str_off, btf_size, "BTF string table");
    const size_t str_end = checked_add(str_start, hdr.str_len, btf_size, "BTF string table");
    return {btf_data + str_start, str_end - str_start};
}

std::string_view btf_string_at(const btf_string_table_view_t& strings, uint32_t string_offset,
                               const std::string& name) {
    if (string_offset >= strings.size) {
        throw UnmarshalError("Invalid BTF string offset for " + name);
    }
    const char* str = strings.base + string_offset;
    const size_t max_len = strings.size - string_offset;
    const void* nul = std::memchr(str, '\0', max_len);
    if (!nul) {
        throw UnmarshalError("Unterminated BTF string for " + name);
    }
    return {str, static_cast<size_t>(static_cast<const char*>(nul) - str)};
}

uint32_t strip_type_modifiers(const libbtf::btf_type_data& btf_data, uint32_t type_id) {
    int depth = 0;
    while (true) {
        if (++depth > 255) {
            throw UnmarshalError("CO-RE type resolution exceeded depth limit (possible corrupt BTF)");
        }

        switch (btf_data.get_kind_index(type_id)) {
        case libbtf::BTF_KIND_TYPEDEF: type_id = btf_data.get_kind_type<libbtf::btf_kind_typedef>(type_id).type; break;
        case libbtf::BTF_KIND_CONST: type_id = btf_data.get_kind_type<libbtf::btf_kind_const>(type_id).type; break;
        case libbtf::BTF_KIND_VOLATILE:
            type_id = btf_data.get_kind_type<libbtf::btf_kind_volatile>(type_id).type;
            break;
        case libbtf::BTF_KIND_RESTRICT:
            type_id = btf_data.get_kind_type<libbtf::btf_kind_restrict>(type_id).type;
            break;
        case libbtf::BTF_KIND_TYPE_TAG:
            type_id = btf_data.get_kind_type<libbtf::btf_kind_type_tag>(type_id).type;
            break;
        default: return type_id;
        }
    }
}

std::vector<uint32_t> parse_core_access_string(std::string_view s);

core_field_resolution_t resolve_core_field(const libbtf::btf_type_data& btf_data, uint32_t type_id,
                                           std::string_view access_string) {
    auto indices = parse_core_access_string(access_string);
    // Clang/libbpf encode root type with a leading "0" accessor.
    if (!indices.empty() && indices.front() == 0) {
        indices.erase(indices.begin());
    }
    core_field_resolution_t result{type_id, 0, std::nullopt};

    for (const uint32_t index : indices) {
        result.type_id = strip_type_modifiers(btf_data, result.type_id);
        switch (btf_data.get_kind_index(result.type_id)) {
        case libbtf::BTF_KIND_STRUCT: {
            const auto s = btf_data.get_kind_type<libbtf::btf_kind_struct>(result.type_id);
            if (index >= s.members.size()) {
                throw UnmarshalError("CO-RE: struct member index " + std::to_string(index) + " out of bounds (size " +
                                     std::to_string(s.members.size()) + ") for access path " +
                                     std::string(access_string));
            }
            const auto& member = s.members[index];
            result.offset_bits += BTF_MEMBER_BIT_OFFSET(member.offset_from_start_in_bits);
            result.member_offset_encoding = member.offset_from_start_in_bits;
            result.type_id = member.type;
            break;
        }
        case libbtf::BTF_KIND_UNION: {
            const auto u = btf_data.get_kind_type<libbtf::btf_kind_union>(result.type_id);
            if (index >= u.members.size()) {
                throw UnmarshalError("CO-RE: union member index " + std::to_string(index) + " out of bounds (size " +
                                     std::to_string(u.members.size()) + ") for access path " +
                                     std::string(access_string));
            }
            const auto& member = u.members[index];
            result.offset_bits += BTF_MEMBER_BIT_OFFSET(member.offset_from_start_in_bits);
            result.member_offset_encoding = member.offset_from_start_in_bits;
            result.type_id = member.type;
            break;
        }
        case libbtf::BTF_KIND_ARRAY: {
            const auto a = btf_data.get_kind_type<libbtf::btf_kind_array>(result.type_id);
            if (index >= a.count_of_elements) {
                throw UnmarshalError("CO-RE: array index " + std::to_string(index) + " out of bounds (size " +
                                     std::to_string(a.count_of_elements) + ") for access path " +
                                     std::string(access_string));
            }
            result.offset_bits += static_cast<uint64_t>(index) * btf_data.get_size(a.element_type) * 8;
            result.member_offset_encoding.reset();
            result.type_id = a.element_type;
            break;
        }
        default: throw UnmarshalError("CO-RE: indexing into non-aggregate type");
        }
    }

    result.type_id = strip_type_modifiers(btf_data, result.type_id);
    return result;
}

uint32_t core_field_bit_width(const libbtf::btf_type_data& btf_data, const core_field_resolution_t& field) {
    if (field.member_offset_encoding && BTF_MEMBER_BITFIELD_SIZE(*field.member_offset_encoding) != 0) {
        return BTF_MEMBER_BITFIELD_SIZE(*field.member_offset_encoding);
    }

    const auto kind = btf_data.get_kind_index(field.type_id);
    if (kind == libbtf::BTF_KIND_INT) {
        const auto int_kind = btf_data.get_kind_type<libbtf::btf_kind_int>(field.type_id);
        return int_kind.field_width_in_bits != 0 ? int_kind.field_width_in_bits : int_kind.size_in_bytes * 8;
    }

    return btf_data.get_size(field.type_id) * 8;
}

bool core_field_offset_uses_offset_field(const EbpfInst& inst) {
    const uint8_t cls = inst.opcode & INST_CLS_MASK;
    if (cls != INST_CLS_LDX && cls != INST_CLS_ST && cls != INST_CLS_STX) {
        return false;
    }

    const uint8_t mode = inst.opcode & INST_MODE_MASK;
    return mode == INST_MODE_MEM || mode == INST_MODE_MEMSX || mode == INST_MODE_ATOMIC;
}

std::vector<uint32_t> parse_core_access_string(const std::string_view s) {
    std::vector<uint32_t> indices;
    std::stringstream ss(std::string{s});
    std::string item;
    while (std::getline(ss, item, ':')) {
        if (!item.empty()) {
            try {
                indices.push_back(gsl::narrow<uint32_t>(std::stoul(item)));
            } catch (const std::exception&) {
                throw UnmarshalError("Invalid CO-RE access string: " + std::string{s});
            }
        }
    }
    return indices;
}

class ProgramReader {
    struct unresolved_symbol_error_t {
        std::string section;
        std::string message;
    };

    const parse_params_t& parse_params;
    const ELFIO::elfio& reader;
    const ELFIO::const_symbol_section_accessor& symbols;
    const ElfGlobalData& global;
    std::vector<FunctionRelocation> function_relocations;
    std::vector<unresolved_symbol_error_t> unresolved_symbol_errors;
    std::set<size_t> builtin_offsets_for_current_program;

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
    /// - FIELD_*: struct/union/array access metadata (offset, size, signedness, bitfield shifts, existence)
    /// - TYPE_*: type ID/size/existence/match checks
    /// - ENUMVAL_*: enum value probing
    ///
    /// @param prog RawProgram containing the instruction to relocate
    /// @param relo CO-RE relocation descriptor (from .BTF.ext section)
    /// @param btf_data BTF type information for offset calculations
    /// @throws UnmarshalError if relocation is invalid or unsupported
    static void apply_core_relocation(RawProgram& prog, const bpf_core_relo& relo, std::string_view access_string,
                                      const libbtf::btf_type_data& btf_data);
    void process_core_relocations(const libbtf::btf_type_data& btf_data);

    int32_t compute_lddw_reloc_offset_imm(ELFIO::Elf_Sxword addend, ELFIO::Elf_Word index,
                                          std::reference_wrapper<EbpfInst> lo_inst) const;
    [[nodiscard]]
    bool has_function_relocation(size_t prog_index, size_t source_offset) const;
    void enqueue_synthetic_local_calls(const std::vector<EbpfInst>& instructions, ELFIO::Elf_Half section_index,
                                       ELFIO::Elf_Xword program_offset);

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
    /// @param symbol_type Symbol type
    /// @param instructions Instruction vector to modify
    /// @param location Instruction index to relocate
    /// @param index Symbol table index for additional lookup
    /// @param addend Additional offset to apply
    /// @return true if relocation succeeded or should be skipped, false if unresolved
    bool try_reloc(const std::string& symbol_name, ELFIO::Elf_Half symbol_section_index, unsigned char symbol_type,
                   std::vector<EbpfInst>& instructions, size_t location, ELFIO::Elf_Word index,
                   ELFIO::Elf_Sxword addend);
    void process_relocations(std::vector<EbpfInst>& instructions, const ELFIO::const_relocation_section_accessor& reloc,
                             const std::string& section_name, ELFIO::Elf_Xword program_offset, size_t program_size);
    [[nodiscard]]
    const ELFIO::section* get_relocation_section(const std::string& name) const;
    void read_programs();
};

void ProgramReader::apply_core_relocation(RawProgram& prog, const bpf_core_relo& relo, std::string_view access_string,
                                          const libbtf::btf_type_data& btf_data) {
    if (relo.insn_off < prog.insn_off) {
        throw UnmarshalError("CO-RE relocation offset before program start");
    }
    const size_t byte_offset = relo.insn_off - prog.insn_off;
    if (byte_offset % sizeof(EbpfInst) != 0) {
        throw UnmarshalError("CO-RE relocation offset is not instruction-aligned");
    }

    const size_t inst_idx = byte_offset / sizeof(EbpfInst);
    if (inst_idx >= prog.prog.size()) {
        throw UnmarshalError("CO-RE relocation offset out of bounds");
    }
    EbpfInst& inst = prog.prog[inst_idx];
    std::optional<core_field_resolution_t> resolved_field;
    const auto get_field = [&]() -> const core_field_resolution_t& {
        if (!resolved_field) {
            resolved_field = resolve_core_field(btf_data, relo.type_id, access_string);
        }
        return *resolved_field;
    };
    prog.core_relocation_count++;

    switch (relo.kind) {
    case BPF_CORE_FIELD_BYTE_OFFSET: {
        const auto core_field_byte_offset = gsl::narrow<int64_t>(get_field().offset_bits / 8);
        // CO-RE FIELD_BYTE_OFFSET targets instruction-dependent storage:
        // memory ops use 16-bit inst.offset, while ALU/other forms use inst.imm.
        if (core_field_offset_uses_offset_field(inst)) {
            if (core_field_byte_offset < std::numeric_limits<int16_t>::min() ||
                core_field_byte_offset > std::numeric_limits<int16_t>::max()) {
                throw UnmarshalError("CO-RE field offset does not fit instruction offset field");
            }
            inst.offset = gsl::narrow<int16_t>(core_field_byte_offset);
        } else {
            inst.imm = gsl::narrow<int32_t>(core_field_byte_offset);
        }
        break;
    }
    case BPF_CORE_FIELD_BYTE_SIZE: inst.imm = gsl::narrow<int32_t>(btf_data.get_size(get_field().type_id)); break;
    case BPF_CORE_FIELD_EXISTS: inst.imm = 1; break;
    case BPF_CORE_FIELD_SIGNED: {
        switch (btf_data.get_kind_index(get_field().type_id)) {
        case libbtf::BTF_KIND_INT:
            inst.imm = btf_data.get_kind_type<libbtf::btf_kind_int>(get_field().type_id).is_signed;
            break;
        case libbtf::BTF_KIND_ENUM:
            inst.imm = btf_data.get_kind_type<libbtf::btf_kind_enum>(get_field().type_id).is_signed;
            break;
        case libbtf::BTF_KIND_ENUM64:
            inst.imm = btf_data.get_kind_type<libbtf::btf_kind_enum64>(get_field().type_id).is_signed;
            break;
        default: inst.imm = 0; break;
        }
        break;
    }
    case BPF_CORE_FIELD_LSHIFT_U64: {
        const auto& field = get_field();
        const auto field_bit_width = core_field_bit_width(btf_data, field);
        const uint32_t bit_offset_in_byte = static_cast<uint32_t>(field.offset_bits % 8);
        if (field_bit_width == 0 || field_bit_width > 64 || bit_offset_in_byte + field_bit_width > 64) {
            throw UnmarshalError("CO-RE field bit width exceeds 64 bits");
        }
        inst.imm = gsl::narrow<int32_t>(64 - (bit_offset_in_byte + field_bit_width));
        break;
    }
    case BPF_CORE_FIELD_RSHIFT_U64: {
        const auto field_bit_width = core_field_bit_width(btf_data, get_field());
        if (field_bit_width == 0 || field_bit_width > 64) {
            throw UnmarshalError("CO-RE field bit width exceeds 64 bits");
        }
        inst.imm = gsl::narrow<int32_t>(64 - field_bit_width);
        break;
    }
    case BPF_CORE_TYPE_ID_LOCAL:
    case BPF_CORE_TYPE_ID_TARGET: inst.imm = gsl::narrow<int32_t>(strip_type_modifiers(btf_data, relo.type_id)); break;
    // Prevail is a static verifier without target-kernel BTF, so existence/match predicates
    // are resolved against local BTF only and therefore fold to true.
    case BPF_CORE_TYPE_EXISTS:
    case BPF_CORE_TYPE_MATCHES: inst.imm = 1; break;
    case BPF_CORE_TYPE_SIZE:
        inst.imm = gsl::narrow<int32_t>(btf_data.get_size(strip_type_modifiers(btf_data, relo.type_id)));
        break;
    case BPF_CORE_ENUMVAL_EXISTS:
    case BPF_CORE_ENUMVAL_VALUE: {
        const auto indices = parse_core_access_string(access_string);
        if (indices.empty()) {
            throw UnmarshalError("CO-RE enum relocation missing enum value index");
        }
        const auto enum_member_index = indices.back();
        const auto enum_type_id = strip_type_modifiers(btf_data, relo.type_id);

        switch (btf_data.get_kind_index(enum_type_id)) {
        case libbtf::BTF_KIND_ENUM: {
            const auto e = btf_data.get_kind_type<libbtf::btf_kind_enum>(enum_type_id);
            if (enum_member_index >= e.members.size()) {
                throw UnmarshalError("CO-RE enum member index out of bounds");
            }
            inst.imm =
                relo.kind == BPF_CORE_ENUMVAL_EXISTS ? 1 : gsl::narrow<int32_t>(e.members[enum_member_index].value);
            break;
        }
        case libbtf::BTF_KIND_ENUM64: {
            const auto e = btf_data.get_kind_type<libbtf::btf_kind_enum64>(enum_type_id);
            if (enum_member_index >= e.members.size()) {
                throw UnmarshalError("CO-RE enum64 member index out of bounds");
            }
            // eBPF instruction immediates are 32-bit, so enum64 values must be narrowed (checked via gsl::narrow).
            inst.imm =
                relo.kind == BPF_CORE_ENUMVAL_EXISTS ? 1 : gsl::narrow<int32_t>(e.members[enum_member_index].value);
            break;
        }
        default: throw UnmarshalError("CO-RE enum relocation target is not enum/enum64");
        }
        break;
    }
    default: throw UnmarshalError("Unsupported CO-RE relocation kind: " + std::to_string(relo.kind));
    }
}

void ProgramReader::process_core_relocations(const libbtf::btf_type_data& btf_data) {
    const ELFIO::section* btf_ext_sec = reader.sections[".BTF.ext"];
    if (!btf_ext_sec || !btf_ext_sec->get_data()) {
        return;
    }
    const ELFIO::section* btf_sec = reader.sections[".BTF"];
    if (!btf_sec || !btf_sec->get_data()) {
        return;
    }

    const char* btf_ext_data = btf_ext_sec->get_data();
    const size_t btf_ext_size = btf_ext_sec->get_size();
    const auto btf_ext_header = read_struct_at<btf_ext_header_t>(btf_ext_data, btf_ext_size, 0, "BTF.ext header");
    if (btf_ext_header.magic != BTF_HEADER_MAGIC || btf_ext_header.version != BTF_HEADER_VERSION) {
        throw UnmarshalError("Invalid .BTF.ext header");
    }
    if (btf_ext_header.hdr_len < sizeof(btf_ext_header_t) || btf_ext_header.hdr_len > btf_ext_size) {
        throw UnmarshalError("Invalid .BTF.ext header length");
    }

    // Older BTF.ext headers might not include core_relo fields.
    if (btf_ext_header.hdr_len < offsetof(btf_ext_header_core_t, core_relo_len) + sizeof(uint32_t)) {
        return;
    }
    const auto core_relo_off = read_struct_at<uint32_t>(
        btf_ext_data, btf_ext_size, offsetof(btf_ext_header_core_t, core_relo_off), "BTF.ext core_relo_off");
    const auto core_relo_len = read_struct_at<uint32_t>(
        btf_ext_data, btf_ext_size, offsetof(btf_ext_header_core_t, core_relo_len), "BTF.ext core_relo_len");

    const size_t core_relo_start =
        checked_add(btf_ext_header.hdr_len, core_relo_off, btf_ext_size, "BTF.ext core_relo subsection");
    const size_t core_relo_end =
        checked_add(core_relo_start, core_relo_len, btf_ext_size, "BTF.ext core_relo subsection");
    if (core_relo_start == core_relo_end) {
        return;
    }

    size_t offset = core_relo_start;
    if (core_relo_end - offset < sizeof(uint32_t)) {
        throw UnmarshalError("BTF.ext core_relo subsection truncated");
    }
    const auto core_relo_rec_size =
        read_struct_at<uint32_t>(btf_ext_data, btf_ext_size, offset, "BTF.ext core_relo record size");
    offset += sizeof(uint32_t);
    if (core_relo_rec_size < sizeof(bpf_core_relo)) {
        throw UnmarshalError("Invalid CO-RE relocation record size");
    }

    const auto strings = parse_btf_string_table(*btf_sec);
    std::map<std::string, std::vector<RawProgram*>> programs_by_section;
    for (auto& prog : raw_programs) {
        programs_by_section[prog.section_name].push_back(&prog);
    }

    for (; offset < core_relo_end;) {
        const auto section =
            read_struct_at<btf_ext_info_sec_t>(btf_ext_data, btf_ext_size, offset, "CO-RE section info");
        offset += sizeof(btf_ext_info_sec_t);
        if (offset > core_relo_end) {
            throw UnmarshalError("CO-RE section records out of bounds");
        }

        if (section.num_info != 0 && core_relo_rec_size > (core_relo_end - offset) / section.num_info) {
            throw UnmarshalError("CO-RE section records out of bounds");
        }
        const size_t records_size = static_cast<size_t>(section.num_info) * core_relo_rec_size;
        const size_t records_end = offset + records_size;
        const std::string section_name{btf_string_at(strings, section.sec_name_off, "CO-RE section name")};

        const auto prog_it = programs_by_section.find(section_name);
        if (prog_it == programs_by_section.end()) {
            offset = records_end;
            continue;
        }

        for (size_t i = 0; i < section.num_info; ++i) {
            const size_t record_offset = offset + i * core_relo_rec_size;
            const auto reloc =
                read_struct_at<bpf_core_relo>(btf_ext_data, btf_ext_size, record_offset, "CO-RE relocation");
            const auto access_string = btf_string_at(strings, reloc.access_str_off, "CO-RE access string");

            bool applied = false;
            for (RawProgram* prog : prog_it->second) {
                const size_t prog_size = prog->prog.size() * sizeof(EbpfInst);
                if (reloc.insn_off >= prog->insn_off && reloc.insn_off < prog->insn_off + prog_size) {
                    apply_core_relocation(*prog, reloc, access_string, btf_data);
                    applied = true;
                    break;
                }
            }

            if (!applied) {
                throw UnmarshalError("Failed to find program for CO-RE relocation at instruction offset " +
                                     std::to_string(reloc.insn_off) + " in section " + section_name);
            }
        }

        offset = records_end;
    }
}

bool ProgramReader::has_function_relocation(const size_t prog_index, const size_t source_offset) const {
    return std::ranges::any_of(function_relocations, [&](const auto& reloc) {
        return reloc.prog_index == prog_index && reloc.source_offset == source_offset;
    });
}

void ProgramReader::enqueue_synthetic_local_calls(const std::vector<EbpfInst>& instructions,
                                                  const ELFIO::Elf_Half section_index,
                                                  const ELFIO::Elf_Xword program_offset) {
    if (section_index >= reader.sections.size()) {
        throw UnmarshalError("Invalid section index");
    }
    const auto* section = reader.sections[section_index];
    if (!section) {
        throw UnmarshalError("Invalid section index");
    }

    const int64_t section_insn_count = gsl::narrow<int64_t>(section->get_size() / sizeof(EbpfInst));
    const int64_t program_start = gsl::narrow<int64_t>(program_offset / sizeof(EbpfInst));
    const int64_t program_end = program_start + gsl::narrow<int64_t>(instructions.size());

    for (size_t loc = 0; loc < instructions.size(); ++loc) {
        const EbpfInst& inst = instructions[loc];
        if (!(inst.opcode == INST_OP_CALL && inst.src == INST_CALL_LOCAL)) {
            continue;
        }
        if (has_function_relocation(raw_programs.size(), loc)) {
            continue;
        }

        const int64_t target = program_start + gsl::narrow<int64_t>(loc) + 1 + inst.imm;
        if (target >= program_start && target < program_end) {
            continue;
        }
        if (target < 0 || target >= section_insn_count) {
            throw UnmarshalError("Local call target out of section bounds");
        }

        const auto target_offset = gsl::narrow<ELFIO::Elf_Xword>(target * sizeof(EbpfInst));
        const auto target_name = find_function_symbol_at_offset(symbols, section_index, target_offset);
        if (!target_name) {
            throw UnmarshalError("Subprogram not found at section offset " + std::to_string(target_offset));
        }

        function_relocations.emplace_back(FunctionRelocation{
            .prog_index = raw_programs.size(),
            .source_offset = loc,
            .relocation_entry_index = std::nullopt,
            .target_section_index = section_index,
            .target_function_name = *target_name,
        });
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
/// @param prog RawProgram to process
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
        const auto& target_function_name = reloc.target_function_name;
        if (!subprogram_offsets.contains(target_function_name)) {
            subprogram_offsets[target_function_name] = prog.prog.size();
            if (reloc.target_section_index >= reader.sections.size()) {
                throw UnmarshalError("Invalid section index");
            }
            const auto& sub_sec = *reader.sections[reloc.target_section_index];
            if (const auto sub = find_subprogram(raw_programs, sub_sec, target_function_name)) {
                if (sub == &prog) {
                    throw UnmarshalError("Recursive subprogram call");
                }
                const std::string err = append_subprograms(*sub);
                if (!err.empty()) {
                    return err;
                }
                const size_t base = subprogram_offsets[target_function_name];

                // Append subprogram to program
                prog.prog.insert(prog.prog.end(), sub->prog.begin(), sub->prog.end());
                if (parse_params.options.verbosity_opts.print_line_info) {
                    for (const auto& [k, info] : sub->info.line_info) {
                        prog.info.line_info[base + k] = info;
                    }
                }
                for (const size_t builtin_offset : sub->info.builtin_call_offsets) {
                    prog.info.builtin_call_offsets.insert(base + builtin_offset);
                }
            } else {
                return "Subprogram not found: " + target_function_name;
            }
        }
        // BPF uses signed 32-bit immediates: offset = target - (source + 1)
        const auto target_offset = gsl::narrow<int64_t>(subprogram_offsets[target_function_name]);
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

/// Compute the 32-bit offset to store in the *high* LDDW imm for a global-variable relocation.
///
/// The encoding rules differ depending on the relocation kind:
/// - For relocations against a _section_ symbol (sym.type == STT_SECTION):
///   * In RELA ELFs, the relocation addend holds the section-relative offset.
///   * In REL ELFs, the addend is zero and the compiler encodes the offset in the
///     low LDDW instruction's imm field (`lo_inst_imm`).
///   In both cases, we interpret:
///       offset = (addend != 0) ? addend : lo_inst_imm
///
/// - For relocations against a _data_ symbol (e.g., `global_var4`):
///   The symbol value is already section-relative, so the offset is:
///       offset = sym.value + addend
///
/// The result is narrowed to int32_t, matching the 32-bit imm field of a BPF instruction.
///
/// This function is only used for global-variable LDDW relocations.
int32_t ProgramReader::compute_lddw_reloc_offset_imm(const ELFIO::Elf_Sxword addend, const ELFIO::Elf_Word index,
                                                     const std::reference_wrapper<EbpfInst> lo_inst) const {
    const auto& sym = get_symbol_details(symbols, index);
    if (sym.type == ELFIO::STT_SECTION) {
        return addend != 0 ? gsl::narrow<int32_t>(addend) : lo_inst.get().imm;
    }
    return gsl::narrow<int32_t>(sym.value + addend);
}

bool ProgramReader::try_reloc(const std::string& symbol_name, const ELFIO::Elf_Half symbol_section_index,
                              const unsigned char symbol_type, std::vector<EbpfInst>& instructions,
                              const size_t location, const ELFIO::Elf_Word index, const ELFIO::Elf_Sxword addend) {
    EbpfInst& instruction_to_relocate = instructions[location];

    if (symbol_section_index == ELFIO::SHN_UNDEF) {
        if (const auto value = resolve_known_linux_extern_symbol(symbol_name)) {
            if (rewrite_extern_constant_load(instructions, location, *value)) {
                return true;
            }
        }
        if (rewrite_extern_address_load_to_zero(instructions, location)) {
            return true;
        }
    }

    // Handle local function calls - queue for post-processing.
    // Builtins such as memset/memcpy may arrive as local calls against SHN_UNDEF symbols;
    // those are rewritten to static helper calls and gated via builtin_call_offsets.
    if (instruction_to_relocate.opcode == INST_OP_CALL && instruction_to_relocate.src == INST_CALL_LOCAL) {
        if (symbol_section_index == ELFIO::SHN_UNDEF && parse_params.platform->resolve_builtin_call) {
            if (const auto builtin_id = parse_params.platform->resolve_builtin_call(symbol_name)) {
                instruction_to_relocate.src = INST_CALL_STATIC_HELPER;
                instruction_to_relocate.imm = *builtin_id;
                if (*builtin_id < 0) {
                    builtin_offsets_for_current_program.insert(location);
                }
                return true;
            }
        }
        if (symbol_section_index == ELFIO::SHN_UNDEF) {
            return false;
        }

        std::string target_function_name = symbol_name;
        if (target_function_name.empty() && symbol_type == ELFIO::STT_SECTION) {
            const int64_t target_byte_offset =
                addend != 0 ? addend : (gsl::narrow<int64_t>(instruction_to_relocate.imm) + 1) * sizeof(EbpfInst);
            if (target_byte_offset < 0 || target_byte_offset % sizeof(EbpfInst) != 0) {
                throw UnmarshalError("Invalid section-local call target offset");
            }
            if (const auto target = find_function_symbol_at_offset(symbols, symbol_section_index,
                                                                   gsl::narrow<ELFIO::Elf_Xword>(target_byte_offset))) {
                target_function_name = *target;
            }
        }

        if (!target_function_name.empty() && !has_function_relocation(raw_programs.size(), location)) {
            function_relocations.emplace_back(FunctionRelocation{
                .prog_index = raw_programs.size(),
                .source_offset = location,
                .relocation_entry_index = index,
                .target_section_index = symbol_section_index,
                .target_function_name = target_function_name,
            });
            return true;
        }
        return false;
    }

    // Handle empty symbol names for global variable sections
    // These occur in legacy ELF files where relocations reference
    // section symbols rather than named variable symbols
    if (symbol_name.empty()) {
        if (global.variable_section_indices.contains(symbol_section_index)) {
            if (!std::holds_alternative<MapOffsets>(global.map_record_size_or_map_offsets)) {
                return false; // Legacy path without MapOffsets; let caller handle
            }

            auto [lo_inst, hi_inst] = validate_and_get_lddw_pair(instructions, location, "global variable");

            hi_inst.get().imm = compute_lddw_reloc_offset_imm(addend, index, lo_inst);
            lo_inst.get().src = INST_LD_MODE_MAP_VALUE;

            const std::string section_name = reader.sections[symbol_section_index]->get_name();
            lo_inst.get().imm = relocate_global_variable(section_name);
            return true;
        }
        // Empty symbol name in non-variable section - skip it
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

        hi_inst.get().imm = compute_lddw_reloc_offset_imm(addend, index, lo_inst);
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
        if (!reloc.get_entry(i, o, idx, type, addend)) {
            throw MalformedElf("Malformed relocation entry in section " + section_name + " at index " +
                               std::to_string(i));
        }
        if (!is_supported_bpf_relocation_type(type)) {
            throw MalformedElf("Unsupported relocation type " + std::to_string(type) + " in section " + section_name);
        }
        // Compatibility: some producer pipelines encode map relocations as
        // R_BPF_NONE with a non-zero symbol index in executable sections.
        // Keep STN_UNDEF (idx==0) as an explicit no-op relocation.
        if (type == R_BPF_NONE_TYPE && idx == 0) {
            continue;
        }
        if (idx >= symbols.get_symbols_num()) {
            throw MalformedElf("Invalid relocation symbol index " + std::to_string(idx) + " in section " +
                               section_name);
        }
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

        if (!try_reloc(sym.name, sym.section_index, sym.type, instructions, loc, idx, addend)) {
            unresolved_symbol_errors.push_back(unresolved_symbol_error_t{
                .section = section_name,
                .message = "Unresolved external symbol " + (sym.name.empty() ? "<anonymous>" : sym.name) +
                           " in section " + section_name + " at location " + std::to_string(loc),
            });
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
        auto section_instructions = vector_of<EbpfInst>(*sec);
        const auto& sec_name = sec->get_name();
        const auto prog_type = parse_params.platform->get_program_type(sec_name, parse_params.path);
        for (ELFIO::Elf_Xword offset = 0; offset < sec->get_size();) {
            builtin_offsets_for_current_program.clear();
            auto [name, symbol_size] = get_program_name_and_size(*sec, offset, symbols);
            const auto extracted_size = compute_reachable_program_span(section_instructions, offset, symbol_size);
            auto instructions = vector_of<EbpfInst>(sec->get_data() + offset, extracted_size);
            if (const auto reloc_sec = get_relocation_section(sec_name)) {
                process_relocations(instructions, ELFIO::const_relocation_section_accessor{reader, reloc_sec}, sec_name,
                                    offset, extracted_size);
            }
            enqueue_synthetic_local_calls(instructions, sec->get_index(), offset);
            ProgramInfo program_info{
                .platform = parse_params.platform,
                .map_descriptors = global.map_descriptors,
                .type = prog_type,
                .builtin_call_offsets = std::move(builtin_offsets_for_current_program),
            };
            raw_programs.emplace_back(RawProgram{
                parse_params.path,
                sec_name,
                gsl::narrow<uint32_t>(offset),
                name,
                std::move(instructions),
                std::move(program_info),
            });
            offset += symbol_size;
        }
    }

    if (const auto btf_sec = reader.sections[".BTF"]) {
        try {
            process_core_relocations({vector_of<std::byte>(*btf_sec)});
        } catch (const std::exception& e) {
            throw UnmarshalError(std::string("Unsupported or invalid CO-RE/BTF relocation data: ") + e.what());
        }
    }

    bool has_relevant_unresolved_symbols = false;
    for (const auto& err : unresolved_symbol_errors) {
        if (!parse_params.desired_section.empty() && err.section != parse_params.desired_section) {
            continue;
        }
        has_relevant_unresolved_symbols = true;
        std::cerr << err.message << std::endl;
    }
    if (has_relevant_unresolved_symbols) {
        throw UnmarshalError("Unresolved symbols found.");
    }

    if (parse_params.options.verbosity_opts.print_line_info) {
        if (const auto btf_sec = reader.sections[".BTF"]) {
            if (const auto btf_ext = reader.sections[".BTF.ext"]) {
                try {
                    update_line_info(raw_programs, btf_sec, btf_ext);
                } catch (const std::exception& e) {
                    throw UnmarshalError(std::string("Unsupported or invalid BTF line info: ") + e.what());
                }
            }
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
                                 const std::string& desired_section, const std::string& desired_program,
                                 const ebpf_verifier_options_t& options, const ebpf_platform_t* platform) {
    try {
        std::vector<RawProgram> res;
        parse_params_t params{path, options, platform, desired_section};
        auto reader = load_elf(input_stream, path);
        auto symbols = read_and_validate_symbol_section(reader, path);
        auto global = extract_global_data(params, reader, symbols);
        ProgramReader program_reader{params, reader, symbols, global};
        program_reader.read_programs();

        // Return the desired_program, or raw_programs
        if (desired_program.empty()) {
            return std::move(program_reader.raw_programs);
        }
        for (RawProgram& cur : program_reader.raw_programs) {
            if (cur.function_name == desired_program) {
                res.emplace_back(std::move(cur));
                return res;
            }
        }
        return std::move(program_reader.raw_programs);
    } catch (const UnmarshalError&) {
        throw;
    } catch (const std::exception& e) {
        throw UnmarshalError(std::string("Unsupported or invalid ELF/BTF data: ") + e.what());
    }
}

std::vector<RawProgram> read_elf(const std::string& path, const std::string& desired_section,
                                 const std::string& desired_program, const ebpf_verifier_options_t& options,
                                 const ebpf_platform_t* platform) {
    if (std::ifstream stream{path, std::ios::in | std::ios::binary}) {
        return read_elf(stream, path, desired_section, desired_program, options, platform);
    }
    struct stat st; // NOLINT(*-pro-type-member-init)
    if (stat(path.c_str(), &st)) {
        throw UnmarshalError(std::string(strerror(errno)) + " opening " + path);
    }
    throw UnmarshalError("Can't process ELF file " + path);
}

size_t ElfObject::QueryKeyHash::operator()(const QueryKey& key) const noexcept {
    size_t seed = std::hash<std::string>{}(key.section);
    seed ^= std::hash<std::string>{}(key.program) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
    return seed;
}

ElfObject::ElfObject(std::string path, ebpf_verifier_options_t options, const ebpf_platform_t* platform)
    : path_(std::move(path)), options_(std::move(options)), platform_(platform) {}

const std::string& ElfObject::path() const noexcept { return path_; }

void ElfObject::discover_programs() {
    if (catalog_loaded_) {
        return;
    }

    if (std::ifstream stream{path_, std::ios::in | std::ios::binary}) {
        auto reader = load_elf(stream, path_);
        auto symbols = read_and_validate_symbol_section(reader, path_);

        for (const auto& section : reader.sections) {
            if (!(section->get_flags() & ELFIO::SHF_EXECINSTR) || !section->get_size() || !section->get_data()) {
                continue;
            }

            const std::string section_name = section->get_name();
            if (!section_cache_.contains(section_name)) {
                section_order_.push_back(section_name);
                section_cache_.emplace(section_name, SectionCacheEntry{});
            }

            for (ELFIO::Elf_Xword offset = 0; offset < section->get_size();) {
                auto [function_name, size] = get_program_name_and_size(*section, offset, symbols);
                programs_.push_back(ElfProgramInfo{
                    .section_name = section_name,
                    .function_name = function_name,
                    .section_offset = gsl::narrow<uint32_t>(offset),
                });
                section_program_indices_[section_name].push_back(programs_.size() - 1);
                offset += size;
            }
        }

        catalog_loaded_ = true;
        if (programs_.empty()) {
            throw UnmarshalError("No executable sections");
        }
        return;
    }

    struct stat st; // NOLINT(*-pro-type-member-init)
    if (stat(path_.c_str(), &st)) {
        throw UnmarshalError(std::string(strerror(errno)) + " opening " + path_);
    }
    throw UnmarshalError("Can't process ELF file " + path_);
}

void ElfObject::mark_section_validity(const std::string& section_name, const bool valid, const std::string& reason) {
    if (!section_program_indices_.contains(section_name)) {
        return;
    }
    for (const size_t index : section_program_indices_.at(section_name)) {
        programs_[index].invalid = !valid;
        programs_[index].invalid_reason = valid ? std::string{} : reason;
    }
}

void ElfObject::load_section(const std::string& section_name) {
    discover_programs();
    auto section_it = section_cache_.find(section_name);
    if (section_it == section_cache_.end()) {
        throw UnmarshalError("Section not found");
    }

    SectionCacheEntry& cache_entry = section_it->second;
    if (cache_entry.loaded) {
        return;
    }

    cache_entry.loaded = true;
    try {
        cache_entry.programs = read_elf(path_, section_name, "", options_, platform_);
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

std::vector<RawProgram> ElfObject::filter_section_programs(const std::vector<RawProgram>& programs,
                                                           const std::string& desired_program) const {
    if (desired_program.empty()) {
        return programs;
    }

    std::vector<RawProgram> selected;
    for (const RawProgram& program : programs) {
        if (program.function_name == desired_program) {
            selected.push_back(program);
        }
    }
    return selected;
}

const std::vector<RawProgram>& ElfObject::get_programs(const std::string& desired_section,
                                                       const std::string& desired_program) {
    discover_programs();
    QueryKey key{.section = desired_section, .program = desired_program};
    if (const auto cached = query_cache_.find(key); cached != query_cache_.end()) {
        return cached->second;
    }

    if (!desired_section.empty()) {
        load_section(desired_section);
        const auto section_it = section_cache_.find(desired_section);
        if (section_it == section_cache_.end()) {
            throw UnmarshalError("Section not found");
        }
        if (!section_it->second.valid) {
            throw UnmarshalError(section_it->second.error);
        }
        auto selected = filter_section_programs(section_it->second.programs, desired_program);
        if (!desired_program.empty()) {
            if (selected.empty()) {
                throw UnmarshalError("Program not found in section '" + desired_section + "': " + desired_program);
            }
            if (selected.size() > 1) {
                throw UnmarshalError("Program name is ambiguous in section '" + desired_section +
                                     "': " + desired_program);
            }
        }
        auto [it, _] = query_cache_.emplace(std::move(key), std::move(selected));
        return it->second;
    }

    std::vector<RawProgram> all_programs;
    for (const auto& section_name : section_order_) {
        load_section(section_name);
        const auto& cache_entry = section_cache_.at(section_name);
        if (cache_entry.valid) {
            all_programs.insert(all_programs.end(), cache_entry.programs.begin(), cache_entry.programs.end());
        }
    }
    if (all_programs.empty()) {
        throw UnmarshalError("No executable sections");
    }

    auto selected = filter_section_programs(all_programs, desired_program);
    if (!desired_program.empty()) {
        if (selected.empty()) {
            throw UnmarshalError("Program not found: " + desired_program);
        }
        if (selected.size() > 1) {
            throw UnmarshalError("Program name is ambiguous across sections: " + desired_program +
                                 "; please specify a section");
        }
    }
    auto [it, _] = query_cache_.emplace(std::move(key), std::move(selected));
    return it->second;
}

const std::vector<ElfProgramInfo>& ElfObject::list_programs() {
    discover_programs();
    for (const auto& section_name : section_order_) {
        load_section(section_name);
    }
    return programs_;
}

} // namespace prevail

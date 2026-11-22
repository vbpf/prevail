// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <variant>
#include <vector>

#include <elfio/elfio.hpp>

#include "crab_utils/num_safety.hpp"
#include "io/elf_reader.hpp"

namespace prevail {

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

static_assert(sizeof(ELFIO::Elf32_Ehdr) == 52);
static_assert(offsetof(ELFIO::Elf32_Ehdr, e_shoff) == 32);
static_assert(offsetof(ELFIO::Elf32_Ehdr, e_phnum) == 44);
static_assert(offsetof(ELFIO::Elf32_Ehdr, e_shentsize) == 46);
static_assert(offsetof(ELFIO::Elf32_Ehdr, e_shnum) == 48);
static_assert(sizeof(ELFIO::Elf64_Ehdr) == 64);
static_assert(offsetof(ELFIO::Elf64_Ehdr, e_shoff) == 40);
static_assert(offsetof(ELFIO::Elf64_Ehdr, e_phnum) == 56);
static_assert(offsetof(ELFIO::Elf64_Ehdr, e_shentsize) == 58);
static_assert(offsetof(ELFIO::Elf64_Ehdr, e_shnum) == 60);
static_assert(sizeof(ELFIO::Elf32_Shdr) == 40);
static_assert(offsetof(ELFIO::Elf32_Shdr, sh_type) == 4);
static_assert(offsetof(ELFIO::Elf32_Shdr, sh_size) == 20);
static_assert(sizeof(ELFIO::Elf64_Shdr) == 64);
static_assert(offsetof(ELFIO::Elf64_Shdr, sh_type) == 4);
static_assert(offsetof(ELFIO::Elf64_Shdr, sh_size) == 32);
static_assert(sizeof(ELFIO::Elf32_Rel) == 8);
static_assert(offsetof(ELFIO::Elf32_Rel, r_offset) == 0);
static_assert(offsetof(ELFIO::Elf32_Rel, r_info) == 4);
static_assert(sizeof(ELFIO::Elf32_Rela) == 12);
static_assert(offsetof(ELFIO::Elf32_Rela, r_addend) == 8);
static_assert(sizeof(ELFIO::Elf64_Rel) == 16);
static_assert(offsetof(ELFIO::Elf64_Rel, r_offset) == 0);
static_assert(offsetof(ELFIO::Elf64_Rel, r_info) == 8);
static_assert(sizeof(ELFIO::Elf64_Rela) == 24);
static_assert(offsetof(ELFIO::Elf64_Rela, r_addend) == 16);

std::pair<std::reference_wrapper<EbpfInst>, std::reference_wrapper<EbpfInst>>
validate_and_get_lddw_pair(std::vector<EbpfInst>& instructions, const size_t location, const std::string& context) {
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

bool is_map_section(const std::string& name) {
    return name == "maps" || name == ".maps" || name.starts_with("maps/") || name.starts_with(".maps/");
}

bool is_global_section(const std::string& name) {
    return name == ".data" || name == ".rodata" || name == ".bss" || name.starts_with(".data.") ||
           name.starts_with(".rodata.") || name.starts_with(".bss.");
}

std::string bad_reloc_value(const size_t reloc_value) {
    return "Bad reloc value (" + std::to_string(reloc_value) + "). " + "Make sure to compile with -O2.";
}

bool is_supported_bpf_relocation_type(const unsigned type) {
    return type == R_BPF_NONE_TYPE || type == R_BPF_64_64_TYPE || type == R_BPF_64_32_TYPE;
}

template <std::unsigned_integral T>
T read_reloc_uint(const char* data, const size_t offset, const bool little_endian) {
    T value = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        const size_t byte_index = little_endian ? i : sizeof(T) - 1U - i;
        value |= static_cast<T>(static_cast<unsigned char>(data[offset + byte_index])) << (8U * i);
    }
    return value;
}

template <std::signed_integral T>
T read_reloc_int(const char* data, const size_t offset, const bool little_endian) {
    const auto raw = read_reloc_uint<std::make_unsigned_t<T>>(data, offset, little_endian);
    T value{};
    std::memcpy(&value, &raw, sizeof(value));
    return value;
}

struct RelocationEntry {
    ELFIO::Elf64_Addr offset;
    ELFIO::Elf_Word symbol_index;
    unsigned type;
    // The r_addend of an SHT_RELA entry. SHT_REL entries have no addend field; theirs is carried
    // in the relocated instruction, so an absent addend is not the same as an explicit 0.
    std::optional<ELFIO::Elf_Sxword> explicit_addend;
};

struct RelocationSectionLayout {
    unsigned char elf_class;
    ELFIO::Elf_Word section_type;
    size_t entry_size;
    ELFIO::Elf_Xword entries_num;
    bool little_endian;
};

size_t expected_relocation_entry_size(const unsigned char elf_class, const ELFIO::Elf_Word section_type) {
    if (elf_class == ELFIO::ELFCLASS64) {
        return section_type == ELFIO::SHT_RELA ? sizeof(ELFIO::Elf64_Rela) : sizeof(ELFIO::Elf64_Rel);
    }
    return section_type == ELFIO::SHT_RELA ? sizeof(ELFIO::Elf32_Rela) : sizeof(ELFIO::Elf32_Rel);
}

RelocationSectionLayout relocation_section_layout(const ELFIO::elfio& reader, const ELFIO::section& section,
                                                  const std::string& section_name) {
    const auto elf_class = reader.get_class();
    const auto section_type = section.get_type();
    if (section_type != ELFIO::SHT_REL && section_type != ELFIO::SHT_RELA) {
        throw UnmarshalError("Malformed relocation section " + section_name);
    }

    const size_t expected_entry_size = expected_relocation_entry_size(elf_class, section_type);
    const size_t entry_size = section.get_entry_size();
    // ELFIO's relocation accessor silently treats zero entry size as no
    // entries and then uses typed loads for non-zero entries. Validate the raw
    // table first so every indexed byte read below is inside one complete entry.
    if (entry_size != expected_entry_size || section.get_data() == nullptr || section.get_size() % entry_size != 0) {
        throw UnmarshalError("Malformed relocation section " + section_name);
    }
    // Symbol indices in the table refer to the section sh_link names, which must be the symbol table.
    const ELFIO::section* linked_symbols = reader.sections[section.get_link()];
    if (linked_symbols == nullptr || linked_symbols->get_type() != ELFIO::SHT_SYMTAB) {
        throw UnmarshalError("Relocation section " + section_name + " is not linked to the symbol table");
    }
    return {
        .elf_class = elf_class,
        .section_type = section_type,
        .entry_size = entry_size,
        .entries_num = section.get_size() / entry_size,
        .little_endian = reader.get_encoding() == ELFIO::ELFDATA2LSB,
    };
}

RelocationEntry read_relocation_entry(const ELFIO::section& section, const ELFIO::Elf_Xword index,
                                      const RelocationSectionLayout& layout) {
    const char* data = section.get_data() + index * layout.entry_size;
    if (layout.elf_class == ELFIO::ELFCLASS64) {
        const uint64_t info =
            read_reloc_uint<ELFIO::Elf_Xword>(data, offsetof(ELFIO::Elf64_Rel, r_info), layout.little_endian);
        return {
            .offset =
                read_reloc_uint<ELFIO::Elf64_Addr>(data, offsetof(ELFIO::Elf64_Rel, r_offset), layout.little_endian),
            .symbol_index = static_cast<ELFIO::Elf_Word>(info >> 32U),
            .type = static_cast<unsigned>(info & 0xffffffffULL),
            .explicit_addend = layout.section_type == ELFIO::SHT_RELA
                                   ? std::optional{read_reloc_int<ELFIO::Elf_Sxword>(
                                         data, offsetof(ELFIO::Elf64_Rela, r_addend), layout.little_endian)}
                                   : std::nullopt,
        };
    }

    const uint32_t info =
        read_reloc_uint<ELFIO::Elf_Word>(data, offsetof(ELFIO::Elf32_Rel, r_info), layout.little_endian);
    return {
        .offset = read_reloc_uint<ELFIO::Elf32_Addr>(data, offsetof(ELFIO::Elf32_Rel, r_offset), layout.little_endian),
        .symbol_index = static_cast<ELFIO::Elf_Word>(info >> 8U),
        .type = static_cast<unsigned>(info & 0xffU),
        .explicit_addend = layout.section_type == ELFIO::SHT_RELA
                               ? std::optional<ELFIO::Elf_Sxword>{read_reloc_int<ELFIO::Elf_Sword>(
                                     data, offsetof(ELFIO::Elf32_Rela, r_addend), layout.little_endian)}
                               : std::nullopt,
    };
}

symbol_details_t get_symbol_details(const ELFIO::const_symbol_section_accessor& symbols, const ELFIO::Elf_Xword index) {
    symbol_details_t details;
    if (!symbols.get_symbol(index, details.name, details.value, details.size, details.bind, details.type,
                            details.section_index, details.other)) {
        throw UnmarshalError("Invalid symbol index in ELF symbol table: " + std::to_string(index));
    }
    return details;
}

FunctionSymbols collect_function_symbols(const ELFIO::const_symbol_section_accessor& symbols) {
    FunctionSymbols function_symbols;
    const ELFIO::Elf_Xword symbol_count = symbols.get_symbols_num();
    for (ELFIO::Elf_Xword index = 0; index < symbol_count; index++) {
        const auto symbol = get_symbol_details(symbols, index);
        if (symbol.type != ELFIO::STT_FUNC || symbol.name.empty()) {
            continue;
        }
        auto& section_symbols = function_symbols[symbol.section_index];
        auto [at_offset, inserted] = section_symbols.by_offset.try_emplace(symbol.value, index, index);
        if (!inserted) {
            at_offset->second.second = index;
        }
        if (symbol.value % sizeof(EbpfInst) != 0 && !section_symbols.misaligned) {
            section_symbols.misaligned = index;
        }
    }
    return function_symbols;
}

std::tuple<std::string, ELFIO::Elf_Xword> get_program_name_and_size(const ELFIO::section& sec,
                                                                    const ELFIO::Elf_Xword start,
                                                                    const ELFIO::const_symbol_section_accessor& symbols,
                                                                    const FunctionSymbols& function_symbols) {
    std::string program_name = sec.get_name();
    ELFIO::Elf_Xword size = sec.get_size() - start;
    const auto section_symbols = function_symbols.find(sec.get_index());
    if (section_symbols == function_symbols.end()) {
        return {program_name, size};
    }
    const auto& [by_offset, misaligned] = section_symbols->second;
    if (misaligned) {
        const auto symbol_details = get_symbol_details(symbols, *misaligned);
        throw UnmarshalError("Non-instruction-aligned FUNC symbol '" + symbol_details.name + "' at offset " +
                             std::to_string(symbol_details.value) + " in section " + sec.get_name());
    }
    // The last symbol at `start` names the program, and the next function in the section ends it.
    auto it = by_offset.lower_bound(start);
    if (it != by_offset.end() && it->first == start) {
        program_name = get_symbol_details(symbols, it->second.second).name;
        ++it;
    }
    if (it != by_offset.end() && it->first < start + size) {
        size = it->first - start;
    }
    return {program_name, size};
}

std::optional<std::string> find_function_symbol_at_offset(const ELFIO::const_symbol_section_accessor& symbols,
                                                          const FunctionSymbols& function_symbols,
                                                          const ELFIO::Elf_Half section_index,
                                                          const ELFIO::Elf_Xword offset) {
    const auto section_symbols = function_symbols.find(section_index);
    if (section_symbols == function_symbols.end()) {
        return std::nullopt;
    }
    const auto it = section_symbols->second.by_offset.find(offset);
    if (it == section_symbols->second.by_offset.end()) {
        return std::nullopt;
    }
    return get_symbol_details(symbols, it->second.first).name;
}

std::optional<ControlFlowEscape> find_control_flow_escape(const std::vector<EbpfInst>& instructions) {
    const auto size = gsl::narrow<int64_t>(instructions.size());
    for (int64_t pc = 0; pc < size;) {
        const EbpfInst& inst = instructions[gsl::narrow<size_t>(pc)];
        const int64_t next = pc + (inst.opcode == INST_OP_LDDW_IMM ? 2 : 1);
        if (next > size) {
            // An lddw without its second slot is not a control-flow question; unmarshal rejects it.
            break;
        }
        bool falls_through = true;
        const uint8_t cls = inst.opcode & INST_CLS_MASK;
        if (cls == INST_CLS_JMP || cls == INST_CLS_JMP32) {
            const uint8_t op = (inst.opcode >> 4) & 0xF;
            if (op == INST_EXIT) {
                falls_through = false;
            } else if (op != INST_CALL) {
                const int32_t offset = inst.opcode == INST_OP_JA32 ? inst.imm : inst.offset;
                const int64_t target = pc + 1 + offset;
                if (target < 0 || target >= size) {
                    return ControlFlowEscape{.pc = gsl::narrow<size_t>(pc), .target = target, .is_jump = true};
                }
                falls_through = op != INST_JA;
            }
        }
        if (falls_through && next >= size) {
            return ControlFlowEscape{.pc = gsl::narrow<size_t>(pc), .target = next, .is_jump = false};
        }
        pc = next;
    }
    return std::nullopt;
}

std::vector<ELFIO::section*> global_sections(const ELFIO::elfio& reader) {
    std::vector<ELFIO::section*> result;
    for (auto& section : reader.sections) {
        if (!section || !is_global_section(section->get_name())) {
            continue;
        }

        const auto type = section->get_type();
        if ((type == ELFIO::SHT_NOBITS || type == ELFIO::SHT_PROGBITS) && section->get_size() != 0) {
            result.push_back(section.get());
        }
    }
    return result;
}

static std::uintmax_t get_data_size(std::istream& input_stream, const std::string& path) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (!ec) {
        return size;
    }
    // Fallback: compute size from the input stream (handles in-memory ELF data
    // where path is not a real filesystem path, e.g. path="memory").
    input_stream.seekg(0, std::ios::end);
    const auto end_pos = input_stream.tellg();
    if (end_pos < 0) {
        throw UnmarshalError("Cannot determine data size for " + path);
    }
    input_stream.seekg(0);
    return end_pos;
}

template <std::unsigned_integral T>
static T read_uint(const unsigned char* bytes, const bool little_endian) {
    T value = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        const size_t byte_index = little_endian ? i : sizeof(T) - 1U - i;
        value |= static_cast<T>(bytes[byte_index]) << (8U * i);
    }
    return value;
}

static std::streamsize read_stream_bytes_at(std::istream& input_stream, const std::uintmax_t offset,
                                            unsigned char* output, const size_t size) {
    input_stream.clear();
    input_stream.seekg(gsl::narrow<std::streamoff>(offset));
    input_stream.read(reinterpret_cast<char*>(output), gsl::narrow<std::streamsize>(size));
    const auto bytes_read = input_stream.gcount();
    input_stream.clear();
    input_stream.seekg(0);
    return bytes_read;
}

struct SectionHeaderTableLayout {
    uint64_t offset{};
    uint16_t entry_size{};
    uint16_t count{};
    size_t min_entry_size{};
    size_t section_size_offset{};
};

static std::optional<SectionHeaderTableLayout>
read_section_header_table_layout(const std::array<unsigned char, sizeof(ELFIO::Elf64_Ehdr)>& header,
                                 const std::streamsize bytes_read, const unsigned char elf_class,
                                 const bool little_endian) {
    constexpr size_t elf64_header_size = sizeof(ELFIO::Elf64_Ehdr);
    constexpr size_t elf32_section_header_size = sizeof(ELFIO::Elf32_Shdr);
    constexpr size_t elf64_section_header_size = sizeof(ELFIO::Elf64_Shdr);
    constexpr size_t elf32_section_size_offset = offsetof(ELFIO::Elf32_Shdr, sh_size);
    constexpr size_t elf64_section_size_offset = offsetof(ELFIO::Elf64_Shdr, sh_size);

    if (elf_class == ELFIO::ELFCLASS32) {
        return SectionHeaderTableLayout{
            .offset = read_uint<ELFIO::Elf32_Off>(header.data() + offsetof(ELFIO::Elf32_Ehdr, e_shoff), little_endian),
            .entry_size =
                read_uint<ELFIO::Elf_Half>(header.data() + offsetof(ELFIO::Elf32_Ehdr, e_shentsize), little_endian),
            .count = read_uint<ELFIO::Elf_Half>(header.data() + offsetof(ELFIO::Elf32_Ehdr, e_shnum), little_endian),
            .min_entry_size = elf32_section_header_size,
            .section_size_offset = elf32_section_size_offset,
        };
    }

    if (elf_class == ELFIO::ELFCLASS64 && bytes_read >= gsl::narrow<std::streamsize>(elf64_header_size)) {
        return SectionHeaderTableLayout{
            .offset = read_uint<ELFIO::Elf64_Off>(header.data() + offsetof(ELFIO::Elf64_Ehdr, e_shoff), little_endian),
            .entry_size =
                read_uint<ELFIO::Elf_Half>(header.data() + offsetof(ELFIO::Elf64_Ehdr, e_shentsize), little_endian),
            .count = read_uint<ELFIO::Elf_Half>(header.data() + offsetof(ELFIO::Elf64_Ehdr, e_shnum), little_endian),
            .min_entry_size = elf64_section_header_size,
            .section_size_offset = elf64_section_size_offset,
        };
    }

    return std::nullopt;
}

static void validate_section_header_table_bounds(std::istream& input_stream, const std::string& path,
                                                 const std::uintmax_t data_size) {
    // This pre-load check validates the section header table extent and bounds the memory ELFIO needs to load
    // the file: ELFIO copies the file range of every program header and every section header into a buffer of
    // its own and checks each range against the stream size only, so overlapping ranges would cost
    // (number of headers) x (file size). Individual section payload ranges are checked after ELFIO loads metadata.
    constexpr size_t min_elf_header_size = sizeof(ELFIO::Elf32_Ehdr);
    constexpr size_t elf64_header_size = sizeof(ELFIO::Elf64_Ehdr);
    constexpr unsigned char elf_magic[] = {0x7f, 'E', 'L', 'F'};

    std::array<unsigned char, elf64_header_size> header{};
    const auto bytes_read = read_stream_bytes_at(input_stream, 0, header.data(), header.size());

    if (bytes_read < gsl::narrow<std::streamsize>(min_elf_header_size) ||
        !std::equal(std::begin(elf_magic), std::end(elf_magic), header.begin())) {
        return;
    }

    const unsigned char elf_class = header[ELFIO::EI_CLASS];
    const unsigned char elf_data = header[ELFIO::EI_DATA];
    const bool little_endian = elf_data == ELFIO::ELFDATA2LSB;
    if (elf_data != ELFIO::ELFDATA2LSB && elf_data != ELFIO::ELFDATA2MSB) {
        return;
    }

    const std::optional<SectionHeaderTableLayout> layout =
        read_section_header_table_layout(header, bytes_read, elf_class, little_endian);
    if (!layout) {
        return;
    }
    const SectionHeaderTableLayout table = *layout;

    // Relocatable BPF objects have no program headers, and segments are never consulted.
    const auto program_header_count = read_uint<ELFIO::Elf_Half>(
        header.data() + (elf_class == ELFIO::ELFCLASS32 ? offsetof(ELFIO::Elf32_Ehdr, e_phnum)
                                                        : offsetof(ELFIO::Elf64_Ehdr, e_phnum)),
        little_endian);
    if (program_header_count != 0) {
        throw UnmarshalError("ELF file " + path + " has program headers: expected a relocatable object");
    }

    if (table.offset == 0 && table.count == 0) {
        return;
    }
    if (table.entry_size < table.min_entry_size) {
        throw UnmarshalError("ELF section header table in " + path + " has invalid entry size");
    }
    if (table.offset > data_size) {
        throw UnmarshalError("ELF section header table in " + path + " is out of bounds");
    }

    const std::uintmax_t available = data_size - table.offset;
    std::uintmax_t required_entries = table.count;
    if (table.count == 0) {
        if (available < table.min_entry_size) {
            throw UnmarshalError("ELF section header table in " + path + " is out of bounds");
        }

        std::array<unsigned char, sizeof(ELFIO::Elf64_Shdr)> null_section_header{};
        const auto null_section_bytes_read =
            read_stream_bytes_at(input_stream, table.offset, null_section_header.data(), table.min_entry_size);
        if (null_section_bytes_read < gsl::narrow<std::streamsize>(table.min_entry_size)) {
            throw UnmarshalError("ELF section header table in " + path + " is out of bounds");
        }

        required_entries =
            elf_class == ELFIO::ELFCLASS32
                ? read_uint<ELFIO::Elf_Word>(null_section_header.data() + table.section_size_offset, little_endian)
                : read_uint<ELFIO::Elf_Xword>(null_section_header.data() + table.section_size_offset, little_endian);
    }
    if (required_entries > available / table.entry_size) {
        throw UnmarshalError("ELF section header table in " + path + " is out of bounds");
    }

    // Sections of a well-formed object do not share file bytes, so together they cannot exceed the file size.
    // ELFIO loads exactly e_shnum sections (table.count), never the extended count.
    std::uintmax_t remaining = data_size;
    for (std::uintmax_t i = 0; i < table.count; ++i) {
        std::array<unsigned char, sizeof(ELFIO::Elf64_Shdr)> section_header{};
        const auto section_bytes_read = read_stream_bytes_at(input_stream, table.offset + i * table.entry_size,
                                                             section_header.data(), table.min_entry_size);
        if (section_bytes_read < gsl::narrow<std::streamsize>(table.min_entry_size)) {
            throw UnmarshalError("ELF section header table in " + path + " is out of bounds");
        }

        const auto section_type =
            read_uint<ELFIO::Elf_Word>(section_header.data() + offsetof(ELFIO::Elf64_Shdr, sh_type), little_endian);
        if (section_type == ELFIO::SHT_NULL || section_type == ELFIO::SHT_NOBITS) {
            continue;
        }

        const std::uintmax_t section_size =
            elf_class == ELFIO::ELFCLASS32
                ? read_uint<ELFIO::Elf_Word>(section_header.data() + table.section_size_offset, little_endian)
                : read_uint<ELFIO::Elf_Xword>(section_header.data() + table.section_size_offset, little_endian);
        if (section_size > remaining) {
            throw UnmarshalError("ELF sections in " + path + " exceed the file size");
        }
        remaining -= section_size;
    }
}

ELFIO::elfio load_elf(std::istream& input_stream, const std::string& path) {
    const std::uintmax_t data_size = get_data_size(input_stream, path);
    validate_section_header_table_bounds(input_stream, path, data_size);

    ELFIO::elfio reader;
    if (!reader.load(input_stream)) {
        throw UnmarshalError("Can't process ELF file " + path);
    }

    if (reader.get_machine() != ELFIO::EM_BPF && reader.get_machine() != ELFIO::EM_NONE) {
        throw UnmarshalError("Unsupported ELF machine in file " + path + ": expected EM_BPF");
    }

    // ELFIO converts the ELF metadata, but section payloads (instructions via
    // vector_of<EbpfInst>, legacy map records) are memcpy'd in host byte order,
    // so an object of the other byte order would be decoded, and verified, as a
    // different program than the one it encodes.
    constexpr unsigned char native_encoding =
        std::endian::native == std::endian::little ? ELFIO::ELFDATA2LSB : ELFIO::ELFDATA2MSB;
    if (reader.get_encoding() != native_encoding) {
        throw UnmarshalError("Unsupported ELF byte order in file " + path + ": expected host byte order");
    }

    for (const auto& section : reader.sections) {
        if (!section || section->get_type() == ELFIO::SHT_NOBITS) {
            continue;
        }

        const std::uintmax_t offset = section->get_offset();
        const std::uintmax_t size = section->get_size();
        if (offset > data_size || size > data_size - offset) {
            throw UnmarshalError("ELF section '" + section->get_name() + "' has out-of-bounds file range");
        }
    }

    return reader;
}

ELFIO::const_symbol_section_accessor read_and_validate_symbol_section(const ELFIO::elfio& reader,
                                                                      const std::string& path) {
    // The symbol table is the section of type SHT_SYMTAB, whatever its name; a relocatable object has one.
    const ELFIO::section* symbol_section = nullptr;
    for (const auto& section : reader.sections) {
        if (section->get_type() != ELFIO::SHT_SYMTAB) {
            continue;
        }
        if (symbol_section) {
            throw UnmarshalError("Multiple symbol sections found in ELF file " + path);
        }
        symbol_section = section.get();
    }
    if (!symbol_section) {
        throw UnmarshalError("No symbol section found in ELF file " + path);
    }
    const auto expected_entry_size =
        reader.get_class() == ELFIO::ELFCLASS32 ? sizeof(ELFIO::Elf32_Sym) : sizeof(ELFIO::Elf64_Sym);
    if (symbol_section->get_entry_size() != expected_entry_size || symbol_section->get_entry_size() == 0 ||
        symbol_section->get_data() == nullptr || symbol_section->get_size() % symbol_section->get_entry_size() != 0) {
        throw UnmarshalError("Invalid symbol section in ELF file " + path);
    }

    const auto linked_strtab_index = symbol_section->get_link();
    if (linked_strtab_index >= reader.sections.size() || reader.sections[linked_strtab_index] == nullptr ||
        reader.sections[linked_strtab_index]->get_data() == nullptr) {
        throw UnmarshalError("Invalid symbol string table link in ELF file " + path);
    }
    return ELFIO::const_symbol_section_accessor{reader, symbol_section};
}

// ---------------------------------------------------------------------------
// ProgramReader methods
// ---------------------------------------------------------------------------

void ProgramReader::record_function_relocation(FunctionRelocation reloc) {
    function_relocation_index_.emplace(reloc.prog_index, reloc.source_offset);
    function_relocations.push_back(std::move(reloc));
}

/// Names longer than this are abbreviated in diagnostics.
constexpr size_t max_reported_name_length = 128;

static std::string abbreviate_name(const std::string& name) {
    if (name.size() <= max_reported_name_length) {
        return name;
    }
    return name.substr(0, max_reported_name_length) + "...";
}

std::string ProgramReader::name_of_function_containing(const ELFIO::section& section,
                                                       const ELFIO::Elf_Xword offset) const {
    const auto section_symbols = function_symbols.find(section.get_index());
    if (section_symbols == function_symbols.end()) {
        return section.get_name();
    }
    const auto& by_offset = section_symbols->second.by_offset;
    auto it = by_offset.upper_bound(offset);
    if (it == by_offset.begin()) {
        return section.get_name();
    }
    --it;
    // The last symbol at an offset names the program there, as in get_program_name_and_size.
    return get_symbol_details(symbols, it->second.second).name;
}

std::string ProgramReader::describe_control_flow_escape(const ELFIO::section& section,
                                                        const ELFIO::Elf_Xword program_offset,
                                                        const std::string& program_name,
                                                        const ControlFlowEscape& escape) const {
    const int64_t section_target = gsl::narrow<int64_t>(program_offset / sizeof(EbpfInst)) + escape.target;
    const bool in_section =
        section_target >= 0 && section_target < gsl::narrow<int64_t>(section.get_size() / sizeof(EbpfInst));
    std::string destination = "out of the section";
    if (in_section) {
        destination =
            "into function " + abbreviate_name(name_of_function_containing(
                                   section, gsl::narrow<ELFIO::Elf_Xword>(section_target) * sizeof(EbpfInst)));
    }
    return "Function " + abbreviate_name(program_name) + " in section " + abbreviate_name(section.get_name()) +
           (escape.is_jump ? " jumps " : " falls through ") + destination + " at instruction " +
           std::to_string(escape.pc);
}

bool ProgramReader::has_function_relocation(const size_t prog_index, const size_t source_offset) const {
    return function_relocation_index_.contains({prog_index, source_offset});
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

        // The target need not start a FUNC symbol: a call into the code of a function lands in
        // that function, which resolve_function_relocation_targets finds by position.
        const auto target_offset = gsl::narrow<ELFIO::Elf_Xword>(target * sizeof(EbpfInst));
        record_function_relocation(FunctionRelocation{
            .prog_index = raw_programs.size(),
            .source_offset = loc,
            .relocation_entry_index = std::nullopt,
            .target = {.section_index = section_index, .offset = target_offset},
            .target_function_name = name_of_function_containing(*section, target_offset),
        });
    }
}

std::span<const FunctionRelocation> ProgramReader::function_relocations_of(const size_t prog_index) const {
    // Match relocations to their owning program by index, not by name.
    // reloc.source_offset is an instruction index into raw_programs[reloc.prog_index];
    // applying it to a different program that merely shares function_name (ELF symbol
    // names need not be unique) can index that program's instruction vector out of bounds.
    // function_relocations is sorted by prog_index (resolve_function_relocation_targets).
    return std::ranges::equal_range(function_relocations, prog_index, {}, &FunctionRelocation::prog_index);
}

void ProgramReader::resolve_function_relocation_targets() {
    std::ranges::stable_sort(function_relocations, {}, &FunctionRelocation::prog_index);
    for (auto& reloc : function_relocations) {
        if (reloc.target.section_index >= reader.sections.size()) {
            throw UnmarshalError("Invalid section index");
        }
        // The callee is the program whose code holds the position the relocation designates, not
        // the first program that happens to share its section name and function name. A relocation
        // entry names its callee by a symbol, so it must designate where a program starts; only a
        // call without one (enqueue_synthetic_local_calls) may land on code no FUNC symbol starts.
        auto it = raw_program_index_.upper_bound(reloc.target);
        if (it == raw_program_index_.begin()) {
            continue;
        }
        --it;
        const auto& [start, prog_index] = *it;
        if (start.section_index != reloc.target.section_index) {
            continue;
        }
        const size_t entry = (reloc.target.offset - start.offset) / sizeof(EbpfInst);
        if (entry < raw_programs[prog_index].prog.size() && (entry == 0 || !reloc.relocation_entry_index)) {
            reloc.target_prog_index = prog_index;
            reloc.target_entry = entry;
        }
    }
}

/// Link `prog`, a copy of raw_programs[prog_index], against raw_programs, which stay unlinked:
/// every function in the transitive call graph of `prog` is appended exactly once, however many
/// callers share it, so the linked program is never larger than all programs together.
/// (Appending each callee together with its own, already appended, callees duplicates a shared
/// callee at every call level, which is exponential in the number of functions.)
std::string ProgramReader::append_subprograms(RawProgram& prog, const size_t prog_index) const {
    // Depth-first walk of the call graph, with an explicit stack rather than recursion: the call
    // depth is only bounded later, by the CFG builder.
    enum class Visit : uint8_t { unvisited, in_progress, done };
    std::vector<Visit> visit(raw_programs.size(), Visit::unvisited);
    std::vector<std::pair<size_t, std::span<const FunctionRelocation>>> path;
    std::vector<size_t> postorder;
    visit[prog_index] = Visit::in_progress;
    path.emplace_back(prog_index, function_relocations_of(prog_index));
    while (!path.empty()) {
        auto& [caller, pending] = path.back();
        if (pending.empty()) {
            visit[caller] = Visit::done;
            postorder.push_back(caller);
            path.pop_back();
            continue;
        }
        // Last call first, so that the reversed postorder below keeps siblings in call order.
        const FunctionRelocation& reloc = pending.back();
        pending = pending.first(pending.size() - 1);
        if (!reloc.target_prog_index) {
            return "Subprogram not found: " + reloc.target_function_name;
        }
        const size_t callee = *reloc.target_prog_index;
        if (callee == caller) {
            throw UnmarshalError("Recursive subprogram call");
        }
        if (visit[callee] == Visit::in_progress) {
            throw UnmarshalError("Mutual recursion in subprogram calls");
        }
        if (visit[callee] == Visit::unvisited) {
            // Its own section reports the relocations themselves; a caller must not take in its unrelocated code.
            if (programs_with_unresolved_relocations.contains(callee)) {
                return "Unresolved symbols found in subprogram " + abbreviate_name(raw_programs[callee].function_name);
            }
            if (const auto escape = programs_with_escaping_control_flow.find(callee);
                escape != programs_with_escaping_control_flow.end()) {
                return escape->second;
            }
            visit[callee] = Visit::in_progress;
            path.emplace_back(callee, function_relocations_of(callee));
        }
    }

    // Place the callees in reversed postorder, which puts every caller before all of its
    // callees. The CFG builder relies on that: it inlines call sites in instruction order and
    // has to clone a callee before the calls in the callee's own body are expanded in place.
    std::vector<size_t> subprogram_offsets(raw_programs.size(), 0);
    for (const size_t sub_index : postorder | std::views::reverse | std::views::drop(1)) {
        const RawProgram& sub = raw_programs[sub_index];
        const size_t base = prog.prog.size();
        subprogram_offsets[sub_index] = base;

        prog.prog.insert(prog.prog.end(), sub.prog.begin(), sub.prog.end());
        if (parse_params.options.verbosity_opts.print_line_info) {
            for (const auto& [k, info] : sub.info.line_info) {
                prog.info.line_info[base + k] = info;
            }
        }
        for (const size_t builtin_offset : sub.info.builtin_call_offsets) {
            prog.info.builtin_call_offsets.insert(base + builtin_offset);
        }
        for (const size_t extern_address_offset : sub.info.extern_address_offsets) {
            prog.info.extern_address_offsets.insert(base + extern_address_offset);
        }
    }

    // Patch every relocated call, in `prog` itself and in each placed callee.
    for (const size_t caller : postorder) {
        const auto base = gsl::narrow<int64_t>(subprogram_offsets[caller]);
        for (const auto& reloc : function_relocations_of(caller)) {
            const auto target_offset =
                gsl::narrow<int64_t>(subprogram_offsets[*reloc.target_prog_index] + reloc.target_entry);
            const auto source_offset = base + gsl::narrow<int64_t>(reloc.source_offset);
            prog.prog[source_offset].imm = gsl::narrow<int32_t>(target_offset - source_offset - 1);
        }
    }
    return {};
}

int ProgramReader::relocate_map(const std::string& name, const ELFIO::Elf_Word index) const {
    size_t val{};
    if (const auto* record_size = std::get_if<size_t>(&global.map_record_size_or_map_offsets)) {
        const auto symbol_value = get_symbol_details(symbols, index).value;
        if (symbol_value % *record_size != 0) {
            throw UnmarshalError("Map symbol offset " + std::to_string(symbol_value) +
                                 " is not aligned to record size " + std::to_string(*record_size));
        }

        val = symbol_value / *record_size;
    } else {
        // Resolve by the identity of the relocation's symbol, not by its name: another symbol may
        // share the name while designating a different map, so the name only serves the error message.
        const auto& offsets = std::get<MapOffsets>(global.map_record_size_or_map_offsets);
        const auto it = offsets.find(index);
        if (it == offsets.end()) {
            throw UnmarshalError("Map descriptor not found: " + name);
        }
        val = it->second;
    }
    if (val >= global.map_descriptors->size()) {
        throw UnmarshalError(bad_reloc_value(val));
    }
    return global.map_descriptors->at(val).original_fd;
}

int ProgramReader::relocate_global_variable(const ELFIO::Elf_Half section_index) const {
    // Resolve by section index, not by section name: ELF section names need not be unique either.
    const auto it = global.variable_section_indices.find(section_index);
    if (it == global.variable_section_indices.end()) {
        throw UnmarshalError("Map descriptor not found for section " + std::to_string(section_index));
    }
    const size_t val = it->second;
    if (val >= global.map_descriptors->size()) {
        throw UnmarshalError(bad_reloc_value(val));
    }
    return global.map_descriptors->at(val).original_fd;
}

int32_t ProgramReader::compute_lddw_reloc_offset_imm(const std::optional<ELFIO::Elf_Sxword> explicit_addend,
                                                     const ELFIO::Elf_Word index,
                                                     const std::reference_wrapper<EbpfInst> lo_inst) const {
    // R_BPF_64_64 resolves to S + A for every symbol type, not only for section symbols.
    // eBPF objects usually carry SHT_REL entries, which have no addend field: A is then the
    // immediate the lddw already holds (libbpf: insn[1].imm = insn[0].imm + sym_off).
    const auto& sym = get_symbol_details(symbols, index);
    const int64_t addend = explicit_addend.value_or(lo_inst.get().imm);
    return gsl::narrow<int32_t>(static_cast<int64_t>(sym.value + addend));
}

void ProgramReader::build_ksym_function_resolution_cache() {
    ksym_function_resolution_cache.clear();
    const auto* btf_sec = reader.sections[".BTF"];
    if (!btf_sec || !btf_sec->get_data()) {
        return;
    }

    const libbtf::btf_type_data btf_data{vector_of<std::byte>(*btf_sec)};

    const auto ksyms_id = btf_data.get_id(".ksyms");
    if (ksyms_id == 0) {
        return;
    }

    libbtf::btf_kind_data_section ksyms;
    try {
        ksyms = btf_data.get_kind_type<libbtf::btf_kind_data_section>(ksyms_id);
    } catch (const std::exception& e) {
        throw UnmarshalError(std::string("Unsupported or invalid BTF .ksyms section (id ") + std::to_string(ksyms_id) +
                             "): " + e.what());
    }

    for (const auto& member : ksyms.members) {
        if (btf_data.get_kind_index(member.type) != libbtf::BTF_KIND_FUNCTION) {
            continue;
        }
        libbtf::btf_kind_function function;
        try {
            function = btf_data.get_kind_type<libbtf::btf_kind_function>(member.type);
        } catch (const std::exception& e) {
            throw UnmarshalError(std::string("Unsupported or invalid BTF .ksyms function (type ") +
                                 std::to_string(member.type) + "): " + e.what());
        }
        if (function.name.empty() || ksym_function_resolution_cache.contains(function.name)) {
            continue;
        }

        std::optional<KsymBtfId> resolved;
        if (parse_params.platform && parse_params.platform->resolve_ksym_btf_id) {
            resolved = parse_params.platform->resolve_ksym_btf_id(function.name);
        }
        ksym_function_resolution_cache.emplace(function.name, resolved);
    }
}

bool ProgramReader::is_absent_weak_kfunc(const std::string& symbol_name, const unsigned char symbol_bind) const {
    if (symbol_bind != ELFIO::STB_WEAK) {
        return false;
    }
    const auto it = ksym_function_resolution_cache.find(symbol_name);
    return it != ksym_function_resolution_cache.end() && !it->second.has_value();
}

bool ProgramReader::try_reloc(const std::string& symbol_name, const ELFIO::Elf_Half symbol_section_index,
                              const unsigned char symbol_type, const unsigned char symbol_bind,
                              std::vector<EbpfInst>& instructions, const size_t location, const ELFIO::Elf_Word index,
                              const std::optional<ELFIO::Elf_Sxword> explicit_addend) {
    EbpfInst& instruction_to_relocate = instructions[location];

    if (symbol_section_index == ELFIO::SHN_UNDEF) {
        // The loader that resolves the extern writes its address into the lddw, so the zero written
        // here is a placeholder, and the lddw is marked as loading an unknown number. Only a weak
        // kernel function that the platform reports absent has the address 0, as libbpf gives it.
        if (const auto value = resolve_known_linux_extern_symbol(symbol_name)) {
            if (rewrite_extern_constant_load(instructions, location, *value, jump_targets_for_current_program)) {
                extern_address_offsets_for_current_program.insert(location);
                return true;
            }
        }
        if (rewrite_extern_address_load_to_zero(instructions, location)) {
            if (!is_absent_weak_kfunc(symbol_name, symbol_bind)) {
                extern_address_offsets_for_current_program.insert(location);
            }
            return true;
        }
    }

    // Handle local function calls - queue for post-processing.
    if (instruction_to_relocate.opcode == INST_OP_CALL && instruction_to_relocate.src == INST_CALL_LOCAL) {
        if (symbol_section_index == ELFIO::SHN_UNDEF) {
            if (const auto it = ksym_function_resolution_cache.find(symbol_name);
                it != ksym_function_resolution_cache.end()) {
                if (it->second.has_value()) {
                    if (!rewrite_extern_kfunc_call(instruction_to_relocate, *it->second)) {
                        throw UnmarshalError("Invalid kfunc call rewrite for symbol " + symbol_name +
                                             ": instruction encoding or resolver output is invalid");
                    }
                    return true;
                }
                if (symbol_bind != ELFIO::STB_WEAK) {
                    return false;
                }
            }
        }
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

        // The relocation designates the callee by position, S + A: the symbol's value plus the addend,
        // which a REL entry carries in the call's imm (clang encodes it as (imm + 1) * 8 bytes).
        const int64_t target_addend = explicit_addend.value_or((gsl::narrow<int64_t>(instruction_to_relocate.imm) + 1) *
                                                               static_cast<int64_t>(sizeof(EbpfInst)));
        const ELFIO::Elf_Xword symbol_value = get_symbol_details(symbols, index).value;
        const ELFIO::Elf_Xword target_offset = symbol_value + to_unsigned(target_addend);
        // The unsigned sum wraps exactly when it lands on the wrong side of the symbol's value.
        if ((target_offset < symbol_value) != (target_addend < 0) || target_offset % sizeof(EbpfInst) != 0) {
            throw UnmarshalError("Invalid section-local call target offset");
        }

        std::string target_function_name = symbol_name;
        if (target_function_name.empty() && symbol_type == ELFIO::STT_SECTION) {
            if (const auto target =
                    find_function_symbol_at_offset(symbols, function_symbols, symbol_section_index, target_offset)) {
                target_function_name = *target;
            }
        }

        if (!target_function_name.empty() && !has_function_relocation(raw_programs.size(), location)) {
            record_function_relocation(FunctionRelocation{
                .prog_index = raw_programs.size(),
                .source_offset = location,
                .relocation_entry_index = index,
                .target = {.section_index = symbol_section_index, .offset = target_offset},
                .target_function_name = target_function_name,
            });
            return true;
        }
        return false;
    }

    // Handle empty symbol names for global variable sections
    if (symbol_name.empty()) {
        if (global.variable_section_indices.contains(symbol_section_index)) {
            if (!std::holds_alternative<MapOffsets>(global.map_record_size_or_map_offsets)) {
                return false;
            }

            auto [lo_inst, hi_inst] = validate_and_get_lddw_pair(instructions, location, "global variable");

            hi_inst.get().imm = compute_lddw_reloc_offset_imm(explicit_addend, index, lo_inst);
            lo_inst.get().src = INST_LD_MODE_MAP_VALUE;
            lo_inst.get().imm = relocate_global_variable(symbol_section_index);
            return true;
        }
        // A code address (e.g., a callback in .text) is kept as the file encodes it. Any other section symbol,
        // such as a static map referenced through its map section, names data this loader cannot resolve, and
        // leaving the placeholder in place would analyze it as a constant.
        const ELFIO::section* target_section = reader.sections[symbol_section_index];
        return target_section != nullptr && (target_section->get_flags() & ELFIO::SHF_EXECINSTR) != 0;
    }

    if ((instruction_to_relocate.opcode & INST_CLS_MASK) != INST_CLS_LD) {
        return false;
    }

    if (global.map_section_indices.contains(symbol_section_index)) {
        instruction_to_relocate.src = INST_LD_MODE_MAP_FD;
        instruction_to_relocate.imm = relocate_map(symbol_name, index);
        return true;
    }

    if (global.variable_section_indices.contains(symbol_section_index)) {
        auto [lo_inst, hi_inst] =
            validate_and_get_lddw_pair(instructions, location, "global variable '" + symbol_name + "'");

        hi_inst.get().imm = compute_lddw_reloc_offset_imm(explicit_addend, index, lo_inst);
        lo_inst.get().src = INST_LD_MODE_MAP_VALUE;
        lo_inst.get().imm = relocate_global_variable(symbol_section_index);
        return true;
    }

    if (symbol_name.rfind("__config_", 0) == 0) {
        instruction_to_relocate.imm = 0;
        return true;
    }

    return false;
}

void ProgramReader::process_relocations(std::vector<EbpfInst>& instructions, const ELFIO::section& reloc,
                                        const std::string& section_name, const ELFIO::Elf_Xword program_offset,
                                        const size_t program_size) {
    const auto layout = relocation_section_layout(reader, reloc, section_name);
    std::set<size_t> relocated_slots;
    for (ELFIO::Elf_Xword i = 0; i < layout.entries_num; i++) {
        const auto entry = read_relocation_entry(reloc, i, layout);
        ELFIO::Elf64_Addr o = entry.offset;
        const ELFIO::Elf_Word idx = entry.symbol_index;
        const unsigned type = entry.type;
        if (!is_supported_bpf_relocation_type(type)) {
            throw UnmarshalError("Unsupported relocation type " + std::to_string(type) + " in section " + section_name);
        }
        if (type == R_BPF_NONE_TYPE && idx == 0) {
            continue;
        }
        if (idx >= symbols.get_symbols_num()) {
            throw UnmarshalError("Invalid relocation symbol index " + std::to_string(idx) + " in section " +
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
        // An entry is resolved against the instruction as the file stores it: a SHT_REL entry keeps its
        // addend in the immediate, which applying a relocation overwrites (in an lddw, with a map fd).
        // So each instruction is relocated at most once: a second entry would take what the first one
        // stored as its addend, one for the second slot of a relocated lddw would replace the offset
        // computed for it, and one for an extern's lddw would retarget a load whose value is already folded.
        const size_t slots = instructions[loc].opcode == INST_OP_LDDW_IMM ? 2 : 1;
        for (size_t slot = loc; slot < loc + slots; ++slot) {
            if (!relocated_slots.insert(slot).second) {
                throw UnmarshalError("Multiple relocations in section " + section_name + " at location " +
                                     std::to_string(slot));
            }
        }
        auto sym = get_symbol_details(symbols, idx);

        if (!try_reloc(sym.name, sym.section_index, sym.type, sym.bind, instructions, loc, idx,
                       entry.explicit_addend)) {
            // raw_programs.size() is the index the program gets when read_programs appends it.
            unresolved_relocations.push_back(
                UnresolvedRelocation{.prog_index = raw_programs.size(), .location = loc, .symbol_index = idx});
            programs_with_unresolved_relocations.insert(raw_programs.size());
        }
    }
}

void ProgramReader::build_relocation_section_cache() {
    relocation_section_cache.clear();
    for (const auto& sec : reader.sections) {
        // A relocation table applies to the section its sh_info names, whatever either is called.
        if (sec->get_type() != ELFIO::SHT_REL && sec->get_type() != ELFIO::SHT_RELA) {
            continue;
        }
        if (!relocation_section_cache.try_emplace(sec->get_info(), sec.get()).second) {
            const ELFIO::section* target = reader.sections[sec->get_info()];
            throw UnmarshalError("Multiple relocation sections for section " +
                                 (target ? target->get_name() : std::to_string(sec->get_info())));
        }
    }
}

const ELFIO::section* ProgramReader::get_relocation_section(const ELFIO::section& target) const {
    const auto it = relocation_section_cache.find(target.get_index());
    if (it == relocation_section_cache.end() || !it->second->get_data()) {
        return nullptr;
    }
    return it->second;
}

std::string ProgramReader::unresolved_relocation_message(const UnresolvedRelocation& unresolved) const {
    const std::string symbol_name = get_symbol_details(symbols, unresolved.symbol_index).name;
    return "Unresolved external symbol " + (symbol_name.empty() ? "<anonymous>" : abbreviate_name(symbol_name)) +
           " in section " + abbreviate_name(raw_programs.at(unresolved.prog_index).section_name) + " at location " +
           std::to_string(unresolved.location);
}

/// At most this many unresolved relocations are reported for one section; the rest are only counted.
constexpr size_t max_reported_unresolved_relocations = 16;

void ProgramReader::read_programs() { read_programs(false); }

void ProgramReader::read_all_programs() { read_programs(true); }

void ProgramReader::read_programs(const bool all_sections) {
    build_ksym_function_resolution_cache();
    build_relocation_section_cache();

    // .BTF.ext attributes CO-RE relocations and line info to a section by name alone, so two program sections sharing
    // a name cannot be told apart there.
    std::set<std::string> program_section_names;
    for (const auto& sec : reader.sections) {
        if (!(sec->get_flags() & ELFIO::SHF_EXECINSTR) || !sec->get_size() || !sec->get_data()) {
            continue;
        }
        if (!program_section_names.insert(sec->get_name()).second) {
            throw UnmarshalError("Duplicate executable section name " + abbreviate_name(sec->get_name()));
        }
        const auto& sec_name = sec->get_name();
        const auto prog_type = parse_params.platform->get_program_type(sec_name, parse_params.path);
        // Collected over the whole section before any program is rewritten, as the caller may follow its callee.
        const std::set<size_t> local_call_targets = collect_local_call_targets(vector_of<EbpfInst>(*sec));
        for (ELFIO::Elf_Xword offset = 0; offset < sec->get_size();) {
            builtin_offsets_for_current_program.clear();
            extern_address_offsets_for_current_program.clear();
            // A program is the code from its FUNC symbol to the next one, so that the programs of a
            // section do not overlap. Control may leave it only by exit or by a call: a callee is
            // appended to the program on linking, and other code it would run into is not.
            auto [name, size] = get_program_name_and_size(*sec, offset, symbols, function_symbols);
            auto instructions = vector_of<EbpfInst>(sec->get_data() + offset, size);
            if (const auto escape = find_control_flow_escape(instructions)) {
                programs_with_escaping_control_flow.emplace(raw_programs.size(),
                                                            describe_control_flow_escape(*sec, offset, name, *escape));
                jump_targets_for_current_program.clear();
            } else {
                jump_targets_for_current_program = collect_jump_targets(instructions);
                // A local call from another function may enter this one anywhere (FunctionRelocation::target_entry),
                // so what it lands on is as much a jump target as the target of a jump in this program.
                const size_t start = offset / sizeof(EbpfInst);
                for (auto it = local_call_targets.lower_bound(start);
                     it != local_call_targets.end() && *it < start + instructions.size(); ++it) {
                    jump_targets_for_current_program.insert(*it - start);
                }
            }
            if (const auto reloc_sec = get_relocation_section(*sec)) {
                process_relocations(instructions, *reloc_sec, sec_name, offset, size);
            }
            enqueue_synthetic_local_calls(instructions, sec->get_index(), offset);
            ProgramInfo program_info{
                .platform = parse_params.platform,
                .map_descriptors = global.map_descriptors,
                .type = prog_type,
                .builtin_call_offsets = std::move(builtin_offsets_for_current_program),
                .extern_address_offsets = std::move(extern_address_offsets_for_current_program),
            };
            raw_program_index_.emplace(SectionOffset{.section_index = sec->get_index(), .offset = offset},
                                       raw_programs.size());
            raw_programs.emplace_back(RawProgram{
                parse_params.path,
                sec_name,
                gsl::narrow<uint32_t>(offset),
                name,
                std::move(instructions),
                std::move(program_info),
            });
            offset += size;
        }
    }

    if (const auto btf_sec = reader.sections[".BTF"]) {
        try {
            process_core_relocations({vector_of<std::byte>(*btf_sec)});
        } catch (const std::exception& e) {
            throw UnmarshalError(std::string("Unsupported or invalid CO-RE/BTF relocation data: ") + e.what());
        }
    }

    // Every unresolved relocation fails the load of its section, however many there are; only the first few of each
    // section are reported.
    std::map<std::string, size_t> unresolved_count_by_section;
    for (const UnresolvedRelocation& unresolved : unresolved_relocations) {
        const std::string& section = raw_programs.at(unresolved.prog_index).section_name;
        if (!all_sections && !parse_params.desired_section.empty() && section != parse_params.desired_section) {
            continue;
        }
        if (++unresolved_count_by_section[section] > max_reported_unresolved_relocations) {
            continue;
        }
        if (all_sections) {
            section_errors[section].diagnostics.push_back(unresolved_relocation_message(unresolved));
        } else {
            std::cerr << unresolved_relocation_message(unresolved) << std::endl;
        }
    }
    for (const auto& [section, count] : unresolved_count_by_section) {
        std::optional<std::string> more;
        if (count > max_reported_unresolved_relocations) {
            more =
                "... and " + std::to_string(count - max_reported_unresolved_relocations) + " more unresolved symbols";
        }
        if (all_sections) {
            section_error_t& section_error = section_errors[section];
            section_error.reason = "Unresolved symbols found.";
            if (more) {
                section_error.diagnostics.push_back(*more);
            }
        } else if (more) {
            std::cerr << *more << std::endl;
        }
    }
    if (!all_sections && !unresolved_count_by_section.empty()) {
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

    resolve_function_relocation_targets();
    // Only the programs returned below are linked: linking copies every callee into each of its
    // callers, so it costs more than all the unlinked programs together.
    const bool keeps_one_section = !all_sections && !parse_params.desired_section.empty();
    std::vector<RawProgram> linked_programs;
    for (size_t i = 0; i < raw_programs.size(); ++i) {
        if (keeps_one_section && raw_programs[i].section_name != parse_params.desired_section) {
            continue;
        }
        RawProgram& prog = linked_programs.emplace_back(raw_programs[i]);
        std::string err;
        if (const auto escape = programs_with_escaping_control_flow.find(i);
            escape != programs_with_escaping_control_flow.end()) {
            err = escape->second;
        } else {
            err = append_subprograms(prog, i);
        }
        if (err.empty()) {
            continue;
        }
        if (all_sections) {
            section_errors.try_emplace(prog.section_name, section_error_t{.reason = err});
        } else {
            // The program is returned below, so it must be fully linked.
            throw UnmarshalError(err);
        }
    }
    raw_programs = std::move(linked_programs);

    if (raw_programs.empty()) {
        throw UnmarshalError(parse_params.desired_section.empty() ? "No executable sections" : "Section not found");
    }
}

// ---------------------------------------------------------------------------
// Top-level read_elf functions
// ---------------------------------------------------------------------------

std::vector<RawProgram> read_elf(std::istream& input_stream, const std::string& path,
                                 const std::string& desired_section, const std::string& desired_program,
                                 const VerifierOptions& options, const ebpf_platform_t* platform) {
    try {
        std::vector<RawProgram> res;
        parse_params_t params{path, options, platform, desired_section};
        auto reader = load_elf(input_stream, path);
        auto symbols = read_and_validate_symbol_section(reader, path);
        auto global = extract_global_data(params, reader, symbols);
        ProgramReader program_reader{params, reader, symbols, global};
        program_reader.read_programs();

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
                                 const std::string& desired_program, const VerifierOptions& options,
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

} // namespace prevail

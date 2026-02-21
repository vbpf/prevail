// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <string>
#include <sys/stat.h>
#include <variant>
#include <vector>

#include <elfio/elfio.hpp>

#include "crab_utils/num_safety.hpp"
#include "io/elf_reader.hpp"

namespace prevail {

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

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

bool is_map_section(const std::string& name) {
    const std::string maps_prefix = "maps/";
    return name == "maps" || (name.length() > 5 && name.compare(0, maps_prefix.length(), maps_prefix) == 0);
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

symbol_details_t get_symbol_details(const ELFIO::const_symbol_section_accessor& symbols, const ELFIO::Elf_Xword index) {
    symbol_details_t details;
    if (!symbols.get_symbol(index, details.name, details.value, details.size, details.bind, details.type,
                            details.section_index, details.other)) {
        throw MalformedElf("Invalid symbol index in ELF symbol table: " + std::to_string(index));
    }
    return details;
}

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

std::vector<ELFIO::section*> global_sections(const ELFIO::elfio& reader) {
    std::vector<ELFIO::section*> result;
    for (auto& section : reader.sections) {
        if (!section || !is_global_section(section->get_name())) {
            continue;
        }

        const auto type = section->get_type();
        if (type == ELFIO::SHT_NOBITS || (type == ELFIO::SHT_PROGBITS && section->get_size() != 0)) {
            result.push_back(section.get());
        }
    }
    return result;
}

RawProgram* find_subprogram(std::vector<RawProgram>& programs, const ELFIO::section& subprogram_section,
                            const std::string& symbol_name) {
    for (auto& subprog : programs) {
        if (subprog.section_name == subprogram_section.get_name() && subprog.function_name == symbol_name) {
            return &subprog;
        }
    }
    return nullptr;
}

ELFIO::elfio load_elf(std::istream& input_stream, const std::string& path) {
    ELFIO::elfio reader;
    if (!reader.load(input_stream)) {
        throw MalformedElf("Can't process ELF file " + path);
    }

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

// ---------------------------------------------------------------------------
// ProgramReader methods
// ---------------------------------------------------------------------------

void ProgramReader::record_function_relocation(FunctionRelocation reloc) {
    function_relocation_index_.emplace(reloc.prog_index, reloc.source_offset);
    function_relocations.push_back(std::move(reloc));
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

        const auto target_offset = gsl::narrow<ELFIO::Elf_Xword>(target * sizeof(EbpfInst));
        const auto target_name = find_function_symbol_at_offset(symbols, section_index, target_offset);
        if (!target_name) {
            throw UnmarshalError("Subprogram not found at section offset " + std::to_string(target_offset));
        }

        record_function_relocation(FunctionRelocation{
            .prog_index = raw_programs.size(),
            .source_offset = loc,
            .relocation_entry_index = std::nullopt,
            .target_section_index = section_index,
            .target_function_name = *target_name,
        });
    }
}

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
        const auto symbol_value = get_symbol_details(symbols, index).value;
        if (symbol_value % *record_size != 0) {
            throw UnmarshalError("Map symbol offset " + std::to_string(symbol_value) +
                                 " is not aligned to record size " + std::to_string(*record_size));
        }

        val = symbol_value / *record_size;
    } else {
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
            record_function_relocation(FunctionRelocation{
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
    if (symbol_name.empty()) {
        if (global.variable_section_indices.contains(symbol_section_index)) {
            if (!std::holds_alternative<MapOffsets>(global.map_record_size_or_map_offsets)) {
                return false;
            }

            auto [lo_inst, hi_inst] = validate_and_get_lddw_pair(instructions, location, "global variable");

            hi_inst.get().imm = compute_lddw_reloc_offset_imm(addend, index, lo_inst);
            lo_inst.get().src = INST_LD_MODE_MAP_VALUE;

            const std::string section_name = reader.sections[symbol_section_index]->get_name();
            lo_inst.get().imm = relocate_global_variable(section_name);
            return true;
        }
        return true;
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

        hi_inst.get().imm = compute_lddw_reloc_offset_imm(addend, index, lo_inst);
        lo_inst.get().src = INST_LD_MODE_MAP_VALUE;
        lo_inst.get().imm = relocate_global_variable(reader.sections[symbol_section_index]->get_name());
        return true;
    }

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

// ---------------------------------------------------------------------------
// Top-level read_elf functions
// ---------------------------------------------------------------------------

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

} // namespace prevail

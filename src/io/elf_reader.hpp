// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
//
// Internal header shared across elf_reader.cpp, elf_map_parser.cpp,
// elf_core_reloc.cpp and elf_extern_resolve.cpp.  Not part of the public API.
#pragma once

#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <elfio/elfio.hpp>
#include <libbtf/btf_parse.h>
#include <libbtf/btf_type_data.h>

#include "crab_utils/num_safety.hpp"
#include "io/elf_loader.hpp"
#include "platform.hpp"

namespace prevail {

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

struct parse_params_t {
    const std::string& path;
    const ebpf_verifier_options_t& options;
    const ebpf_platform_t* platform;
    const std::string desired_section;
};

struct symbol_details_t {
    std::string name;
    ELFIO::Elf64_Addr value{};
    ELFIO::Elf_Xword size{};
    unsigned char bind{};
    unsigned char type{};
    ELFIO::Elf_Half section_index{};
    unsigned char other{};
};

struct FunctionRelocation {
    size_t prog_index{};
    ELFIO::Elf_Xword source_offset{};
    std::optional<ELFIO::Elf_Xword> relocation_entry_index;
    ELFIO::Elf_Half target_section_index{};
    std::string target_function_name;
};

using MapOffsets = std::map<std::string, size_t>;

/// @brief EBPF-Global data extracted from an ELF file during parsing.
struct ElfGlobalData {
    std::set<ELFIO::Elf_Half> map_section_indices;
    std::vector<EbpfMapDescriptor> map_descriptors;
    std::variant<size_t, MapOffsets> map_record_size_or_map_offsets;
    std::set<ELFIO::Elf_Half> variable_section_indices;
};

// ---------------------------------------------------------------------------
// Relocation type constants
// ---------------------------------------------------------------------------

constexpr unsigned R_BPF_NONE_TYPE = 0;
constexpr unsigned R_BPF_64_64_TYPE = 1;
constexpr unsigned R_BPF_64_32_TYPE = 10;

// ---------------------------------------------------------------------------
// Utility functions (implemented in elf_reader.cpp)
// ---------------------------------------------------------------------------

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

bool is_map_section(const std::string& name);
bool is_global_section(const std::string& name);
std::string bad_reloc_value(size_t reloc_value);
bool is_supported_bpf_relocation_type(unsigned type);

symbol_details_t get_symbol_details(const ELFIO::const_symbol_section_accessor& symbols, ELFIO::Elf_Xword index);

std::tuple<std::string, ELFIO::Elf_Xword>
get_program_name_and_size(const ELFIO::section& sec, ELFIO::Elf_Xword start,
                          const ELFIO::const_symbol_section_accessor& symbols);

std::optional<std::string> find_function_symbol_at_offset(const ELFIO::const_symbol_section_accessor& symbols,
                                                          ELFIO::Elf_Half section_index, ELFIO::Elf_Xword offset);

ELFIO::Elf_Xword compute_reachable_program_span(const std::vector<EbpfInst>& section_instructions,
                                                ELFIO::Elf_Xword program_offset, ELFIO::Elf_Xword initial_size);

std::vector<ELFIO::section*> global_sections(const ELFIO::elfio& reader);

RawProgram* find_subprogram(std::vector<RawProgram>& programs, const ELFIO::section& subprogram_section,
                            const std::string& symbol_name);

std::pair<std::reference_wrapper<EbpfInst>, std::reference_wrapper<EbpfInst>>
validate_and_get_lddw_pair(std::vector<EbpfInst>& instructions, size_t location, const std::string& context);

ELFIO::elfio load_elf(std::istream& input_stream, const std::string& path);
ELFIO::const_symbol_section_accessor read_and_validate_symbol_section(const ELFIO::elfio& reader,
                                                                      const std::string& path);

// ---------------------------------------------------------------------------
// Extern symbol resolution (elf_extern_resolve.cpp)
// ---------------------------------------------------------------------------

std::optional<uint64_t> resolve_known_linux_extern_symbol(std::string_view symbol_name);
EbpfInst make_mov_reg_nop(uint8_t reg);
bool rewrite_extern_constant_load(std::vector<EbpfInst>& instructions, size_t location, uint64_t value);
bool rewrite_extern_address_load_to_zero(std::vector<EbpfInst>& instructions, size_t location);

// ---------------------------------------------------------------------------
// Map/global-data parsing (elf_map_parser.cpp)
// ---------------------------------------------------------------------------

ElfGlobalData extract_global_data(const parse_params_t& params, const ELFIO::elfio& reader,
                                  const ELFIO::const_symbol_section_accessor& symbols);

void update_line_info(std::vector<RawProgram>& raw_programs, const ELFIO::section* btf_section,
                      const ELFIO::section* btf_ext);

// ---------------------------------------------------------------------------
// ProgramReader class
// ---------------------------------------------------------------------------

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
    std::set<std::pair<size_t, size_t>> function_relocation_index_;
    std::vector<unresolved_symbol_error_t> unresolved_symbol_errors;
    /// Only negative IDs are platform-internal builtins needing the gate;
    /// positive IDs are standard BPF helpers handled via normal prototype lookup.
    std::set<size_t> builtin_offsets_for_current_program;

    // loop detection for recursive subprogram resolution
    std::map<const RawProgram*, bool> resolved_subprograms;
    std::set<const RawProgram*> currently_visiting;

    // CO-RE relocation (elf_core_reloc.cpp)
    static void apply_core_relocation(RawProgram& prog, const struct bpf_core_relo& relo,
                                      std::string_view access_string, const libbtf::btf_type_data& btf_data);
    void process_core_relocations(const libbtf::btf_type_data& btf_data);

    int32_t compute_lddw_reloc_offset_imm(ELFIO::Elf_Sxword addend, ELFIO::Elf_Word index,
                                          std::reference_wrapper<EbpfInst> lo_inst) const;
    [[nodiscard]]
    bool has_function_relocation(size_t prog_index, size_t source_offset) const;
    void enqueue_synthetic_local_calls(const std::vector<EbpfInst>& instructions, ELFIO::Elf_Half section_index,
                                       ELFIO::Elf_Xword program_offset);

    void record_function_relocation(FunctionRelocation reloc);

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

    bool try_reloc(const std::string& symbol_name, ELFIO::Elf_Half symbol_section_index, unsigned char symbol_type,
                   std::vector<EbpfInst>& instructions, size_t location, ELFIO::Elf_Word index,
                   ELFIO::Elf_Sxword addend);
    void process_relocations(std::vector<EbpfInst>& instructions, const ELFIO::const_relocation_section_accessor& reloc,
                             const std::string& section_name, ELFIO::Elf_Xword program_offset, size_t program_size);
    [[nodiscard]]
    const ELFIO::section* get_relocation_section(const std::string& name) const;
    void read_programs();
};

// ---------------------------------------------------------------------------
// Top-level read_elf (internal, used by ElfObject::Impl)
// ---------------------------------------------------------------------------

std::vector<RawProgram> read_elf(std::istream& input_stream, const std::string& path,
                                 const std::string& desired_section, const std::string& desired_program,
                                 const ebpf_verifier_options_t& options, const ebpf_platform_t* platform);

std::vector<RawProgram> read_elf(const std::string& path, const std::string& desired_section,
                                 const std::string& desired_program, const ebpf_verifier_options_t& options,
                                 const ebpf_platform_t* platform);

} // namespace prevail

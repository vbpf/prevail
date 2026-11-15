// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
//
// Internal header shared across elf_reader.cpp, elf_map_parser.cpp,
// elf_core_reloc.cpp and elf_extern_resolve.cpp.  Not part of the public API.
#pragma once

#include <compare>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
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
    const VerifierOptions& options;
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

/// A position in an ELF object: a section and a byte offset in that section.
struct SectionOffset {
    ELFIO::Elf_Half section_index{};
    ELFIO::Elf_Xword offset{};

    auto operator<=>(const SectionOffset&) const = default;
};

struct FunctionRelocation {
    size_t prog_index{};
    ELFIO::Elf_Xword source_offset{};
    std::optional<ELFIO::Elf_Xword> relocation_entry_index;
    /// Where the call lands. This identifies the callee; target_function_name is only for
    /// diagnostics (ELF symbol names need not be unique).
    SectionOffset target;
    std::string target_function_name;
    /// Index into raw_programs of the program whose code holds `target`, once every program has been read.
    std::optional<size_t> target_prog_index;
    /// Instruction index of `target` within that program: 0 unless the call lands on code that no FUNC symbol starts.
    size_t target_entry{};
};

/// The named STT_FUNC symbols of one section, as indices into the symbol table.
struct SectionFunctionSymbols {
    /// Offset in the section -> the first and the last symbol at that offset, in symbol table order.
    std::map<ELFIO::Elf_Xword, std::pair<ELFIO::Elf_Xword, ELFIO::Elf_Xword>> by_offset;
    /// The first symbol whose offset is not a multiple of the instruction size.
    std::optional<ELFIO::Elf_Xword> misaligned;
};

/// Named STT_FUNC symbols by section index. The symbol table is walked once per load to build this: the
/// number of programs, local calls and symbols, and the length of each symbol name, are all chosen by the
/// file, so looking a function up must not rescan the table.
using FunctionSymbols = std::map<ELFIO::Elf_Half, SectionFunctionSymbols>;

/// Symbol table index of a map symbol -> index of its descriptor in ElfGlobalData::map_descriptors.
/// Keyed by the identity of the symbol a relocation refers to, not by its name: ELF symbol names need not be unique.
using MapOffsets = std::map<ELFIO::Elf_Xword, size_t>;

/// @brief EBPF-Global data extracted from an ELF file during parsing.
struct ElfGlobalData {
    std::set<ELFIO::Elf_Half> map_section_indices;
    Cow<std::vector<EbpfMapDescriptor>> map_descriptors = Cow<std::vector<EbpfMapDescriptor>>::make();
    std::variant<size_t, MapOffsets> map_record_size_or_map_offsets;
    /// Global variable section index -> index of its implicit descriptor in map_descriptors
    /// (keyed by section index for the same reason: section names need not be unique either).
    std::map<ELFIO::Elf_Half, size_t> variable_section_indices;
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
std::vector<T> vector_of(const char* data, const ELFIO::Elf_Xword size) {
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

FunctionSymbols collect_function_symbols(const ELFIO::const_symbol_section_accessor& symbols);

std::tuple<std::string, ELFIO::Elf_Xword> get_program_name_and_size(const ELFIO::section& sec, ELFIO::Elf_Xword start,
                                                                    const ELFIO::const_symbol_section_accessor& symbols,
                                                                    const FunctionSymbols& function_symbols);

std::optional<std::string> find_function_symbol_at_offset(const ELFIO::const_symbol_section_accessor& symbols,
                                                          const FunctionSymbols& function_symbols,
                                                          ELFIO::Elf_Half section_index, ELFIO::Elf_Xword offset);

/// A place where control leaves a function's instructions other than by exit or by a call: a jump to an instruction
/// outside them, or an instruction that continues past the last of them.
struct ControlFlowEscape {
    size_t pc{};      ///< Index of the escaping instruction in the function.
    int64_t target{}; ///< Index, relative to the start of the function, where control would continue.
    bool is_jump{};   ///< A jump, rather than the fall-through of the last instruction.
};

/// The first escape of control from `instructions`, the code of one function. Calls are not escapes, since a callee
/// returns to the instruction after the call.
std::optional<ControlFlowEscape> find_control_flow_escape(const std::vector<EbpfInst>& instructions);

std::vector<ELFIO::section*> global_sections(const ELFIO::elfio& reader);

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
/// Indices of the instructions that some jump or local call in the program lands on.
/// Throws UnmarshalError if a jump leaves the program.
std::set<size_t> collect_jump_targets(const std::vector<EbpfInst>& instructions);
bool rewrite_extern_constant_load(std::vector<EbpfInst>& instructions, size_t location, uint64_t value,
                                  const std::set<size_t>& jump_targets);
bool rewrite_extern_address_load_to_zero(std::vector<EbpfInst>& instructions, size_t location);
bool rewrite_extern_kfunc_call(EbpfInst& instruction, const KsymBtfId& resolved_target);

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
    /// A relocation entry that try_reloc could not apply. It holds indices rather than text, so that its size does not
    /// depend on the length of the names the file supplies; the message is built only to report it.
    struct UnresolvedRelocation {
        size_t prog_index{}; ///< Index in raw_programs of the program holding the relocated instruction.
        size_t location{};   ///< Instruction index within that program.
        ELFIO::Elf_Word symbol_index{};
    };

    const parse_params_t& parse_params;
    const ELFIO::elfio& reader;
    const ELFIO::const_symbol_section_accessor& symbols;
    const ElfGlobalData& global;
    const FunctionSymbols function_symbols;
    std::vector<FunctionRelocation> function_relocations;
    std::set<std::pair<size_t, size_t>> function_relocation_index_;
    /// Maps the position where each program starts to its index in raw_programs.
    std::map<SectionOffset, size_t> raw_program_index_;
    std::map<std::string, std::optional<KsymBtfId>> ksym_function_resolution_cache;
    /// The relocation table of each section, by the index of the section it applies to (its sh_info).
    std::map<ELFIO::Elf_Word, const ELFIO::section*> relocation_section_cache;
    std::vector<UnresolvedRelocation> unresolved_relocations;
    /// Indices in raw_programs of the programs holding an entry of unresolved_relocations.
    std::set<size_t> programs_with_unresolved_relocations;
    /// Programs whose control flow leaves their own code other than by exit or a call, by index in raw_programs,
    /// with the description of the first such place.
    std::map<size_t, std::string> programs_with_escaping_control_flow;
    /// Only negative IDs are platform-internal builtins needing the gate;
    /// positive IDs are standard BPF helpers handled via normal prototype lookup.
    std::set<size_t> builtin_offsets_for_current_program;
    std::set<size_t> jump_targets_for_current_program;

    // CO-RE relocation (elf_core_reloc.cpp)
    static void apply_core_relocation(RawProgram& prog, const struct bpf_core_relo& relo,
                                      std::string_view access_string, const struct CoreBtf& btf);
    void process_core_relocations(const libbtf::btf_type_data& btf_data);

    int32_t compute_lddw_reloc_offset_imm(std::optional<ELFIO::Elf_Sxword> explicit_addend, ELFIO::Elf_Word index,
                                          std::reference_wrapper<EbpfInst> lo_inst) const;
    [[nodiscard]]
    bool has_function_relocation(size_t prog_index, size_t source_offset) const;
    [[nodiscard]]
    std::span<const FunctionRelocation> function_relocations_of(size_t prog_index) const;
    void resolve_function_relocation_targets();
    void build_ksym_function_resolution_cache();
    void build_relocation_section_cache();
    void enqueue_synthetic_local_calls(const std::vector<EbpfInst>& instructions, ELFIO::Elf_Half section_index,
                                       ELFIO::Elf_Xword program_offset);

    void record_function_relocation(FunctionRelocation reloc);
    /// The name of the function whose code holds `offset` of `section`: its FUNC symbol, or the section name for code
    /// before the first FUNC symbol of the section.
    [[nodiscard]]
    std::string name_of_function_containing(const ELFIO::section& section, ELFIO::Elf_Xword offset) const;
    [[nodiscard]]
    std::string describe_control_flow_escape(const ELFIO::section& section, ELFIO::Elf_Xword program_offset,
                                             const std::string& program_name, const ControlFlowEscape& escape) const;
    [[nodiscard]]
    std::string unresolved_relocation_message(const UnresolvedRelocation& unresolved) const;
    void read_programs(bool all_sections);

  public:
    struct section_error_t {
        std::string reason;
        std::vector<std::string> diagnostics;
    };

    std::vector<RawProgram> raw_programs;
    /// Filled by read_all_programs(): the sections whose programs failed to load, and why.
    std::map<std::string, section_error_t> section_errors;

    ProgramReader(const parse_params_t& p, const ELFIO::elfio& r, const ELFIO::const_symbol_section_accessor& s,
                  const ElfGlobalData& g)
        : parse_params{p}, reader{r}, symbols{s}, global{g}, function_symbols{collect_function_symbols(s)} {}

    std::string append_subprograms(RawProgram& prog, size_t prog_index) const;
    [[nodiscard]]
    int relocate_map(const std::string& name, ELFIO::Elf_Word index) const;
    [[nodiscard]]
    int relocate_global_variable(ELFIO::Elf_Half section_index) const;

    bool try_reloc(const std::string& symbol_name, ELFIO::Elf_Half symbol_section_index, unsigned char symbol_type,
                   unsigned char symbol_bind, std::vector<EbpfInst>& instructions, size_t location,
                   ELFIO::Elf_Word index, std::optional<ELFIO::Elf_Sxword> explicit_addend);
    void process_relocations(std::vector<EbpfInst>& instructions, const ELFIO::section& reloc,
                             const std::string& section_name, ELFIO::Elf_Xword program_offset, size_t program_size);
    [[nodiscard]]
    const ELFIO::section* get_relocation_section(const ELFIO::section& target) const;
    /// Reads every executable section and keeps the programs of parse_params.desired_section
    /// (all of them when it is empty); errors that would fail the load of that section are thrown.
    void read_programs();
    /// Like read_programs() for each section in turn, but in a single pass: keeps the programs of
    /// every section and records the errors local to one section in section_errors instead of
    /// throwing them.  Errors that fail the whole file are still thrown.
    void read_all_programs();
};

// ---------------------------------------------------------------------------
// Top-level read_elf (internal, used by ElfObject::Impl)
// ---------------------------------------------------------------------------

std::vector<RawProgram> read_elf(std::istream& input_stream, const std::string& path,
                                 const std::string& desired_section, const std::string& desired_program,
                                 const VerifierOptions& options, const ebpf_platform_t* platform);

std::vector<RawProgram> read_elf(const std::string& path, const std::string& desired_section,
                                 const std::string& desired_program, const VerifierOptions& options,
                                 const ebpf_platform_t* platform);

} // namespace prevail

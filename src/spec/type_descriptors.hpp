// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "spec/ebpf_base.h"
#include "spec/vm_isa.hpp"

namespace prevail {
enum class EbpfMapValueType { ANY, MAP, PROGRAM };

struct EbpfMapType {
    uint32_t platform_specific_type; // EbpfMapDescriptor.type value.
    std::string name;                // For ease of display, not used by the verifier.
    bool is_array;                   // True if key is integer in range [0,max_entries-1].
    EbpfMapValueType value_type;     // The type of items stored in the map.
};

struct EbpfMapDescriptor {
    int original_fd;
    uint32_t type; // Platform-specific type value in ELF file.
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    int inner_map_fd;
    std::string name;                  // Map name from ELF (empty if not available).
    bool is_inner_map_template{false}; // True if this descriptor is referenced as an inner map template.
};

struct EbpfProgramType {
    std::string name{}; // For ease of display, not used by the verifier.
    const ebpf_context_descriptor_t* context_descriptor{};
    uint64_t platform_specific_data{}; // E.g., integer program type.
    std::vector<std::string> section_prefixes{};
    bool is_privileged{};
};

// Represents the key characteristics that determine equivalence between eBPF maps.
// Used to cache and compare map configurations across the program.
struct EquivalenceKey {
    EbpfMapValueType value_type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    std::strong_ordering operator<=>(const EquivalenceKey&) const = default;
};

struct btf_line_info_t {
    std::string file_name{};
    std::string source_line{};
    uint32_t line_number{};
    uint32_t column_number{};
};

// Per-program environment: a reference to the immutable platform (PlatformSpec) plus the
// loader-derived facts that describe one program. Stable after ELF load; analysis-prep facts
// derived from the CFG (e.g. callback metadata) live on `Program`, not here.
struct ProgramInfo {
    // --- Platform reference (non-owning; immutable across programs) ---
    const struct ebpf_platform_t* platform{};

    // --- Loader outputs (populated during ELF parse; stable thereafter) ---
    std::vector<EbpfMapDescriptor> map_descriptors{};
    EbpfProgramType type{};
    std::map<size_t, btf_line_info_t> line_info{};
    // Raw per-program instruction indices rewritten from builtin relocations.
    std::set<size_t> builtin_call_offsets{};
};

struct RawProgram {
    std::string filename{};
    std::string section_name{};
    uint32_t insn_off{}; // Byte offset in section of first instruction in this program.
    std::string function_name{};
    std::vector<EbpfInst> prog{};
    ProgramInfo info{};
    size_t core_relocation_count{}; // Number of CO-RE relocation records applied to this program.
};

void print_map_descriptors(const std::vector<EbpfMapDescriptor>& descriptors, std::ostream& o);

std::ostream& operator<<(std::ostream& os, const btf_line_info_t& line_info);

} // namespace prevail

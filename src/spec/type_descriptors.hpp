// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "crab_utils/lazy_allocator.hpp"
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

struct ProgramInfo {
    const struct ebpf_platform_t* platform{};
    std::vector<EbpfMapDescriptor> map_descriptors{};
    EbpfProgramType type{};
    std::map<EquivalenceKey, int> cache{};
    std::map<size_t, btf_line_info_t> line_info{};
    // Valid top-level instruction labels that can be used as callback entry targets via PTR_TO_FUNC.
    std::set<int32_t> callback_target_labels{};
    // Subset of callback_target_labels for which a top-level Exit is reachable in the CFG.
    std::set<int32_t> callback_targets_with_exit{};
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
};

void print_map_descriptors(const std::vector<EbpfMapDescriptor>& descriptors, std::ostream& o);

std::ostream& operator<<(std::ostream& os, const btf_line_info_t& line_info);

extern thread_local LazyAllocator<ProgramInfo> thread_local_program_info;
} // namespace prevail

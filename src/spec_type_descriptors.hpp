// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <map>
#include <string>
#include <vector>

#include "crab_utils/lazy_allocator.hpp"
#include "ebpf_base.h"
#include "ebpf_vm_isa.hpp"

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
    unsigned int inner_map_fd;
};

constexpr unsigned int DEFAULT_MAP_FD = 0xffffffff;

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

struct program_info {
    const struct ebpf_platform_t* platform{};
    std::vector<EbpfMapDescriptor> map_descriptors{};
    EbpfProgramType type{};
    std::map<EquivalenceKey, int> cache{};
    std::map<int, btf_line_info_t> line_info{};
};

struct raw_program {
    std::string filename{};
    std::string section_name{};
    uint32_t insn_off{}; // Byte offset in section of first instruction in this program.
    std::string function_name{};
    std::vector<ebpf_inst> prog{};
    program_info info{};
};

void print_map_descriptors(const std::vector<EbpfMapDescriptor>& descriptors, std::ostream& o);

std::ostream& operator<<(std::ostream& os, const btf_line_info_t& line_info);

extern thread_local prevail::lazy_allocator<program_info> thread_local_program_info;

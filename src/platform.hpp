// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file provides a Platform Abstraction Layer where any environment
// that supports eBPF can have an ebpf_platform_t struct that the verifier
// can use to call platform-specific functions.

#include "../external/bpf_conformance/include/bpf_conformance.h"

#include "config.hpp"
#include "helpers.hpp"
#include "spec_type_descriptors.hpp"

namespace prevail {
typedef EbpfProgramType (*ebpf_get_program_type_fn)(const std::string& section, const std::string& path);

typedef EbpfMapType (*ebpf_get_map_type_fn)(uint32_t platform_specific_type);

typedef EbpfHelperPrototype (*ebpf_get_helper_prototype_fn)(int32_t n);

typedef bool (*ebpf_is_helper_usable_fn)(int32_t n);

#if 0
// Return an fd for a map created with the given parameters.
typedef int (*ebpf_create_map_fn)(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options);
#endif

// Parse map records and allocate map fd's.
// In the future we may want to move map fd allocation after the verifier step.
typedef void (*ebpf_parse_maps_section_fn)(std::vector<EbpfMapDescriptor>& map_descriptors, const char* data,
                                           size_t map_record_size, int map_count,
                                           const ebpf_platform_t* platform, ebpf_verifier_options_t options);
typedef void (*ebpf_resolve_inner_map_references_fn)(std::vector<EbpfMapDescriptor>& map_descriptors);

typedef EbpfMapDescriptor& (*ebpf_get_map_descriptor_fn)(int map_fd);

struct ebpf_platform_t {
    ebpf_get_program_type_fn get_program_type;
    ebpf_get_helper_prototype_fn get_helper_prototype;
    ebpf_is_helper_usable_fn is_helper_usable;

    // Size of a record in the "maps" section of an ELF file.
    size_t map_record_size;

    ebpf_parse_maps_section_fn parse_maps_section;
    ebpf_get_map_descriptor_fn get_map_descriptor;
    ebpf_get_map_type_fn get_map_type;
    ebpf_resolve_inner_map_references_fn resolve_inner_map_references;
    bpf_conformance_groups_t supported_conformance_groups;

    bool supports_group(bpf_conformance_groups_t group) const {
        return (supported_conformance_groups & group) == group;
    }
};

extern const ebpf_platform_t g_ebpf_platform_linux;
} // namespace prevail

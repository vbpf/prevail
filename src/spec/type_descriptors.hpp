// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <numeric>
#include <set>
#include <string>
#include <vector>

#include "crab/cow.hpp"
#include "spec/ebpf_base.h"
#include "spec/vm_isa.hpp"

namespace prevail {
enum class EbpfMapValueType { ANY, MAP, PROGRAM };

/// What a program, as opposed to user space, may do with the memory of a map's values. The values are those of the
/// shared_access variable of a register that points into such memory: reading needs shared_access <= 0 and writing
/// needs shared_access >= 0, so a register that may point into maps of different access may do only what all of
/// them allow.
enum class EbpfMapAccess : int { read_only = -1, read_write = 0, write_only = 1 };

struct EbpfMapType {
    uint32_t platform_specific_type{}; // EbpfMapDescriptor.type value.
    std::string name;                  // For ease of display, not used by the verifier.
    bool is_array{};                   // True if key is integer in range [0,max_entries-1].
    EbpfMapValueType value_type{};     // The type of items stored in the map.
    bool usable_in_sleepable{};        // True if a sleepable program may use maps of this type.
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
    EbpfMapAccess program_access{EbpfMapAccess::read_write}; // E.g., BPF_F_RDONLY_PROG, or the map behind .rodata.
};

/// @brief Distinct mock fds for maps of the given platform-specific types, starting at @p first_fd.
///
/// Maps are numbered by type, with declaration order breaking ties. A register that may hold one of several
/// maps holds an interval of fds, and map checks consider every fd in that interval, so numbering maps of one
/// type adjacently keeps an interval spanning compatible maps free of unrelated ones.
inline std::vector<int> mock_map_fds_by_type(const std::vector<uint32_t>& types, const int first_fd) {
    std::vector<size_t> order(types.size());
    std::iota(order.begin(), order.end(), size_t{0});
    std::ranges::stable_sort(order, {}, [&](const size_t i) { return types[i]; });
    std::vector<int> fds(types.size());
    int fd = first_fd;
    for (const size_t i : order) {
        fds[i] = fd++;
    }
    return fds;
}

struct EbpfStructDescriptor;

struct EbpfProgramType {
    std::string name{}; // For ease of display, not used by the verifier.
    const ebpf_ctx_descriptor_t* ctx_descriptor{};
    uint64_t platform_specific_data{}; // E.g., integer program type.
    std::vector<std::string> section_prefixes{};
    bool is_privileged{};
    bool is_sleepable{};
    // No store through the context pointer is allowed: the context is live kernel
    // state (e.g. the pt_regs of a probed function) rather than a scratch structure.
    bool ctx_read_only{};
    // LD_ABS/LD_IND may be used: they read through R6 as the platform's packet buffer object (an sk_buff on Linux),
    // so the context must be one.
    bool legacy_packet_access{};
    // Direct packet access may read but not write the packet.
    bool packet_read_only{};
    // The fields of the context and the accesses each one admits, for a runtime that does not run a context
    // access as written but rewrites it by the field it names (see context_access_requires_zero_offset in
    // ebpf_platform_t). A load or store through the context must then be an access that one field admits.
    // Null when the context is plain memory: any access within ctx_descriptor->size is allowed.
    const EbpfStructDescriptor* ctx_layout{};
};

enum class EbpfStructFieldPermission { read_only, read_write };

/// A field of a structure that the runtime exposes field by field, and the accesses it admits.
/// With allow_narrow_access, any access of a power-of-two width up to max_access_width that lies within the
/// field. Without it, only an access of exactly max_access_width at the start of the field.
/// Every access must also be aligned to its own width (is_valid_struct_access).
struct EbpfStructFieldDescriptor {
    int offset{};
    int span{};
    // Default read_only so a descriptor that omits an explicit permission fails
    // closed (rejects writes); writable fields must opt in with read_write.
    EbpfStructFieldPermission permission{EbpfStructFieldPermission::read_only};
    int max_access_width{};
    bool allow_narrow_access{};
    // Additional exact-width read allowed only at the field start.
    int extra_read_width_at_start{};
    // The field is an array of this many elements, `span` bytes each, of which `offset` is the first.
    // Each element admits the accesses described above.
    int count{1};
};

/// A field that admits only an access of its whole width.
constexpr EbpfStructFieldDescriptor
exact_field(const int offset, const int width,
            const EbpfStructFieldPermission permission = EbpfStructFieldPermission::read_only) {
    return {.offset = offset, .span = width, .permission = permission, .max_access_width = width};
}

/// A field that admits any aligned access of a power-of-two width within it.
constexpr EbpfStructFieldDescriptor
narrow_field(const int offset, const int width,
             const EbpfStructFieldPermission permission = EbpfStructFieldPermission::read_only) {
    return {.offset = offset,
            .span = width,
            .permission = permission,
            .max_access_width = width,
            .allow_narrow_access = true};
}

/// `count` consecutive copies of `element`, which describes the first.
constexpr EbpfStructFieldDescriptor array_of(EbpfStructFieldDescriptor element, const int count) {
    element.count = count;
    return element;
}

struct EbpfStructDescriptor {
    int size{};
    const EbpfStructFieldDescriptor* fields{};
    size_t field_count{};
};

struct btf_line_info_t {
    std::string file_name{};
    std::string source_line{};
    uint32_t line_number{};
    uint32_t column_number{};
};

// Per-program environment: a pointer to the immutable platform plus loader-derived facts
// for one program. Stable after ELF load. CFG-derived facts (e.g. callback metadata) live
// on `Program`, not here.
struct ProgramInfo {
    // --- Platform reference (non-owning; immutable across programs) ---
    const struct ebpf_platform_t* platform{};

    // --- Loader outputs (populated during ELF parse; stable thereafter) ---
    // One table per ELF object, shared by all of its programs rather than copied into each.
    Cow<std::vector<EbpfMapDescriptor>> map_descriptors = Cow<std::vector<EbpfMapDescriptor>>::make();
    EbpfProgramType type{};
    std::map<size_t, btf_line_info_t> line_info{};
    // Instruction indices rewritten from builtin-call relocations.
    std::set<size_t> builtin_call_offsets{};
    // Instruction indices of the lddw instructions that load the address of an extern symbol the loader cannot
    // resolve: whatever immediate they hold, the loader that resolves the symbol writes its address there, so
    // their destination holds an unknown number.
    std::set<size_t> extern_address_offsets{};
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

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <string>

namespace prevail {

// DataKind is eBPF-specific.
enum class DataKind {
    types,
    svalues,
    uvalues,
    ctx_offsets,
    map_fds,
    packet_offsets,
    shared_offsets,
    stack_offsets,
    shared_region_sizes,
    stack_numeric_sizes
};
constexpr auto KIND_MIN = DataKind::types;
constexpr auto KIND_MAX = DataKind::stack_numeric_sizes;

std::string name_of(DataKind kind);
DataKind regkind(const std::string& s);
std::vector<DataKind> iterate_kinds(DataKind lb = KIND_MIN, DataKind ub = KIND_MAX);
std::ostream& operator<<(std::ostream& o, const DataKind& s);

// The exact numbers are taken advantage of in EbpfDomain
enum TypeEncoding {
    T_UNINIT = -7,
    T_MAP_PROGRAMS = -6,
    T_MAP = -5,
    T_NUM = -4,
    T_CTX = -3,
    T_PACKET = -2,
    T_STACK = -1,
    T_SHARED = 0
};

constexpr TypeEncoding T_MIN = T_UNINIT;
constexpr TypeEncoding T_MAX = T_SHARED;

std::vector<TypeEncoding> iterate_types(TypeEncoding lb, TypeEncoding ub);
std::string typeset_to_string(const std::vector<TypeEncoding>& items);

std::ostream& operator<<(std::ostream& os, TypeEncoding s);
TypeEncoding string_to_type_encoding(const std::string& s);

enum class TypeGroup {
    empty,
    uninit,

    // Concrete/Conceptual Groups
    number,
    map_fd,          // E.g., for BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH
    map_fd_programs, // E.g., for BPF_MAP_TYPE_PROG_ARRAY
    ctx,
    packet,
    stack,
    shared,

    // Composed Groups - these are distinct elements in our lattice
    mem,             // stack | packet | shared
    pointer,         // ctx | mem
    ptr_or_num,      // pointer | number
    stack_or_packet, // stack | packet
    singleton_ptr,   // ctx | stack | packet
    mem_or_num,      // number | mem

    any, // Top of the lattice
};

bool is_singleton_type(TypeGroup t);
bool has_type(TypeGroup t, TypeEncoding enc);

std::ostream& operator<<(std::ostream& os, TypeGroup ts);
} // namespace prevail

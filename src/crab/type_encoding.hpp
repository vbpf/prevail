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
    map_fd_programs,
    packet_offsets,
    shared_offsets,
    stack_offsets,
    shared_region_sizes,
    stack_numeric_sizes
};
constexpr auto KIND_MIN = DataKind::types;
constexpr auto KIND_VALUE_MIN = DataKind::svalues;
constexpr auto KIND_MAX = DataKind::stack_numeric_sizes;

std::string name_of(DataKind kind);
DataKind regkind(const std::string& s);
std::vector<DataKind> iterate_kinds(DataKind lb = KIND_VALUE_MIN, DataKind ub = KIND_MAX);
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
constexpr TypeEncoding T_MIN_VALID = T_MAP_PROGRAMS;
constexpr TypeEncoding T_MAX = T_SHARED;

std::vector<TypeEncoding> iterate_types(TypeEncoding lb, TypeEncoding ub);
std::string typeset_to_string(const std::vector<TypeEncoding>& items);

std::ostream& operator<<(std::ostream& os, TypeEncoding s);
TypeEncoding string_to_type_encoding(const std::string& s);

enum class TypeGroup {
    number,
    map_fd,
    ctx,             ///< pointer to the special memory region named 'ctx'
    ctx_or_num,      ///< reg == T_NUM || reg == T_CTX
    packet,          ///< pointer to the packet
    stack,           ///< pointer to the stack
    stack_or_num,    ///< pointer to the stack or a null
    shared,          ///< pointer to shared memory
    map_fd_programs, ///< reg == T_MAP_PROGRAMS
    mem,             ///< shared | stack | packet = reg >= T_PACKET
    mem_or_num,      ///< reg >= T_NUM && reg != T_CTX
    pointer,         ///< reg >= T_CTX
    ptr_or_num,      ///< reg >= T_NUM
    stack_or_packet, ///< reg <= T_STACK && reg >= T_PACKET
    singleton_ptr,   ///< reg <= T_STACK && reg >= T_CTX
};

bool is_singleton_type(TypeGroup t);
std::ostream& operator<<(std::ostream& os, TypeGroup ts);
} // namespace prevail

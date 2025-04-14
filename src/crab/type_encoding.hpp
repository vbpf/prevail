// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <string>

namespace prevail {

// data_kind_t is eBPF-specific.
enum class data_kind_t {
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
constexpr auto KIND_MIN = data_kind_t::types;
constexpr auto KIND_MAX = data_kind_t::stack_numeric_sizes;

std::string name_of(data_kind_t kind);
data_kind_t regkind(const std::string& s);
std::vector<data_kind_t> iterate_kinds(data_kind_t lb = KIND_MIN, data_kind_t ub = KIND_MAX);
std::ostream& operator<<(std::ostream& o, const data_kind_t& s);

// The exact numbers are taken advantage of in ebpf_domain_t
enum type_encoding_t {
    T_UNINIT = -7,
    T_MAP_PROGRAMS = -6,
    T_MAP = -5,
    T_NUM = -4,
    T_CTX = -3,
    T_PACKET = -2,
    T_STACK = -1,
    T_SHARED = 0
};

constexpr type_encoding_t T_MIN = T_UNINIT;
constexpr type_encoding_t T_MAX = T_SHARED;

std::vector<type_encoding_t> iterate_types(type_encoding_t lb, type_encoding_t ub);
std::string typeset_to_string(const std::vector<type_encoding_t>& items);

std::ostream& operator<<(std::ostream& os, type_encoding_t s);
type_encoding_t string_to_type_encoding(const std::string& s);

enum class TypeGroup {
    number,
    map_fd,
    ctx,             ///< pointer to the special memory region named 'ctx'
    packet,          ///< pointer to the packet
    stack,           ///< pointer to the stack
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

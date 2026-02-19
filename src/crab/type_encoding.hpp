// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <bitset>
#include <initializer_list>
#include <optional>
#include <string>
#include <vector>

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
    stack_numeric_sizes,
    socket_offsets,
    btf_id_offsets,
    alloc_mem_offsets,
    alloc_mem_sizes,
};
constexpr auto KIND_MIN = DataKind::types;
constexpr auto KIND_VALUE_MIN = DataKind::svalues;
constexpr auto KIND_MAX = DataKind::alloc_mem_sizes;

std::string name_of(DataKind kind);
DataKind regkind(const std::string& s);
std::vector<DataKind> iterate_kinds(DataKind lb = KIND_VALUE_MIN, DataKind ub = KIND_MAX);
std::ostream& operator<<(std::ostream& o, const DataKind& s);

enum class TypeEncoding {
    T_UNINIT = 0,
    T_MAP_PROGRAMS = 1,
    T_MAP = 2,
    T_NUM = 3,
    T_CTX = 4,
    T_PACKET = 5,
    T_STACK = 6,
    T_SHARED = 7,
    T_SOCKET = 8,
    T_BTF_ID = 9,
    T_ALLOC_MEM = 10,
    T_FUNC = 11,
};
using enum TypeEncoding;
constexpr size_t NUM_TYPE_ENCODINGS = 12;

std::string typeset_to_string(const std::vector<TypeEncoding>& items);

std::ostream& operator<<(std::ostream& os, TypeEncoding s);
TypeEncoding string_to_type_encoding(const std::string& s);
std::optional<TypeEncoding> int_to_type_encoding(int v);

// ============================================================================
// TypeSet — compact u8 bitset over TypeEncoding values
// ============================================================================

/// Map a TypeEncoding to its bit position (0..7).
constexpr unsigned type_to_bit(const TypeEncoding te) { return static_cast<unsigned>(te); }

/// A compact bitset over the 8 TypeEncoding values, backed by std::bitset.
/// Join = OR, Meet = AND, subsumption = subset.
class TypeSet {
    std::bitset<NUM_TYPE_ENCODINGS> bits_;

    explicit TypeSet(std::bitset<NUM_TYPE_ENCODINGS> bits) : bits_{bits} {}

  public:
    TypeSet() = default;

    /// Build a TypeSet from one or more TypeEncoding values.
    /// Supports brace initialization: TypeSet{T_MAP, T_CTX}
    TypeSet(const std::initializer_list<TypeEncoding> types) {
        for (const auto te : types) {
            bits_.set(type_to_bit(te));
        }
    }

    /// The full set (all 8 types).
    static TypeSet all() {
        TypeSet result;
        result.bits_.set();
        return result;
    }

    // Lattice operations
    TypeSet operator|(const TypeSet o) const { return TypeSet{bits_ | o.bits_}; }
    TypeSet operator&(const TypeSet o) const { return TypeSet{bits_ & o.bits_}; }
    TypeSet operator~() const { return TypeSet{~bits_}; }
    TypeSet& operator|=(const TypeSet o) {
        bits_ |= o.bits_;
        return *this;
    }

    bool operator==(const TypeSet o) const { return bits_ == o.bits_; }
    bool operator!=(const TypeSet o) const { return bits_ != o.bits_; }

    /// Whether this set is empty.
    [[nodiscard]]
    bool is_empty() const {
        return bits_.none();
    }

    /// Whether this set contains exactly one type.
    [[nodiscard]]
    bool is_singleton() const {
        return bits_.count() == 1;
    }

    /// Number of types in the set.
    [[nodiscard]]
    int count() const {
        return static_cast<int>(bits_.count());
    }

    /// Whether this set contains a given type.
    [[nodiscard]]
    bool contains(const TypeEncoding te) const {
        return bits_.test(type_to_bit(te));
    }

    /// Whether self is a subset of other.
    [[nodiscard]]
    bool is_subset_of(const TypeSet other) const {
        return (bits_ & other.bits_) == bits_;
    }

    /// Remove a single type from the set.
    [[nodiscard]]
    TypeSet remove(const TypeEncoding te) const {
        auto copy = bits_;
        copy.reset(type_to_bit(te));
        return TypeSet{copy};
    }

    /// Get the singleton type, if exactly one element.
    [[nodiscard]]
    std::optional<TypeEncoding> as_singleton() const;

    /// Iterate over all types in this set, in encoding order.
    [[nodiscard]]
    std::vector<TypeEncoding> to_vector() const;

    /// Format as string: singleton -> "typename", multi -> "{t1, t2, ...}".
    [[nodiscard]]
    std::string to_string() const;
};

// Named type sets for common semantic groups.
extern const TypeSet TS_NUM;
extern const TypeSet TS_MAP;
extern const TypeSet TS_POINTER;
extern const TypeSet TS_SINGLETON_PTR;
extern const TypeSet TS_MEM;
extern const TypeSet TS_SOCKET;
extern const TypeSet TS_BTF_ID;
extern const TypeSet TS_ALLOC_MEM;

// ============================================================================
// TypeGroup
// ============================================================================

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
    mem,             ///< shared | stack | packet
    mem_or_num,      ///< mem | number
    pointer,         ///< any pointer type (ctx | packet | stack | shared | socket | btf_id | alloc_mem)
    ptr_or_num,      ///< pointer | number
    stack_or_packet, ///< stack | packet
    singleton_ptr,   ///< ctx | packet | stack (NOT "single region" — see is_singleton_type())
    socket,          ///< pointer to a socket structure
    btf_id,          ///< pointer to a BTF-typed kernel object
    alloc_mem,       ///< pointer to helper-allocated memory
    func,            ///< pointer to a BPF function (callback)
};

/// Convert a TypeGroup to its corresponding TypeSet.
TypeSet to_typeset(TypeGroup group);

bool is_singleton_type(TypeGroup t);
std::ostream& operator<<(std::ostream& os, TypeGroup ts);
} // namespace prevail

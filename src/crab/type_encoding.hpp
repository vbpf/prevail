// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <vector>

#include "crab/small_bitset_domain.hpp"

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
std::optional<TypeEncoding> int_to_type_encoding(int v);

// ============================================================================
// TypeSet — compact u8 bitset over TypeEncoding values
// ============================================================================

/// Map a TypeEncoding to its bit position (0..7).
constexpr unsigned type_to_bit(const TypeEncoding te) { return static_cast<unsigned>(static_cast<int>(te) + 7); }

/// A compact bitset over the 8 TypeEncoding values.
/// Uses SmallBitsetDomain<uint8_t> for lattice operations (join = OR, meet = AND,
/// subsumption = subset). Adds type-specific accessors (contains, singleton, remove
/// by TypeEncoding).
class TypeSet {
    SmallBitsetDomain<uint8_t> dom_;

  public:
    constexpr TypeSet() = default;
    constexpr explicit TypeSet(uint8_t bits) : dom_{bits} {}

    /// The empty set.
    static constexpr TypeSet empty() { return TypeSet{0}; }
    /// The full set (all 8 types).
    static constexpr TypeSet all() { return TypeSet{0xFF}; }

    /// Singleton set containing one type.
    static constexpr TypeSet singleton(const TypeEncoding te) {
        return TypeSet{static_cast<uint8_t>(1u << type_to_bit(te))};
    }

    /// Build a TypeSet from a list of TypeEncoding values.
    static constexpr TypeSet of(const std::initializer_list<TypeEncoding> types) {
        TypeSet result = empty();
        for (const auto te : types) {
            result |= singleton(te);
        }
        return result;
    }

    // Lattice operations delegated to SmallBitsetDomain
    constexpr TypeSet operator|(const TypeSet o) const { return TypeSet{(dom_ | o.dom_).raw()}; }
    constexpr TypeSet operator&(const TypeSet o) const { return TypeSet{(dom_ & o.dom_).raw()}; }
    constexpr TypeSet operator~() const { return TypeSet{(~dom_).raw()}; }
    constexpr TypeSet& operator|=(const TypeSet o) { dom_ |= o.dom_; return *this; }

    constexpr bool operator==(const TypeSet o) const { return dom_ == o.dom_; }
    constexpr bool operator!=(const TypeSet o) const { return dom_ != o.dom_; }

    /// Whether this set is empty.
    [[nodiscard]] constexpr bool is_empty() const { return dom_.is_empty(); }
    /// Whether this set contains exactly one type.
    [[nodiscard]] constexpr bool is_singleton() const { return dom_.is_singleton(); }
    /// Number of types in the set.
    [[nodiscard]] int count() const { return dom_.count(); }
    /// Raw bits (for hashing/debugging).
    [[nodiscard]] constexpr uint8_t raw() const { return dom_.raw(); }

    /// Whether this set contains a given type.
    [[nodiscard]] constexpr bool contains(const TypeEncoding te) const { return dom_.test(type_to_bit(te)); }

    /// Whether self is a subset of other.
    [[nodiscard]] constexpr bool is_subset_of(const TypeSet o) const { return dom_ <= o.dom_; }

    /// Remove a single type from the set.
    [[nodiscard]] constexpr TypeSet remove(const TypeEncoding te) const {
        auto copy = dom_;
        copy.reset(type_to_bit(te));
        return TypeSet{copy.raw()};
    }

    /// Get the singleton type, if exactly one element.
    [[nodiscard]] std::optional<TypeEncoding> as_singleton() const;

    /// Iterate over all types in this set, in encoding order.
    [[nodiscard]] std::vector<TypeEncoding> to_vector() const;

    /// Format as string: singleton → "typename", multi → "{t1, t2, ...}".
    [[nodiscard]] std::string to_string() const;
};

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
    mem,             ///< shared | stack | packet = reg >= T_PACKET
    mem_or_num,      ///< reg >= T_NUM && reg != T_CTX
    pointer,         ///< reg >= T_CTX
    ptr_or_num,      ///< reg >= T_NUM
    stack_or_packet, ///< reg <= T_STACK && reg >= T_PACKET
    singleton_ptr,   ///< reg <= T_STACK && reg >= T_CTX
};

/// Convert a TypeGroup to its corresponding TypeSet.
TypeSet to_typeset(TypeGroup group);

bool is_singleton_type(TypeGroup t);
std::ostream& operator<<(std::ostream& os, TypeGroup ts);
} // namespace prevail

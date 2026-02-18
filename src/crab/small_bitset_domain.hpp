// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <bit>
#include <type_traits>

namespace prevail {

/// A bitwise lattice over a small unsigned integer (up to 64 bits).
///
/// Join = bitwise OR, Meet = bitwise AND, Top = all-ones, Bottom = zero.
/// Subsumption: a <= b iff (a | b) == b (i.e. a's bits are a subset of b's).
///
/// This is the same lattice structure used by BitsetDomain (for stack tracking)
/// but for small, fixed-width bitsets stored in a single integer.
template <typename UInt>
class SmallBitsetDomain {
    static_assert(std::is_unsigned_v<UInt>, "SmallBitsetDomain requires an unsigned integer type");
    UInt bits_{};

  public:
    constexpr SmallBitsetDomain() = default;
    constexpr explicit SmallBitsetDomain(UInt bits) : bits_{bits} {}

    // Lattice operations (bitwise)
    constexpr SmallBitsetDomain operator|(const SmallBitsetDomain o) const {
        return SmallBitsetDomain{static_cast<UInt>(bits_ | o.bits_)};
    }
    constexpr SmallBitsetDomain operator&(const SmallBitsetDomain o) const {
        return SmallBitsetDomain{static_cast<UInt>(bits_ & o.bits_)};
    }
    constexpr SmallBitsetDomain operator~() const { return SmallBitsetDomain{static_cast<UInt>(~bits_)}; }
    constexpr SmallBitsetDomain& operator|=(const SmallBitsetDomain o) {
        bits_ |= o.bits_;
        return *this;
    }
    constexpr SmallBitsetDomain& operator&=(const SmallBitsetDomain o) {
        bits_ &= o.bits_;
        return *this;
    }

    /// Subsumption: a <= b iff a's bits are a subset of b's bits.
    constexpr bool operator<=(const SmallBitsetDomain o) const { return (bits_ | o.bits_) == o.bits_; }
    constexpr bool operator==(const SmallBitsetDomain o) const { return bits_ == o.bits_; }
    constexpr bool operator!=(const SmallBitsetDomain o) const { return bits_ != o.bits_; }

    constexpr SmallBitsetDomain widen(const SmallBitsetDomain o) const { return *this | o; }
    constexpr SmallBitsetDomain narrow(const SmallBitsetDomain o) const { return *this & o; }

    // Bit access
    [[nodiscard]]
    constexpr bool test(unsigned i) const {
        return (bits_ & (UInt{1} << i)) != 0;
    }
    constexpr void set(unsigned i) { bits_ |= (UInt{1} << i); }
    constexpr void reset(unsigned i) { bits_ &= ~(UInt{1} << i); }

    [[nodiscard]]
    constexpr bool is_empty() const {
        return bits_ == 0;
    }
    [[nodiscard]]
    constexpr bool is_singleton() const {
        return bits_ != 0 && (bits_ & (bits_ - 1)) == 0;
    }
    [[nodiscard]]
    constexpr int count() const {
        return std::popcount(bits_);
    }

    /// The underlying integer value.
    [[nodiscard]]
    constexpr UInt raw() const {
        return bits_;
    }
};

} // namespace prevail

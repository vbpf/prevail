// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// Portable 128-bit integers used only as an intermediate representation for widening
// arithmetic over <=64-bit eBPF values (see num_big.hpp). GCC/Clang use native __int128;
// this header provides a Boost-free fallback for compilers without a 128-bit builtin
// (MSVC), so consumers of the installed library do not need Boost.Multiprecision.
//
// Semantics match two's-complement __int128 exactly: wrap-around add/sub/mul, truncation-
// toward-zero div/mod, arithmetic right shift, and signed/unsigned comparisons. Correctness
// is checked against native __int128 in test_int128.cpp and by running the whole test suite
// with -DPREVAIL_FORCE_CUSTOM_INT128 on a platform that has __int128.

#include <compare>
#include <concepts>
#include <cstdint>
#include <type_traits>

namespace prevail::detail {

struct Int128Custom;

// Unsigned 128-bit integer as two 64-bit limbs (little-endian: lo is the low 64 bits).
struct UInt128Custom {
    uint64_t lo{};
    uint64_t hi{};

    constexpr UInt128Custom() = default;
    constexpr UInt128Custom(const uint64_t high, const uint64_t low) : lo{low}, hi{high} {}

    // From any integral: unsigned zero-extends, signed sign-extends (two's complement).
    template <std::integral T>
    constexpr UInt128Custom(const T v)
        : lo{static_cast<uint64_t>(v)},
          hi{(std::is_signed_v<T> && v < 0) ? ~static_cast<uint64_t>(0) : static_cast<uint64_t>(0)} {}

    constexpr UInt128Custom(const Int128Custom& v);

    // Explicit narrowing to a builtin integral: take the low bits (matches static_cast from __int128).
    template <std::integral T>
    explicit constexpr operator T() const {
        return static_cast<T>(lo);
    }
    explicit constexpr operator bool() const { return (lo | hi) != 0; }

    // -- comparisons --
    constexpr bool operator==(const UInt128Custom& o) const { return lo == o.lo && hi == o.hi; }
    constexpr auto operator<=>(const UInt128Custom& o) const {
        if (hi != o.hi) {
            return hi <=> o.hi;
        }
        return lo <=> o.lo;
    }

    // -- bitwise --
    constexpr UInt128Custom operator~() const { return {~hi, ~lo}; }
    constexpr UInt128Custom operator&(const UInt128Custom& o) const { return {hi & o.hi, lo & o.lo}; }
    constexpr UInt128Custom operator|(const UInt128Custom& o) const { return {hi | o.hi, lo | o.lo}; }
    constexpr UInt128Custom operator^(const UInt128Custom& o) const { return {hi ^ o.hi, lo ^ o.lo}; }

    constexpr UInt128Custom operator<<(const int s) const {
        if (s <= 0) {
            return *this;
        }
        if (s >= 128) {
            return {};
        }
        if (s >= 64) {
            return {lo << (s - 64), 0};
        }
        return {(hi << s) | (lo >> (64 - s)), lo << s};
    }
    constexpr UInt128Custom operator>>(const int s) const {
        if (s <= 0) {
            return *this;
        }
        if (s >= 128) {
            return {};
        }
        if (s >= 64) {
            return {0, hi >> (s - 64)};
        }
        return {hi >> s, (lo >> s) | (hi << (64 - s))};
    }

    // -- arithmetic (wrap-around, two's complement) --
    constexpr UInt128Custom operator-() const {
        // ~x + 1
        const uint64_t nlo = ~lo + 1;
        const uint64_t carry = nlo == 0 ? 1 : 0;
        return {~hi + carry, nlo};
    }
    constexpr UInt128Custom operator+(const UInt128Custom& o) const {
        const uint64_t nlo = lo + o.lo;
        const uint64_t carry = nlo < lo ? 1 : 0;
        return {hi + o.hi + carry, nlo};
    }
    constexpr UInt128Custom operator-(const UInt128Custom& o) const { return *this + (-o); }

    constexpr UInt128Custom operator*(const UInt128Custom& o) const {
        // 64x64 -> 128 for the low product, plus cross terms into hi.
        const uint64_t a0 = lo & 0xffffffffULL, a1 = lo >> 32;
        const uint64_t b0 = o.lo & 0xffffffffULL, b1 = o.lo >> 32;
        const uint64_t p00 = a0 * b0;
        const uint64_t p01 = a0 * b1;
        const uint64_t p10 = a1 * b0;
        const uint64_t p11 = a1 * b1;
        const uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffULL) + (p10 & 0xffffffffULL);
        const uint64_t reslo = (p00 & 0xffffffffULL) | (mid << 32);
        const uint64_t reshi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32) + lo * o.hi + hi * o.lo;
        return {reshi, reslo};
    }

    // Unsigned division and modulo via binary long division. Precondition: divisor != 0.
    static constexpr void divmod(const UInt128Custom& n, const UInt128Custom& d, UInt128Custom& q, UInt128Custom& r) {
        q = UInt128Custom{};
        r = UInt128Custom{};
        for (int i = 127; i >= 0; --i) {
            r = r << 1;
            const uint64_t bit = (i >= 64) ? ((n.hi >> (i - 64)) & 1) : ((n.lo >> i) & 1);
            r.lo |= bit;
            if (r >= d) {
                r = r - d;
                if (i >= 64) {
                    q.hi |= (uint64_t{1} << (i - 64));
                } else {
                    q.lo |= (uint64_t{1} << i);
                }
            }
        }
    }
    constexpr UInt128Custom operator/(const UInt128Custom& o) const {
        UInt128Custom q, r;
        divmod(*this, o, q, r);
        return q;
    }
    constexpr UInt128Custom operator%(const UInt128Custom& o) const {
        UInt128Custom q, r;
        divmod(*this, o, q, r);
        return r;
    }

    constexpr UInt128Custom& operator+=(const UInt128Custom& o) { return *this = *this + o; }
    constexpr UInt128Custom& operator-=(const UInt128Custom& o) { return *this = *this - o; }
    constexpr UInt128Custom& operator*=(const UInt128Custom& o) { return *this = *this * o; }
    constexpr UInt128Custom& operator/=(const UInt128Custom& o) { return *this = *this / o; }
    constexpr UInt128Custom& operator%=(const UInt128Custom& o) { return *this = *this % o; }
    constexpr UInt128Custom& operator&=(const UInt128Custom& o) { return *this = *this & o; }
    constexpr UInt128Custom& operator|=(const UInt128Custom& o) { return *this = *this | o; }
    constexpr UInt128Custom& operator^=(const UInt128Custom& o) { return *this = *this ^ o; }
    constexpr UInt128Custom& operator>>=(const int s) { return *this = *this >> s; }
    constexpr UInt128Custom& operator<<=(const int s) { return *this = *this << s; }
};

// Signed 128-bit integer, stored as its two's-complement bit pattern in a UInt128Custom.
struct Int128Custom {
    UInt128Custom u{};

    constexpr Int128Custom() = default;
    constexpr Int128Custom(const UInt128Custom v) : u{v} {}

    template <std::integral T>
    constexpr Int128Custom(const T v) : u{v} {}

    template <std::integral T>
    explicit constexpr operator T() const {
        return static_cast<T>(u.lo);
    }
    explicit constexpr operator bool() const { return static_cast<bool>(u); }

    [[nodiscard]]
    constexpr bool negative() const {
        return (u.hi >> 63) != 0;
    }

    // -- comparisons (signed) --
    constexpr bool operator==(const Int128Custom& o) const { return u == o.u; }
    constexpr auto operator<=>(const Int128Custom& o) const {
        const auto lhi = static_cast<int64_t>(u.hi);
        const auto rhi = static_cast<int64_t>(o.u.hi);
        if (lhi != rhi) {
            return lhi <=> rhi;
        }
        return u.lo <=> o.u.lo;
    }

    // -- bitwise --
    constexpr Int128Custom operator~() const { return {~u}; }
    constexpr Int128Custom operator&(const Int128Custom& o) const { return {u & o.u}; }
    constexpr Int128Custom operator|(const Int128Custom& o) const { return {u | o.u}; }
    constexpr Int128Custom operator^(const Int128Custom& o) const { return {u ^ o.u}; }
    constexpr Int128Custom operator<<(const int s) const { return {u << s}; }
    constexpr Int128Custom operator>>(const int s) const {
        // Arithmetic (sign-extending) right shift.
        if (s <= 0) {
            return *this;
        }
        const UInt128Custom logical = u >> s;
        if (!negative()) {
            return {logical};
        }
        // Fill the vacated high bits with ones.
        const UInt128Custom ones = ~UInt128Custom{};
        const UInt128Custom mask = s >= 128 ? ones : (ones << (128 - s));
        return {logical | mask};
    }

    // -- arithmetic (wrap-around; div/mod truncate toward zero, like __int128) --
    constexpr Int128Custom operator-() const { return {-u}; }
    constexpr Int128Custom operator+(const Int128Custom& o) const { return {u + o.u}; }
    constexpr Int128Custom operator-(const Int128Custom& o) const { return {u - o.u}; }
    constexpr Int128Custom operator*(const Int128Custom& o) const { return {u * o.u}; }

    constexpr Int128Custom operator/(const Int128Custom& o) const {
        const bool neg = negative() != o.negative();
        const UInt128Custom a = negative() ? (-u) : u;
        const UInt128Custom b = o.negative() ? (-o.u) : o.u;
        const UInt128Custom q = a / b;
        return {neg ? -q : q};
    }
    constexpr Int128Custom operator%(const Int128Custom& o) const {
        // Result takes the sign of the dividend (truncation toward zero).
        const UInt128Custom a = negative() ? (-u) : u;
        const UInt128Custom b = o.negative() ? (-o.u) : o.u;
        const UInt128Custom r = a % b;
        return {negative() ? -r : r};
    }

    constexpr Int128Custom& operator+=(const Int128Custom& o) { return *this = *this + o; }
    constexpr Int128Custom& operator-=(const Int128Custom& o) { return *this = *this - o; }
    constexpr Int128Custom& operator*=(const Int128Custom& o) { return *this = *this * o; }
    constexpr Int128Custom& operator/=(const Int128Custom& o) { return *this = *this / o; }
    constexpr Int128Custom& operator%=(const Int128Custom& o) { return *this = *this % o; }
    constexpr Int128Custom& operator&=(const Int128Custom& o) { return *this = *this & o; }
    constexpr Int128Custom& operator|=(const Int128Custom& o) { return *this = *this | o; }
    constexpr Int128Custom& operator^=(const Int128Custom& o) { return *this = *this ^ o; }
    constexpr Int128Custom& operator<<=(const int s) { return *this = *this << s; }
    constexpr Int128Custom& operator>>=(const int s) { return *this = *this >> s; }
};

constexpr UInt128Custom::UInt128Custom(const Int128Custom& v) : lo{v.u.lo}, hi{v.u.hi} {}

} // namespace prevail::detail

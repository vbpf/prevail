// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cassert>
#include <climits>
#include <cstdint>
#include <functional>
#include <sstream>
#include <string>

#ifdef __GNUC__
// GCC/Clang: use compiler-native 128-bit integers.
#else
#include <boost/multiprecision/cpp_int.hpp>
#endif

#include "crab_utils/debug.hpp"
#include "crab_utils/num_safety.hpp"

namespace prevail {

// Number is an abstract-interpretation value for eBPF verification.
// All inputs and outputs are ≤64-bit; i128 is used as intermediate
// representation to hold results of widening arithmetic (e.g. add two
// int64 values) without overflow, not as general 128-bit integer support.

// --- Int128 type aliases ---
#ifdef __GNUC__
using Int128 = __int128;
using UInt128 = unsigned __int128;
#else
using Int128 = boost::multiprecision::int128_t;
using UInt128 = boost::multiprecision::uint128_t;
#endif

// Manual min/max since std::numeric_limits<__int128> is unspecialized.
inline constexpr UInt128 kUInt128Max = ~static_cast<UInt128>(0);
inline constexpr Int128 kInt128Max = static_cast<Int128>(kUInt128Max >> 1);
inline constexpr Int128 kInt128Min = -kInt128Max - 1;

// --- Checked arithmetic helpers ---

inline Int128 checked_add(const Int128 a, const Int128 b) {
#ifdef __GNUC__
    Int128 result;
    if (__builtin_add_overflow(a, b, &result)) {
        CRAB_ERROR("Number overflow during addition");
    }
    return result;
#else
    if ((b > 0 && a > kInt128Max - b) || (b < 0 && a < kInt128Min - b)) {
        CRAB_ERROR("Number overflow during addition");
    }
    return a + b;
#endif
}

inline Int128 checked_sub(const Int128 a, const Int128 b) {
#ifdef __GNUC__
    Int128 result;
    if (__builtin_sub_overflow(a, b, &result)) {
        CRAB_ERROR("Number overflow during subtraction");
    }
    return result;
#else
    if ((b < 0 && a > kInt128Max + b) || (b > 0 && a < kInt128Min + b)) {
        CRAB_ERROR("Number overflow during subtraction");
    }
    return a - b;
#endif
}

inline Int128 checked_mul(const Int128 a, const Int128 b) {
#ifdef __GNUC__
    Int128 result;
    if (__builtin_mul_overflow(a, b, &result)) {
        CRAB_ERROR("Number overflow during multiplication");
    }
    return result;
#else
    if (a != 0 && b != 0) {
        if ((a > 0 && b > 0 && a > kInt128Max / b) || (a < 0 && b < 0 && a < kInt128Max / b) ||
            (a > 0 && b < 0 && b < kInt128Min / a) || (a < 0 && b > 0 && a < kInt128Min / b)) {
            CRAB_ERROR("Number overflow during multiplication");
        }
    }
    return a * b;
#endif
}

inline Int128 checked_div(const Int128 a, const Int128 b) {
    if (b == 0) {
        CRAB_ERROR("Number: division by zero");
    }
    if (a == kInt128Min && b == -1) {
        CRAB_ERROR("Number overflow during division");
    }
    return a / b;
}

inline Int128 checked_mod(const Int128 a, const Int128 b) {
    if (b == 0) {
        CRAB_ERROR("Number: division by zero");
    }
    if (a == kInt128Min && b == -1) {
        CRAB_ERROR("Number overflow during modulo");
    }
    return a % b;
}

inline Int128 checked_neg(const Int128 a) {
    if (a == kInt128Min) {
        CRAB_ERROR("Number overflow during negation");
    }
    return -a;
}

// Count leading zeros for a 128-bit value. Returns 128 when n == 0.
inline int clz128(const UInt128 n) {
    const auto hi = static_cast<uint64_t>(n >> 64);
    const auto lo = static_cast<uint64_t>(n);
    if (hi != 0) {
#ifdef __GNUC__
        return __builtin_clzll(hi);
#else
        int count = 0;
        for (uint64_t mask = uint64_t(1) << 63; mask != 0 && !(hi & mask); mask >>= 1) {
            count++;
        }
        return count;
#endif
    }
    if (lo != 0) {
#ifdef __GNUC__
        return 64 + __builtin_clzll(lo);
#else
        int count = 0;
        for (uint64_t mask = uint64_t(1) << 63; mask != 0 && !(lo & mask); mask >>= 1) {
            count++;
        }
        return 64 + count;
#endif
    }
    return 128;
}

// Parse a decimal string into Int128. Only decimal digits are accepted;
// hex/octal prefixes are not supported.
inline Int128 parse_decimal_int128(const std::string& s) {
    if (s.empty()) {
        CRAB_ERROR("Number: empty string");
    }
    bool negative = false;
    size_t i = 0;
    if (s[0] == '-') {
        negative = true;
        i = 1;
    } else if (s[0] == '+') {
        i = 1;
    }
    if (i >= s.size()) {
        CRAB_ERROR("Number: invalid string '", s, "'");
    }
    // Accumulate in unsigned to avoid signed overflow UB.
    UInt128 result = 0;
    for (; i < s.size(); i++) {
        const char c = s[i];
        if (c < '0' || c > '9') {
            CRAB_ERROR("Number: invalid character in string '", s, "'");
        }
        const UInt128 prev = result;
        result = result * 10 + static_cast<UInt128>(c - '0');
        if (result / 10 != prev) {
            CRAB_ERROR("Number: overflow parsing string '", s, "'");
        }
    }
    if (negative) {
        if (result > static_cast<UInt128>(kInt128Max) + 1) {
            CRAB_ERROR("Number: overflow parsing string '", s, "'");
        }
        return -static_cast<Int128>(result - 1) - 1;
    }
    if (result > static_cast<UInt128>(kInt128Max)) {
        CRAB_ERROR("Number: overflow parsing string '", s, "'");
    }
    return static_cast<Int128>(result);
}

class Number final {
    Int128 _n{};

  public:
    constexpr Number() = default;
    constexpr Number(const Int128 n) : _n{n} {}
    constexpr Number(std::integral auto n) : _n{static_cast<Int128>(n)} {}
    constexpr Number(is_enum auto n) : _n{static_cast<Int128>(static_cast<std::underlying_type_t<decltype(n)>>(n))} {}
    explicit Number(const std::string& s) : _n{parse_decimal_int128(s)} {}

    template <std::integral T>
    T narrow() const {
        if (!fits<T>()) {
            CRAB_ERROR("Number ", *this, " does not fit into ", typeid(T).name());
        }
        return static_cast<T>(_n);
    }

    template <is_enum T>
    T narrow() const {
        using underlying = std::underlying_type_t<T>;
        if (!fits<underlying>()) {
            CRAB_ERROR("Number ", *this, " does not fit into ", typeid(T).name());
        }
        return static_cast<T>(static_cast<underlying>(_n));
    }

    template <is_enum T>
    constexpr T cast_to() const {
        return static_cast<T>(cast_to<std::underlying_type_t<T>>());
    }

    [[nodiscard]]
    friend std::size_t hash_value(const Number& z) {
        // Hash by combining high and low 64-bit halves.
        const auto lo = static_cast<uint64_t>(static_cast<UInt128>(z._n));
        const auto hi = static_cast<uint64_t>(static_cast<UInt128>(z._n) >> 64);
        return std::hash<uint64_t>{}(lo) ^ (std::hash<uint64_t>{}(hi) * 2654435761u);
    }

    template <std::integral T>
    [[nodiscard]]
    constexpr bool fits() const {
        return static_cast<Int128>(std::numeric_limits<T>::min()) <= _n &&
               _n <= static_cast<Int128>(std::numeric_limits<T>::max());
    }

    template <std::integral T>
    [[nodiscard]]
    constexpr bool fits_cast_to() const {
        return fits<T>() || fits<SwapSignedness<T>>();
    }

    template <std::integral T>
    [[nodiscard]]
    T cast_to() const {
        if (fits<T>()) {
            return static_cast<T>(_n);
        }
        using Q = SwapSignedness<T>;
        if (fits<Q>()) {
            return static_cast<T>(static_cast<Q>(_n));
        }
        CRAB_ERROR("Number ", *this, " does not fit into ", typeid(T).name());
    }

    [[nodiscard]]
    Number cast_to_sint(const int width) const {
        switch (width) {
        case 0: return *this;
        case 8: return cast_to<int8_t>();
        case 16: return cast_to<int16_t>();
        case 32: return cast_to<int32_t>();
        case 64: return cast_to<int64_t>();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    [[nodiscard]]
    Number cast_to_uint(const int width) const {
        switch (width) {
        case 0: return *this;
        case 8: return cast_to<uint8_t>();
        case 16: return cast_to<uint16_t>();
        case 32: return cast_to<uint32_t>();
        case 64: return cast_to<uint64_t>();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    template <std::integral T>
    constexpr T truncate_to() const {
        using U = std::make_unsigned_t<T>;
        constexpr auto mask = static_cast<UInt128>(std::numeric_limits<U>::max());
        return static_cast<T>(static_cast<U>(static_cast<UInt128>(_n) & mask));
    }

    // Width must be in [0, 64]; 0 means no truncation.
    [[nodiscard]]
    Number sign_extend(const int width) const {
        if (width == 0) {
            return *this;
        }
        assert(width > 0 && width <= 64);
        const Int128 mask = (static_cast<Int128>(1) << width) - 1;
        const Int128 sign_bit = static_cast<Int128>(1) << (width - 1);
        const Int128 truncated = _n & mask;
        if (truncated & sign_bit) {
            return Number{truncated - (static_cast<Int128>(1) << width)};
        }
        return Number{truncated};
    }

    // Width must be in [0, 64]; 0 means no truncation.
    [[nodiscard]]
    Number zero_extend(const int width) const {
        if (width == 0) {
            return *this;
        }
        assert(width > 0 && width <= 64);
        const Int128 value_mask = (static_cast<Int128>(1) << width) - 1;
        return Number{_n & value_mask};
    }

    // Width is the number of bits including sign. Valid range: [1, 65] for eBPF (up to 64-bit values).
    static Number max_uint(const int width) { return max_int(width + 1); }

    static Number max_int(const int width) {
        assert(width >= 1 && width <= 128);
        return Number{(static_cast<Int128>(1) << (width - 1)) - 1};
    }

    static Number min_int(const int width) {
        assert(width >= 1 && width <= 128);
        return Number{-(static_cast<Int128>(1) << (width - 1))};
    }

    Number operator+(const Number& x) const { return Number{checked_add(_n, x._n)}; }

    Number operator*(const Number& x) const { return Number{checked_mul(_n, x._n)}; }

    Number operator-(const Number& x) const { return Number{checked_sub(_n, x._n)}; }

    Number operator-() const { return Number{checked_neg(_n)}; }

    Number operator/(const Number& x) const { return Number{checked_div(_n, x._n)}; }

    Number operator%(const Number& x) const { return Number{checked_mod(_n, x._n)}; }

    Number& operator+=(const Number& x) {
        _n = checked_add(_n, x._n);
        return *this;
    }

    Number& operator*=(const Number& x) {
        _n = checked_mul(_n, x._n);
        return *this;
    }

    Number& operator-=(const Number& x) {
        _n = checked_sub(_n, x._n);
        return *this;
    }

    Number& operator/=(const Number& x) {
        _n = checked_div(_n, x._n);
        return *this;
    }

    Number& operator%=(const Number& x) {
        _n = checked_mod(_n, x._n);
        return *this;
    }

    Number& operator--() & {
        _n = checked_sub(_n, static_cast<Int128>(1));
        return *this;
    }

    Number& operator++() & {
        _n = checked_add(_n, static_cast<Int128>(1));
        return *this;
    }

    Number operator++(int) & {
        Number r(*this);
        ++*this;
        return r;
    }

    Number operator--(int) & {
        Number r(*this);
        --*this;
        return r;
    }

    constexpr bool operator==(const Number& x) const { return _n == x._n; }

    constexpr bool operator!=(const Number& x) const { return _n != x._n; }

    constexpr bool operator<(const Number& x) const { return _n < x._n; }

    constexpr bool operator<=(const Number& x) const { return _n <= x._n; }

    constexpr bool operator>(const Number& x) const { return _n > x._n; }

    constexpr bool operator>=(const Number& x) const { return _n >= x._n; }

    [[nodiscard]]
    Number abs() const {
        return _n < 0 ? Number{checked_neg(_n)} : *this;
    }

    Number operator&(const Number& x) const { return Number{_n & x._n}; }

    Number operator|(const Number& x) const { return Number{_n | x._n}; }

    Number operator^(const Number& x) const { return Number{_n ^ x._n}; }

    Number operator<<(const Number& x) const {
        if (x._n < 0 || x._n > 127) {
            CRAB_ERROR("Shift amount must be in [0, 127], got ", x);
        }
        const auto shift = static_cast<int>(x._n);
        return Number{_n << shift};
    }

    // Right shift of signed integers is arithmetic (sign-extending) in C++20.
    Number operator>>(const Number& x) const {
        if (x._n < 0 || x._n > 127) {
            CRAB_ERROR("Shift amount must be in [0, 127], got ", x);
        }
        const auto shift = static_cast<int>(x._n);
        return Number{_n >> shift};
    }

    // Return a number with all bits set up to the highest set bit.
    // Precondition: _n >= 0 (callers guard this via lb() >= 0).
    [[nodiscard]]
    Number fill_ones() const {
        assert(_n >= 0);
        if (_n == 0) {
            return Number{0};
        }
        const auto u = static_cast<UInt128>(_n);
        const int bits = 128 - clz128(u);
        assert(bits > 0 && bits <= 127);
        return Number{(static_cast<Int128>(1) << bits) - 1};
    }

    friend std::ostream& operator<<(std::ostream& o, const Number& z);

    [[nodiscard]]
    std::string to_string() const;
}; // class Number

constexpr bool operator<=(std::integral auto left, const Number& rhs) { return rhs >= left; }
constexpr bool operator<=(is_enum auto left, const Number& rhs) { return rhs >= left; }

template <typename T>
concept finite_integral = std::integral<T> || std::is_same_v<T, Number>;

} // namespace prevail

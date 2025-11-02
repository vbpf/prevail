// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <climits>
#include <sstream>
#include <string>
#include <utility>

#include <boost/multiprecision/cpp_int.hpp>

#include "crab_utils/debug.hpp"
#include "crab_utils/num_safety.hpp"

using boost::multiprecision::cpp_int;

namespace prevail {

class Number final {
    cpp_int _n{};

  public:
    constexpr Number() = default;
    Number(cpp_int n) : _n(std::move(n)) {}
    constexpr Number(std::integral auto n) : _n{n} {}
    constexpr Number(is_enum auto n) : _n{static_cast<std::underlying_type_t<decltype(n)>>(n)} {}
    explicit Number(const std::string& s) { _n = cpp_int(s); }

    template <std::integral T>
    T narrow() const {
        if (!fits<T>()) {
            CRAB_ERROR("Number ", _n, " does not fit into ", typeid(T).name());
        }
        return static_cast<T>(_n);
    }

    template <is_enum T>
    T narrow() const {
        using underlying = std::underlying_type_t<T>;
        // Note: This does not check that the enum is a valid enum value
        if (!fits<underlying>()) {
            CRAB_ERROR("Number ", _n, " does not fit into ", typeid(T).name());
        }
        return static_cast<T>(static_cast<underlying>(_n));
    }

    template <is_enum T>
    constexpr T cast_to() const {
        return static_cast<T>(cast_to<std::underlying_type_t<T>>(_n));
    }

    explicit operator cpp_int() const { return _n; }

    [[nodiscard]]
    constexpr friend std::size_t hash_value(const Number& z) {
        return hash_value(z._n);
    }

    template <std::integral T>
    [[nodiscard]]
    constexpr bool fits() const {
        return std::numeric_limits<T>::min() <= _n && _n <= std::numeric_limits<T>::max();
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
        CRAB_ERROR("Number ", _n, " does not fit into ", typeid(T).name());
    }

    // Allow casting to intX_t as needed for finite width operations.
    [[nodiscard]]
    Number cast_to_sint(const int width) const {
        switch (width) {
        case 0: return *this; // No finite width.
        case 8: return cast_to<int8_t>();
        case 16: return cast_to<int16_t>();
        case 32: return cast_to<int32_t>();
        case 64: return cast_to<int64_t>();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    // Allow casting to uintX_t as needed for finite width operations.
    [[nodiscard]]
    Number cast_to_uint(const int width) const {
        switch (width) {
        case 0: return *this; // No finite width.
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
        constexpr U mask = std::numeric_limits<U>::max();
        return static_cast<T>(static_cast<U>(_n & mask));
    }

    template <int width>
    Number sign_extend_impl() const {
        using namespace boost::multiprecision;
        static const cpp_int sign_bit = cpp_int(1) << (width - 1);
        static const cpp_int value_mask = (cpp_int(1) << width) - 1;
        static const cpp_int offset = cpp_int(1) << width;

        const cpp_int truncated = _n & value_mask;
        if (truncated & sign_bit) {
            return evaluate_if_expression((truncated - offset));
        }
        return truncated;
    }

    template <int width>
    Number zero_extend_impl() const {
        using namespace boost::multiprecision;
        static const cpp_int value_mask = (cpp_int(1) << width) - 1;
        return evaluate_if_expression(_n & value_mask);
    }

    // Allow truncating to signed int as needed for finite width operations.
    // Unlike casting, sign_extend will not throw a prevail error if the number doesn't fit.
    [[nodiscard]]
    Number sign_extend(const int width) const {
        switch (width) {
        case 1: return sign_extend_impl<1>();
        case 2: return sign_extend_impl<2>();
        case 4: return sign_extend_impl<4>();
        case 8: return sign_extend_impl<8>();
        case 16: return sign_extend_impl<16>();
        case 32: return sign_extend_impl<32>();
        case 64: return sign_extend_impl<64>();
        case 0: return *this;
        default: {
            using namespace boost::multiprecision;
            const cpp_int sign_bit = cpp_int(1) << (width - 1);
            const cpp_int value_mask = (cpp_int(1) << width) - 1;
            const cpp_int offset = cpp_int(1) << width;

            const cpp_int truncated = _n & value_mask;
            if (truncated & sign_bit) {
                return evaluate_if_expression((truncated - offset));
            }
            return truncated;
        }
        }
    }

    // Allow truncating to unsigned int as needed for finite width operations.
    // Unlike casting, zero_extend will not throw a prevail error if the number doesn't fit.
    [[nodiscard]]
    Number zero_extend(const int width) const {
        switch (width) {
        case 1: return zero_extend_impl<1>();
        case 2: return zero_extend_impl<2>();
        case 4: return zero_extend_impl<4>();
        case 8: return zero_extend_impl<8>();
        case 16: return zero_extend_impl<16>();
        case 32: return zero_extend_impl<32>();
        case 64: return zero_extend_impl<64>();
        case 0: return *this;
        default: {
            using namespace boost::multiprecision;
            const cpp_int value_mask = (cpp_int(1) << width) - 1;
            return evaluate_if_expression(_n & value_mask);
        }
        }
    }

    static Number max_uint(const int width) { return max_int(width + 1); }

    static Number max_int(const int width) { return Number{(cpp_int(1) << (width - 1)) - 1}; }

    static Number min_int(const int width) { return Number{-(cpp_int(1) << (width - 1))}; }

    Number operator+(const Number& x) const { return Number(_n + x._n); }

    Number operator*(const Number& x) const { return Number(_n * x._n); }

    Number operator-(const Number& x) const { return Number(_n - x._n); }

    Number operator-() const { return Number(-_n); }

    Number operator/(const Number& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("Number: division by zero [1]");
        }
        return Number(_n / x._n);
    }

    Number operator%(const Number& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("Number: division by zero [2]");
        }
        return Number(_n % x._n);
    }

    Number& operator+=(const Number& x) {
        _n += x._n;
        return *this;
    }

    Number& operator*=(const Number& x) {
        _n *= x._n;
        return *this;
    }

    Number& operator-=(const Number& x) {
        _n -= x._n;
        return *this;
    }

    Number& operator/=(const Number& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("Number: division by zero [3]");
        }
        _n /= x._n;
        return *this;
    }

    Number& operator%=(const Number& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("Number: division by zero [4]");
        }
        _n %= x._n;
        return *this;
    }

    Number& operator--() & {
        --_n;
        return *this;
    }

    Number& operator++() & {
        ++_n;
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

    Number abs() const { return _n < 0 ? -_n : _n; }

    Number operator&(const Number& x) const { return Number(_n & x._n); }

    Number operator|(const Number& x) const { return Number(_n | x._n); }

    Number operator^(const Number& x) const { return Number(_n ^ x._n); }

    Number operator<<(const Number& x) const {
        if (x < 0) {
            CRAB_ERROR("Shift amount cannot be negative");
        }
        if (!x.fits<int32_t>()) {
            CRAB_ERROR("Number ", x._n, " does not fit into an int32");
        }
        return Number(_n << x.narrow<int32_t>());
    }

    Number operator>>(const Number& x) const {
        if (x < 0) {
            CRAB_ERROR("Shift amount cannot be negative");
        }
        if (!x.fits<int32_t>()) {
            CRAB_ERROR("Number ", x._n, " does not fit into an int32");
        }
        return Number(_n >> x.narrow<int32_t>());
    }

    [[nodiscard]]
    Number fill_ones() const {
        if (_n.is_zero()) {
            return Number(static_cast<signed long long>(0));
        }
        return Number{(cpp_int(1) << (msb(_n) + 1)) - 1};
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

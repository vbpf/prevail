// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <climits>
#include <sstream>
#include <string>
#include <utility>

#include <boost/multiprecision/cpp_int.hpp>

#include "crab_utils/num_safety.hpp"
#include "debug.hpp"

using boost::multiprecision::cpp_int;

namespace prevail {

class number_t final {
    cpp_int _n{};

  public:
    number_t() = default;
    number_t(cpp_int n) : _n(std::move(n)) {}
    number_t(std::integral auto n) : _n{n} {}
    number_t(is_enum auto n) : _n{static_cast<std::underlying_type_t<decltype(n)>>(n)} {}
    explicit number_t(const std::string& s) { _n = cpp_int(s); }

    template <std::integral T>
    T narrow() const {
        if (!fits<T>()) {
            CRAB_ERROR("number_t ", _n, " does not fit into ", typeid(T).name());
        }
        return static_cast<T>(_n);
    }

    template <is_enum T>
    T narrow() const {
        return static_cast<T>(static_cast<std::underlying_type_t<T>>(_n));
    }

    template <is_enum T>
    T cast_to() const {
        return static_cast<T>(static_cast<std::underlying_type_t<T>>(_n));
    }

    explicit operator cpp_int() const { return _n; }

    [[nodiscard]]
    friend std::size_t hash_value(const number_t& z) {
        return hash_value(z._n);
    }

    template <std::integral T>
    [[nodiscard]]
    bool fits() const {
        return std::numeric_limits<T>::min() <= _n && _n <= std::numeric_limits<T>::max();
    }

    template <std::integral T>
    [[nodiscard]]
    bool fits_cast_to() const {
        return fits<T>() || fits<swap_signedness<T>>();
    }

    template <std::integral T>
    [[nodiscard]]
    T cast_to() const {
        if (fits<T>()) {
            return static_cast<T>(_n);
        }
        using Q = swap_signedness<T>;
        if (fits<Q>()) {
            return static_cast<T>(static_cast<Q>(_n));
        }
        CRAB_ERROR("number_t ", _n, " does not fit into ", typeid(T).name());
    }

    // Allow casting to intX_t as needed for finite width operations.
    [[nodiscard]]
    number_t cast_to_sint(const int width) const {
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
    number_t cast_to_uint(const int width) const {
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
    T truncate_to() const {
        using U = std::make_unsigned_t<T>;
        constexpr U mask = std::numeric_limits<U>::max();
        return static_cast<T>(static_cast<U>(_n & mask));
    }

    // Allow truncating to signed int as needed for finite width operations.
    // Unlike casting, sign_extend will not throw a prevail error if the number doesn't fit.
    [[nodiscard]]
    number_t sign_extend(const int width) const {
        using namespace boost::multiprecision;
        if (width <= 0) {
            return *this;
        }

        // Create a mask for the sign bit.
        const cpp_int sign_bit = cpp_int(1) << (width - 1);
        const cpp_int value_mask = (cpp_int(1) << width) - 1;

        const cpp_int truncated = _n & value_mask;

        // If sign bit is set, extend with 1s; otherwise, return truncated.
        if (truncated & sign_bit) {
            return truncated - (cpp_int(1) << width);
        }
        return truncated;
    }

    // Allow truncating to unsigned int as needed for finite width operations.
    // Unlike casting, zero_extend will not throw a prevail error if the number doesn't fit.
    [[nodiscard]]
    number_t zero_extend(const int width) const {
        using namespace boost::multiprecision;
        if (width <= 0) {
            return *this;
        }
        const cpp_int value_mask = (cpp_int(1) << width) - 1;
        const cpp_int truncated = _n & value_mask;
        return truncated;
    }

    static number_t max_uint(const int width) { return max_int(width + 1); }

    static number_t max_int(const int width) { return number_t{(cpp_int(1) << (width - 1)) - 1}; }

    static number_t min_int(const int width) { return number_t{-(cpp_int(1) << (width - 1))}; }

    number_t operator+(const number_t& x) const { return number_t(_n + x._n); }

    number_t operator*(const number_t& x) const { return number_t(_n * x._n); }

    number_t operator-(const number_t& x) const { return number_t(_n - x._n); }

    number_t operator-() const { return number_t(-_n); }

    number_t operator/(const number_t& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("number_t: division by zero [1]");
        }
        return number_t(_n / x._n);
    }

    number_t operator%(const number_t& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("number_t: division by zero [2]");
        }
        return number_t(_n % x._n);
    }

    number_t& operator+=(const number_t& x) {
        _n += x._n;
        return *this;
    }

    number_t& operator*=(const number_t& x) {
        _n *= x._n;
        return *this;
    }

    number_t& operator-=(const number_t& x) {
        _n -= x._n;
        return *this;
    }

    number_t& operator/=(const number_t& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("number_t: division by zero [3]");
        }
        _n /= x._n;
        return *this;
    }

    number_t& operator%=(const number_t& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("number_t: division by zero [4]");
        }
        _n %= x._n;
        return *this;
    }

    number_t& operator--() & {
        --_n;
        return *this;
    }

    number_t& operator++() & {
        ++_n;
        return *this;
    }

    number_t operator++(int) & {
        number_t r(*this);
        ++*this;
        return r;
    }

    number_t operator--(int) & {
        number_t r(*this);
        --*this;
        return r;
    }

    bool operator==(const number_t& x) const { return _n == x._n; }

    bool operator!=(const number_t& x) const { return _n != x._n; }

    bool operator<(const number_t& x) const { return _n < x._n; }

    bool operator<=(const number_t& x) const { return _n <= x._n; }

    bool operator>(const number_t& x) const { return _n > x._n; }

    bool operator>=(const number_t& x) const { return _n >= x._n; }

    number_t abs() const { return _n < 0 ? -_n : _n; }

    number_t operator&(const number_t& x) const { return number_t(_n & x._n); }

    number_t operator|(const number_t& x) const { return number_t(_n | x._n); }

    number_t operator^(const number_t& x) const { return number_t(_n ^ x._n); }

    number_t operator<<(const number_t& x) const {
        if (x < 0) {
            CRAB_ERROR("Shift amount cannot be negative");
        }
        if (!x.fits<int32_t>()) {
            CRAB_ERROR("number_t ", x._n, " does not fit into an int32");
        }
        return number_t(_n << x.narrow<int32_t>());
    }

    number_t operator>>(const number_t& x) const {
        if (x < 0) {
            CRAB_ERROR("Shift amount cannot be negative");
        }
        if (!x.fits<int32_t>()) {
            CRAB_ERROR("number_t ", x._n, " does not fit into an int32");
        }
        return number_t(_n >> x.narrow<int32_t>());
    }

    [[nodiscard]]
    number_t fill_ones() const {
        if (_n.is_zero()) {
            return number_t(static_cast<signed long long>(0));
        }
        return number_t{(cpp_int(1) << (msb(_n) + 1)) - 1};
    }

    friend std::ostream& operator<<(std::ostream& o, const number_t& z);

    [[nodiscard]]
    std::string to_string() const;
};
// class number_t

bool operator<=(std::integral auto left, const number_t& rhs) { return rhs >= left; }
bool operator<=(is_enum auto left, const number_t& rhs) { return rhs >= left; }

template <typename T>
concept finite_integral = std::integral<T> || std::is_same_v<T, number_t>;

} // namespace prevail

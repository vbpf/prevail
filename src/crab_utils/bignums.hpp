// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <climits>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>

#include <boost/functional/hash.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include "debug.hpp"
using boost::multiprecision::cpp_int;

namespace crab {

template <typename T>
concept is_enum = std::is_enum_v<T>;

template <std::integral T>
T truncate_to(const cpp_int& n) {
    using U = std::make_unsigned_t<T>;
    constexpr U mask = std::numeric_limits<U>::max();
    return static_cast<T>(static_cast<U>(n & mask));
}

// coderabbit implementation - TODO try in the future
template <std::unsigned_integral U>
U truncate_to_coderabbit(const cpp_int& n) {
    constexpr U mask = std::numeric_limits<U>::max();
    return static_cast<U>(n & mask);
}

// coderabbit implementation - TODO try in the future
template <std::signed_integral S>
S truncate_to_coderabbit(const cpp_int& n) {
    using U = std::make_unsigned_t<S>;
    constexpr uint32_t size = sizeof(S) * CHAR_BIT;
    constexpr U mask = (U{1} << size) - 1;
    const auto truncated = n & mask;
    if (truncated >= cpp_int{1} << (size - 1)) {
        truncated -= cpp_int{1} << size;
    }
    return static_cast<S>(truncated);
}

template <std::integral T>
bool fits(const cpp_int& n) {
    return std::numeric_limits<T>::min() <= n && n <= std::numeric_limits<T>::max();
}

class z_number final {
  private:
    cpp_int _n{nullptr};

  public:
    z_number() = default;
    z_number(cpp_int n) : _n(std::move(n)) {}
    z_number(std::integral auto n) : _n{n} {}
    z_number(is_enum auto n) : _n{static_cast<int64_t>(n)} {}
    explicit z_number(const std::string& s) { _n = cpp_int(s); }

    // overloaded typecast operators
    explicit operator int64_t() const {
        if (!fits<int64_t>()) {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into a signed 64-bit integer");
        } else {
            return (int64_t)_n;
        }
    }

    explicit operator uint64_t() const {
        if (!fits<uint64_t>()) {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into an unsigned 64-bit integer");
        } else {
            return (uint64_t)_n;
        }
    }

    explicit operator int32_t() const {
        if (!fits<int32_t>()) {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into a signed integer");
        } else {
            return (int)_n;
        }
    }

    explicit operator uint32_t() const {
        if (!fits<uint32_t>()) {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into an unsigned integer");
        } else {
            return (unsigned int)_n;
        }
    }

    explicit operator cpp_int() const { return _n; }

    [[nodiscard]]
    std::size_t hash() const {
        boost::hash<std::string> hasher;
        return hasher(_n.str());
    }

    template <std::integral T>
    [[nodiscard]]
    bool fits() const {
        return crab::fits<T>(_n);
    }

    template <std::integral T>
    [[nodiscard]]
    bool fits_cast_to() const {
        return crab::fits<std::make_signed_t<T>>(_n) || crab::fits<std::make_unsigned_t<T>>(_n);
    }

    template <std::unsigned_integral U>
    [[nodiscard]]
    U cast_to() const {
        if (fits<U>()) {
            return (U)_n;
        }
        using S = std::make_signed_t<U>;
        if (fits<S>()) {
            return (U)(S)_n;
        }
        CRAB_ERROR("z_number ", _n.str(), " does not fit into ", typeid(U).name());
    }

    template <std::signed_integral S>
    [[nodiscard]]
    S cast_to() const {
        if (fits<S>()) {
            return (S)_n;
        }
        using U = std::make_unsigned_t<S>;
        if (fits<U>()) {
            return (S)(U)_n;
        }
        CRAB_ERROR("z_number ", _n.str(), " does not fit into ", typeid(S).name());
    }

    // Allow casting to intX_t as needed for finite width operations.
    [[nodiscard]]
    z_number cast_to_signed_finite_width(int finite_width) const {
        switch (finite_width) {
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
    z_number cast_to_unsigned_finite_width(int finite_width) const {
        switch (finite_width) {
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
        return crab::truncate_to<T>(_n);
    }

    // Allow truncating to int32_t or int64_t as needed for finite width operations.
    // Unlike casting, truncating will not throw a crab error if the number doesn't fit.
    [[nodiscard]]
    z_number truncate_to_signed_finite_width(int finite_width) const {
        switch (finite_width) {
        case 0: return *this; // No finite width.
        case 8: return truncate_to<int8_t>();
        case 16: return truncate_to<int16_t>();
        case 32: return truncate_to<int32_t>();
        case 64: return truncate_to<int64_t>();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    // Allow truncating to uint32_t or uint64_t as needed for finite width operations.
    // Unlike casting, truncating will not throw a crab error if the number doesn't fit.
    [[nodiscard]]
    z_number truncate_to_unsigned_finite_width(int finite_width) const {
        switch (finite_width) {
        case 0: return *this; // No finite width.
        case 8: return truncate_to<uint8_t>();
        case 16: return truncate_to<uint16_t>();
        case 32: return truncate_to<uint32_t>();
        case 64: return truncate_to<uint64_t>();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    z_number operator+(const z_number& x) const { return z_number(_n + x._n); }

    z_number operator*(const z_number& x) const { return z_number(_n * x._n); }

    z_number operator-(const z_number& x) const { return z_number(_n - x._n); }

    z_number operator-() const { return z_number(-_n); }

    z_number operator/(const z_number& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [1]");
        } else {
            return z_number(_n / x._n);
        }
    }

    z_number operator%(const z_number& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [2]");
        } else {
            return z_number(_n % x._n);
        }
    }

    z_number& operator+=(const z_number& x) {
        _n += x._n;
        return *this;
    }

    z_number& operator*=(const z_number& x) {
        _n *= x._n;
        return *this;
    }

    z_number& operator-=(const z_number& x) {
        _n -= x._n;
        return *this;
    }

    z_number& operator/=(const z_number& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [3]");
        } else {
            _n /= x._n;
            return *this;
        }
    }

    z_number& operator%=(const z_number& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [4]");
        } else {
            _n %= x._n;
            return *this;
        }
    }

    z_number& operator--() & {
        _n--;
        return *this;
    }

    z_number& operator++() & {
        _n++;
        return *this;
    }

    z_number operator++(int) & {
        z_number r(*this);
        ++(*this);
        return r;
    }

    z_number operator--(int) & {
        z_number r(*this);
        --(*this);
        return r;
    }

    bool operator==(const z_number& x) const { return (_n == x._n); }

    bool operator!=(const z_number& x) const { return (_n != x._n); }

    bool operator<(const z_number& x) const { return (_n < x._n); }

    bool operator<=(const z_number& x) const { return (_n <= x._n); }

    bool operator>(const z_number& x) const { return (_n > x._n); }

    bool operator>=(const z_number& x) const { return (_n >= x._n); }

    z_number operator&(const z_number& x) const { return z_number(_n & x._n); }

    z_number operator|(const z_number& x) const { return z_number(_n | x._n); }

    z_number operator^(const z_number& x) const { return z_number(_n ^ x._n); }

    z_number operator<<(z_number x) const {
        if (!x.fits<int32_t>()) {
            CRAB_ERROR("z_number ", x._n.str(), " does not fit into an int32");
        }
        return z_number(_n << (int32_t)x);
    }

    z_number operator>>(z_number x) const {
        if (!x.fits<int32_t>()) {
            CRAB_ERROR("z_number ", x._n.str(), " does not fit into an int32");
        }
        return z_number(_n >> (int32_t)x);
    }

    [[nodiscard]]
    z_number fill_ones() const {
        if (_n.is_zero()) {
            return z_number((signed long long)0);
        }

        z_number result;
        for (result = 1; result < *this; result = result * 2 + 1)
            ;
        return result;
    }

    friend std::ostream& operator<<(std::ostream& o, const z_number& z) { return o << z._n.str(); }

    [[nodiscard]]
    std::string to_string() const;
};
// class z_number

using number_t = z_number;

inline std::size_t hash_value(const z_number& z) { return z.hash(); }
} // namespace crab

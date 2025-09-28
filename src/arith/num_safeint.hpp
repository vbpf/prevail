// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

/**
 *  Safe signed integers.
 **/

#include <cstdint>
#include <limits>
#ifndef __GNUC__
#include <boost/multiprecision/cpp_int.hpp>
#endif

#include "arith/num_big.hpp"

namespace prevail {

class SafeI64 {
    // Current implementation is based on
    // https://blog.regehr.org/archives/1139 using wider integers.

#ifdef __GNUC__
    // TODO/FIXME: the current code compiles assuming the type __int128
    // exists. Both clang and gcc supports __int128 if the targeted
    // architecture is x86/64, but it won't work with 32 bits.
    using WideInt = __int128;
#else
    using WideInt = boost::multiprecision::int128_t;
#endif

    [[nodiscard]]
    static constexpr int64_t get_max() {
        return std::numeric_limits<int64_t>::max();
    }
    [[nodiscard]]
    static constexpr int64_t get_min() {
        return std::numeric_limits<int64_t>::min();
    }

    static std::optional<int64_t> checked_add(const int64_t a, const int64_t b) {
        const WideInt lr = static_cast<WideInt>(a) + static_cast<WideInt>(b);
        if (lr > get_max() || lr < get_min()) {
            return {};
        }
        return static_cast<int64_t>(lr);
    }

    static std::optional<int64_t> checked_sub(const int64_t a, const int64_t b) {
        const WideInt lr = static_cast<WideInt>(a) - static_cast<WideInt>(b);
        if (lr > get_max() || lr < get_min()) {
            return {};
        }
        return static_cast<int64_t>(lr);
    }
    static std::optional<int64_t> checked_mul(const int64_t a, const int64_t b) {
        const WideInt lr = static_cast<WideInt>(a) * static_cast<WideInt>(b);
        if (lr > get_max() || lr < get_min()) {
            return {};
        }
        return static_cast<int64_t>(lr);
    }
    static std::optional<int64_t> checked_div(const int64_t a, const int64_t b) {
        const WideInt lr = static_cast<WideInt>(a) / static_cast<WideInt>(b);
        if (lr > get_max() || lr < get_min()) {
            return {};
        }
        return static_cast<int64_t>(lr);
    }

  public:
    SafeI64() : m_num{0} {}

    SafeI64(const int64_t num) : m_num{num} {}

    SafeI64(const Number& n) : m_num{n.narrow<int64_t>()} {}

    operator int64_t() const { return m_num; }

    // TODO: output parameters whether operation overflows
    SafeI64 operator+(const SafeI64 x) const {
        if (const auto z = checked_add(m_num, x.m_num)) {
            return SafeI64(*z);
        }
        CRAB_ERROR("Integer overflow during addition");
    }

    // TODO: output parameters whether operation overflows
    SafeI64 operator-(const SafeI64 x) const {
        if (const auto z = checked_sub(m_num, x.m_num)) {
            return SafeI64(*z);
        }
        CRAB_ERROR("Integer overflow during subtraction");
    }

    // TODO: output parameters whether operation overflows
    SafeI64 operator*(const SafeI64 x) const {
        if (const auto z = checked_mul(m_num, x.m_num)) {
            return SafeI64(*z);
        }
        CRAB_ERROR("Integer overflow during multiplication");
    }

    // TODO: output parameters whether operation overflows
    SafeI64 operator/(const SafeI64 x) const {
        if (const auto z = checked_div(m_num, x.m_num)) {
            return SafeI64(*z);
        }
        CRAB_ERROR("Integer overflow during division");
    }

    // TODO: output parameters whether operation overflows
    SafeI64 operator-() const { return SafeI64(0) - *this; }

    // TODO: output parameters whether operation overflows
    SafeI64& operator+=(const SafeI64 x) { return *this = *this + x; }

    // TODO: output parameters whether operation overflows
    SafeI64& operator-=(const SafeI64 x) { return *this = *this - x; }

    bool operator==(const SafeI64 x) const { return m_num == x.m_num; }

    bool operator!=(const SafeI64 x) const { return m_num != x.m_num; }

    bool operator<(const SafeI64 x) const { return m_num < x.m_num; }

    bool operator<=(const SafeI64 x) const { return m_num <= x.m_num; }

    bool operator>(const SafeI64 x) const { return m_num > x.m_num; }

    bool operator>=(const SafeI64 x) const { return m_num >= x.m_num; }

    friend std::ostream& operator<<(std::ostream& o, const SafeI64& n) { return o << n.m_num; }

  private:
    int64_t m_num;
};

} // end namespace prevail

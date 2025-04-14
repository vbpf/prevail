// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
/*******************************************************************************
 *
 * A simple class for representing intervals and performing interval arithmetic.
 *
 ******************************************************************************/

#pragma once

#include <optional>
#include <utility>

#include "crab_utils/num_big.hpp"
#include "crab_utils/num_extended.hpp"
#include "crab_utils/stats.hpp"

namespace prevail {

using bound_t = extended_number;

class interval_t final {
    bound_t _lb;
    bound_t _ub;

  public:
    static interval_t top() { return interval_t{bound_t::minus_infinity(), bound_t::plus_infinity()}; }

    static interval_t bottom() { return interval_t{}; }

    [[nodiscard]]
    std::optional<number_t> finite_size() const {
        return (_ub - _lb).number();
    }

  private:
    interval_t() : _lb(number_t{0}), _ub(-1) {}

  public:
    interval_t(const bound_t& lb, const bound_t& ub)
        : _lb(lb > ub ? bound_t{number_t{0}} : lb), _ub(lb > ub ? bound_t{-1} : ub) {}

    template <std::integral T>
    interval_t(T lb, T ub) : _lb(bound_t{lb}), _ub(bound_t{ub}) {
        if (lb > ub) {
            _lb = bound_t{number_t{0}};
            _ub = bound_t{-1};
        }
    }

    template <is_enum T>
    interval_t(T lb, T ub) : _lb(bound_t{lb}), _ub(bound_t{ub}) {
        if (lb > ub) {
            _lb = bound_t{number_t{0}};
            _ub = bound_t{-1};
        }
    }
    explicit interval_t(const bound_t& b)
        : _lb(b.is_infinite() ? bound_t{number_t{0}} : b), _ub(b.is_infinite() ? bound_t{-1} : b) {}

    explicit interval_t(const number_t& n) : _lb(n), _ub(n) {}
    explicit interval_t(std::integral auto n) : _lb(n), _ub(n) {}

    interval_t(const interval_t& i) = default;

    interval_t& operator=(const interval_t& i) = default;

    [[nodiscard]]
    bound_t lb() const {
        return _lb;
    }

    [[nodiscard]]
    bound_t ub() const {
        return _ub;
    }

    [[nodiscard]]
    std::tuple<bound_t, bound_t> pair() const {
        return {_lb, _ub};
    }

    template <std::integral T>
    [[nodiscard]]
    std::tuple<T, T> pair() const {
        return {_lb.narrow<T>(), _ub.narrow<T>()};
    }

    [[nodiscard]]
    std::tuple<number_t, number_t> pair_number() const {
        return {_lb.number().value(), _ub.number().value()};
    }

    template <std::integral T>
    [[nodiscard]]
    std::tuple<T, T> bound(T lb, T ub) const {
        const interval_t b = interval_t{lb, ub} & *this;
        if (b.is_bottom()) {
            CRAB_ERROR("Cannot convert bottom to tuple");
        }
        return {b._lb.narrow<T>(), b._ub.narrow<T>()};
    }

    template <is_enum T>
    [[nodiscard]]
    std::tuple<T, T> bound(T elb, T eub) const {
        using C = std::underlying_type_t<T>;
        auto [lb, ub] = bound(static_cast<C>(elb), static_cast<C>(eub));
        return {static_cast<T>(lb), static_cast<T>(ub)};
    }

    [[nodiscard]]
    explicit operator bool() const {
        return !is_bottom();
    }

    [[nodiscard]]
    bool is_bottom() const {
        return _lb > _ub;
    }

    [[nodiscard]]
    bool is_top() const {
        return _lb.is_infinite() && _ub.is_infinite();
    }

    bool operator==(const interval_t& x) const {
        if (is_bottom()) {
            return x.is_bottom();
        } else {
            return _lb == x._lb && _ub == x._ub;
        }
    }

    bool operator!=(const interval_t& x) const { return !operator==(x); }

    bool operator<=(const interval_t& x) const {
        if (is_bottom()) {
            return true;
        } else if (x.is_bottom()) {
            return false;
        } else {
            return x._lb <= _lb && _ub <= x._ub;
        }
    }

    interval_t operator|(const interval_t& x) const {
        if (is_bottom()) {
            return x;
        } else if (x.is_bottom()) {
            return *this;
        } else {
            return interval_t{std::min(_lb, x._lb), std::max(_ub, x._ub)};
        }
    }

    interval_t operator&(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t{std::max(_lb, x._lb), std::min(_ub, x._ub)};
        }
    }

    [[nodiscard]]
    interval_t widen(const interval_t& x) const {
        if (is_bottom()) {
            return x;
        } else if (x.is_bottom()) {
            return *this;
        } else {
            return interval_t{x._lb < _lb ? bound_t::minus_infinity() : _lb,
                              _ub < x._ub ? bound_t::plus_infinity() : _ub};
        }
    }

    template <typename Thresholds>
    interval_t widening_thresholds(interval_t x, const Thresholds& ts) {
        if (is_bottom()) {
            return x;
        } else if (x.is_bottom()) {
            return *this;
        } else {
            const bound_t lb = x._lb < _lb ? ts.get_prev(x._lb) : _lb;
            const bound_t ub = _ub < x._ub ? ts.get_next(x._ub) : _ub;
            return interval_t{lb, ub};
        }
    }

    [[nodiscard]]
    interval_t narrow(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t{_lb.is_infinite() && x._lb.is_finite() ? x._lb : _lb,
                              _ub.is_infinite() && x._ub.is_finite() ? x._ub : _ub};
        }
    }

    interval_t operator+(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t{_lb + x._lb, _ub + x._ub};
        }
    }

    interval_t& operator+=(const interval_t& x) { return operator=(operator+(x)); }

    interval_t operator-() const {
        if (is_bottom()) {
            return bottom();
        } else {
            return interval_t{-_ub, -_lb};
        }
    }

    interval_t operator-(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t{_lb - x._ub, _ub - x._lb};
        }
    }

    interval_t& operator-=(const interval_t& x) { return operator=(operator-(x)); }

    interval_t operator*(const interval_t& x) const;

    interval_t& operator*=(const interval_t& x) { return operator=(operator*(x)); }

    interval_t operator/(const interval_t& x) const;

    interval_t& operator/=(const interval_t& x) { return operator=(operator/(x)); }

    bound_t size() const {
        if (is_bottom()) {
            return bound_t{number_t{0}};
        }
        return _ub - _lb + 1;
    }

    [[nodiscard]]
    bool is_singleton() const {
        return _lb == _ub;
    }

    [[nodiscard]]
    std::optional<number_t> singleton() const {
        if (is_singleton()) {
            return _lb.number();
        } else {
            return std::optional<number_t>();
        }
    }

    bool contains(const number_t& n) const {
        if (is_bottom()) {
            return false;
        }
        const bound_t b{n};
        return _lb <= b && b <= _ub;
    }

    friend std::ostream& operator<<(std::ostream& o, const interval_t& interval);

    // division and remainder operations

    [[nodiscard]]
    interval_t sdiv(const interval_t& x) const;

    [[nodiscard]]
    interval_t udiv(const interval_t& x) const;

    [[nodiscard]]
    interval_t srem(const interval_t& x) const;

    [[nodiscard]]
    interval_t urem(const interval_t& x) const;

    // bitwise operations
    [[nodiscard]]
    interval_t bitwise_and(const interval_t& x) const;

    [[nodiscard]]
    interval_t bitwise_or(const interval_t& x) const;

    [[nodiscard]]
    interval_t bitwise_xor(const interval_t& x) const;

    [[nodiscard]]
    interval_t shl(const interval_t& x) const;

    [[nodiscard]]
    interval_t lshr(const interval_t& x) const;

    [[nodiscard]]
    interval_t ashr(const interval_t& x) const;

    interval_t sign_extend(bool is64) const = delete;
    [[nodiscard]]
    interval_t sign_extend(int width) const;

    interval_t zero_extend(bool is64) const = delete;
    [[nodiscard]]
    interval_t zero_extend(int width) const;

    template <std::signed_integral T>
    [[nodiscard]]
    interval_t truncate_to() const {
        return sign_extend(static_cast<int>(sizeof(T)) * 8);
    }

    template <std::unsigned_integral T>
    [[nodiscard]]
    interval_t truncate_to() const {
        return zero_extend(static_cast<int>(sizeof(T)) * 8);
    }

    interval_t signed_int(bool is64) const = delete;
    // Return an interval in the range [INT_MIN, INT_MAX] which can only
    // be represented as an svalue.
    static interval_t signed_int(const int width) {
        return interval_t{number_t::min_int(width), number_t::max_int(width)};
    }

    interval_t unsigned_int(bool is64) const = delete;
    // Return an interval in the range [0, UINT_MAX] which can only be
    // represented as a uvalue.
    static interval_t unsigned_int(const int width) { return interval_t{0, number_t::max_uint(width)}; }

    interval_t nonnegative(bool is64) const = delete;
    // Return a non-negative interval in the range [0, INT_MAX],
    // which can be represented as both an svalue and a uvalue.
    static interval_t nonnegative(const int width) { return interval_t{number_t{0}, number_t::max_int(width)}; }

    interval_t negative(bool is64) const = delete;
    // Return a negative interval in the range [INT_MIN, -1],
    // which can be represented as both an svalue and a uvalue.
    static interval_t negative(const int width) { return interval_t{number_t::min_int(width), number_t{-1}}; }

    interval_t unsigned_high(bool is64) const = delete;
    // Return an interval in the range [INT_MAX+1, UINT_MAX], which can only be represented as a uvalue.
    // The svalue equivalent using the same width would be negative().
    static interval_t unsigned_high(const int width) {
        return interval_t{number_t::max_int(width) + 1, number_t::max_uint(width)};
    }

    [[nodiscard]]
    std::string to_string() const;
}; //  class interval

namespace interval_operators {

inline interval_t operator+(const number_t& c, const interval_t& x) { return interval_t{c} + x; }

inline interval_t operator+(const interval_t& x, const number_t& c) { return x + interval_t{c}; }

inline interval_t operator*(const number_t& c, const interval_t& x) { return interval_t{c} * x; }

inline interval_t operator*(const interval_t& x, const number_t& c) { return x * interval_t{c}; }

inline interval_t operator/(const number_t& c, const interval_t& x) { return interval_t{c} / x; }

inline interval_t operator/(const interval_t& x, const number_t& c) { return x / interval_t{c}; }

inline interval_t operator-(const number_t& c, const interval_t& x) { return interval_t{c} - x; }

inline interval_t operator-(const interval_t& x, const number_t& c) { return x - interval_t{c}; }

} // namespace interval_operators

} // namespace prevail

std::string to_string(const prevail::interval_t& interval) noexcept;

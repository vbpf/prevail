// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
/*******************************************************************************
 *
 * A simple class for representing intervals and performing interval arithmetic.
 *
 ******************************************************************************/

#pragma once

#include <optional>

#include "arith/num_big.hpp"
#include "arith/num_extended.hpp"

namespace prevail {

using Bound = ExtendedNumber;

class Interval final {
    Bound _lb;
    Bound _ub;

  public:
    static Interval top() { return Interval{MINUS_INFINITY, PLUS_INFINITY}; }

    static Interval bottom() { return Interval{}; }

    [[nodiscard]]
    std::optional<Number> finite_size() const {
        return (_ub - _lb).number();
    }

  private:
    Interval() : _lb{0}, _ub{-1} {}

  public:
    Interval(const Bound& lb, const Bound& ub) : _lb(lb > ub ? Bound{Number{0}} : lb), _ub(lb > ub ? Bound{-1} : ub) {}

    template <std::integral T>
    Interval(T lb, T ub) : _lb(Bound{lb}), _ub(Bound{ub}) {
        if (lb > ub) {
            _lb = Bound{Number{0}};
            _ub = Bound{-1};
        }
    }

    template <is_enum T>
    Interval(T lb, T ub) : _lb(Bound{lb}), _ub(Bound{ub}) {
        if (lb > ub) {
            _lb = Bound{Number{0}};
            _ub = Bound{-1};
        }
    }
    explicit Interval(const Bound& b)
        : _lb(b.is_infinite() ? Bound{Number{0}} : b), _ub(b.is_infinite() ? Bound{-1} : b) {}

    explicit Interval(const Number& n) : _lb(n), _ub(n) {}
    explicit Interval(std::integral auto n) : _lb(n), _ub(n) {}

    Interval(const Interval& i) = default;

    Interval& operator=(const Interval& i) = default;

    [[nodiscard]]
    Bound lb() const {
        return _lb;
    }

    [[nodiscard]]
    Bound ub() const {
        return _ub;
    }

    [[nodiscard]]
    std::tuple<Bound, Bound> pair() const {
        return {_lb, _ub};
    }

    template <std::integral T>
    [[nodiscard]]
    std::tuple<T, T> pair() const {
        return {_lb.narrow<T>(), _ub.narrow<T>()};
    }

    [[nodiscard]]
    std::tuple<Number, Number> pair_number() const {
        return {_lb.number().value(), _ub.number().value()};
    }

    template <std::integral T>
    [[nodiscard]]
    std::tuple<T, T> bound(T lb, T ub) const {
        const Interval b = Interval{lb, ub} & *this;
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

    bool operator==(const Interval& x) const {
        if (is_bottom()) {
            return x.is_bottom();
        } else {
            return _lb == x._lb && _ub == x._ub;
        }
    }

    bool operator!=(const Interval& x) const { return !operator==(x); }

    bool operator<=(const Interval& x) const {
        if (is_bottom()) {
            return true;
        } else if (x.is_bottom()) {
            return false;
        } else {
            return x._lb <= _lb && _ub <= x._ub;
        }
    }

    Interval operator|(const Interval& x) const {
        if (is_bottom()) {
            return x;
        } else if (x.is_bottom()) {
            return *this;
        } else {
            return Interval{std::min(_lb, x._lb), std::max(_ub, x._ub)};
        }
    }

    Interval operator&(const Interval& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return Interval{std::max(_lb, x._lb), std::min(_ub, x._ub)};
        }
    }

    [[nodiscard]]
    Interval widen(const Interval& x) const {
        if (is_bottom()) {
            return x;
        } else if (x.is_bottom()) {
            return *this;
        } else {
            return Interval{x._lb < _lb ? MINUS_INFINITY : _lb, _ub < x._ub ? PLUS_INFINITY : _ub};
        }
    }

    [[nodiscard]]
    Interval narrow(const Interval& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return Interval{_lb.is_infinite() && x._lb.is_finite() ? x._lb : _lb,
                            _ub.is_infinite() && x._ub.is_finite() ? x._ub : _ub};
        }
    }

    Interval operator+(const Interval& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return Interval{_lb + x._lb, _ub + x._ub};
        }
    }

    Interval& operator+=(const Interval& x) { return operator=(operator+(x)); }

    Interval operator-() const {
        if (is_bottom()) {
            return bottom();
        } else {
            return Interval{-_ub, -_lb};
        }
    }

    Interval operator-(const Interval& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return Interval{_lb - x._ub, _ub - x._lb};
        }
    }

    Interval& operator-=(const Interval& x) { return operator=(operator-(x)); }

    Interval operator*(const Interval& x) const;

    Interval& operator*=(const Interval& x) { return operator=(operator*(x)); }

    Interval operator/(const Interval& x) const;

    Interval& operator/=(const Interval& x) { return operator=(operator/(x)); }

    Bound size() const {
        if (is_bottom()) {
            return Bound{Number{0}};
        }
        return _ub - _lb + 1;
    }

    [[nodiscard]]
    bool is_singleton() const {
        return _lb == _ub;
    }

    [[nodiscard]]
    std::optional<Number> singleton() const {
        if (is_singleton()) {
            return _lb.number();
        } else {
            return std::optional<Number>();
        }
    }

    bool contains(const Number& n) const {
        if (is_bottom()) {
            return false;
        }
        const Bound b{n};
        return _lb <= b && b <= _ub;
    }

    friend std::ostream& operator<<(std::ostream& o, const Interval& interval);

    // division and remainder operations
    [[nodiscard]]
    Interval sdiv(const Interval& x) const;

    [[nodiscard]]
    Interval udiv(const Interval& x) const;

    [[nodiscard]]
    Interval srem(const Interval& x) const;

    [[nodiscard]]
    Interval urem(const Interval& x) const;

    // bitwise operations
    void mask_value(int width);
    void mask_shift_count(int width);

    [[nodiscard]]
    Interval bitwise_and(const Interval& x) const;

    [[nodiscard]]
    Interval bitwise_or(const Interval& x) const;

    [[nodiscard]]
    Interval bitwise_xor(const Interval& x) const;

    [[nodiscard]]
    Interval shl(const Interval& x) const;

    [[nodiscard]]
    Interval lshr(const Interval& x) const;

    [[nodiscard]]
    Interval ashr(const Interval& x) const;

    Interval sign_extend(bool is64) const = delete;
    [[nodiscard]]
    Interval sign_extend(int width) const;

    Interval zero_extend(bool is64) const = delete;
    [[nodiscard]]
    Interval zero_extend(int width) const;

    template <std::signed_integral T>
    [[nodiscard]]
    Interval truncate_to() const {
        return sign_extend(static_cast<int>(sizeof(T)) * 8);
    }

    template <std::unsigned_integral T>
    [[nodiscard]]
    Interval truncate_to() const {
        return zero_extend(static_cast<int>(sizeof(T)) * 8);
    }

    Interval signed_int(bool is64) const = delete;
    // Return an interval in the range [INT_MIN, INT_MAX] which can only
    // be represented as an svalue.
    static Interval signed_int(const int width) { return Interval{Number::min_int(width), Number::max_int(width)}; }
    template <int width>
    static Interval signed_int() {
        static Interval res{Number::min_int(width), Number::max_int(width)};
        return res;
    }

    Interval unsigned_int(bool is64) const = delete;
    // Return an interval in the range [0, UINT_MAX] which can only be
    // represented as a uvalue.
    static Interval unsigned_int(const int width) { return Interval{0, Number::max_uint(width)}; }
    template <int width>
    static Interval unsigned_int() {
        static Interval res{0, Number::max_uint(width)};
        return res;
    }

    Interval nonnegative(bool is64) const = delete;
    // Return a non-negative interval in the range [0, INT_MAX],
    // which can be represented as both an svalue and a uvalue.
    static Interval nonnegative(const int width) { return Interval{Number{0}, Number::max_int(width)}; }
    template <int width>
    static Interval nonnegative() {
        static Interval res{Number{0}, Number::max_int(width)};
        return res;
    }

    Interval negative(bool is64) const = delete;
    // Return a negative interval in the range [INT_MIN, -1],
    // which can be represented as both an svalue and a uvalue.
    static Interval negative(const int width) { return Interval{Number::min_int(width), Number{-1}}; }
    template <int width>
    static Interval negative() {
        static Interval res{Number::min_int(width), Number{-1}};
        return res;
    }

    Interval unsigned_high(bool is64) const = delete;
    // Return an interval in the range [INT_MAX+1, UINT_MAX], which can only be represented as a uvalue.
    // The svalue equivalent using the same width would be negative().
    static Interval unsigned_high(const int width) {
        return Interval{Number::max_int(width) + 1, Number::max_uint(width)};
    }
    template <int width>
    static Interval unsigned_high() {
        static Interval res{Number::max_int(width) + 1, Number::max_uint(width)};
        return res;
    }

    [[nodiscard]]
    std::string to_string() const;
}; //  class interval

namespace interval_operators {

inline Interval operator+(const Number& c, const Interval& x) { return Interval{c} + x; }

inline Interval operator+(const Interval& x, const Number& c) { return x + Interval{c}; }

inline Interval operator*(const Number& c, const Interval& x) { return Interval{c} * x; }

inline Interval operator*(const Interval& x, const Number& c) { return x * Interval{c}; }

inline Interval operator/(const Number& c, const Interval& x) { return Interval{c} / x; }

inline Interval operator/(const Interval& x, const Number& c) { return x / Interval{c}; }

inline Interval operator-(const Number& c, const Interval& x) { return Interval{c} - x; }

inline Interval operator-(const Interval& x, const Number& c) { return x - Interval{c}; }

} // namespace interval_operators

std::string to_string(const Interval& interval) noexcept;

} // namespace prevail

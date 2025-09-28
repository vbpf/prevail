// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <utility>

#include "arith/num_big.hpp"
#include "crab_utils/stats.hpp"

namespace prevail {

class ExtendedNumber final {
    bool _is_infinite;
    Number _n;

    ExtendedNumber(const bool is_infinite, const Number& n) : _is_infinite(is_infinite), _n(n) {
        if (is_infinite) {
            if (n > 0) {
                _n = 1;
            } else {
                _n = -1;
            }
        }
    }

  public:
    static ExtendedNumber plus_infinity() { return ExtendedNumber(true, 1); }

    static ExtendedNumber minus_infinity() { return ExtendedNumber(true, -1); }

    explicit ExtendedNumber(const std::string& s) : _n(1) {
        if (s == "+oo") {
            _is_infinite = true;
        } else if (s == "-oo") {
            _is_infinite = true;
            _n = -1;
        } else {
            _is_infinite = false;
            _n = Number(s);
        }
    }

    ExtendedNumber(Number n) : _is_infinite(false), _n(std::move(n)) {}
    ExtendedNumber(std::integral auto n) : _is_infinite(false), _n{n} {}

    ExtendedNumber(const ExtendedNumber& o) = default;

    ExtendedNumber(ExtendedNumber&&) noexcept = default;

    template <std::integral T>
    T narrow() const {
        if (_is_infinite) {
            CRAB_ERROR("Bound: cannot narrow infinite value");
        }
        return _n.narrow<T>();
    }

    template <is_enum T>
    T narrow() const {
        return static_cast<T>(narrow<std::underlying_type_t<T>>());
    }

    ExtendedNumber& operator=(ExtendedNumber&&) noexcept = default;

    ExtendedNumber& operator=(const ExtendedNumber& o) {
        if (this != &o) {
            _is_infinite = o._is_infinite;
            _n = o._n;
        }
        return *this;
    }

    [[nodiscard]]
    bool is_infinite() const {
        return _is_infinite;
    }

    [[nodiscard]]
    bool is_finite() const {
        return !_is_infinite;
    }

    [[nodiscard]]
    bool is_plus_infinity() const {
        return (is_infinite() && _n > 0);
    }

    [[nodiscard]]
    bool is_minus_infinity() const {
        return (is_infinite() && _n < 0);
    }

    ExtendedNumber operator-() const { return ExtendedNumber(_is_infinite, -_n); }

    ExtendedNumber operator+(const ExtendedNumber& x) const {
        if (is_finite()) {
            if (x.is_finite()) {
                return ExtendedNumber(_n + x._n);
            }
            return x;
        }
        if (x.is_finite() || x._n == _n) {
            return *this;
        }
        CRAB_ERROR("Bound: undefined operation -oo + +oo");
    }

    ExtendedNumber& operator+=(const ExtendedNumber& x) { return operator=(operator+(x)); }

    ExtendedNumber operator-(const ExtendedNumber& x) const { return operator+(x.operator-()); }

    ExtendedNumber& operator-=(const ExtendedNumber& x) { return operator=(operator-(x)); }

    ExtendedNumber operator*(const ExtendedNumber& x) const {
        if (x._n == 0) {
            return x;
        } else if (_n == 0) {
            return *this;
        } else {
            return ExtendedNumber(_is_infinite || x._is_infinite, _n * x._n);
        }
    }

    ExtendedNumber& operator*=(const ExtendedNumber& x) { return operator=(operator*(x)); }

  private:
    ExtendedNumber AbsDiv(const ExtendedNumber& x, ExtendedNumber (*f)(const Number&, const Number&)) const {
        if (x._n == 0) {
            CRAB_ERROR("Bound: division by zero");
        }
        if (x.is_infinite()) {
            if (is_infinite()) {
                CRAB_ERROR("Bound: inf / inf");
            }
            return Number{0};
        }
        if (is_infinite()) {
            return *this;
        }
        return f(_n, x._n);
    }

  public:
    ExtendedNumber operator/(const ExtendedNumber& x) const {
        return AbsDiv(x,
                      [](const Number& dividend, const Number& divisor) { return ExtendedNumber{dividend / divisor}; });
    }

    ExtendedNumber operator%(const ExtendedNumber& x) const {
        return AbsDiv(x,
                      [](const Number& dividend, const Number& divisor) { return ExtendedNumber{dividend % divisor}; });
    }

    [[nodiscard]]
    ExtendedNumber udiv(const ExtendedNumber& x) const {
        using M = uint64_t;
        return AbsDiv(x, [](const Number& dividend, const Number& divisor) {
            return ExtendedNumber{(dividend >= 0 ? dividend : Number{dividend.cast_to<M>()}) /
                                  (divisor >= 0 ? divisor : Number{divisor.cast_to<M>()})};
        });
    }

    [[nodiscard]]
    ExtendedNumber urem(const ExtendedNumber& x) const {
        using M = uint64_t;
        return AbsDiv(x, [](const Number& dividend, const Number& divisor) {
            return ExtendedNumber{(dividend >= 0 ? dividend : Number{dividend.cast_to<M>()}) %
                                  (divisor >= 0 ? divisor : Number{divisor.cast_to<M>()})};
        });
    }

    ExtendedNumber& operator/=(const ExtendedNumber& x) { return operator=(operator/(x)); }

    bool operator<(const ExtendedNumber& x) const { return !operator>=(x); }

    bool operator>(const ExtendedNumber& x) const { return !operator<=(x); }

    bool operator==(const ExtendedNumber& x) const { return (_is_infinite == x._is_infinite && _n == x._n); }

    bool operator!=(const ExtendedNumber& x) const { return !operator==(x); }

    [[nodiscard]]
    Number sign_extend(const int width) const {
        if (is_infinite()) {
            CRAB_ERROR("Bound: infinity cannot be sign_extended");
        }
        return _n.sign_extend(width);
    }

    [[nodiscard]]
    Number zero_extend(const int width) const {
        if (is_infinite()) {
            CRAB_ERROR("Bound: infinity cannot be zero_extended");
        }
        return _n.zero_extend(width);
    }

    /*	operator<= and operator>= use a somewhat optimized implementation.
     *	results include up to 20% improvements in performance in the octagon domain
     *	over a more naive implementation.
     */
    bool operator<=(const ExtendedNumber& x) const {
        if (_is_infinite xor x._is_infinite) {
            if (_is_infinite) {
                return _n < 0;
            }
            return x._n > 0;
        }
        return _n <= x._n;
    }

    bool operator>=(const ExtendedNumber& x) const {
        if (_is_infinite xor x._is_infinite) {
            if (_is_infinite) {
                return _n > 0;
            }
            return x._n < 0;
        }
        return _n >= x._n;
    }

    [[nodiscard]]
    ExtendedNumber abs() const {
        if (operator>=(Number{0})) {
            return *this;
        } else {
            return operator-();
        }
    }

    [[nodiscard]]
    std::optional<Number> number() const {
        if (is_infinite()) {
            return {};
        } else {
            return {_n};
        }
    }

    friend std::ostream& operator<<(std::ostream& o, const ExtendedNumber& b) {
        if (b.is_plus_infinity()) {
            o << "+oo";
        } else if (b.is_minus_infinity()) {
            o << "-oo";
        } else {
            o << b._n;
        }
        return o;
    }

}; // class ExtendedNumber

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <utility>

#include "crab_utils/num_big.hpp"
#include "crab_utils/stats.hpp"

namespace prevail {

class extended_number final {
    bool _is_infinite;
    number_t _n;

    extended_number(const bool is_infinite, const number_t& n) : _is_infinite(is_infinite), _n(n) {
        if (is_infinite) {
            if (n > 0) {
                _n = 1;
            } else {
                _n = -1;
            }
        }
    }

  public:
    static extended_number plus_infinity() { return extended_number(true, 1); }

    static extended_number minus_infinity() { return extended_number(true, -1); }

    explicit extended_number(const std::string& s) : _n(1) {
        if (s == "+oo") {
            _is_infinite = true;
        } else if (s == "-oo") {
            _is_infinite = true;
            _n = -1;
        } else {
            _is_infinite = false;
            _n = number_t(s);
        }
    }

    extended_number(number_t n) : _is_infinite(false), _n(std::move(n)) {}
    extended_number(std::integral auto n) : _is_infinite(false), _n{n} {}

    extended_number(const extended_number& o) = default;

    extended_number(extended_number&&) noexcept = default;

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

    extended_number& operator=(extended_number&&) noexcept = default;

    extended_number& operator=(const extended_number& o) {
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

    extended_number operator-() const { return extended_number(_is_infinite, -_n); }

    extended_number operator+(const extended_number& x) const {
        if (is_finite()) {
            if (x.is_finite()) {
                return extended_number(_n + x._n);
            }
            return x;
        }
        if (x.is_finite() || x._n == _n) {
            return *this;
        }
        CRAB_ERROR("Bound: undefined operation -oo + +oo");
    }

    extended_number& operator+=(const extended_number& x) { return operator=(operator+(x)); }

    extended_number operator-(const extended_number& x) const { return operator+(x.operator-()); }

    extended_number& operator-=(const extended_number& x) { return operator=(operator-(x)); }

    extended_number operator*(const extended_number& x) const {
        if (x._n == 0) {
            return x;
        } else if (_n == 0) {
            return *this;
        } else {
            return extended_number(_is_infinite || x._is_infinite, _n * x._n);
        }
    }

    extended_number& operator*=(const extended_number& x) { return operator=(operator*(x)); }

  private:
    extended_number AbsDiv(const extended_number& x, extended_number (*f)(number_t, number_t)) const {
        if (x._n == 0) {
            CRAB_ERROR("Bound: division by zero");
        }
        if (x.is_infinite()) {
            if (is_infinite()) {
                CRAB_ERROR("Bound: inf / inf");
            }
            return number_t{0};
        }
        if (is_infinite()) {
            return *this;
        }
        return f(_n, x._n);
    }

  public:
    extended_number operator/(const extended_number& x) const {
        return AbsDiv(x, [](number_t dividend, number_t divisor) { return extended_number{dividend / divisor}; });
    }

    extended_number operator%(const extended_number& x) const {
        return AbsDiv(x, [](number_t dividend, number_t divisor) { return extended_number{dividend % divisor}; });
    }

    [[nodiscard]]
    extended_number udiv(const extended_number& x) const {
        using M = uint64_t;
        return AbsDiv(x, [](number_t dividend, number_t divisor) {
            dividend = dividend >= 0 ? dividend : number_t{dividend.cast_to<M>()};
            divisor = divisor >= 0 ? divisor : number_t{divisor.cast_to<M>()};
            return extended_number{dividend / divisor};
        });
    }

    [[nodiscard]]
    extended_number urem(const extended_number& x) const {
        using M = uint64_t;
        return AbsDiv(x, [](number_t dividend, number_t divisor) {
            dividend = dividend >= 0 ? dividend : number_t{dividend.cast_to<M>()};
            divisor = divisor >= 0 ? divisor : number_t{divisor.cast_to<M>()};
            return extended_number{dividend % divisor};
        });
    }

    extended_number& operator/=(const extended_number& x) { return operator=(operator/(x)); }

    bool operator<(const extended_number& x) const { return !operator>=(x); }

    bool operator>(const extended_number& x) const { return !operator<=(x); }

    bool operator==(const extended_number& x) const { return (_is_infinite == x._is_infinite && _n == x._n); }

    bool operator!=(const extended_number& x) const { return !operator==(x); }

    [[nodiscard]]
    number_t sign_extend(const int width) const {
        if (is_infinite()) {
            CRAB_ERROR("Bound: infinity cannot be sign_extended");
        }
        return _n.sign_extend(width);
    }

    [[nodiscard]]
    number_t zero_extend(const int width) const {
        if (is_infinite()) {
            CRAB_ERROR("Bound: infinity cannot be zero_extended");
        }
        return _n.zero_extend(width);
    }

    /*	operator<= and operator>= use a somewhat optimized implementation.
     *	results include up to 20% improvements in performance in the octagon domain
     *	over a more naive implementation.
     */
    bool operator<=(const extended_number& x) const {
        if (_is_infinite xor x._is_infinite) {
            if (_is_infinite) {
                return _n < 0;
            }
            return x._n > 0;
        }
        return _n <= x._n;
    }

    bool operator>=(const extended_number& x) const {
        if (_is_infinite xor x._is_infinite) {
            if (_is_infinite) {
                return _n > 0;
            }
            return x._n < 0;
        }
        return _n >= x._n;
    }

    [[nodiscard]]
    extended_number abs() const {
        if (operator>=(number_t{0})) {
            return *this;
        } else {
            return operator-();
        }
    }

    [[nodiscard]]
    std::optional<number_t> number() const {
        if (is_infinite()) {
            return {};
        } else {
            return {_n};
        }
    }

    friend std::ostream& operator<<(std::ostream& o, const extended_number& b) {
        if (b.is_plus_infinity()) {
            o << "+oo";
        } else if (b.is_minus_infinity()) {
            o << "-oo";
        } else {
            o << b._n;
        }
        return o;
    }

}; // class extended_number

} // namespace prevail

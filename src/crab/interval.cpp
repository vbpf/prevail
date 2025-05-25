// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "crab/interval.hpp"

namespace prevail {

static Interval make_dividend_when_both_nonzero(const Interval& dividend, const Interval& divisor) {
    if (dividend.ub() >= 0) {
        return dividend;
    }
    if (divisor.ub() < 0) {
        return dividend + divisor + Interval{1};
    }
    return dividend + Interval{1} - divisor;
}

Interval Interval::operator*(const Interval& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    const auto [clb, cub] = std::minmax({
        _lb * x._lb,
        _lb * x._ub,
        _ub * x._lb,
        _ub * x._ub,
    });
    return Interval{clb, cub};
}

// Signed division. eBPF has no instruction for this.
Interval Interval::operator/(const Interval& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        // Divisor is a singleton:
        //   the linear interval solver can perform many divisions where
        //   the divisor is a singleton interval. We optimize for this case.
        Number c = *n;
        if (c == 1) {
            return *this;
        } else if (c > 0) {
            return Interval{_lb / c, _ub / c};
        } else if (c < 0) {
            return Interval{_ub / c, _lb / c};
        } else {
            // The eBPF ISA defines division by 0 as resulting in 0.
            return Interval{0};
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        Interval l{x._lb, -1};
        Interval u{1, x._ub};
        return operator/(l) | operator/(u) | Interval{0};
    } else if (contains(0)) {
        // The dividend contains 0.
        Interval l{_lb, -1};
        Interval u{1, _ub};
        return (l / x) | (u / x) | Interval{0};
    } else {
        // Neither the dividend nor the divisor contains 0
        Interval a = make_dividend_when_both_nonzero(*this, x);
        const auto [clb, cub] = std::minmax({
            a._lb / x._lb,
            a._lb / x._ub,
            a._ub / x._lb,
            a._ub / x._ub,
        });
        return Interval{clb, cub};
    }
}

// Signed division.
Interval Interval::sdiv(const Interval& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        if (n->fits_cast_to<int64_t>()) {
            // Divisor is a singleton:
            //   the linear interval solver can perform many divisions where
            //   the divisor is a singleton interval. We optimize for this case.
            Number c{n->cast_to<int64_t>()};
            if (c == 1) {
                return *this;
            } else if (c != 0) {
                return Interval{_lb / c, _ub / c};
            } else {
                // The eBPF ISA defines division by 0 as resulting in 0.
                return Interval{0};
            }
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        Interval l{x._lb, -1};
        Interval u{1, x._ub};
        return sdiv(l) | sdiv(u) | Interval{0};
    } else if (contains(0)) {
        // The dividend contains 0.
        Interval l{_lb, -1};
        Interval u{1, _ub};
        return l.sdiv(x) | u.sdiv(x) | Interval{0};
    } else {
        // Neither the dividend nor the divisor contains 0
        Interval a = make_dividend_when_both_nonzero(*this, x);
        const auto [clb, cub] = std::minmax({
            a._lb / x._lb,
            a._lb / x._ub,
            a._ub / x._lb,
            a._ub / x._ub,
        });
        return Interval{clb, cub};
    }
}

// Unsigned division.
Interval Interval::udiv(const Interval& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        if (n->fits_cast_to<int64_t>()) {
            // Divisor is a singleton:
            //   the linear interval solver can perform many divisions where
            //   the divisor is a singleton interval. We optimize for this case.
            Number c{n->cast_to<uint64_t>()};
            if (c == 1) {
                return *this;
            } else if (c > 0) {
                return Interval{_lb.udiv(c), _ub.udiv(c)};
            } else {
                // The eBPF ISA defines division by 0 as resulting in 0.
                return Interval{0};
            }
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        Interval l{x._lb, -1};
        Interval u{1, x._ub};
        return udiv(l) | udiv(u) | Interval{0};
    }
    if (contains(0)) {
        // The dividend contains 0.
        Interval l{_lb, -1};
        Interval u{1, _ub};
        return l.udiv(x) | u.udiv(x) | Interval{0};
    }
    // Neither the dividend nor the divisor contains 0
    Interval a = make_dividend_when_both_nonzero(*this, x);
    const auto [clb, cub] = std::minmax({
        a._lb.udiv(x._lb),
        a._lb.udiv(x._ub),
        a._ub.udiv(x._lb),
        a._ub.udiv(x._ub),
    });
    return Interval{clb, cub};
}

// Signed remainder (modulo).
Interval Interval::srem(const Interval& x) const {
    // note that the sign of the divisor does not matter

    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto dividend = singleton()) {
        if (const auto divisor = x.singleton()) {
            if (*divisor == 0) {
                return Interval{*dividend};
            }
            return Interval{*dividend % *divisor};
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        Interval l{x._lb, -1};
        Interval u{1, x._ub};
        return srem(l) | srem(u) | *this;
    }
    if (x.ub().is_finite() && x.lb().is_finite()) {
        auto [xlb, xub] = x.pair_number();
        const auto [min_divisor, max_divisor] = std::minmax({xlb.abs(), xub.abs()});

        if (ub() < min_divisor && -lb() < min_divisor) {
            // The modulo operation won't change the destination register.
            return *this;
        }

        if (lb() < 0) {
            if (ub() > 0) {
                return Interval{-(max_divisor - 1), max_divisor - 1};
            } else {
                return Interval{-(max_divisor - 1), 0};
            }
        }
        return Interval{0, max_divisor - 1};
    }
    // Divisor has infinite range, so result can be anything between the dividend and zero.
    return *this | Interval{0};
}

// Unsigned remainder (modulo).
Interval Interval::urem(const Interval& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto dividend = singleton()) {
        if (const auto divisor = x.singleton()) {
            if (dividend->fits_cast_to<uint64_t>() && divisor->fits_cast_to<uint64_t>()) {
                // The BPF ISA defines modulo by 0 as resulting in the original value.
                if (*divisor == 0) {
                    return Interval{*dividend};
                }
                uint64_t dividend_val = dividend->cast_to<uint64_t>();
                uint64_t divisor_val = divisor->cast_to<uint64_t>();
                return Interval{dividend_val % divisor_val};
            }
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        Interval l{x._lb, -1};
        Interval u{1, x._ub};
        return urem(l) | urem(u) | *this;
    } else if (contains(0)) {
        // The dividend contains 0.
        Interval l{_lb, -1};
        Interval u{1, _ub};
        return l.urem(x) | u.urem(x) | *this;
    } else {
        // Neither the dividend nor the divisor contains 0
        if (x._lb.is_infinite() || x._ub.is_infinite()) {
            // Divisor is infinite. A "negative" dividend could result in anything except
            // a value between the upper bound and 0, so set to top.  A "positive" dividend
            // could result in anything between 0 and the dividend - 1.
            return _ub < 0 ? top() : (*this - Interval{1}) | Interval{0};
        } else if (_ub.is_finite() && _ub.number()->cast_to<uint64_t>() < x._lb.number()->cast_to<uint64_t>()) {
            // Dividend lower than divisor, so the dividend is the remainder.
            return *this;
        } else {
            Number max_divisor{x._ub.number()->cast_to<uint64_t>()};
            return Interval{0, max_divisor - 1};
        }
    }
}

// Do a bitwise-AND between two uvalue intervals.
Interval Interval::bitwise_and(const Interval& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    assert(is_top() || (lb() >= 0));
    assert(x.is_top() || (x.lb() >= 0));

    if (*this == Interval{0} || x == Interval{0}) {
        return Interval{0};
    }

    if (const auto right = x.singleton()) {
        if (const auto left = singleton()) {
            return Interval{*left & *right};
        }
        if (right == Number::max_uint(32)) {
            return zero_extend(32);
        }
        if (right == Number::max_uint(16)) {
            return zero_extend(16);
        }
        if (right == Number::max_uint(8)) {
            return zero_extend(8);
        }
    }
    if (x.contains(std::numeric_limits<uint64_t>::max())) {
        return truncate_to<uint64_t>();
    } else if (!is_top() && !x.is_top()) {
        return Interval{0, std::min(ub(), x.ub())};
    } else if (!x.is_top()) {
        return Interval{0, x.ub()};
    } else if (!is_top()) {
        return Interval{0, ub()};
    } else {
        return top();
    }
}

Interval Interval::bitwise_or(const Interval& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto left_op = singleton()) {
        if (const auto right_op = x.singleton()) {
            return Interval{*left_op | *right_op};
        }
    }
    if (lb() >= 0 && x.lb() >= 0) {
        if (const auto left_ub = ub().number()) {
            if (const auto right_ub = x.ub().number()) {
                return Interval{0, std::max(*left_ub, *right_ub).fill_ones()};
            }
        }
        return Interval{0, Bound::plus_infinity()};
    }
    return top();
}

Interval Interval::bitwise_xor(const Interval& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto left_op = singleton()) {
        if (const auto right_op = x.singleton()) {
            return Interval{*left_op ^ *right_op};
        }
    }
    return bitwise_or(x);
}

Interval Interval::shl(const Interval& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto shift = x.singleton()) {
        const Number k = *shift;
        if (k < 0) {
            return top();
        }
        // Some crazy linux drivers generate shl instructions with huge shifts.
        // We limit the number of times the loop is run to avoid wasting too much time on it.
        if (k <= 128) {
            Number factor = 1;
            for (int i = 0; k > i; i++) {
                factor *= 2;
            }
            return this->operator*(Interval{factor});
        }
    }
    return top();
}

Interval Interval::ashr(const Interval& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto shift = x.singleton()) {
        const Number k = *shift;
        if (k < 0) {
            return top();
        }
        // Some crazy linux drivers generate ashr instructions with huge shifts.
        // We limit the number of times the loop is run to avoid wasting too much time on it.
        if (k <= 128) {
            Number factor = 1;
            for (int i = 0; k > i; i++) {
                factor *= 2;
            }
            return this->operator/(Interval{factor});
        }
    }
    return top();
}

Interval Interval::lshr(const Interval& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto shift = x.singleton()) {
        if (*shift > 0 && lb() >= 0 && ub().is_finite()) {
            const auto [lb, ub] = this->pair_number();
            return Interval{lb >> *shift, ub >> *shift};
        }
    }
    return top();
}

Interval Interval::sign_extend(const int width) const {
    if (width <= 0) {
        CRAB_ERROR("Invalid width ", width);
    }

    const Interval full_range = signed_int(width);
    if (size() < full_range.size()) {
        if (Interval extended{_lb.sign_extend(width), _ub.sign_extend(width)}) {
            // If the sign–extended endpoints are in order, no wrap occurred.
            return extended;
        }
    }
    // [0b0111..., 0b1000...] is in the original range, so the result is [0b1000..., 0b0111...] which is the full range.
    return full_range;
}

Interval Interval::zero_extend(const int width) const {
    if (width <= 0) {
        CRAB_ERROR("Invalid width ", width);
    }

    const Interval full_range = unsigned_int(width);
    if (size() < full_range.size()) {
        if (Interval extended{_lb.zero_extend(width), _ub.zero_extend(width)}) {
            // If the sign–extended endpoints are in order, no wrap occurred.
            return extended;
        }
    }
    // [0b1111..., 0b0000...] is in the original range, so the result is [0b0000..., 0b1111...] which is the full
    return full_range;
}
} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "crab/interval.hpp"

namespace prevail {

static interval_t make_dividend_when_both_nonzero(const interval_t& dividend, const interval_t& divisor) {
    if (dividend.ub() >= 0) {
        return dividend;
    }
    if (divisor.ub() < 0) {
        return dividend + divisor + interval_t{1};
    }
    return dividend + interval_t{1} - divisor;
}

interval_t interval_t::operator*(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    const auto [clb, cub] = std::minmax({
        _lb * x._lb,
        _lb * x._ub,
        _ub * x._lb,
        _ub * x._ub,
    });
    return interval_t{clb, cub};
}

// Signed division. eBPF has no instruction for this.
interval_t interval_t::operator/(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        // Divisor is a singleton:
        //   the linear interval solver can perform many divisions where
        //   the divisor is a singleton interval. We optimize for this case.
        number_t c = *n;
        if (c == 1) {
            return *this;
        } else if (c > 0) {
            return interval_t{_lb / c, _ub / c};
        } else if (c < 0) {
            return interval_t{_ub / c, _lb / c};
        } else {
            // The eBPF ISA defines division by 0 as resulting in 0.
            return interval_t{0};
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l{x._lb, -1};
        interval_t u{1, x._ub};
        return operator/(l) | operator/(u) | interval_t{0};
    } else if (contains(0)) {
        // The dividend contains 0.
        interval_t l{_lb, -1};
        interval_t u{1, _ub};
        return (l / x) | (u / x) | interval_t{0};
    } else {
        // Neither the dividend nor the divisor contains 0
        interval_t a = make_dividend_when_both_nonzero(*this, x);
        const auto [clb, cub] = std::minmax({
            a._lb / x._lb,
            a._lb / x._ub,
            a._ub / x._lb,
            a._ub / x._ub,
        });
        return interval_t{clb, cub};
    }
}

// Signed division.
interval_t interval_t::sdiv(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        if (n->fits_cast_to<int64_t>()) {
            // Divisor is a singleton:
            //   the linear interval solver can perform many divisions where
            //   the divisor is a singleton interval. We optimize for this case.
            number_t c{n->cast_to<int64_t>()};
            if (c == 1) {
                return *this;
            } else if (c != 0) {
                return interval_t{_lb / c, _ub / c};
            } else {
                // The eBPF ISA defines division by 0 as resulting in 0.
                return interval_t{0};
            }
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l{x._lb, -1};
        interval_t u{1, x._ub};
        return sdiv(l) | sdiv(u) | interval_t{0};
    } else if (contains(0)) {
        // The dividend contains 0.
        interval_t l{_lb, -1};
        interval_t u{1, _ub};
        return l.sdiv(x) | u.sdiv(x) | interval_t{0};
    } else {
        // Neither the dividend nor the divisor contains 0
        interval_t a = make_dividend_when_both_nonzero(*this, x);
        const auto [clb, cub] = std::minmax({
            a._lb / x._lb,
            a._lb / x._ub,
            a._ub / x._lb,
            a._ub / x._ub,
        });
        return interval_t{clb, cub};
    }
}

// Unsigned division.
interval_t interval_t::udiv(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        if (n->fits_cast_to<int64_t>()) {
            // Divisor is a singleton:
            //   the linear interval solver can perform many divisions where
            //   the divisor is a singleton interval. We optimize for this case.
            number_t c{n->cast_to<uint64_t>()};
            if (c == 1) {
                return *this;
            } else if (c > 0) {
                return interval_t{_lb.udiv(c), _ub.udiv(c)};
            } else {
                // The eBPF ISA defines division by 0 as resulting in 0.
                return interval_t{0};
            }
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l{x._lb, -1};
        interval_t u{1, x._ub};
        return udiv(l) | udiv(u) | interval_t{0};
    }
    if (contains(0)) {
        // The dividend contains 0.
        interval_t l{_lb, -1};
        interval_t u{1, _ub};
        return l.udiv(x) | u.udiv(x) | interval_t{0};
    }
    // Neither the dividend nor the divisor contains 0
    interval_t a = make_dividend_when_both_nonzero(*this, x);
    const auto [clb, cub] = std::minmax({
        a._lb.udiv(x._lb),
        a._lb.udiv(x._ub),
        a._ub.udiv(x._lb),
        a._ub.udiv(x._ub),
    });
    return interval_t{clb, cub};
}

// Signed remainder (modulo).
interval_t interval_t::srem(const interval_t& x) const {
    // note that the sign of the divisor does not matter

    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto dividend = singleton()) {
        if (const auto divisor = x.singleton()) {
            if (*divisor == 0) {
                return interval_t{*dividend};
            }
            return interval_t{*dividend % *divisor};
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l{x._lb, -1};
        interval_t u{1, x._ub};
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
                return interval_t{-(max_divisor - 1), max_divisor - 1};
            } else {
                return interval_t{-(max_divisor - 1), 0};
            }
        }
        return interval_t{0, max_divisor - 1};
    }
    // Divisor has infinite range, so result can be anything between the dividend and zero.
    return *this | interval_t{0};
}

// Unsigned remainder (modulo).
interval_t interval_t::urem(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto dividend = singleton()) {
        if (const auto divisor = x.singleton()) {
            if (dividend->fits_cast_to<uint64_t>() && divisor->fits_cast_to<uint64_t>()) {
                // The BPF ISA defines modulo by 0 as resulting in the original value.
                if (*divisor == 0) {
                    return interval_t{*dividend};
                }
                uint64_t dividend_val = dividend->cast_to<uint64_t>();
                uint64_t divisor_val = divisor->cast_to<uint64_t>();
                return interval_t{dividend_val % divisor_val};
            }
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l{x._lb, -1};
        interval_t u{1, x._ub};
        return urem(l) | urem(u) | *this;
    } else if (contains(0)) {
        // The dividend contains 0.
        interval_t l{_lb, -1};
        interval_t u{1, _ub};
        return l.urem(x) | u.urem(x) | *this;
    } else {
        // Neither the dividend nor the divisor contains 0
        if (x._lb.is_infinite() || x._ub.is_infinite()) {
            // Divisor is infinite. A "negative" dividend could result in anything except
            // a value between the upper bound and 0, so set to top.  A "positive" dividend
            // could result in anything between 0 and the dividend - 1.
            return _ub < 0 ? top() : (*this - interval_t{1}) | interval_t{0};
        } else if (_ub.is_finite() && _ub.number()->cast_to<uint64_t>() < x._lb.number()->cast_to<uint64_t>()) {
            // Dividend lower than divisor, so the dividend is the remainder.
            return *this;
        } else {
            number_t max_divisor{x._ub.number()->cast_to<uint64_t>()};
            return interval_t{0, max_divisor - 1};
        }
    }
}

// Do a bitwise-AND between two uvalue intervals.
interval_t interval_t::bitwise_and(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    assert(is_top() || (lb() >= 0));
    assert(x.is_top() || (x.lb() >= 0));

    if (*this == interval_t{0} || x == interval_t{0}) {
        return interval_t{0};
    }

    if (const auto right = x.singleton()) {
        if (const auto left = singleton()) {
            return interval_t{*left & *right};
        }
        if (right == number_t::max_uint(32)) {
            return zero_extend(32);
        }
        if (right == number_t::max_uint(16)) {
            return zero_extend(16);
        }
        if (right == number_t::max_uint(8)) {
            return zero_extend(8);
        }
    }
    if (x.contains(std::numeric_limits<uint64_t>::max())) {
        return truncate_to<uint64_t>();
    } else if (!is_top() && !x.is_top()) {
        return interval_t{0, std::min(ub(), x.ub())};
    } else if (!x.is_top()) {
        return interval_t{0, x.ub()};
    } else if (!is_top()) {
        return interval_t{0, ub()};
    } else {
        return top();
    }
}

interval_t interval_t::bitwise_or(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto left_op = singleton()) {
        if (const auto right_op = x.singleton()) {
            return interval_t{*left_op | *right_op};
        }
    }
    if (lb() >= 0 && x.lb() >= 0) {
        if (const auto left_ub = ub().number()) {
            if (const auto right_ub = x.ub().number()) {
                return interval_t{0, std::max(*left_ub, *right_ub).fill_ones()};
            }
        }
        return interval_t{0, bound_t::plus_infinity()};
    }
    return top();
}

interval_t interval_t::bitwise_xor(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto left_op = singleton()) {
        if (const auto right_op = x.singleton()) {
            return interval_t{*left_op ^ *right_op};
        }
    }
    return bitwise_or(x);
}

interval_t interval_t::shl(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto shift = x.singleton()) {
        const number_t k = *shift;
        if (k < 0) {
            return top();
        }
        // Some crazy linux drivers generate shl instructions with huge shifts.
        // We limit the number of times the loop is run to avoid wasting too much time on it.
        if (k <= 128) {
            number_t factor = 1;
            for (int i = 0; k > i; i++) {
                factor *= 2;
            }
            return this->operator*(interval_t{factor});
        }
    }
    return top();
}

interval_t interval_t::ashr(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto shift = x.singleton()) {
        const number_t k = *shift;
        if (k < 0) {
            return top();
        }
        // Some crazy linux drivers generate ashr instructions with huge shifts.
        // We limit the number of times the loop is run to avoid wasting too much time on it.
        if (k <= 128) {
            number_t factor = 1;
            for (int i = 0; k > i; i++) {
                factor *= 2;
            }
            return this->operator/(interval_t{factor});
        }
    }
    return top();
}

interval_t interval_t::lshr(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto shift = x.singleton()) {
        if (*shift > 0 && lb() >= 0 && ub().is_finite()) {
            const auto [lb, ub] = this->pair_number();
            return interval_t{lb >> *shift, ub >> *shift};
        }
    }
    return top();
}

interval_t interval_t::sign_extend(const int width) const {
    if (width <= 0) {
        CRAB_ERROR("Invalid width ", width);
    }

    const interval_t full_range = signed_int(width);
    if (size() < full_range.size()) {
        if (interval_t extended{_lb.sign_extend(width), _ub.sign_extend(width)}) {
            // If the sign–extended endpoints are in order, no wrap occurred.
            return extended;
        }
    }
    // [0b0111..., 0b1000...] is in the original range, so the result is [0b1000..., 0b0111...] which is the full range.
    return full_range;
}

interval_t interval_t::zero_extend(const int width) const {
    if (width <= 0) {
        CRAB_ERROR("Invalid width ", width);
    }

    const interval_t full_range = unsigned_int(width);
    if (size() < full_range.size()) {
        if (interval_t extended{_lb.zero_extend(width), _ub.zero_extend(width)}) {
            // If the sign–extended endpoints are in order, no wrap occurred.
            return extended;
        }
    }
    // [0b1111..., 0b0000...] is in the original range, so the result is [0b0000..., 0b1111...] which is the full
    return full_range;
}
} // namespace prevail

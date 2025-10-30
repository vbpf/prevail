// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <optional>
#include <utility>

#include "arith/dsl_syntax.hpp"
#include "arith/linear_constraint.hpp"
#include "arith/variable.hpp"
#include "crab/finite_domain.hpp"
#include "crab/interval.hpp"
#include "crab/split_dbm.hpp"
#include "ir/syntax.hpp"
#include "string_constraints.hpp"

namespace prevail {

using NumAbsDomain = SplitDBM;

Interval FiniteDomain::eval_interval(const Variable v, const int finite_width) const {
    const Interval span = dom.eval_interval(v);
    return variable_registry->is_unsigned(v) ? span.zero_extend(finite_width) : span.sign_extend(finite_width);
}

static std::vector<LinearConstraint> assume_bit_cst_interval(Condition::Op op, bool is64, Interval dst_interval,
                                                             Interval src_interval) {
    using namespace dsl_syntax;
    using Op = Condition::Op;

    const auto dst_n = dst_interval.singleton();
    if (!dst_n || !dst_n.value().fits_cast_to<int64_t>()) {
        return {};
    }

    const auto src_n = src_interval.singleton();
    if (!src_n || !src_n->fits_cast_to<int64_t>()) {
        return {};
    }
    uint64_t src_int_value = src_n.value().cast_to<uint64_t>();
    if (!is64) {
        src_int_value = gsl::narrow_cast<uint32_t>(src_int_value);
    }

    bool result;
    switch (op) {
    case Op::SET: result = (dst_n.value().cast_to<uint64_t>() & src_int_value) != 0; break;
    case Op::NSET: result = (dst_n.value().cast_to<uint64_t>() & src_int_value) == 0; break;
    default: throw std::exception();
    }

    return {result ? LinearConstraint::true_const() : LinearConstraint::false_const()};
}

std::vector<LinearConstraint> FiniteDomain::assume_signed_64bit_eq(const Variable left_svalue,
                                                                   const Variable left_uvalue,
                                                                   const Interval& right_interval,
                                                                   const LinearExpression& right_svalue,
                                                                   const LinearExpression& right_uvalue) const {
    using namespace dsl_syntax;
    if (right_interval <= Interval::nonnegative(64) && !right_interval.is_singleton()) {
        return {(left_svalue == right_svalue), (left_uvalue == right_uvalue), eq(left_svalue, left_uvalue)};
    } else {
        return {(left_svalue == right_svalue), (left_uvalue == right_uvalue)};
    }
}

std::vector<LinearConstraint> FiniteDomain::assume_signed_32bit_eq(const Variable left_svalue,
                                                                   const Variable left_uvalue,
                                                                   const Interval& right_interval) const {
    using namespace dsl_syntax;

    if (const auto rn = right_interval.singleton()) {
        const auto left_svalue_interval = eval_interval(left_svalue);
        if (auto size = left_svalue_interval.finite_size()) {
            // Find the lowest 64-bit svalue whose low 32 bits match the singleton.

            // Get lower bound as a 64-bit value.
            int64_t lb = left_svalue_interval.lb().number()->cast_to<int64_t>();

            // Use the high 32-bits from the left lower bound and the low 32-bits from the right singleton.
            // The result might be lower than the lower bound.
            const int64_t lb_match = (lb & 0xFFFFFFFF00000000) | (rn->cast_to<int64_t>() & 0xFFFFFFFF);
            if (lb_match < lb) {
                // The result is lower than the left interval, so try the next higher matching 64-bit value.
                // It's ok if this goes higher than the left upper bound.
                lb += 0x100000000;
            }

            // Find the highest 64-bit svalue whose low 32 bits match the singleton.

            // Get upper bound as a 64-bit value.
            const int64_t ub = left_svalue_interval.ub().number()->cast_to<int64_t>();

            // Use the high 32-bits from the left upper bound and the low 32-bits from the right singleton.
            // The result might be higher than the upper bound.
            const int64_t ub_match = (ub & 0xFFFFFFFF00000000) | (rn->cast_to<int64_t>() & 0xFFFFFFFF);
            if (ub_match > ub) {
                // The result is higher than the left interval, so try the next lower matching 64-bit value.
                // It's ok if this goes lower than the left lower bound.
                lb -= 0x100000000;
            }

            if (to_unsigned(lb_match) <= to_unsigned(ub_match)) {
                // The interval is also valid when cast to a uvalue, meaning
                // both bounds are positive or both are negative.
                return {left_svalue >= lb_match, left_svalue <= ub_match, left_uvalue >= to_unsigned(lb_match),
                        left_uvalue <= to_unsigned(ub_match)};
            } else {
                // The interval can only be represented as an svalue.
                return {left_svalue >= lb_match, left_svalue <= ub_match};
            }
        }
    }
    return {};
}

// Given left and right values, get the left and right intervals, and also split
// the left interval into separate negative and positive intervals.
void FiniteDomain::get_signed_intervals(bool is64, const Variable left_svalue, const Variable left_uvalue,
                                        const LinearExpression& right_svalue, Interval& left_interval,
                                        Interval& right_interval, Interval& left_interval_positive,
                                        Interval& left_interval_negative) const {

    using namespace dsl_syntax;

    // Get intervals as 32-bit or 64-bit as appropriate.
    left_interval = eval_interval(left_svalue);
    right_interval = eval_interval(right_svalue);
    if (!is64) {
        if ((left_interval <= Interval::nonnegative(32) && right_interval <= Interval::nonnegative(32)) ||
            (left_interval <= Interval::negative(32) && right_interval <= Interval::negative(32))) {
            is64 = true;
            // fallthrough as 64bit, including deduction of relational information
        } else {
            left_interval = left_interval.truncate_to<int32_t>();
            right_interval = right_interval.truncate_to<int32_t>();
            // continue as 32bit
        }
    }

    if (!left_interval.is_top()) {
        left_interval_positive = left_interval & Interval::nonnegative(64);
        left_interval_negative = left_interval & Interval::negative(64);
    } else {
        left_interval = eval_interval(left_uvalue);
        if (!left_interval.is_top()) {
            // The interval is TOP as a signed interval but is represented precisely as an unsigned interval,
            // so split into two signed intervals that can be treated separately.
            left_interval_positive = left_interval & Interval::nonnegative(64);
            const Number lih_ub =
                left_interval.ub().number() ? left_interval.ub().number()->truncate_to<int64_t>() : -1;
            left_interval_negative = Interval{std::numeric_limits<int64_t>::min(), lih_ub};
        } else {
            left_interval_positive = Interval::nonnegative(64);
            left_interval_negative = Interval::negative(64);
        }
    }

    left_interval = left_interval.truncate_to<int64_t>();
    right_interval = right_interval.truncate_to<int64_t>();
}

// Given left and right values, get the left and right intervals, and also split
// the left interval into separate low and high intervals.
void FiniteDomain::get_unsigned_intervals(bool is64, const Variable left_svalue, const Variable left_uvalue,
                                          const LinearExpression& right_uvalue, Interval& left_interval,
                                          Interval& right_interval, Interval& left_interval_low,
                                          Interval& left_interval_high) const {

    using namespace dsl_syntax;

    // Get intervals as 32-bit or 64-bit as appropriate.
    left_interval = eval_interval(left_uvalue);
    right_interval = eval_interval(right_uvalue);
    if (!is64) {
        if ((left_interval <= Interval::nonnegative(32) && right_interval <= Interval::nonnegative(32)) ||
            (left_interval <= Interval::unsigned_high(32) && right_interval <= Interval::unsigned_high(32))) {
            is64 = true;
            // fallthrough as 64bit, including deduction of relational information
        } else {
            left_interval = left_interval.truncate_to<uint32_t>();
            right_interval = right_interval.truncate_to<uint32_t>();
            // continue as 32bit
        }
    }

    if (!left_interval.is_top()) {
        left_interval_low = left_interval & Interval::nonnegative(64);
        left_interval_high = left_interval & Interval::unsigned_high(64);
    } else {
        left_interval = eval_interval(left_svalue);
        if (!left_interval.is_top()) {
            // The interval is TOP as an unsigned interval but is represented precisely as a signed interval,
            // so split into two unsigned intervals that can be treated separately.
            left_interval_low = Interval(0, left_interval.ub()).truncate_to<uint64_t>();
            left_interval_high = Interval(left_interval.lb(), -1).truncate_to<uint64_t>();
        } else {
            left_interval_low = Interval::nonnegative(64);
            left_interval_high = Interval::unsigned_high(64);
        }
    }

    left_interval = left_interval.truncate_to<uint64_t>();
    right_interval = right_interval.truncate_to<uint64_t>();
}

std::vector<LinearConstraint>
FiniteDomain::assume_signed_64bit_lt(const bool strict, const Variable left_svalue, const Variable left_uvalue,
                                     const Interval& left_interval_positive, const Interval& left_interval_negative,
                                     const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                                     const Interval& right_interval) const {

    using namespace dsl_syntax;

    if (right_interval <= Interval::negative(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1].
        return {strict ? left_svalue < right_svalue : left_svalue <= right_svalue, 0 <= left_uvalue,
                strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
    } else if ((left_interval_negative | left_interval_positive) <= Interval::nonnegative(64) &&
               right_interval <= Interval::nonnegative(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        return {strict ? left_svalue < right_svalue : left_svalue <= right_svalue, 0 <= left_uvalue,
                strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
    } else {
        // Interval can only be represented as an svalue.
        return {strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    }
}

std::vector<LinearConstraint>
FiniteDomain::assume_signed_32bit_lt(const bool strict, const Variable left_svalue, const Variable left_uvalue,
                                     const Interval& left_interval_positive, const Interval& left_interval_negative,
                                     const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                                     const Interval& right_interval) const {

    using namespace dsl_syntax;

    if (right_interval <= Interval::negative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1],
        // aka [INT_MAX+1, UINT_MAX].
        return {std::numeric_limits<int32_t>::max() < left_uvalue,
                strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else if ((left_interval_negative | left_interval_positive) <= Interval::nonnegative(32) &&
               right_interval <= Interval::nonnegative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX]
        const auto lpub = left_interval_positive.truncate_to<int32_t>().ub();
        return {left_svalue >= 0,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue,
                left_svalue <= left_uvalue,
                left_svalue >= left_uvalue,
                left_uvalue >= 0,
                strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                left_uvalue <= *lpub.number()};
    } else if (eval_interval(left_svalue) <= Interval::signed_int(32) &&
               eval_interval(right_svalue) <= Interval::signed_int(32)) {
        // Interval can only be represented as an svalue.
        return {strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else {
        // We can't directly compare the svalues since they may differ in high order bits.
        return {};
    }
}

std::vector<LinearConstraint>
FiniteDomain::assume_signed_64bit_gt(const bool strict, const Variable left_svalue, const Variable left_uvalue,
                                     const Interval& left_interval_positive, const Interval& left_interval_negative,
                                     const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                                     const Interval& right_interval) const {

    using namespace dsl_syntax;

    if (right_interval <= Interval::nonnegative(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        const auto lpub = left_interval_positive.truncate_to<int64_t>().ub();
        return {left_svalue >= 0,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue,
                left_svalue <= left_uvalue,
                left_svalue >= left_uvalue,
                left_uvalue >= 0,
                strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                left_uvalue <= *lpub.number()};
    } else if ((left_interval_negative | left_interval_positive) <= Interval::negative(64) &&
               right_interval <= Interval::negative(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1],
        // aka [INT_MAX+1, UINT_MAX].
        return {std::numeric_limits<int64_t>::max() < left_uvalue,
                strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else {
        // Interval can only be represented as an svalue.
        return {strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    }
}

std::vector<LinearConstraint>
FiniteDomain::assume_signed_32bit_gt(const bool strict, const Variable left_svalue, const Variable left_uvalue,
                                     const Interval& left_interval_positive, const Interval& left_interval_negative,
                                     const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                                     const Interval& right_interval) const {

    using namespace dsl_syntax;

    if (right_interval <= Interval::nonnegative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        const auto lpub = left_interval_positive.truncate_to<int32_t>().ub();
        return {left_svalue >= 0,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue,
                left_svalue <= left_uvalue,
                left_svalue >= left_uvalue,
                left_uvalue >= 0,
                strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                left_uvalue <= *lpub.number()};
    } else if ((left_interval_negative | left_interval_positive) <= Interval::negative(32) &&
               right_interval <= Interval::negative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1],
        // aka [INT_MAX+1, UINT_MAX].
        return {left_uvalue >= Number{std::numeric_limits<int32_t>::max()} + 1,
                strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else if (eval_interval(left_svalue) <= Interval::signed_int(32) &&
               eval_interval(right_svalue) <= Interval::signed_int(32)) {
        // Interval can only be represented as an svalue.
        return {strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else {
        // We can't directly compare the svalues since they may differ in high order bits.
        return {};
    }
}

std::vector<LinearConstraint> FiniteDomain::assume_signed_cst_interval(Condition::Op op, bool is64,
                                                                       Variable left_svalue, Variable left_uvalue,
                                                                       const LinearExpression& right_svalue,
                                                                       const LinearExpression& right_uvalue) const {

    using namespace dsl_syntax;

    Interval left_interval = Interval::bottom();
    Interval right_interval = Interval::bottom();
    Interval left_interval_positive = Interval::bottom();
    Interval left_interval_negative = Interval::bottom();
    get_signed_intervals(is64, left_svalue, left_uvalue, right_svalue, left_interval, right_interval,
                         left_interval_positive, left_interval_negative);

    if (op == Condition::Op::EQ) {
        // Handle svalue == right.
        if (is64) {
            return assume_signed_64bit_eq(left_svalue, left_uvalue, right_interval, right_svalue, right_uvalue);
        } else {
            return assume_signed_32bit_eq(left_svalue, left_uvalue, right_interval);
        }
    }

    const bool is_lt = op == Condition::Op::SLT || op == Condition::Op::SLE;
    bool strict = op == Condition::Op::SLT || op == Condition::Op::SGT;

    auto llb = left_interval.lb();
    auto lub = left_interval.ub();
    auto rlb = right_interval.lb();
    auto rub = right_interval.ub();
    if (!is_lt && (strict ? lub <= rlb : lub < rlb)) {
        // Left signed interval is lower than right signed interval.
        return {LinearConstraint::false_const()};
    } else if (is_lt && (strict ? llb >= rub : llb > rub)) {
        // Left signed interval is higher than right signed interval.
        return {LinearConstraint::false_const()};
    }
    if (is_lt && (strict ? lub < rlb : lub <= rlb)) {
        // Left signed interval is lower than right signed interval.
        return {LinearConstraint::true_const()};
    } else if (!is_lt && (strict ? llb > rub : llb >= rub)) {
        // Left signed interval is higher than right signed interval.
        return {LinearConstraint::true_const()};
    }

    if (is64) {
        if (is_lt) {
            return assume_signed_64bit_lt(strict, left_svalue, left_uvalue, left_interval_positive,
                                          left_interval_negative, right_svalue, right_uvalue, right_interval);
        } else {
            return assume_signed_64bit_gt(strict, left_svalue, left_uvalue, left_interval_positive,
                                          left_interval_negative, right_svalue, right_uvalue, right_interval);
        }
    } else {
        // 32-bit compare.
        if (is_lt) {
            return assume_signed_32bit_lt(strict, left_svalue, left_uvalue, left_interval_positive,
                                          left_interval_negative, right_svalue, right_uvalue, right_interval);
        } else {
            return assume_signed_32bit_gt(strict, left_svalue, left_uvalue, left_interval_positive,
                                          left_interval_negative, right_svalue, right_uvalue, right_interval);
        }
    }
    return {};
}

std::vector<LinearConstraint>
FiniteDomain::assume_unsigned_64bit_lt(bool strict, Variable left_svalue, Variable left_uvalue,
                                       const Interval& left_interval_low, const Interval& left_interval_high,
                                       const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                                       const Interval& right_interval) const {

    using namespace dsl_syntax;

    auto rub = right_interval.ub();
    auto lllb = left_interval_low.truncate_to<uint64_t>().lb();
    if (right_interval <= Interval::nonnegative(64) && (strict ? lllb >= rub : lllb > rub)) {
        // The high interval is out of range.
        if (auto lsubn = eval_interval(left_svalue).ub().number()) {
            return {left_uvalue >= 0, (strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue),
                    left_uvalue <= *lsubn, left_svalue >= 0};
        } else {
            return {left_uvalue >= 0, (strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue),
                    left_svalue >= 0};
        }
    }
    auto lhlb = left_interval_high.truncate_to<uint64_t>().lb();
    if (right_interval <= Interval::unsigned_high(64) && (strict ? lhlb >= rub : lhlb > rub)) {
        // The high interval is out of range.
        if (auto lsubn = eval_interval(left_svalue).ub().number()) {
            return {left_uvalue >= 0, (strict ? left_uvalue < *rub.number() : left_uvalue <= *rub.number()),
                    left_uvalue <= *lsubn, left_svalue >= 0};
        } else {
            return {left_uvalue >= 0, (strict ? left_uvalue < *rub.number() : left_uvalue <= *rub.number()),
                    left_svalue >= 0};
        }
    }
    if (right_interval <= Interval::signed_int(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        auto llub = left_interval_low.truncate_to<uint64_t>().ub();
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                left_uvalue <= *llub.number(), 0 <= left_svalue,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else if (left_interval_low.is_bottom() && right_interval <= Interval::unsigned_high(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MAX+1, UINT_MAX].
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else if ((left_interval_low | left_interval_high) == Interval::unsigned_int(64)) {
        // Interval can only be represented as a uvalue, and was TOP before.
        return {strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
    } else {
        // Interval can only be represented as a uvalue.
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
    }
}

std::vector<LinearConstraint> FiniteDomain::assume_unsigned_32bit_lt(const bool strict, const Variable left_svalue,
                                                                     const Variable left_uvalue,
                                                                     const LinearExpression& right_svalue,
                                                                     const LinearExpression& right_uvalue) const {

    using namespace dsl_syntax;

    if (eval_interval(left_uvalue) <= Interval::nonnegative(32) &&
        eval_interval(right_uvalue) <= Interval::nonnegative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT32_MAX].
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else if (eval_interval(left_svalue) <= Interval::negative(32) &&
               eval_interval(right_svalue) <= Interval::negative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT32_MIN, -1].
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else if (eval_interval(left_uvalue) <= Interval::unsigned_int(32) &&
               eval_interval(right_uvalue) <= Interval::unsigned_int(32)) {
        // Interval can only be represented as a uvalue.
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
    } else {
        // We can't directly compare the uvalues since they may differ in high order bits.
        return {};
    }
}

std::vector<LinearConstraint>
FiniteDomain::assume_unsigned_64bit_gt(const bool strict, const Variable left_svalue, const Variable left_uvalue,
                                       const Interval& left_interval_low, const Interval& left_interval_high,
                                       const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                                       const Interval& right_interval) const {

    using namespace dsl_syntax;

    const auto rlb = right_interval.lb();
    const auto llub = left_interval_low.truncate_to<uint64_t>().ub();
    const auto lhlb = left_interval_high.truncate_to<uint64_t>().lb();

    if (right_interval <= Interval::nonnegative(64) && (strict ? llub <= rlb : llub < rlb)) {
        // The low interval is out of range.
        return {strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                *lhlb.number() == std::numeric_limits<uint64_t>::max() ? left_uvalue == *lhlb.number()
                                                                       : left_uvalue >= *lhlb.number(),
                left_svalue < 0};
    } else if (right_interval <= Interval::unsigned_high(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MAX+1, UINT_MAX].
        return {0 <= left_uvalue, strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else if ((left_interval_low | left_interval_high) <= Interval::nonnegative(64) &&
               right_interval <= Interval::nonnegative(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        return {0 <= left_uvalue, strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else {
        // Interval can only be represented as a uvalue.
        return {0 <= left_uvalue, strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue};
    }
}

std::vector<LinearConstraint>
FiniteDomain::assume_unsigned_32bit_gt(const bool strict, const Variable left_svalue, const Variable left_uvalue,
                                       const Interval& left_interval_low, const Interval& left_interval_high,
                                       const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                                       const Interval& right_interval) const {

    using namespace dsl_syntax;

    if (right_interval <= Interval::unsigned_high(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MAX+1, UINT_MAX].
        return {0 <= left_uvalue, strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else if (eval_interval(left_uvalue) <= Interval::unsigned_int(32) &&
               eval_interval(right_uvalue) <= Interval::unsigned_int(32)) {
        // Interval can only be represented as a uvalue.
        return {0 <= left_uvalue, strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue};
    } else {
        // We can't directly compare the uvalues since they may differ in high order bits.
        return {};
    }
}

std::vector<LinearConstraint> FiniteDomain::assume_unsigned_cst_interval(Condition::Op op, bool is64,
                                                                         Variable left_svalue, Variable left_uvalue,
                                                                         const LinearExpression& right_svalue,
                                                                         const LinearExpression& right_uvalue) const {

    using namespace dsl_syntax;

    Interval left_interval = Interval::bottom();
    Interval right_interval = Interval::bottom();
    Interval left_interval_low = Interval::bottom();
    Interval left_interval_high = Interval::bottom();
    get_unsigned_intervals(is64, left_svalue, left_uvalue, right_uvalue, left_interval, right_interval,
                           left_interval_low, left_interval_high);

    // Handle uvalue != right.
    if (op == Condition::Op::NE) {
        if (auto rn = right_interval.singleton()) {
            if (rn == left_interval.zero_extend(is64 ? 64 : 32).lb().number()) {
                // "NE lower bound" is equivalent to "GT lower bound".
                op = Condition::Op::GT;
                right_interval = Interval{left_interval.lb()};
            } else if (rn == left_interval.ub().number()) {
                // "NE upper bound" is equivalent to "LT upper bound".
                op = Condition::Op::LT;
                right_interval = Interval{left_interval.ub()};
            } else {
                return {};
            }
        } else {
            return {};
        }
    }

    const bool is_lt = op == Condition::Op::LT || op == Condition::Op::LE;
    bool strict = op == Condition::Op::LT || op == Condition::Op::GT;

    auto [llb, lub] = left_interval.pair();
    auto [rlb, rub] = right_interval.pair();
    if (is_lt ? (strict ? llb >= rub : llb > rub) : (strict ? lub <= rlb : lub < rlb)) {
        // Left unsigned interval is lower than right unsigned interval.
        return {LinearConstraint::false_const()};
    }
    if (is_lt && (strict ? lub < rlb : lub <= rlb)) {
        // Left unsigned interval is lower than right unsigned interval. We still add a
        // relationship for use when widening, such as is used in the prime conformance test.
        if (is64) {
            return {strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
        }
        return {};
    } else if (!is_lt && (strict ? llb > rub : llb >= rub)) {
        // Left unsigned interval is higher than right unsigned interval. We still add a
        // relationship for use when widening, such as is used in the prime conformance test.
        if (is64) {
            return {strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue};
        } else {
            return {};
        }
    }

    if (is64) {
        if (is_lt) {
            return assume_unsigned_64bit_lt(strict, left_svalue, left_uvalue, left_interval_low, left_interval_high,
                                            right_svalue, right_uvalue, right_interval);
        } else {
            return assume_unsigned_64bit_gt(strict, left_svalue, left_uvalue, left_interval_low, left_interval_high,
                                            right_svalue, right_uvalue, right_interval);
        }
    } else {
        if (is_lt) {
            return assume_unsigned_32bit_lt(strict, left_svalue, left_uvalue, right_svalue, right_uvalue);
        } else {
            return assume_unsigned_32bit_gt(strict, left_svalue, left_uvalue, left_interval_low, left_interval_high,
                                            right_svalue, right_uvalue, right_interval);
        }
    }
}

/** Linear constraints for a comparison with a constant.
 */
std::vector<LinearConstraint> FiniteDomain::assume_cst_imm(const Condition::Op op, const bool is64,
                                                           const Variable dst_svalue, const Variable dst_uvalue,
                                                           const int64_t imm) const {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ:
    case Op::SGE:
    case Op::SLE:
    case Op::SGT:
    case Op::SLT:
        return assume_signed_cst_interval(op, is64, dst_svalue, dst_uvalue, imm, gsl::narrow_cast<uint64_t>(imm));
    case Op::SET:
    case Op::NSET: return assume_bit_cst_interval(op, is64, eval_interval(dst_uvalue), Interval{imm});
    case Op::NE:
    case Op::GE:
    case Op::LE:
    case Op::GT:
    case Op::LT:
        return assume_unsigned_cst_interval(op, is64, dst_svalue, dst_uvalue, imm, gsl::narrow_cast<uint64_t>(imm));
    }
    return {};
}

/** Linear constraint for a numerical comparison between registers.
 */
std::vector<LinearConstraint> FiniteDomain::assume_cst_reg(const Condition::Op op, const bool is64,
                                                           const Variable dst_svalue, const Variable dst_uvalue,
                                                           const Variable src_svalue, const Variable src_uvalue) const {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    if (is64) {
        switch (op) {
        case Op::EQ: {
            const Interval src_interval = eval_interval(src_svalue);
            if (!src_interval.is_singleton() && src_interval <= Interval::nonnegative(64)) {
                return {eq(dst_svalue, src_svalue), eq(dst_uvalue, src_uvalue), eq(dst_svalue, dst_uvalue)};
            } else {
                return {eq(dst_svalue, src_svalue), eq(dst_uvalue, src_uvalue)};
            }
        }
        case Op::NE: return {neq(dst_svalue, src_svalue)};
        case Op::SGE: return {dst_svalue >= src_svalue};
        case Op::SLE: return {dst_svalue <= src_svalue};
        case Op::SGT: return {dst_svalue > src_svalue};
        // Note: reverse the test as a workaround strange lookup:
        case Op::SLT: return {src_svalue > dst_svalue};
        case Op::SET:
        case Op::NSET: return assume_bit_cst_interval(op, is64, eval_interval(dst_uvalue), eval_interval(src_uvalue));
        case Op::GE:
        case Op::LE:
        case Op::GT:
        case Op::LT: return assume_unsigned_cst_interval(op, is64, dst_svalue, dst_uvalue, src_svalue, src_uvalue);
        }
    } else {
        switch (op) {
        case Op::EQ:
        case Op::SGE:
        case Op::SLE:
        case Op::SGT:
        case Op::SLT: return assume_signed_cst_interval(op, is64, dst_svalue, dst_uvalue, src_svalue, src_uvalue);
        case Op::SET:
        case Op::NSET: return assume_bit_cst_interval(op, is64, eval_interval(dst_uvalue), eval_interval(src_uvalue));
        case Op::NE:
        case Op::GE:
        case Op::LE:
        case Op::GT:
        case Op::LT: return assume_unsigned_cst_interval(op, is64, dst_svalue, dst_uvalue, src_svalue, src_uvalue);
        }
    }
    assert(false);
    throw std::exception();
}

void FiniteDomain::assign(const Variable x, const std::optional<LinearExpression>& e) { dom.assign(x, e); }
void FiniteDomain::assign(const Variable x, const Variable e) { dom.assign(x, e); }
void FiniteDomain::assign(const Variable x, const LinearExpression& e) { dom.assign(x, e); }
void FiniteDomain::assign(const Variable x, const int64_t e) { dom.set(x, Interval(e)); }

// As defined in the BPF ISA specification, the immediate value of an unsigned modulo and division is treated
// differently depending on the width:
// * for 32 bit, as a 32-bit unsigned integer
// * for 64 bit, as a 32-bit (not 64 bit) signed integer
static Number read_imm_for_udiv_or_umod(const Number& imm, const int width) {
    assert(width == 32 || width == 64);
    if (width == 32) {
        return Number{imm.cast_to<uint32_t>()};
    }
    return Number{imm.cast_to<int32_t>()};
}

void FiniteDomain::apply(const ArithBinOp op, const Variable x, const Variable y, const Variable z,
                         const int finite_width) {
    switch (op) {
    case ArithBinOp::ADD: assign(x, LinearExpression(y).plus(z)); break;
    case ArithBinOp::SUB: assign(x, LinearExpression(y).subtract(z)); break;
    case ArithBinOp::MUL: set(x, eval_interval(y, finite_width) * eval_interval(z, finite_width)); break;
    default: CRAB_ERROR("DBM: unreachable");
    }
}

void FiniteDomain::apply(const ArithBinOp op, const Variable x, const Variable y, const Number& z,
                         const int finite_width) {
    switch (op) {
    case ArithBinOp::ADD: assign(x, LinearExpression(y).plus(z)); break;
    case ArithBinOp::SUB: assign(x, LinearExpression(y).subtract(z)); break;
    case ArithBinOp::MUL: set(x, eval_interval(y, finite_width) * Interval{z}); break;
    default: CRAB_ERROR("DBM: unreachable");
    }
}

// As defined in the BPF ISA specification, the immediate value of a signed modulo and division is treated
// differently depending on the width:
// * for 32 bit, as a 32-bit signed integer
// * for 64 bit, as a 64-bit signed integer
static Number read_imm_for_sdiv_or_smod(const Number& imm, const int width) {
    assert(width == 32 || width == 64);
    if (width == 32) {
        return Number{imm.cast_to<int32_t>()};
    }
    return Number{imm.cast_to<int64_t>()};
}

void FiniteDomain::apply(const SignedArithBinOp op, const Variable x, const Variable y, const Number& k,
                         const int finite_width) {
    switch (op) {
    case SignedArithBinOp::SDIV:
        set(x, eval_interval(y, finite_width).sdiv(Interval{read_imm_for_sdiv_or_smod(k, finite_width)}));
        break;
    case SignedArithBinOp::UDIV:
        set(x, eval_interval(y, finite_width).udiv(Interval{read_imm_for_udiv_or_umod(k, finite_width)}));
        break;
    case SignedArithBinOp::SREM:
        set(x, eval_interval(y, finite_width).srem(Interval{read_imm_for_sdiv_or_smod(k, finite_width)}));
        break;
    case SignedArithBinOp::UREM:
        set(x, eval_interval(y, finite_width).urem(Interval{read_imm_for_udiv_or_umod(k, finite_width)}));
        break;
    default: CRAB_ERROR("DBM: unreachable");
    }
}

void FiniteDomain::apply(const SignedArithBinOp op, const Variable x, const Variable y, const Variable z,
                         const int finite_width) {
    switch (op) {
    case SignedArithBinOp::SDIV: set(x, eval_interval(y, finite_width).sdiv(eval_interval(z, finite_width))); break;
    case SignedArithBinOp::UDIV: set(x, eval_interval(y, finite_width).udiv(eval_interval(z, finite_width))); break;
    case SignedArithBinOp::SREM: set(x, eval_interval(y, finite_width).srem(eval_interval(z, finite_width))); break;
    case SignedArithBinOp::UREM: set(x, eval_interval(y, finite_width).urem(eval_interval(z, finite_width))); break;
    default: CRAB_ERROR("DBM: unreachable");
    }
}

void FiniteDomain::apply(BitwiseBinOp op, Variable x, Variable y, Variable z, int finite_width) {
    // Convert to intervals and perform the operation
    Interval yi = dom.eval_interval(y);
    Interval zi = dom.eval_interval(z);
    Interval xi = Interval::bottom();
    switch (op) {
    case BitwiseBinOp::AND: xi = yi.bitwise_and(zi); break;
    case BitwiseBinOp::OR: xi = yi.bitwise_or(zi); break;
    case BitwiseBinOp::XOR: xi = yi.bitwise_xor(zi); break;
    case BitwiseBinOp::SHL: xi = yi.shl(zi); break;
    case BitwiseBinOp::LSHR: xi = yi.lshr(zi); break;
    case BitwiseBinOp::ASHR: xi = yi.ashr(zi); break;
    default: CRAB_ERROR("DBM: unreachable");
    }
    set(x, xi);
}

// Apply a bitwise operator to a uvalue.
void FiniteDomain::apply(BitwiseBinOp op, Variable x, Variable y, const Number& k, int finite_width) {
    // Convert to intervals and perform the operation
    Interval yi = dom.eval_interval(y);
    Interval zi(Number(k.cast_to<uint64_t>()));
    Interval xi = Interval::bottom();

    switch (op) {
    case BitwiseBinOp::AND: xi = yi.bitwise_and(zi); break;
    case BitwiseBinOp::OR: xi = yi.bitwise_or(zi); break;
    case BitwiseBinOp::XOR: xi = yi.bitwise_xor(zi); break;
    case BitwiseBinOp::SHL: xi = yi.shl(zi); break;
    case BitwiseBinOp::LSHR: xi = yi.lshr(zi); break;
    case BitwiseBinOp::ASHR: xi = yi.ashr(zi); break;
    default: CRAB_ERROR("DBM: unreachable");
    }
    set(x, xi);
}

void FiniteDomain::apply(BinOp op, Variable x, Variable y, const Number& z, int finite_width) {
    std::visit([&](auto top) { apply(top, x, y, z, finite_width); }, op);
}

void FiniteDomain::apply(BinOp op, Variable x, Variable y, Variable z, int finite_width) {
    std::visit([&](auto top) { apply(top, x, y, z, finite_width); }, op);
}

void FiniteDomain::apply(const BinOp op, const Variable x, const Variable y, const Variable z) {
    apply(op, x, y, z, 0);
}

void FiniteDomain::overflow_bounds(Variable lhs, int finite_width, bool issigned) {
    using namespace dsl_syntax;
    auto interval = eval_interval(lhs);
    if (interval.size() >= Interval::unsigned_int(finite_width).size()) {
        // Interval covers the full space.
        havoc(lhs);
        return;
    }
    if (interval.is_bottom()) {
        havoc(lhs);
        return;
    }
    Number lb_value = interval.lb().number().value();
    Number ub_value = interval.ub().number().value();

    // Compute the interval, taking overflow into account.
    // For a signed result, we need to ensure the signed and unsigned results match
    // so for a 32-bit operation, 0x80000000 should be a positive 64-bit number not
    // a sign extended negative one.
    Number lb = lb_value.zero_extend(finite_width);
    Number ub = ub_value.zero_extend(finite_width);
    if (issigned) {
        lb = lb.truncate_to<int64_t>();
        ub = ub.truncate_to<int64_t>();
    }
    if (lb > ub) {
        // Range wraps in the middle, so we cannot represent as an unsigned interval.
        havoc(lhs);
        return;
    }
    auto new_interval = Interval{lb, ub};
    if (new_interval != interval) {
        // Update the variable, which will lose any relationships to other variables.
        dom.set(lhs, new_interval);
    }
}

void FiniteDomain::overflow_bounds(const Variable svalue, const Variable uvalue, const int finite_width) {
    overflow_bounds(svalue, finite_width, true);
    overflow_bounds(uvalue, finite_width, false);
}

void FiniteDomain::apply_signed(const BinOp& op, const Variable xs, const Variable xu, const Variable y,
                                const Number& z, const int finite_width) {
    apply(op, xs, y, z, finite_width);
    if (finite_width) {
        assign(xu, xs);
        overflow_bounds(xs, xu, finite_width);
    }
}

void FiniteDomain::apply_signed(const BinOp& op, const Variable xs, const Variable xu, const Variable y,
                                const Variable z, const int finite_width) {
    apply(op, xs, y, z, finite_width);
    if (finite_width) {
        assign(xu, xs);
        overflow_bounds(xs, xu, finite_width);
    }
}

void FiniteDomain::apply_unsigned(const BinOp& op, const Variable xs, const Variable xu, const Variable y,
                                  const Number& z, const int finite_width) {
    apply(op, xu, y, z, finite_width);
    if (finite_width) {
        assign(xs, xu);
        overflow_bounds(xs, xu, finite_width);
    }
}

void FiniteDomain::apply_unsigned(const BinOp& op, const Variable xs, const Variable xu, const Variable y,
                                  const Variable z, const int finite_width) {
    apply(op, xu, y, z, finite_width);
    if (finite_width) {
        assign(xs, xu);
        overflow_bounds(xs, xu, finite_width);
    }
}

void FiniteDomain::add(const Variable lhs, const Variable op2) { apply_signed(ArithBinOp::ADD, lhs, lhs, lhs, op2, 0); }
void FiniteDomain::add(const Variable lhs, const Number& op2) { apply_signed(ArithBinOp::ADD, lhs, lhs, lhs, op2, 0); }
void FiniteDomain::sub(const Variable lhs, const Variable op2) { apply_signed(ArithBinOp::SUB, lhs, lhs, lhs, op2, 0); }
void FiniteDomain::sub(const Variable lhs, const Number& op2) { apply_signed(ArithBinOp::SUB, lhs, lhs, lhs, op2, 0); }

// Add/subtract with overflow are both signed and unsigned. We can use either one of the two to compute the
// result before adjusting for overflow, though if one is top we want to use the other to retain precision.
void FiniteDomain::add_overflow(const Variable lhss, const Variable lhsu, const Variable op2, const int finite_width) {
    apply_signed(ArithBinOp::ADD, lhss, lhsu, !eval_interval(lhss).is_top() ? lhss : lhsu, op2, finite_width);
}
void FiniteDomain::add_overflow(const Variable lhss, const Variable lhsu, const Number& op2, const int finite_width) {
    apply_signed(ArithBinOp::ADD, lhss, lhsu, !eval_interval(lhss).is_top() ? lhss : lhsu, op2, finite_width);
}
void FiniteDomain::sub_overflow(const Variable lhss, const Variable lhsu, const Variable op2, const int finite_width) {
    apply_signed(ArithBinOp::SUB, lhss, lhsu, !eval_interval(lhss).is_top() ? lhss : lhsu, op2, finite_width);
}
void FiniteDomain::sub_overflow(const Variable lhss, const Variable lhsu, const Number& op2, const int finite_width) {
    apply_signed(ArithBinOp::SUB, lhss, lhsu, !eval_interval(lhss).is_top() ? lhss : lhsu, op2, finite_width);
}

void FiniteDomain::neg(const Variable lhss, const Variable lhsu, const int finite_width) {
    apply_signed(ArithBinOp::MUL, lhss, lhsu, lhss, -1, finite_width);
}
void FiniteDomain::mul(const Variable lhss, const Variable lhsu, const Variable op2, const int finite_width) {
    apply_signed(ArithBinOp::MUL, lhss, lhsu, lhss, op2, finite_width);
}
void FiniteDomain::mul(const Variable lhss, const Variable lhsu, const Number& op2, const int finite_width) {
    apply_signed(ArithBinOp::MUL, lhss, lhsu, lhss, op2, finite_width);
}
void FiniteDomain::sdiv(const Variable lhss, const Variable lhsu, const Variable op2, const int finite_width) {
    apply_signed(SignedArithBinOp::SDIV, lhss, lhsu, lhss, op2, finite_width);
}
void FiniteDomain::sdiv(const Variable lhss, const Variable lhsu, const Number& op2, const int finite_width) {
    apply_signed(SignedArithBinOp::SDIV, lhss, lhsu, lhss, op2, finite_width);
}
void FiniteDomain::udiv(const Variable lhss, const Variable lhsu, const Variable op2, const int finite_width) {
    apply_unsigned(SignedArithBinOp::UDIV, lhss, lhsu, lhsu, op2, finite_width);
}
void FiniteDomain::udiv(const Variable lhss, const Variable lhsu, const Number& op2, const int finite_width) {
    apply_unsigned(SignedArithBinOp::UDIV, lhss, lhsu, lhsu, op2, finite_width);
}
void FiniteDomain::srem(const Variable lhss, const Variable lhsu, const Variable op2, const int finite_width) {
    apply_signed(SignedArithBinOp::SREM, lhss, lhsu, lhss, op2, finite_width);
}
void FiniteDomain::srem(const Variable lhss, const Variable lhsu, const Number& op2, const int finite_width) {
    apply_signed(SignedArithBinOp::SREM, lhss, lhsu, lhss, op2, finite_width);
}
void FiniteDomain::urem(const Variable lhss, const Variable lhsu, const Variable op2, const int finite_width) {
    apply_unsigned(SignedArithBinOp::UREM, lhss, lhsu, lhsu, op2, finite_width);
}
void FiniteDomain::urem(const Variable lhss, const Variable lhsu, const Number& op2, const int finite_width) {
    apply_unsigned(SignedArithBinOp::UREM, lhss, lhsu, lhsu, op2, finite_width);
}

void FiniteDomain::bitwise_and(const Variable lhss, const Variable lhsu, const Variable op2, const int finite_width) {
    apply_unsigned(BitwiseBinOp::AND, lhss, lhsu, lhsu, op2, finite_width);
}
void FiniteDomain::bitwise_and(const Variable lhss, const Variable lhsu, const Number& op2) {
    // Use finite width 64 to make the svalue be set as well as the uvalue.
    apply_unsigned(BitwiseBinOp::AND, lhss, lhsu, lhsu, op2, 64);
}
void FiniteDomain::bitwise_or(const Variable lhss, const Variable lhsu, const Variable op2, const int finite_width) {
    apply_unsigned(BitwiseBinOp::OR, lhss, lhsu, lhsu, op2, finite_width);
}
void FiniteDomain::bitwise_or(const Variable lhss, const Variable lhsu, const Number& op2) {
    apply_unsigned(BitwiseBinOp::OR, lhss, lhsu, lhsu, op2, 64);
}
void FiniteDomain::bitwise_xor(const Variable lhss, const Variable lhsu, const Variable op2, const int finite_width) {
    apply_unsigned(BitwiseBinOp::XOR, lhss, lhsu, lhsu, op2, finite_width);
}
void FiniteDomain::bitwise_xor(const Variable lhss, const Variable lhsu, const Number& op2) {
    apply_unsigned(BitwiseBinOp::XOR, lhss, lhsu, lhsu, op2, 64);
}
void FiniteDomain::shl_overflow(const Variable lhss, const Variable lhsu, const Variable op2) {
    apply_unsigned(BitwiseBinOp::SHL, lhss, lhsu, lhsu, op2, 64);
}
void FiniteDomain::shl_overflow(const Variable lhss, const Variable lhsu, const Number& op2) {
    apply_unsigned(BitwiseBinOp::SHL, lhss, lhsu, lhsu, op2, 64);
}

void FiniteDomain::shl(const Variable svalue, const Variable uvalue, const int imm, const int finite_width) {
    const auto uinterval = eval_interval(uvalue);
    if (!uinterval.finite_size()) {
        shl_overflow(svalue, uvalue, imm);
        return;
    }
    auto [lb_n, ub_n] = uinterval.pair<uint64_t>();
    const uint64_t uint_max = finite_width == 64 ? uint64_t{std::numeric_limits<uint64_t>::max()}
                                                 : uint64_t{std::numeric_limits<uint32_t>::max()};
    if (lb_n >> (finite_width - imm) != ub_n >> (finite_width - imm)) {
        // The bits that will be shifted out to the left are different,
        // which means all combinations of remaining bits are possible.
        lb_n = 0;
        ub_n = uint_max << imm & uint_max;
    } else {
        // The bits that will be shifted out to the left are identical
        // for all values in the interval, so we can safely shift left
        // to get a new interval.
        lb_n = lb_n << imm & uint_max;
        ub_n = ub_n << imm & uint_max;
    }
    set(uvalue, Interval{lb_n, ub_n});
    assign(svalue, uvalue);
    overflow_bounds(svalue, uvalue, finite_width);
}

void FiniteDomain::lshr(const Variable svalue, const Variable uvalue, int imm, int finite_width) {
    const auto uinterval = eval_interval(uvalue);
    if (uinterval.finite_size()) {
        auto [lb_n, ub_n] = uinterval.pair_number();
        if (finite_width == 64) {
            lb_n = lb_n.cast_to<uint64_t>() >> imm;
            ub_n = ub_n.cast_to<uint64_t>() >> imm;
        } else {
            const Number lb_w = lb_n.cast_to_sint(finite_width);
            const Number ub_w = ub_n.cast_to_sint(finite_width);
            lb_n = lb_w.cast_to<uint32_t>() >> imm;
            ub_n = ub_w.cast_to<uint32_t>() >> imm;

            // The interval must be valid since a signed range crossing 0
            // was earlier converted to a full unsigned range.
            assert(lb_n <= ub_n);
        }
        set(uvalue, Interval{lb_n, ub_n});
    } else {
        set(uvalue, Interval{0, std::numeric_limits<uint64_t>::max() >> imm});
    }
    assign(svalue, uvalue);
    overflow_bounds(svalue, uvalue, finite_width);
}

void FiniteDomain::ashr(const Variable svalue, const Variable uvalue, const LinearExpression& right_svalue,
                        int finite_width) {
    Interval left_interval = Interval::bottom();
    Interval right_interval = Interval::bottom();
    Interval left_interval_positive = Interval::bottom();
    Interval left_interval_negative = Interval::bottom();
    get_signed_intervals(finite_width == 64, svalue, uvalue, right_svalue, left_interval, right_interval,
                         left_interval_positive, left_interval_negative);
    if (auto sn = right_interval.singleton()) {
        // The BPF ISA requires masking the imm.
        const int64_t imm = sn->cast_to<int64_t>() & (finite_width - 1);

        int64_t lb_n = std::numeric_limits<int64_t>::min() >> imm;
        int64_t ub_n = std::numeric_limits<int64_t>::max() >> imm;
        if (left_interval.finite_size()) {
            const auto [lb, ub] = left_interval.pair_number();
            if (finite_width == 64) {
                lb_n = lb.cast_to<int64_t>() >> imm;
                ub_n = ub.cast_to<int64_t>() >> imm;
            } else {
                const Number lb_w = lb.cast_to_sint(finite_width) >> gsl::narrow<int>(imm);
                const Number ub_w = ub.cast_to_sint(finite_width) >> gsl::narrow<int>(imm);
                if (lb_w.cast_to<uint32_t>() <= ub_w.cast_to<uint32_t>()) {
                    lb_n = lb_w.cast_to<uint32_t>();
                    ub_n = ub_w.cast_to<uint32_t>();
                }
            }
        }
        set(svalue, Interval{lb_n, ub_n});
        assign(uvalue, svalue);
        overflow_bounds(svalue, uvalue, finite_width);
    } else {
        havoc(svalue);
        havoc(uvalue);
    }
}

void FiniteDomain::sign_extend(const Variable svalue, const Variable uvalue, const LinearExpression& right_svalue,
                               const int target_width, const int source_width) {
    const Interval right_interval = eval_interval(right_svalue);
    const Interval extended = right_interval.sign_extend(source_width);
    if (extended.is_bottom()) {
        CRAB_ERROR("Sign extension failed ", right_interval, source_width, " becomes bottom");
    }
    set(svalue, extended);
    assign(uvalue, svalue);
    overflow_bounds(svalue, uvalue, target_width);
}

} // namespace prevail

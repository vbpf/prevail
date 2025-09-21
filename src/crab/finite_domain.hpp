// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <utility>

#include "arith/linear_constraint.hpp"
#include "arith/progvar.hpp"
#include "asm_syntax.hpp" // for Condition::Op
#include "crab/interval.hpp"
#include "crab/split_dbm.hpp"
#include "string_constraints.hpp"

namespace prevail {

class FiniteDomain {
    SplitDBM dom;

    explicit FiniteDomain(const SplitDBM& dom) : dom{dom} {}

  public:
    explicit FiniteDomain() = default;

    FiniteDomain(const FiniteDomain& o) = default;
    FiniteDomain(FiniteDomain&& o) = default;

    FiniteDomain& operator=(const FiniteDomain& o) = default;
    FiniteDomain& operator=(FiniteDomain&& o) = default;

    void set_to_top() { dom.set_to_top(); }

    static FiniteDomain top() { return FiniteDomain(); }

    [[nodiscard]]
    bool is_top() const {
        return dom.is_top();
    }

    bool operator<=(const FiniteDomain& o) const { return dom <= o.dom; }

    // FIXME: can be done more efficient
    void operator|=(const FiniteDomain& o) { *this = *this | o; }
    void operator|=(FiniteDomain&& o) { *this = *this | std::move(o); }

    FiniteDomain operator|(const FiniteDomain& o) const& { return FiniteDomain{dom | o.dom}; }

    FiniteDomain operator|(FiniteDomain&& o) && { return FiniteDomain{std::move(dom) | std::move(o.dom)}; }

    FiniteDomain operator|(const FiniteDomain& o) && { return FiniteDomain{std::move(dom) | o.dom}; }

    FiniteDomain operator|(FiniteDomain&& o) const& { return FiniteDomain{dom | std::move(o.dom)}; }

    [[nodiscard]]
    FiniteDomain widen(const FiniteDomain& o) const {
        return FiniteDomain{dom.widen(o.dom)};
    }

    std::optional<FiniteDomain> meet(const FiniteDomain& o) const {
        const auto res = dom.meet(o.dom);
        if (!res) {
            return {};
        }
        return FiniteDomain{*res};
    }

    [[nodiscard]]
    FiniteDomain narrow(const FiniteDomain& o) const {
        return FiniteDomain{dom.narrow(o.dom)};
    }

    Interval eval_interval(const ProgVar& v) const { return dom.eval_interval(v); }
    Interval eval_interval(const LinearExpression& exp) const { return dom.eval_interval(exp); }

    void assign(const ProgVar& x, const std::optional<LinearExpression>& e);
    void assign(const ProgVar& x, const ProgVar& e);
    void assign(const ProgVar& x, const LinearExpression& e);
    void assign(const ProgVar& x, int64_t e);

    void apply(ArithBinOp op, const ProgVar& x, const ProgVar& y, const Number& z, int finite_width);
    void apply(ArithBinOp op, const ProgVar& x, const ProgVar& y, const ProgVar& z, int finite_width);
    void apply(BitwiseBinOp op, const ProgVar& x, const ProgVar& y, const ProgVar& z, int finite_width);
    void apply(BitwiseBinOp op, const ProgVar& x, const ProgVar& y, const Number& k, int finite_width);
    void apply(BinOp op, ProgVar x, ProgVar y, const Number& z, int finite_width);
    void apply(BinOp op, ProgVar x, ProgVar y, ProgVar z, int finite_width);
    void apply(const BinOp& op, const ProgVar& x, const ProgVar& y, const ProgVar& z) { apply(op, x, y, z, 0); }

    void overflow_bounds(ProgVar lhs, int finite_width, bool issigned);
    void overflow_bounds(const ProgVar& svalue, const ProgVar& uvalue, int finite_width);

    void apply_signed(const BinOp& op, const ProgVar& xs, const ProgVar& xu, const ProgVar& y, const Number& z,
                      int finite_width);
    void apply_signed(const BinOp& op, const ProgVar& xs, const ProgVar& xu, const ProgVar& y, const ProgVar& z,
                      int finite_width);
    void apply_unsigned(const BinOp& op, const ProgVar& xs, const ProgVar& xu, const ProgVar& y, const Number& z,
                        int finite_width);
    void apply_unsigned(const BinOp& op, const ProgVar& xs, const ProgVar& xu, const ProgVar& y, const ProgVar& z,
                        int finite_width);

    void add(const ProgVar& lhs, const ProgVar& op2);
    void add(const ProgVar& lhs, const Number& op2);
    void sub(const ProgVar& lhs, const ProgVar& op2);
    void sub(const ProgVar& lhs, const Number& op2);
    void add_overflow(const ProgVar& lhss, const ProgVar& lhsu, const ProgVar& op2, int finite_width);
    void add_overflow(const ProgVar& lhss, const ProgVar& lhsu, const Number& op2, int finite_width);
    void sub_overflow(const ProgVar& lhss, const ProgVar& lhsu, const ProgVar& op2, int finite_width);
    void sub_overflow(const ProgVar& lhss, const ProgVar& lhsu, const Number& op2, int finite_width);
    void neg(const ProgVar& lhss, const ProgVar& lhsu, int finite_width);
    void mul(const ProgVar& lhss, const ProgVar& lhsu, const ProgVar& op2, int finite_width);
    void mul(const ProgVar& lhss, const ProgVar& lhsu, const Number& op2, int finite_width);
    void sdiv(const ProgVar& lhss, const ProgVar& lhsu, const ProgVar& op2, int finite_width);
    void sdiv(const ProgVar& lhss, const ProgVar& lhsu, const Number& op2, int finite_width);
    void udiv(const ProgVar& lhss, const ProgVar& lhsu, const ProgVar& op2, int finite_width);
    void udiv(const ProgVar& lhss, const ProgVar& lhsu, const Number& op2, int finite_width);
    void srem(const ProgVar& lhss, const ProgVar& lhsu, const ProgVar& op2, int finite_width);
    void srem(const ProgVar& lhss, const ProgVar& lhsu, const Number& op2, int finite_width);
    void urem(const ProgVar& lhss, const ProgVar& lhsu, const ProgVar& op2, int finite_width);
    void urem(const ProgVar& lhss, const ProgVar& lhsu, const Number& op2, int finite_width);

    void bitwise_and(const ProgVar& lhss, const ProgVar& lhsu, const ProgVar& op2, int finite_width);
    void bitwise_and(const ProgVar& lhss, const ProgVar& lhsu, const Number& op2);
    void bitwise_or(const ProgVar& lhss, const ProgVar& lhsu, const ProgVar& op2, int finite_width);
    void bitwise_or(const ProgVar& lhss, const ProgVar& lhsu, const Number& op2);
    void bitwise_xor(const ProgVar& lhss, const ProgVar& lhsu, const ProgVar& op2, int finite_width);
    void bitwise_xor(const ProgVar& lhss, const ProgVar& lhsu, const Number& op2);
    void shl_overflow(const ProgVar& lhss, const ProgVar& lhsu, const ProgVar& op2);
    void shl_overflow(const ProgVar& lhss, const ProgVar& lhsu, const Number& op2);
    void shl(const ProgVar& svalue, const ProgVar& uvalue, int imm, int finite_width);
    void lshr(const ProgVar& svalue, const ProgVar& uvalue, int imm, int finite_width);
    void ashr(const ProgVar& svalue, const ProgVar& uvalue, const LinearExpression& right_svalue, int finite_width);
    void sign_extend(const ProgVar& svalue, const ProgVar& uvalue, const LinearExpression& right_svalue,
                     int target_width, int source_width);

    bool add_constraint(const LinearConstraint& cst) { return dom.add_constraint(cst); }

    void set(const ProgVar& x, const Interval& intv) { dom.set(x, intv); }

    /// Forget everything we know about the value of a variable.
    void havoc(const ProgVar& v) { dom.havoc(v); }

    [[nodiscard]]
    std::pair<std::size_t, std::size_t> size() const {
        return dom.size();
    }

    // Return true if inv intersects with cst.
    [[nodiscard]]
    bool intersect(const LinearConstraint& cst) const {
        return dom.intersect(cst);
    }

    // Return true if entails rhs.
    [[nodiscard]]
    bool entail(const LinearConstraint& rhs) const {
        return dom.entail(rhs);
    }

    friend std::ostream& operator<<(std::ostream& o, const FiniteDomain& dom) { return o << dom.dom; }

    [[nodiscard]]
    StringInvariant to_set() const {
        return dom.to_set();
    }

    static void clear_thread_local_state() { SplitDBM::clear_thread_local_state(); }

  private:
    std::vector<LinearConstraint> assume_signed_64bit_eq(const ProgVar& left_svalue, const ProgVar& left_uvalue,
                                                         const Interval& right_interval,
                                                         const LinearExpression& right_svalue,
                                                         const LinearExpression& right_uvalue) const;
    std::vector<LinearConstraint> assume_signed_32bit_eq(const ProgVar& left_svalue, const ProgVar& left_uvalue,
                                                         const Interval& right_interval) const;

    std::vector<LinearConstraint> assume_bit_cst_interval(Condition::Op op, bool is64, Interval dst_interval,
                                                          Interval src_interval) const;

    void get_unsigned_intervals(bool is64, const ProgVar& left_svalue, const ProgVar& left_uvalue,
                                const LinearExpression& right_uvalue, Interval& left_interval, Interval& right_interval,
                                Interval& left_interval_low, Interval& left_interval_high) const;
    std::vector<LinearConstraint>
    assume_signed_64bit_lt(bool strict, const ProgVar& left_svalue, const ProgVar& left_uvalue,
                           const Interval& left_interval_positive, const Interval& left_interval_negative,
                           const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                           const Interval& right_interval) const;
    std::vector<LinearConstraint>
    assume_signed_32bit_lt(bool strict, const ProgVar& left_svalue, const ProgVar& left_uvalue,
                           const Interval& left_interval_positive, const Interval& left_interval_negative,
                           const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                           const Interval& right_interval) const;
    std::vector<LinearConstraint>
    assume_signed_64bit_gt(bool strict, const ProgVar& left_svalue, const ProgVar& left_uvalue,
                           const Interval& left_interval_positive, const Interval& left_interval_negative,
                           const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                           const Interval& right_interval) const;
    std::vector<LinearConstraint>
    assume_signed_32bit_gt(bool strict, const ProgVar& left_svalue, const ProgVar& left_uvalue,
                           const Interval& left_interval_positive, const Interval& left_interval_negative,
                           const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                           const Interval& right_interval) const;
    std::vector<LinearConstraint> assume_signed_cst_interval(Condition::Op op, bool is64, ProgVar left_svalue,
                                                             ProgVar left_uvalue, const LinearExpression& right_svalue,
                                                             const LinearExpression& right_uvalue) const;
    std::vector<LinearConstraint>
    assume_unsigned_64bit_lt(bool strict, ProgVar left_svalue, ProgVar left_uvalue, const Interval& left_interval_low,
                             const Interval& left_interval_high, const LinearExpression& right_svalue,
                             const LinearExpression& right_uvalue, const Interval& right_interval) const;
    std::vector<LinearConstraint> assume_unsigned_32bit_lt(bool strict, const ProgVar& left_svalue,
                                                           const ProgVar& left_uvalue,
                                                           const LinearExpression& right_svalue,
                                                           const LinearExpression& right_uvalue) const;
    std::vector<LinearConstraint>
    assume_unsigned_64bit_gt(bool strict, const ProgVar& left_svalue, const ProgVar& left_uvalue,
                             const Interval& left_interval_low, const Interval& left_interval_high,
                             const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                             const Interval& right_interval) const;
    std::vector<LinearConstraint>
    assume_unsigned_32bit_gt(bool strict, const ProgVar& left_svalue, const ProgVar& left_uvalue,
                             const Interval& left_interval_low, const Interval& left_interval_high,
                             const LinearExpression& right_svalue, const LinearExpression& right_uvalue,
                             const Interval& right_interval) const;
    std::vector<LinearConstraint> assume_unsigned_cst_interval(Condition::Op op, bool is64, ProgVar left_svalue,
                                                               ProgVar left_uvalue,
                                                               const LinearExpression& right_svalue,
                                                               const LinearExpression& right_uvalue) const;

    void get_signed_intervals(bool is64, const ProgVar& left_svalue, const ProgVar& left_uvalue,
                              const LinearExpression& right_svalue, Interval& left_interval, Interval& right_interval,
                              Interval& left_interval_positive, Interval& left_interval_negative) const;

  public:
    std::vector<LinearConstraint> assume_cst_imm(Condition::Op op, bool is64, const ProgVar& dst_svalue,
                                                 const ProgVar& dst_uvalue, int64_t imm) const;
    std::vector<LinearConstraint> assume_cst_reg(Condition::Op op, bool is64, const ProgVar& dst_svalue,
                                                 const ProgVar& dst_uvalue, const ProgVar& src_svalue,
                                                 const ProgVar& src_uvalue) const;
};
} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <utility>
#include <variant>

#include "asm_syntax.hpp" // for Condition::Op
#include "crab/interval.hpp"
#include "crab/linear_constraint.hpp"
#include "crab/split_dbm.hpp"
#include "crab/variable.hpp"
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

    Interval eval_interval(const Variable& v) const { return dom.eval_interval(v); }
    Interval eval_interval(const LinearExpression& exp) const { return dom.eval_interval(exp); }

    void assign(Variable x, const std::optional<LinearExpression>& e);
    void assign(Variable x, Variable e);
    void assign(Variable x, const LinearExpression& e);
    void assign(Variable x, int64_t e);

    void apply(ArithBinOp op, Variable x, Variable y, const Number& z, int finite_width);
    void apply(ArithBinOp op, Variable x, Variable y, Variable z, int finite_width);
    void apply(BitwiseBinOp op, Variable x, Variable y, Variable z, int finite_width);
    void apply(BitwiseBinOp op, Variable x, Variable y, const Number& k, int finite_width);
    void apply(BinOp op, Variable x, Variable y, const Number& z, int finite_width);
    void apply(BinOp op, Variable x, Variable y, Variable z, int finite_width);
    void apply(const BinOp& op, const Variable x, const Variable y, const Variable z) { apply(op, x, y, z, 0); }

    void overflow_bounds(Variable lhs, int finite_width, bool issigned);
    void overflow_bounds(Variable svalue, Variable uvalue, int finite_width);

    void apply_signed(const BinOp& op, Variable xs, Variable xu, Variable y, const Number& z, int finite_width);
    void apply_signed(const BinOp& op, Variable xs, Variable xu, Variable y, Variable z, int finite_width);
    void apply_unsigned(const BinOp& op, Variable xs, Variable xu, Variable y, const Number& z, int finite_width);
    void apply_unsigned(const BinOp& op, Variable xs, Variable xu, Variable y, Variable z, int finite_width);

    void add(Variable lhs, Variable op2);
    void add(Variable lhs, const Number& op2);
    void sub(Variable lhs, Variable op2);
    void sub(Variable lhs, const Number& op2);
    void add_overflow(Variable lhss, Variable lhsu, Variable op2, int finite_width);
    void add_overflow(Variable lhss, Variable lhsu, const Number& op2, int finite_width);
    void sub_overflow(Variable lhss, Variable lhsu, Variable op2, int finite_width);
    void sub_overflow(Variable lhss, Variable lhsu, const Number& op2, int finite_width);
    void neg(Variable lhss, Variable lhsu, int finite_width);
    void mul(Variable lhss, Variable lhsu, Variable op2, int finite_width);
    void mul(Variable lhss, Variable lhsu, const Number& op2, int finite_width);
    void sdiv(Variable lhss, Variable lhsu, Variable op2, int finite_width);
    void sdiv(Variable lhss, Variable lhsu, const Number& op2, int finite_width);
    void udiv(Variable lhss, Variable lhsu, Variable op2, int finite_width);
    void udiv(Variable lhss, Variable lhsu, const Number& op2, int finite_width);
    void srem(Variable lhss, Variable lhsu, Variable op2, int finite_width);
    void srem(Variable lhss, Variable lhsu, const Number& op2, int finite_width);
    void urem(Variable lhss, Variable lhsu, Variable op2, int finite_width);
    void urem(Variable lhss, Variable lhsu, const Number& op2, int finite_width);

    void bitwise_and(Variable lhss, Variable lhsu, Variable op2, int finite_width);
    void bitwise_and(Variable lhss, Variable lhsu, const Number& op2);
    void bitwise_or(Variable lhss, Variable lhsu, Variable op2, int finite_width);
    void bitwise_or(Variable lhss, Variable lhsu, const Number& op2);
    void bitwise_xor(Variable lhss, Variable lhsu, Variable op2, int finite_width);
    void bitwise_xor(Variable lhss, Variable lhsu, const Number& op2);
    void shl_overflow(Variable lhss, Variable lhsu, Variable op2);
    void shl_overflow(Variable lhss, Variable lhsu, const Number& op2);
    void shl(Variable svalue, Variable uvalue, int imm, int finite_width);
    void lshr(Variable svalue, Variable uvalue, int imm, int finite_width);
    void ashr(Variable svalue, Variable uvalue, const LinearExpression& right_svalue, int finite_width);
    void sign_extend(Variable svalue, Variable uvalue, const LinearExpression& right_svalue, int target_width,
                     int source_width);

    bool add_constraint(const LinearConstraint& cst) { return dom.add_constraint(cst); }

    void set(const Variable x, const Interval& intv) { dom.set(x, intv); }

    /// Forget everything we know about the value of a variable.
    void havoc(Variable v) { dom.havoc(v); }

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
    std::vector<LinearConstraint> assume_signed_64bit_eq(Variable left_svalue, Variable left_uvalue,
                                                         const Interval& right_interval,
                                                         const LinearExpression& right_svalue,
                                                         const LinearExpression& right_uvalue) const;
    std::vector<LinearConstraint> assume_signed_32bit_eq(Variable left_svalue, Variable left_uvalue,
                                                         const Interval& right_interval) const;

    std::vector<LinearConstraint> assume_bit_cst_interval(Condition::Op op, bool is64, Interval dst_interval,
                                                          Interval src_interval) const;

    void get_unsigned_intervals(bool is64, Variable left_svalue, Variable left_uvalue,
                                const LinearExpression& right_uvalue, Interval& left_interval, Interval& right_interval,
                                Interval& left_interval_low, Interval& left_interval_high) const;
    std::vector<LinearConstraint> assume_signed_64bit_lt(bool strict, Variable left_svalue, Variable left_uvalue,
                                                         const Interval& left_interval_positive,
                                                         const Interval& left_interval_negative,
                                                         const LinearExpression& right_svalue,
                                                         const LinearExpression& right_uvalue,
                                                         const Interval& right_interval) const;
    std::vector<LinearConstraint> assume_signed_32bit_lt(bool strict, Variable left_svalue, Variable left_uvalue,
                                                         const Interval& left_interval_positive,
                                                         const Interval& left_interval_negative,
                                                         const LinearExpression& right_svalue,
                                                         const LinearExpression& right_uvalue,
                                                         const Interval& right_interval) const;
    std::vector<LinearConstraint> assume_signed_64bit_gt(bool strict, Variable left_svalue, Variable left_uvalue,
                                                         const Interval& left_interval_positive,
                                                         const Interval& left_interval_negative,
                                                         const LinearExpression& right_svalue,
                                                         const LinearExpression& right_uvalue,
                                                         const Interval& right_interval) const;
    std::vector<LinearConstraint> assume_signed_32bit_gt(bool strict, Variable left_svalue, Variable left_uvalue,
                                                         const Interval& left_interval_positive,
                                                         const Interval& left_interval_negative,
                                                         const LinearExpression& right_svalue,
                                                         const LinearExpression& right_uvalue,
                                                         const Interval& right_interval) const;
    std::vector<LinearConstraint> assume_signed_cst_interval(Condition::Op op, bool is64, Variable left_svalue,
                                                             Variable left_uvalue, const LinearExpression& right_svalue,
                                                             const LinearExpression& right_uvalue) const;
    std::vector<LinearConstraint>
    assume_unsigned_64bit_lt(bool strict, Variable left_svalue, Variable left_uvalue, const Interval& left_interval_low,
                             const Interval& left_interval_high, const LinearExpression& right_svalue,
                             const LinearExpression& right_uvalue, const Interval& right_interval) const;
    std::vector<LinearConstraint> assume_unsigned_32bit_lt(bool strict, Variable left_svalue, Variable left_uvalue,
                                                           const LinearExpression& right_svalue,
                                                           const LinearExpression& right_uvalue) const;
    std::vector<LinearConstraint>
    assume_unsigned_64bit_gt(bool strict, Variable left_svalue, Variable left_uvalue, const Interval& left_interval_low,
                             const Interval& left_interval_high, const LinearExpression& right_svalue,
                             const LinearExpression& right_uvalue, const Interval& right_interval) const;
    std::vector<LinearConstraint>
    assume_unsigned_32bit_gt(bool strict, Variable left_svalue, Variable left_uvalue, const Interval& left_interval_low,
                             const Interval& left_interval_high, const LinearExpression& right_svalue,
                             const LinearExpression& right_uvalue, const Interval& right_interval) const;
    std::vector<LinearConstraint> assume_unsigned_cst_interval(Condition::Op op, bool is64, Variable left_svalue,
                                                               Variable left_uvalue,
                                                               const LinearExpression& right_svalue,
                                                               const LinearExpression& right_uvalue) const;

    void get_signed_intervals(bool is64, Variable left_svalue, Variable left_uvalue,
                              const LinearExpression& right_svalue, Interval& left_interval, Interval& right_interval,
                              Interval& left_interval_positive, Interval& left_interval_negative) const;

  public:
    std::vector<LinearConstraint> assume_cst_imm(Condition::Op op, bool is64, Variable dst_svalue, Variable dst_uvalue,
                                                 int64_t imm) const;
    std::vector<LinearConstraint> assume_cst_reg(Condition::Op op, bool is64, Variable dst_svalue, Variable dst_uvalue,
                                                 Variable src_svalue, Variable src_uvalue) const;
};
} // namespace prevail

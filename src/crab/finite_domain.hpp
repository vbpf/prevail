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
#include "crab/thresholds.hpp"
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

    [[nodiscard]]
    FiniteDomain widening_thresholds(const FiniteDomain& o, const thresholds_t& ts) const {
        // TODO: use thresholds
        return this->widen(o);
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

    interval_t eval_interval(const variable_t& v) const { return dom.eval_interval(v); }
    interval_t eval_interval(const linear_expression_t& exp) const { return dom.eval_interval(exp); }

    void assign(variable_t x, const std::optional<linear_expression_t>& e);
    void assign(variable_t x, variable_t e);
    void assign(variable_t x, const linear_expression_t& e);
    void assign(variable_t x, int64_t e);

    void apply(arith_binop_t op, variable_t x, variable_t y, const number_t& z, int finite_width);
    void apply(arith_binop_t op, variable_t x, variable_t y, variable_t z, int finite_width);
    void apply(bitwise_binop_t op, variable_t x, variable_t y, variable_t z, int finite_width);
    void apply(bitwise_binop_t op, variable_t x, variable_t y, const number_t& k, int finite_width);
    void apply(binop_t op, variable_t x, variable_t y, const number_t& z, int finite_width);
    void apply(binop_t op, variable_t x, variable_t y, variable_t z, int finite_width);
    void apply(const binop_t& op, const variable_t x, const variable_t y, const variable_t z) { apply(op, x, y, z, 0); }

    void overflow_bounds(variable_t lhs, int finite_width, bool issigned);
    void overflow_bounds(variable_t svalue, variable_t uvalue, int finite_width);

    void apply_signed(const binop_t& op, variable_t xs, variable_t xu, variable_t y, const number_t& z,
                      int finite_width);
    void apply_signed(const binop_t& op, variable_t xs, variable_t xu, variable_t y, variable_t z, int finite_width);
    void apply_unsigned(const binop_t& op, variable_t xs, variable_t xu, variable_t y, const number_t& z,
                        int finite_width);
    void apply_unsigned(const binop_t& op, variable_t xs, variable_t xu, variable_t y, variable_t z, int finite_width);

    void add(variable_t lhs, variable_t op2);
    void add(variable_t lhs, const number_t& op2);
    void sub(variable_t lhs, variable_t op2);
    void sub(variable_t lhs, const number_t& op2);
    void add_overflow(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void add_overflow(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void sub_overflow(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void sub_overflow(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void neg(variable_t lhss, variable_t lhsu, int finite_width);
    void mul(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void mul(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void sdiv(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void sdiv(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void udiv(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void udiv(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void srem(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void srem(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void urem(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void urem(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);

    void bitwise_and(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void bitwise_and(variable_t lhss, variable_t lhsu, const number_t& op2);
    void bitwise_or(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void bitwise_or(variable_t lhss, variable_t lhsu, const number_t& op2);
    void bitwise_xor(variable_t lhsss, variable_t lhsu, variable_t op2, int finite_width);
    void bitwise_xor(variable_t lhss, variable_t lhsu, const number_t& op2);
    void shl_overflow(variable_t lhss, variable_t lhsu, variable_t op2);
    void shl_overflow(variable_t lhss, variable_t lhsu, const number_t& op2);
    void shl(variable_t svalue, variable_t uvalue, int imm, int finite_width);
    void lshr(variable_t svalue, variable_t uvalue, int imm, int finite_width);
    void ashr(variable_t svalue, variable_t uvalue, const linear_expression_t& right_svalue, int finite_width);
    void sign_extend(variable_t svalue, variable_t uvalue, const linear_expression_t& right_svalue, int target_width,
                     int source_width);

    bool add_constraint(const linear_constraint_t& cst) { return dom.add_constraint(cst); }

    void set(const variable_t x, const interval_t& intv) { dom.set(x, intv); }

    /// Forget everything we know about the value of a variable.
    void havoc(variable_t v) { dom.havoc(v); }

    [[nodiscard]]
    std::pair<std::size_t, std::size_t> size() const {
        return dom.size();
    }

    // Return true if inv intersects with cst.
    [[nodiscard]]
    bool intersect(const linear_constraint_t& cst) const {
        return dom.intersect(cst);
    }

    // Return true if entails rhs.
    [[nodiscard]]
    bool entail(const linear_constraint_t& rhs) const {
        return dom.entail(rhs);
    }

    friend std::ostream& operator<<(std::ostream& o, const FiniteDomain& dom) { return o << dom.dom; }

    [[nodiscard]]
    string_invariant to_set() const {
        return dom.to_set();
    }

    static void clear_thread_local_state() { SplitDBM::clear_thread_local_state(); }

  private:
    std::vector<linear_constraint_t> assume_signed_64bit_eq(variable_t left_svalue, variable_t left_uvalue,
                                                            const interval_t& right_interval,
                                                            const linear_expression_t& right_svalue,
                                                            const linear_expression_t& right_uvalue) const;
    std::vector<linear_constraint_t> assume_signed_32bit_eq(variable_t left_svalue, variable_t left_uvalue,
                                                            const interval_t& right_interval) const;

    std::vector<linear_constraint_t> assume_bit_cst_interval(Condition::Op op, bool is64, interval_t dst_interval,
                                                             interval_t src_interval) const;

    void get_unsigned_intervals(bool is64, variable_t left_svalue, variable_t left_uvalue,
                                const linear_expression_t& right_uvalue, interval_t& left_interval,
                                interval_t& right_interval, interval_t& left_interval_low,
                                interval_t& left_interval_high) const;
    std::vector<linear_constraint_t> assume_signed_64bit_lt(bool strict, variable_t left_svalue, variable_t left_uvalue,
                                                            const interval_t& left_interval_positive,
                                                            const interval_t& left_interval_negative,
                                                            const linear_expression_t& right_svalue,
                                                            const linear_expression_t& right_uvalue,
                                                            const interval_t& right_interval) const;
    std::vector<linear_constraint_t> assume_signed_32bit_lt(bool strict, variable_t left_svalue, variable_t left_uvalue,
                                                            const interval_t& left_interval_positive,
                                                            const interval_t& left_interval_negative,
                                                            const linear_expression_t& right_svalue,
                                                            const linear_expression_t& right_uvalue,
                                                            const interval_t& right_interval) const;
    std::vector<linear_constraint_t> assume_signed_64bit_gt(bool strict, variable_t left_svalue, variable_t left_uvalue,
                                                            const interval_t& left_interval_positive,
                                                            const interval_t& left_interval_negative,
                                                            const linear_expression_t& right_svalue,
                                                            const linear_expression_t& right_uvalue,
                                                            const interval_t& right_interval) const;
    std::vector<linear_constraint_t> assume_signed_32bit_gt(bool strict, variable_t left_svalue, variable_t left_uvalue,
                                                            const interval_t& left_interval_positive,
                                                            const interval_t& left_interval_negative,
                                                            const linear_expression_t& right_svalue,
                                                            const linear_expression_t& right_uvalue,
                                                            const interval_t& right_interval) const;
    std::vector<linear_constraint_t> assume_signed_cst_interval(Condition::Op op, bool is64, variable_t left_svalue,
                                                                variable_t left_uvalue,
                                                                const linear_expression_t& right_svalue,
                                                                const linear_expression_t& right_uvalue) const;
    std::vector<linear_constraint_t>
    assume_unsigned_64bit_lt(bool strict, variable_t left_svalue, variable_t left_uvalue,
                             const interval_t& left_interval_low, const interval_t& left_interval_high,
                             const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                             const interval_t& right_interval) const;
    std::vector<linear_constraint_t> assume_unsigned_32bit_lt(bool strict, variable_t left_svalue,
                                                              variable_t left_uvalue,
                                                              const linear_expression_t& right_svalue,
                                                              const linear_expression_t& right_uvalue) const;
    std::vector<linear_constraint_t>
    assume_unsigned_64bit_gt(bool strict, variable_t left_svalue, variable_t left_uvalue,
                             const interval_t& left_interval_low, const interval_t& left_interval_high,
                             const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                             const interval_t& right_interval) const;
    std::vector<linear_constraint_t>
    assume_unsigned_32bit_gt(bool strict, variable_t left_svalue, variable_t left_uvalue,
                             const interval_t& left_interval_low, const interval_t& left_interval_high,
                             const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                             const interval_t& right_interval) const;
    std::vector<linear_constraint_t> assume_unsigned_cst_interval(Condition::Op op, bool is64, variable_t left_svalue,
                                                                  variable_t left_uvalue,
                                                                  const linear_expression_t& right_svalue,
                                                                  const linear_expression_t& right_uvalue) const;

    void get_signed_intervals(bool is64, variable_t left_svalue, variable_t left_uvalue,
                              const linear_expression_t& right_svalue, interval_t& left_interval,
                              interval_t& right_interval, interval_t& left_interval_positive,
                              interval_t& left_interval_negative) const;

  public:
    std::vector<linear_constraint_t> assume_cst_imm(Condition::Op op, bool is64, variable_t dst_svalue,
                                                    variable_t dst_uvalue, int64_t imm) const;
    std::vector<linear_constraint_t> assume_cst_reg(Condition::Op op, bool is64, variable_t dst_svalue,
                                                    variable_t dst_uvalue, variable_t src_svalue,
                                                    variable_t src_uvalue) const;
};
} // namespace prevail

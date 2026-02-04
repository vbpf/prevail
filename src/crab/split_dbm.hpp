// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
/*******************************************************************************
 *
 * Difference Bound Matrix domain based on the paper "Exploiting
 * Sparsity in Difference-Bound Matrices" by Gange, Navas, Schachte,
 * Sondergaard, and Stuckey published in SAS'16.

 * A re-engineered implementation of the Difference Bound Matrix
 * domain, which maintains bounds and relations separately.
 *
 * Closure operations based on the paper "Fast and Flexible Difference
 * Constraint Propagation for DPLL(T)" by Cotton and Maler.
 *
 * Author: Graeme Gange (gkgange@unimelb.edu.au)
 *
 * Contributors: Jorge A. Navas (jorge.navas@sri.com)
 ******************************************************************************/

#pragma once

#include <memory>
#include <optional>
#include <unordered_set>
#include <utility>
#include <variant>

#include <boost/container/flat_map.hpp>

#include "crab/splitdbm/core_dbm.hpp"
#include "arith/linear_constraint.hpp"
#include "arith/num_big.hpp"
#include "arith/num_safeint.hpp"
#include "arith/variable.hpp"
#include "crab/interval.hpp"
#include "string_constraints.hpp"

namespace prevail {

enum class ArithBinOp { ADD, SUB, MUL };

class SplitDBM final {
    friend SplitDBM do_join(const SplitDBM&, const SplitDBM&);

  public:
    using Graph = splitdbm::AdaptGraph;
    using Weight = splitdbm::Weight;
    using VertId = splitdbm::VertId;
    using VertMap = boost::container::flat_map<Variable, VertId>;

  private:
    using VariableVector = std::vector<Variable>;

    using RevMap = std::vector<std::optional<Variable>>;
    // < <x, y>, k> == x - y <= k.
    using diffcst_t = std::pair<std::pair<Variable, Variable>, Weight>;
    using VertSet = std::unordered_set<VertId>;
    friend class VertSetWrap;

    std::unique_ptr<splitdbm::CoreDBM> core_;

    VertMap vert_map_; // Mapping from variables to vertices
    RevMap rev_map_;

    VertId get_vert(Variable v);
    // Evaluate the potential value of a variable.
    [[nodiscard]]
    Weight pot_value(Variable v) const;

    // Evaluate an expression under the chosen potentials
    [[nodiscard]]
    bool eval_expression_overflow(const LinearExpression& e, Weight& out) const;

    [[nodiscard]]
    Interval compute_residual(const LinearExpression& e, Variable pivot) const;

    /**
     *  Turn an assignment into a set of difference constraints.
     *
     *  Given v := a*x + b*y + k, where a,b >= 0, we generate the
     *  difference constraints:
     *
     *  if extract_upper_bounds
     *     v - x <= ub((a-1)*x + b*y + k)
     *     v - y <= ub(a*x + (b-1)*y + k)
     *  else
     *     x - v <= lb((a-1)*x + b*y + k)
     *     y - v <= lb(a*x + (b-1)*y + k)
     **/
    void diffcsts_of_assign(const LinearExpression& exp,
                            /* if true then process the upper
                               bounds, else the lower bounds */
                            bool extract_upper_bounds,
                            /* foreach {v, k} \in diff_csts we have
                               the difference constraint v - k <= k */
                            std::vector<std::pair<Variable, Weight>>& diff_csts) const;

    // Turn an assignment into a set of difference constraints.
    void diffcsts_of_assign(const LinearExpression& exp, std::vector<std::pair<Variable, Weight>>& lb,
                            std::vector<std::pair<Variable, Weight>>& ub) const;

    /**
     * Turn a linear inequality into a set of difference
     * constraints.
     **/
    void diffcsts_of_lin_leq(const LinearExpression& exp,
                             /* difference constraints */
                             std::vector<diffcst_t>& csts,
                             /* x >= lb for each {x,lb} in lbs */
                             std::vector<std::pair<Variable, Weight>>& lbs,
                             /* x <= ub for each {x,ub} in ubs */
                             std::vector<std::pair<Variable, Weight>>& ubs) const;

    bool add_linear_leq(const LinearExpression& exp);

    // x != n
    bool add_univar_disequation(Variable x, const Number& n);

    // Restore potential after an edge addition
    bool repair_potential(VertId src, VertId dest);

    void normalize();

    std::optional<VertId> get_vertid(Variable x) const;
    Bound get_lb(const std::optional<VertId>& v) const;
    Bound get_ub(const std::optional<VertId>& v) const;

    Interval get_interval(Variable x) const;

    Bound get_lb(Variable x) const;
    Bound get_ub(Variable x) const;

    // Private constructor for internal use (join, meet, widen, etc.)
    SplitDBM(VertMap&& vert_map, RevMap&& rev_map, std::unique_ptr<splitdbm::CoreDBM> core);

    // Build AlignedPair from intersection of variables (for join/widen)
    static std::tuple<splitdbm::AlignedPair, RevMap> make_intersection_alignment(const SplitDBM& left, const SplitDBM& right);
    // Build AlignedPair from union of variables (for meet)
    static std::tuple<splitdbm::AlignedPair, RevMap> make_union_alignment(const SplitDBM& left, const SplitDBM& right);

  public:
    explicit SplitDBM();
    ~SplitDBM();

    SplitDBM(const SplitDBM& o);
    SplitDBM(SplitDBM&& o) noexcept;

    SplitDBM& operator=(const SplitDBM& o);
    SplitDBM& operator=(SplitDBM&& o) noexcept;

    void set_to_top();

    static SplitDBM top() { return SplitDBM(); }

    [[nodiscard]]
    bool is_top() const;

    bool operator<=(const SplitDBM& o) const;

    void operator|=(const SplitDBM& right);
    SplitDBM operator|(const SplitDBM& right) const;

    [[nodiscard]]
    SplitDBM widen(const SplitDBM& o) const;

    std::optional<SplitDBM> meet(const SplitDBM& o) const;

    [[nodiscard]]
    SplitDBM narrow(const SplitDBM& o) const;

    void assign(Variable lhs, const LinearExpression& e);

    void assign(const std::optional<Variable> x, const LinearExpression& e) {
        if (x) {
            assign(*x, e);
        }
    }
    void assign(const Variable x, const signed long long int n) { assign(x, LinearExpression(n)); }

    void assign(const Variable x, const Variable v) { assign(x, LinearExpression{v}); }

    void assign(const Variable x, const std::optional<LinearExpression>& e) {
        if (e) {
            assign(x, *e);
        } else {
            havoc(x);
        }
    }

    void havoc(Variable v);

    void apply(ArithBinOp op, Variable x, Variable y, Variable z);

    void apply(ArithBinOp op, Variable x, Variable y, const Number& k);

    bool add_constraint(const LinearConstraint& cst);

    [[nodiscard]]
    Interval eval_interval(const LinearExpression& e) const;

    [[nodiscard]]
    Interval eval_interval(const Variable e) const {
        return get_interval(e);
    }

    void set(Variable x, const Interval& intv);

    void forget(const VariableVector& variables);

    // return number of vertices and edges
    [[nodiscard]]
    std::pair<std::size_t, std::size_t> size() const;

  private:
    [[nodiscard]]
    bool entail_aux(const LinearConstraint& cst) const {
        // copy is necessary
        return !SplitDBM(*this).add_constraint(cst.negate());
    }

    [[nodiscard]]
    bool intersect_aux(const LinearConstraint& cst) const {
        // copy is necessary
        return SplitDBM(*this).add_constraint(cst);
    }

  public:
    // Return true if inv intersects with cst.
    [[nodiscard]]
    bool intersect(const LinearConstraint& cst) const;

    // Return true if entails rhs.
    [[nodiscard]]
    bool entail(const LinearConstraint& rhs) const;

    /**
     * Checks logical implication between two constraints in the current abstract state.
     * Returns true if, for all states represented by this SplitDBM, whenever 'premise' holds,
     * 'conclusion' also holds. This is implemented by adding 'premise' to the current state:
     * - If 'premise' is inconsistent with the current state, implication holds vacuously (returns true).
     * - Otherwise, checks if 'conclusion' is entailed by the state with 'premise' added.
     */
    [[nodiscard]]
    bool implies(const LinearConstraint& premise, const LinearConstraint& conclusion) const {
        SplitDBM result(*this);
        return !result.add_constraint(premise) || result.entail(conclusion);
    }

    friend std::ostream& operator<<(std::ostream& o, const SplitDBM& dom);
    [[nodiscard]]
    StringInvariant to_set() const;

  public:
    static void clear_thread_local_state();
}; // class SplitDBM

} // namespace prevail

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

#include <optional>
#include <unordered_set>
#include <utility>
#include <variant>

#include <boost/container/flat_map.hpp>

#include "crab/interval.hpp"
#include "crab/linear_constraint.hpp"
#include "crab/variable.hpp"
#include "crab_utils/adapt_sgraph.hpp"
#include "crab_utils/debug.hpp"
#include "crab_utils/num_big.hpp"
#include "crab_utils/num_safeint.hpp"
#include "crab_utils/stats.hpp"
#include "string_constraints.hpp"

namespace prevail {

enum class ArithBinOp { ADD, SUB, MUL, SDIV, UDIV, SREM, UREM };
enum class BitwiseBinOp { AND, OR, XOR, SHL, LSHR, ASHR };
using BinOp = std::variant<ArithBinOp, BitwiseBinOp>;

class SplitDBM final {
  public:
    using Graph = AdaptGraph;
    using Weight = Graph::Weight;
    using VertId = Graph::VertId;
    using VertMap = boost::container::flat_map<Variable, VertId>;

  private:
    using VariableVector = std::vector<Variable>;

    using RevMap = std::vector<std::optional<Variable>>;
    // < <x, y>, k> == x - y <= k.
    using diffcst_t = std::pair<std::pair<Variable, Variable>, Weight>;
    using VertSet = std::unordered_set<VertId>;
    friend class VertSetWrap;

    VertMap vert_map; // Mapping from variables to vertices
    RevMap rev_map;
    Graph g;                       // The underlying relation graph
    std::vector<Weight> potential; // Stored potential for the vertex
    VertSet unstable;

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
    void diffcsts_of_assign(Variable x, const LinearExpression& exp,
                            /* if true then process the upper
                               bounds, else the lower bounds */
                            bool extract_upper_bounds,
                            /* foreach {v, k} \in diff_csts we have
                               the difference constraint v - k <= k */
                            std::vector<std::pair<Variable, Weight>>& diff_csts) const;

    // Turn an assignment into a set of difference constraints.
    void diffcsts_of_assign(Variable x, const LinearExpression& exp, std::vector<std::pair<Variable, Weight>>& lb,
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

    [[nodiscard]]
    Interval get_interval(Variable x, int finite_width) const;

    // Restore potential after an edge addition
    bool repair_potential(VertId src, VertId dest);

    void normalize();

    SplitDBM(VertMap&& _vert_map, RevMap&& _rev_map, Graph&& _g, std::vector<Weight>&& _potential, VertSet&& _unstable)
        : vert_map(std::move(_vert_map)), rev_map(std::move(_rev_map)), g(std::move(_g)),
          potential(std::move(_potential)), unstable(std::move(_unstable)) {

        CrabStats::count("SplitDBM.count.copy");
        ScopedCrabStats __st__("SplitDBM.copy");

        CRAB_LOG("zones-split-size", const auto p = size();
                 std::cout << "#nodes = " << p.first << " #edges=" << p.second << "\n";);

        assert(g.size() > 0);
        normalize();
    }

    // Serves as a static cast for the default join operation
    SplitDBM const_join(const SplitDBM& o) const& { return *this | o; }

  public:
    explicit SplitDBM() {
        g.growTo(1); // Allocate the zero vector
        potential.emplace_back(0);
        rev_map.emplace_back(std::nullopt);
    }

    SplitDBM(const SplitDBM& o) = default;
    SplitDBM(SplitDBM&& o) = default;

    SplitDBM& operator=(const SplitDBM& o) = default;
    SplitDBM& operator=(SplitDBM&& o) = default;

    void set_to_top() {
        this->~SplitDBM();
        new (this) SplitDBM();
    }

    static SplitDBM top() { return SplitDBM(); }

    [[nodiscard]]
    bool is_top() const {
        return g.is_empty();
    }

    bool operator<=(const SplitDBM& o) const;

    // FIXME: can be done more efficient
    void operator|=(const SplitDBM& o) { *this = *this | o; }
    void operator|=(SplitDBM&& o) { *this = *this | o; }

    SplitDBM operator|(const SplitDBM& o) const&;

    SplitDBM operator|(SplitDBM&& o) && {
        if (o.is_top()) {
            return std::move(o);
        }
        if (is_top()) {
            return std::move(*this);
        }
        return const_join(o);
    }

    SplitDBM operator|(const SplitDBM& o) && {
        if (is_top()) {
            return std::move(*this);
        }
        return const_join(o);
    }

    SplitDBM operator|(SplitDBM&& o) const& {
        if (o.is_top()) {
            return std::move(o);
        }
        return const_join(o);
    }

    [[nodiscard]]
    SplitDBM widen(const SplitDBM& o) const;

    std::optional<SplitDBM> meet(const SplitDBM& o) const;

    [[nodiscard]]
    SplitDBM narrow(const SplitDBM& o) const;

    void assign(Variable lhs, const LinearExpression& e);

    void assign(std::optional<Variable> x, const LinearExpression& e) {
        if (x) {
            assign(*x, e);
        }
    }
    void assign(Variable x, signed long long int n) { assign(x, LinearExpression(n)); }

    void assign(Variable x, Variable v) { assign(x, LinearExpression{v}); }

    void assign(Variable x, const std::optional<LinearExpression>& e) {
        if (e) {
            assign(x, *e);
        } else {
            havoc(x);
        }
    }

    void havoc(Variable v);

    void apply(ArithBinOp op, Variable x, Variable y, Variable z, int finite_width);

    void apply(ArithBinOp op, Variable x, Variable y, const Number& k, int finite_width);

    // bitwise_operators_api
    void apply(BitwiseBinOp op, Variable x, Variable y, Variable z, int finite_width);

    void apply(BitwiseBinOp op, Variable x, Variable y, const Number& k, int finite_width);

    void apply(BinOp op, Variable x, Variable y, const Number& z, int finite_width) {
        std::visit([&](auto top) { apply(top, x, y, z, finite_width); }, op);
    }

    void apply(BinOp op, Variable x, Variable y, Variable z, int finite_width) {
        std::visit([&](auto top) { apply(top, x, y, z, finite_width); }, op);
    }

    bool add_constraint(const LinearConstraint& cst);

    [[nodiscard]]
    Interval eval_interval(const LinearExpression& e) const;

    Interval operator[](Variable x) const;

    void set(Variable x, const Interval& intv);

    void forget(const VariableVector& variables);

    // return number of vertices and edges
    [[nodiscard]]
    std::pair<std::size_t, std::size_t> size() const {
        return {g.size(), g.num_edges()};
    }

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

    friend std::ostream& operator<<(std::ostream& o, const SplitDBM& dom);
    [[nodiscard]]
    StringInvariant to_set() const;

  public:
    static void clear_thread_local_state();
}; // class SplitDBM

} // namespace prevail

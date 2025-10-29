// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include <utility>

#include <gsl/narrow>

#include "crab/split_dbm.hpp"
#include "crab/var_registry.hpp"
#include "crab_utils/debug.hpp"
#include "crab_utils/graph_ops.hpp"
#include "crab_utils/stats.hpp"
#include "string_constraints.hpp"
#include "type_encoding.hpp"

namespace prevail {

static std::optional<SplitDBM::VertId> try_at(const SplitDBM::VertMap& map, const Variable v) {
    const auto it = map.find(v);
    if (it == map.end()) {
        return std::nullopt;
    }
    return it->second;
}

SplitDBM::VertId SplitDBM::get_vert(Variable v) {
    if (const auto y = try_at(vert_map, v)) {
        return *y;
    }

    VertId vert(g.new_vertex());
    vert_map.emplace(v, vert);
    // Initialize
    assert(vert <= rev_map.size());
    if (vert < rev_map.size()) {
        potential[vert] = Weight(0);
        rev_map[vert] = v;
    } else {
        potential.emplace_back(0);
        rev_map.push_back(v);
    }
    vert_map.emplace(v, vert);

    assert(vert != 0);

    return vert;
}

/**
 * Helper to translate from Number to DBM Weight (graph weights).  Number
 * used to be the template parameter of the DBM-based abstract domain to
 * represent a number. Number might not fit into Weight type.
 **/
[[maybe_unused]]
static bool convert_NtoW_overflow(const Number& n, SafeI64& out) {
    if (n.fits<int64_t>()) {
        out = n;
        return false;
    }
    return true;
}

[[maybe_unused]]
static bool convert_NtoW_overflow(const Number& n, Number& out) {
    out = n;
    return false;
}

void SplitDBM::diffcsts_of_assign(Variable x, const LinearExpression& exp,
                                  /* if true then process the upper
                                     bounds, else the lower bounds */
                                  bool extract_upper_bounds,
                                  /* foreach {v, k} \in diff_csts we have
                                     the difference constraint v - k <= k */
                                  std::vector<std::pair<Variable, Weight>>& diff_csts) const {

    std::optional<Variable> unbounded_var;
    std::vector<std::pair<Variable, Weight>> terms;

    Weight residual;
    if (convert_NtoW_overflow(exp.constant_term(), residual)) {
        return;
    }

    for (const auto& [y, n] : exp.variable_terms()) {
        Weight coeff;
        if (convert_NtoW_overflow(n, coeff)) {
            continue;
        }

        if (coeff < Weight(0)) {
            // Can't do anything with negative coefficients.
            auto y_val = (extract_upper_bounds ? this->operator[](y).lb() : this->operator[](y).ub());

            if (y_val.is_infinite()) {
                return;
            }
            Weight ymax;
            if (convert_NtoW_overflow(*y_val.number(), ymax)) {
                continue;
            }
            // was before the condition
            residual += ymax * coeff;
        } else {
            auto y_val = (extract_upper_bounds ? this->operator[](y).ub() : this->operator[](y).lb());

            if (y_val.is_infinite()) {
                if (unbounded_var || coeff != Weight(1)) {
                    return;
                }
                unbounded_var = y;
            } else {
                Weight ymax;
                if (convert_NtoW_overflow(*y_val.number(), ymax)) {
                    continue;
                }
                residual += ymax * coeff;
                terms.emplace_back(y, ymax);
            }
        }
    }

    if (unbounded_var) {
        // There is exactly one unbounded variable with unit
        // coefficient
        diff_csts.emplace_back(*unbounded_var, residual);
    } else {
        for (const auto& [v, n] : terms) {
            diff_csts.emplace_back(v, residual - n);
        }
    }
}

void SplitDBM::diffcsts_of_lin_leq(const LinearExpression& exp,
                                   /* difference contraints */
                                   std::vector<diffcst_t>& csts,
                                   /* x >= lb for each {x,lb} in lbs */
                                   std::vector<std::pair<Variable, Weight>>& lbs,
                                   /* x <= ub for each {x,ub} in ubs */
                                   std::vector<std::pair<Variable, Weight>>& ubs) const {
    Weight exp_ub;
    if (convert_NtoW_overflow(exp.constant_term(), exp_ub)) {
        return;
    }
    exp_ub = -exp_ub;

    // temporary hack
    Weight _tmp;
    if (convert_NtoW_overflow(exp.constant_term() - 1, _tmp)) {
        // We don't like MIN either because the code will compute
        // minus MIN, and it will silently overflow.
        return;
    }

    Weight unbounded_lbcoeff;
    Weight unbounded_ubcoeff;
    std::optional<Variable> unbounded_lbvar;
    std::optional<Variable> unbounded_ubvar;

    std::vector<std::pair<std::pair<Weight, Variable>, Weight>> pos_terms, neg_terms;
    for (const auto& [y, n] : exp.variable_terms()) {
        Weight coeff;
        if (convert_NtoW_overflow(n, coeff)) {
            continue;
        }
        if (coeff > Weight(0)) {
            auto y_lb = this->operator[](y).lb();
            if (y_lb.is_infinite()) {
                if (unbounded_lbvar) {
                    return;
                }
                unbounded_lbvar = y;
                unbounded_lbcoeff = coeff;
            } else {
                Weight ymin;
                if (convert_NtoW_overflow(*y_lb.number(), ymin)) {
                    continue;
                }
                exp_ub -= ymin * coeff;
                pos_terms.push_back({{coeff, y}, ymin});
            }
        } else {
            auto y_ub = this->operator[](y).ub();
            if (y_ub.is_infinite()) {
                if (unbounded_ubvar) {
                    return;
                }
                unbounded_ubvar = y;
                unbounded_ubcoeff = -coeff;
            } else {
                Weight ymax;
                if (convert_NtoW_overflow(*y_ub.number(), ymax)) {
                    continue;
                }
                exp_ub -= ymax * coeff;
                neg_terms.push_back({{-coeff, y}, ymax});
            }
        }
    }

    if (unbounded_lbvar) {
        Variable x{*unbounded_lbvar};
        if (unbounded_ubvar) {
            if (unbounded_lbcoeff == Weight(1) && unbounded_ubcoeff == Weight(1)) {
                csts.push_back({{x, *unbounded_ubvar}, exp_ub});
            }
        } else {
            if (unbounded_lbcoeff == Weight(1)) {
                for (const auto& [nv, k] : neg_terms) {
                    csts.push_back({{x, nv.second}, exp_ub - k});
                }
            }
            // Add bounds for x
            ubs.emplace_back(x, exp_ub / unbounded_lbcoeff);
        }
    } else {
        if (unbounded_ubvar) {
            Variable y{*unbounded_ubvar};
            if (unbounded_ubcoeff == Weight(1)) {
                for (const auto& [nv, k] : pos_terms) {
                    csts.push_back({{nv.second, y}, exp_ub + k});
                }
            }
            // Add bounds for y
            lbs.emplace_back(y, -exp_ub / unbounded_ubcoeff);
        } else {
            for (const auto& [neg_nv, neg_k] : neg_terms) {
                for (const auto& [pos_nv, pos_k] : pos_terms) {
                    csts.push_back({{pos_nv.second, neg_nv.second}, exp_ub - neg_k + pos_k});
                }
            }
            for (const auto& [neg_nv, neg_k] : neg_terms) {
                lbs.emplace_back(neg_nv.second, -exp_ub / neg_nv.first + neg_k);
            }
            for (const auto& [pos_nv, pos_k] : pos_terms) {
                ubs.emplace_back(pos_nv.second, exp_ub / pos_nv.first + pos_k);
            }
        }
    }
}

static GraphOps::PotentialFunction index_to_call(const GraphOps::WeightVector& p) {
    return [&p](GraphOps::VertId v) -> GraphOps::Weight { return p[v]; };
}

bool SplitDBM::add_linear_leq(const LinearExpression& exp) {
    std::vector<std::pair<Variable, Weight>> lbs, ubs;
    std::vector<diffcst_t> csts;
    diffcsts_of_lin_leq(exp, csts, lbs, ubs);

    for (const auto& [var, n] : lbs) {
        CRAB_LOG("zones-split", std::cout << var << ">=" << n << "\n");
        const VertId vert = get_vert(var);
        if (auto w = g.lookup(vert, 0)) {
            if (*w <= -n) {
                continue;
            }
        }
        g.set_edge(vert, -n, 0);

        if (!repair_potential(vert, 0)) {
            return false;
        }
    }
    for (const auto& [var, n] : ubs) {
        CRAB_LOG("zones-split", std::cout << var << "<=" << n << "\n");
        const VertId vert = get_vert(var);
        if (auto w = g.lookup(0, vert)) {
            if (*w <= n) {
                continue;
            }
        }
        g.set_edge(0, n, vert);
        if (!repair_potential(0, vert)) {
            return false;
        }
    }

    for (const auto& [diff, k] : csts) {
        CRAB_LOG("zones-split", std::cout << diff.first << "-" << diff.second << "<=" << k << "\n");

        const VertId src = get_vert(diff.second);
        const VertId dest = get_vert(diff.first);
        g.update_edge(src, k, dest);
        if (!repair_potential(src, dest)) {
            return false;
        }
        GraphOps::close_over_edge(g, src, dest);
    }
    GraphOps::apply_delta(g, GraphOps::close_after_assign(g, index_to_call(potential), 0));
    normalize();
    return true;
}

static Interval trim_interval(const Interval& i, const Number& n) {
    if (i.lb() == n) {
        return Interval{n + 1, i.ub()};
    }
    if (i.ub() == n) {
        return Interval{i.lb(), n - 1};
    }
    if (i.is_top() && n == 0) {
        return Interval{1, std::numeric_limits<uint64_t>::max()};
    }
    return i;
}

bool SplitDBM::add_univar_disequation(Variable x, const Number& n) {
    Interval i = get_interval(x, 0);
    Interval new_i = trim_interval(i, n);
    if (new_i.is_bottom()) {
        return false;
    }
    if (new_i.is_top() || !(new_i <= i)) {
        return true;
    }

    VertId v = get_vert(x);
    if (new_i.lb().is_finite()) {
        // strengthen lb
        Weight lb_val;
        if (convert_NtoW_overflow(-*new_i.lb().number(), lb_val)) {
            return true;
        }

        if (auto w = g.lookup(v, 0)) {
            if (lb_val < *w) {
                g.set_edge(v, lb_val, 0);
                if (!repair_potential(v, 0)) {
                    return false;
                }
                // Update other bounds
                for (const auto e : g.e_preds(v)) {
                    if (e.vert == 0) {
                        continue;
                    }
                    g.update_edge(e.vert, e.val + lb_val, 0);
                    if (!repair_potential(e.vert, 0)) {
                        return false;
                    }
                }
            }
        }
    }
    if (new_i.ub().is_finite()) {
        // strengthen ub
        Weight ub_val;
        if (convert_NtoW_overflow(*new_i.ub().number(), ub_val)) {
            return true;
        }

        if (auto w = g.lookup(0, v)) {
            if (ub_val < *w) {
                g.set_edge(0, ub_val, v);
                if (!repair_potential(0, v)) {
                    return false;
                }
                // Update other bounds
                for (const auto e : g.e_succs(v)) {
                    if (e.vert == 0) {
                        continue;
                    }
                    g.update_edge(0, e.val + ub_val, e.vert);
                    if (!repair_potential(0, e.vert)) {
                        return false;
                    }
                }
            }
        }
    }
    normalize();
    return true;
}

bool SplitDBM::operator<=(const SplitDBM& o) const {
    CrabStats::count("SplitDBM.count.leq");
    ScopedCrabStats __st__("SplitDBM.leq");

    // cover all trivial cases to avoid allocating a dbm matrix
    if (o.is_top()) {
        return true;
    }
    if (is_top()) {
        return false;
    }

    if (vert_map.size() < o.vert_map.size()) {
        return false;
    }
    constexpr VertId INVALID_VERT = std::numeric_limits<VertId>::max();
    // Set up a mapping from o to this.
    std::vector vert_renaming(o.g.size(), INVALID_VERT);
    vert_renaming[0] = 0;
    for (const auto& [v, n] : o.vert_map) {
        if (o.g.succs(n).size() == 0 && o.g.preds(n).size() == 0) {
            continue;
        }

        // We can't have this <= o if we're missing some vertex.
        if (auto y = try_at(vert_map, v)) {
            vert_renaming[n] = *y;
        } else {
            return false;
        }
    }

    assert(g.size() > 0);
    for (VertId ox : o.g.verts()) {
        if (o.g.succs(ox).size() == 0) {
            continue;
        }

        assert(vert_renaming[ox] != INVALID_VERT);
        VertId x = vert_renaming[ox];
        for (const auto edge : o.g.e_succs(ox)) {
            VertId oy = edge.vert;
            assert(vert_renaming[oy] != INVALID_VERT);
            VertId y = vert_renaming[oy];
            Weight ow = edge.val;

            if (auto w = g.lookup(x, y)) {
                if (*w <= ow) {
                    continue;
                }
            }

            if (auto wx = g.lookup(x, 0)) {
                if (auto wy = g.lookup(0, y)) {
                    if (*wx + *wy <= ow) {
                        continue;
                    }
                }
            }
            return false;
        }
    }
    return true;
}

SplitDBM SplitDBM::operator|(const SplitDBM& o) const& {
    if (o.is_top()) {
        return o;
    }
    if (is_top()) {
        return *this;
    }
    CRAB_LOG("zones-split", std::cout << "Before join:\n"
                                      << "DBM 1\n"
                                      << *this << "\n"
                                      << "DBM 2\n"
                                      << o << "\n");
    // Figure out the common renaming, initializing the
    // resulting potentials as we go.
    std::vector<VertId> perm_x;
    std::vector<VertId> perm_y;
    std::vector<Variable> perm_inv;

    std::vector<Weight> pot_rx;
    std::vector<Weight> pot_ry;
    VertMap out_vmap;
    RevMap out_revmap;
    // Add the zero vertex
    assert(!potential.empty());
    pot_rx.emplace_back(0);
    pot_ry.emplace_back(0);
    perm_x.push_back(0);
    perm_y.push_back(0);
    out_revmap.push_back(std::nullopt);

    for (const auto& [v, n] : vert_map) {
        if (auto y = try_at(o.vert_map, v)) {
            // Variable exists in both
            out_vmap.emplace(v, gsl::narrow<VertId>(perm_x.size()));
            out_revmap.push_back(v);

            pot_rx.push_back(potential[n] - potential[0]);
            // XXX JNL: check this out
            // pot_ry.push_back(o.potential[p.second] - o.potential[0]);
            pot_ry.push_back(o.potential[*y] - o.potential[0]);
            perm_inv.push_back(v);
            perm_x.push_back(n);
            perm_y.push_back(*y);
        }
    }
    size_t sz = perm_x.size();

    // Build the permuted view of x and y.
    assert(g.size() > 0);
    GraphPerm gx(perm_x, g);
    assert(o.g.size() > 0);
    GraphPerm gy(perm_y, o.g);

    // Compute the deferred relations
    Graph g_ix_ry;
    g_ix_ry.growTo(sz);
    SubGraph gy_excl(gy, 0);
    for (VertId s : gy_excl.verts()) {
        for (VertId d : gy_excl.succs(s)) {
            if (auto ws = gx.lookup(s, 0)) {
                if (auto wd = gx.lookup(0, d)) {
                    g_ix_ry.add_edge(s, *ws + *wd, d);
                }
            }
        }
    }
    // Apply the deferred relations, and re-close.
    bool is_closed;
    Graph g_rx(GraphOps::meet(gx, g_ix_ry, is_closed));
    if (!is_closed) {
        GraphOps::apply_delta(g_rx, GraphOps::close_after_meet(SubGraph(g_rx, 0), index_to_call(pot_rx), gx, g_ix_ry));
    }

    Graph g_rx_iy;
    g_rx_iy.growTo(sz);

    SubGraph gx_excl(gx, 0);
    for (VertId s : gx_excl.verts()) {
        for (VertId d : gx_excl.succs(s)) {
            // Assumption: gx.mem(s, d) -> gx.edge_val(s, d) <= ranges[var(s)].ub() - ranges[var(d)].lb()
            // That is, if the relation exists, it's at least as strong as the bounds.
            if (auto ws = gy.lookup(s, 0)) {
                if (auto wd = gy.lookup(0, d)) {
                    g_rx_iy.add_edge(s, *ws + *wd, d);
                }
            }
        }
    }
    // Similarly, should use a SubGraph view.
    Graph g_ry(GraphOps::meet(gy, g_rx_iy, is_closed));
    if (!is_closed) {
        GraphOps::apply_delta(g_ry, GraphOps::close_after_meet(SubGraph(g_ry, 0), index_to_call(pot_ry), gy, g_rx_iy));
    }

    // We now have the relevant set of relations. Because g_rx and g_ry are closed,
    // the result is also closed.
    Graph join_g(GraphOps::join(g_rx, g_ry));

    // Now reapply the missing independent relations.
    // Need to derive vert_ids from lb_up/lb_down, and make sure the vertices exist
    std::vector<VertId> lb_up;
    std::vector<VertId> lb_down;
    std::vector<VertId> ub_up;
    std::vector<VertId> ub_down;

    for (VertId v : gx_excl.verts()) {
        if (auto wx = gx.lookup(0, v)) {
            if (auto wy = gy.lookup(0, v)) {
                if (*wx < *wy) {
                    ub_up.push_back(v);
                }
                if (*wy < *wx) {
                    ub_down.push_back(v);
                }
            }
        }
        if (auto wx = gx.lookup(v, 0)) {
            if (auto wy = gy.lookup(v, 0)) {
                if (*wx < *wy) {
                    lb_down.push_back(v);
                }
                if (*wy < *wx) {
                    lb_up.push_back(v);
                }
            }
        }
    }

    for (VertId s : lb_up) {
        Weight dx_s = gx.edge_val(s, 0);
        Weight dy_s = gy.edge_val(s, 0);
        for (VertId d : ub_up) {
            if (s == d) {
                continue;
            }

            join_g.update_edge(s, std::max(dx_s + gx.edge_val(0, d), dy_s + gy.edge_val(0, d)), d);
        }
    }

    for (VertId s : lb_down) {
        Weight dx_s = gx.edge_val(s, 0);
        Weight dy_s = gy.edge_val(s, 0);
        for (VertId d : ub_down) {
            if (s == d) {
                continue;
            }

            join_g.update_edge(s, std::max(dx_s + gx.edge_val(0, d), dy_s + gy.edge_val(0, d)), d);
        }
    }

    // Conjecture: join_g remains closed.

    // Now garbage collect any unused vertices
    for (VertId v : join_g.verts()) {
        if (v == 0) {
            continue;
        }
        if (join_g.succs(v).size() == 0 && join_g.preds(v).size() == 0) {
            join_g.forget(v);
            if (out_revmap[v]) {
                out_vmap.erase(*(out_revmap[v]));
                out_revmap[v] = std::nullopt;
            }
        }
    }

    // SplitDBM res(join_range, out_vmap, out_revmap, join_g, join_pot);
    SplitDBM res(std::move(out_vmap), std::move(out_revmap), std::move(join_g), std::move(pot_rx), VertSet());
    // join_g.check_adjs();
    CRAB_LOG("zones-split", std::cout << "Result join:\n" << res << "\n");

    return res;
}

SplitDBM SplitDBM::widen(const SplitDBM& o) const {
    // Figure out the common renaming
    assert(!potential.empty());
    std::vector<Weight> widen_pot = {0};
    std::vector<VertId> perm_x = {0};
    std::vector<VertId> perm_y = {0};
    VertMap out_vmap;
    RevMap out_revmap = {std::nullopt};
    for (const auto& [v, n] : vert_map) {
        if (auto y = try_at(o.vert_map, v)) {
            // Variable exists in both
            out_vmap.emplace(v, gsl::narrow<VertId>(perm_x.size()));
            out_revmap.push_back(v);

            widen_pot.push_back(potential[n] - potential[0]);
            perm_x.push_back(n);
            perm_y.push_back(*y);
        }
    }

    // Build the permuted view of x and y.
    assert(g.size() > 0);
    GraphPerm gx(perm_x, g);
    assert(o.g.size() > 0);
    GraphPerm gy(perm_y, o.g);

    // Now perform the widening
    VertSet widen_unstable(unstable);
    Graph widen_g(GraphOps::widen(gx, gy, widen_unstable));

    SplitDBM res(std::move(out_vmap), std::move(out_revmap), std::move(widen_g), std::move(widen_pot),
                 std::move(widen_unstable));
    return res;
}

std::optional<SplitDBM> SplitDBM::meet(const SplitDBM& o) const {
    CrabStats::count("SplitDBM.count.meet");
    ScopedCrabStats __st__("SplitDBM.meet");

    if (is_top()) {
        return o;
    }
    if (o.is_top()) {
        return *this;
    }
    CRAB_LOG("zones-split", std::cout << "Before meet:\n"
                                      << "DBM 1\n"
                                      << *this << "\n"
                                      << "DBM 2\n"
                                      << o << "\n");

    // We map vertices in the left operand onto a contiguous range.
    // This will often be the identity map, but there might be gaps.
    VertMap meet_verts;
    RevMap meet_rev;

    std::vector<VertId> perm_x;
    std::vector<VertId> perm_y;
    std::vector<Weight> meet_pi;
    perm_x.push_back(0);
    perm_y.push_back(0);
    meet_pi.emplace_back(0);
    meet_rev.push_back(std::nullopt);
    for (const auto& [v, n] : vert_map) {
        VertId vv = gsl::narrow<VertId>(perm_x.size());
        meet_verts.emplace(v, vv);
        meet_rev.push_back(v);

        perm_x.push_back(n);
        perm_y.push_back(-1);
        meet_pi.push_back(potential[n] - potential[0]);
    }

    // Add missing mappings from the right operand.
    for (const auto& [v, n] : o.vert_map) {
        auto it = meet_verts.find(v);

        if (it == meet_verts.end()) {
            VertId vv = gsl::narrow<VertId>(perm_y.size());
            meet_rev.push_back(v);

            perm_y.push_back(n);
            perm_x.push_back(-1);
            meet_pi.push_back(o.potential[n] - o.potential[0]);
            meet_verts.emplace(v, vv);
        } else {
            perm_y[it->second] = n;
        }
    }

    // Build the permuted view of x and y.
    assert(g.size() > 0);
    GraphPerm gx(perm_x, g);
    assert(o.g.size() > 0);
    GraphPerm gy(perm_y, o.g);

    // Compute the syntactic meet of the permuted graphs.
    bool is_closed{};
    Graph meet_g(GraphOps::meet(gx, gy, is_closed));

    // Compute updated potentials on the zero-enriched graph
    // vector<Weight> meet_pi(meet_g.size());
    // We've warm-started pi with the operand potentials
    if (!GraphOps::select_potentials(meet_g, meet_pi)) {
        // Potentials cannot be selected -- state is infeasible.
        return {};
    }

    if (!is_closed) {
        const auto potential_func = index_to_call(meet_pi);
        GraphOps::apply_delta(meet_g, GraphOps::close_after_meet(SubGraph(meet_g, 0), potential_func, gx, gy));

        // Recover updated LBs and UBs.<

        GraphOps::apply_delta(meet_g, GraphOps::close_after_assign(meet_g, potential_func, 0));
    }
    SplitDBM res(std::move(meet_verts), std::move(meet_rev), std::move(meet_g), std::move(meet_pi), VertSet());
    CRAB_LOG("zones-split", std::cout << "Result meet:\n" << res << "\n");
    return res;
}

void SplitDBM::havoc(const Variable v) {
    if (const auto y = try_at(vert_map, v)) {
        g.forget(*y);
        rev_map[*y] = std::nullopt;
        vert_map.erase(v);
        normalize();
    }
}

// return false if becomes bottom
bool SplitDBM::add_constraint(const LinearConstraint& cst) {
    CrabStats::count("SplitDBM.count.add_constraints");
    ScopedCrabStats __st__("SplitDBM.add_constraints");

    if (cst.is_tautology()) {
        return true;
    }

    // g.check_adjs();

    if (cst.is_contradiction()) {
        return false;
    }

    switch (cst.kind()) {
    case ConstraintKind::LESS_THAN_OR_EQUALS_ZERO: {
        if (!add_linear_leq(cst.expression())) {
            return false;
        }
        //  g.check_adjs();
        CRAB_LOG("zones-split", std::cout << "--- " << cst << "\n" << *this << "\n");
        break;
    }
    case ConstraintKind::LESS_THAN_ZERO: {
        // We try to convert a strict to non-strict.
        // e < 0 --> e <= -1
        const auto nc = LinearConstraint(cst.expression().plus(1), ConstraintKind::LESS_THAN_OR_EQUALS_ZERO);
        if (!add_linear_leq(nc.expression())) {
            return false;
        }
        CRAB_LOG("zones-split", std::cout << "--- " << cst << "\n" << *this << "\n");
        break;
    }
    case ConstraintKind::EQUALS_ZERO: {
        const LinearExpression& exp = cst.expression();
        if (!add_linear_leq(exp) || !add_linear_leq(exp.negate())) {
            CRAB_LOG("zones-split", std::cout << " ~~> _|_" << "\n");
            return false;
        }
        // g.check_adjs();
        CRAB_LOG("zones-split", std::cout << "--- " << cst << "\n" << *this << "\n");
        break;
    }
    case ConstraintKind::NOT_ZERO: {
        // XXX: similar precision as the interval domain
        const LinearExpression& e = cst.expression();
        for (const auto& [variable, coefficient] : e.variable_terms()) {
            Interval i = compute_residual(e, variable) / Interval(coefficient);
            if (auto k = i.singleton()) {
                if (!add_univar_disequation(variable, *k)) {
                    return false;
                }
            }
        }
    } break;
    }

    CRAB_WARN("Unhandled constraint ", cst, " by split_dbm");
    CRAB_LOG("zones-split", std::cout << "---" << cst << "\n" << *this << "\n");
    normalize();
    return true;
}

void SplitDBM::assign(Variable lhs, const LinearExpression& e) {
    CrabStats::count("SplitDBM.count.assign");
    ScopedCrabStats __st__("SplitDBM.assign");

    CRAB_LOG("zones-split", std::cout << "Before assign: " << *this << "\n");
    CRAB_LOG("zones-split", std::cout << lhs << ":=" << e << "\n");

    Interval value_interval = eval_interval(e);

    std::optional<Weight> lb_w, ub_w;
    if (value_interval.lb().is_finite()) {
        Weight tmp;
        if (convert_NtoW_overflow(-*value_interval.lb().number(), tmp)) {
            havoc(lhs);
            CRAB_LOG("zones-split", std::cout << "---" << lhs << ":=" << e << "\n" << *this << "\n");
            normalize();
            return;
        }
        lb_w = tmp;
    }
    if (value_interval.ub().is_finite()) {
        Weight tmp;
        if (convert_NtoW_overflow(*value_interval.ub().number(), tmp)) {
            havoc(lhs);
            CRAB_LOG("zones-split", std::cout << "---" << lhs << ":=" << e << "\n" << *this << "\n");
            normalize();
            return;
        }
        ub_w = tmp;
    }

    // JN: it seems that we can only do this if
    // close_bounds_inline is disabled (which in eBPF is always the case).
    // Otherwise, the meet operator misses some non-redundant edges.
    if (value_interval.is_singleton()) {
        set(lhs, value_interval);
        normalize();
        return;
    }

    std::vector<std::pair<Variable, Weight>> diffs_lb, diffs_ub;
    // Construct difference constraints from the assignment
    diffcsts_of_assign(lhs, e, diffs_lb, diffs_ub);
    if (diffs_lb.empty() && diffs_ub.empty()) {
        set(lhs, value_interval);
        normalize();
        return;
    }

    Weight e_val;
    if (eval_expression_overflow(e, e_val)) {
        havoc(lhs);
        return;
    }
    // Allocate a new vertex for x
    VertId vert = g.new_vertex();
    assert(vert <= rev_map.size());
    if (vert == rev_map.size()) {
        rev_map.push_back(lhs);
        potential.push_back(potential[0] + e_val);
    } else {
        potential[vert] = potential[0] + e_val;
        rev_map[vert] = lhs;
    }

    {
        GraphOps::EdgeVector delta;
        for (const auto& [var, n] : diffs_lb) {
            delta.emplace_back(vert, get_vert(var), -n);
        }

        for (const auto& [var, n] : diffs_ub) {
            delta.emplace_back(get_vert(var), vert, n);
        }

        // apply_delta should be safe here, as x has no edges in G.
        GraphOps::apply_delta(g, delta);
    }
    GraphOps::apply_delta(g, GraphOps::close_after_assign(SubGraph(g, 0), index_to_call(potential), vert));

    if (lb_w) {
        g.update_edge(vert, *lb_w, 0);
    }
    if (ub_w) {
        g.update_edge(0, *ub_w, vert);
    }
    // Clear the old x vertex
    havoc(lhs);
    vert_map.emplace(lhs, vert);

    normalize();
    CRAB_LOG("zones-split", std::cout << "---" << lhs << ":=" << e << "\n" << *this << "\n");
}

SplitDBM SplitDBM::narrow(const SplitDBM& o) const {
    CrabStats::count("SplitDBM.count.narrowing");
    ScopedCrabStats __st__("SplitDBM.narrowing");

    if (is_top()) {
        return o;
    }
    // FIXME: Implement properly
    // Narrowing as a no-op should be sound.
    return {*this};
}

class VertSetWrap {
  public:
    explicit VertSetWrap(const SplitDBM::VertSet& _vs) : vs(_vs) {}

    bool operator[](const SplitDBM::VertId v) const { return vs.contains(v); }
    const SplitDBM::VertSet& vs;
};

bool SplitDBM::repair_potential(VertId src, VertId dest) { return GraphOps::repair_potential(g, potential, src, dest); }

void SplitDBM::clear_thread_local_state() { GraphOps::clear_thread_local_state(); }

void SplitDBM::normalize() {
    CrabStats::count("SplitDBM.count.normalize");
    ScopedCrabStats __st__("SplitDBM.normalize");

    // dbm_canonical(_dbm);
    // Always maintained in normal form, except for widening
    if (unstable.empty()) {
        return;
    }

    GraphOps::EdgeVector delta;
    // GraphOps::close_after_widen(g, potential, VertSetWrap(unstable), delta);
    // GKG: Check
    const auto p = index_to_call(potential);
    GraphOps::apply_delta(g, GraphOps::close_after_widen(SubGraph(g, 0), p, VertSetWrap(unstable)));
    // Retrieve variable bounds
    GraphOps::apply_delta(g, GraphOps::close_after_assign(g, p, 0));

    unstable.clear();
}

void SplitDBM::set(const Variable x, const Interval& intv) {
    CrabStats::count("SplitDBM.count.assign");
    ScopedCrabStats __st__("SplitDBM.assign");
    assert(!intv.is_bottom());

    havoc(x);

    if (intv.is_top()) {
        return;
    }

    const VertId v = get_vert(x);
    if (intv.ub().is_finite()) {
        Weight ub;
        if (convert_NtoW_overflow(*intv.ub().number(), ub)) {
            normalize();
            return;
        }
        potential[v] = potential[0] + ub;
        g.set_edge(0, ub, v);
    }
    if (intv.lb().is_finite()) {
        Weight lb;
        if (convert_NtoW_overflow(*intv.lb().number(), lb)) {
            normalize();
            return;
        }
        potential[v] = potential[0] + lb;
        g.set_edge(v, -lb, 0);
    }
    normalize();
}

void SplitDBM::apply(const ArithBinOp op, const Variable x, const Variable y, const Variable z,
                     const int finite_width) {
    CrabStats::count("SplitDBM.count.apply");
    ScopedCrabStats __st__("SplitDBM.apply");

    switch (op) {
    case ArithBinOp::ADD: assign(x, LinearExpression(y).plus(z)); break;
    case ArithBinOp::SUB: assign(x, LinearExpression(y).subtract(z)); break;
    // For the rest of operations, we fall back on intervals.
    case ArithBinOp::MUL: set(x, get_interval(y, finite_width) * get_interval(z, finite_width)); break;
    case ArithBinOp::SDIV: set(x, get_interval(y, finite_width).sdiv(get_interval(z, finite_width))); break;
    case ArithBinOp::UDIV: set(x, get_interval(y, finite_width).udiv(get_interval(z, finite_width))); break;
    case ArithBinOp::SREM: set(x, get_interval(y, finite_width).srem(get_interval(z, finite_width))); break;
    case ArithBinOp::UREM: set(x, get_interval(y, finite_width).urem(get_interval(z, finite_width))); break;
    default: CRAB_ERROR("DBM: unreachable");
    }
    normalize();
}

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

void SplitDBM::apply(const ArithBinOp op, const Variable x, const Variable y, const Number& k, const int finite_width) {
    CrabStats::count("SplitDBM.count.apply");
    ScopedCrabStats __st__("SplitDBM.apply");

    switch (op) {
    case ArithBinOp::ADD: assign(x, LinearExpression(y).plus(k)); break;
    case ArithBinOp::SUB: assign(x, LinearExpression(y).subtract(k)); break;
    case ArithBinOp::MUL:
        assign(x, LinearExpression(k, y));
        break;
        // For the rest of operations, we fall back on intervals.
    case ArithBinOp::SDIV:
        set(x, get_interval(y, finite_width).sdiv(Interval{read_imm_for_sdiv_or_smod(k, finite_width)}));
        break;
    case ArithBinOp::UDIV:
        set(x, get_interval(y, finite_width).udiv(Interval{read_imm_for_udiv_or_umod(k, finite_width)}));
        break;
    case ArithBinOp::SREM:
        set(x, get_interval(y, finite_width).srem(Interval{read_imm_for_sdiv_or_smod(k, finite_width)}));
        break;
    case ArithBinOp::UREM:
        set(x, get_interval(y, finite_width).urem(Interval{read_imm_for_udiv_or_umod(k, finite_width)}));
        break;
    default: CRAB_ERROR("DBM: unreachable");
    }
    normalize();
}

void SplitDBM::apply(BitwiseBinOp op, Variable x, Variable y, Variable z, int finite_width) {
    CrabStats::count("SplitDBM.count.apply");
    ScopedCrabStats __st__("SplitDBM.apply");

    // Convert to intervals and perform the operation
    Interval yi = this->operator[](y);
    Interval zi = this->operator[](z);
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
    normalize();
}

// Apply a bitwise operator to a uvalue.
void SplitDBM::apply(BitwiseBinOp op, Variable x, Variable y, const Number& k, int finite_width) {
    CrabStats::count("SplitDBM.count.apply");
    ScopedCrabStats __st__("SplitDBM.apply");

    // Convert to intervals and perform the operation
    normalize();
    Interval yi = this->operator[](y);
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
    normalize();
}

void SplitDBM::forget(const VariableVector& variables) {
    if (is_top()) {
        return;
    }

    for (const auto v : variables) {
        if (vert_map.contains(v)) {
            havoc(v);
        }
    }
    normalize();
}

static std::string to_string(const Variable vd, const Variable vs, const SplitDBM::Weight& w, const bool eq) {
    std::stringstream elem;
    if (eq) {
        if (w.operator>(0)) {
            elem << vd << "=" << vs << "+" << w;
        } else if (w.operator<(0)) {
            elem << vs << "=" << vd << "+" << -w;
        } else {
            const auto [left, right] = std::minmax(vs, vd, variable_registry->printing_order);
            elem << left << "=" << right;
        }
    } else {
        elem << vd << "-" << vs << "<=" << w;
    }
    return elem.str();
}

StringInvariant SplitDBM::to_set() const {
    if (this->is_top()) {
        return StringInvariant::top();
    }
    // Extract all the edges
    SubGraph g_excl{this->g, 0};

    std::map<Variable, Variable> equivalence_classes;
    std::set<std::tuple<Variable, Variable, Weight>> diff_csts;
    for (const VertId s : g_excl.verts()) {
        const Variable vs = *rev_map.at(s);
        Variable least = vs;
        for (const VertId d : g_excl.succs(s)) {
            const Variable vd = *rev_map.at(d);
            const Weight w = g_excl.edge_val(s, d);
            if (w == 0) {
                least = std::min(least, vd, variable_registry->printing_order);
            } else {
                diff_csts.emplace(vd, vs, w);
            }
        }
        equivalence_classes.insert_or_assign(vs, least);
    }

    std::set<Variable> representatives;
    std::set<std::string> result;
    for (const auto [vs, least] : equivalence_classes) {
        if (vs == least) {
            representatives.insert(least);
        } else {
            result.insert(variable_registry->name(vs) + "=" + variable_registry->name(least));
        }
    }

    // simplify: x - y <= k && y - x <= -k
    //        -> x <= y + k <= x
    //        -> x = y + k
    for (const auto& [vd, vs, w] : diff_csts) {
        if (!representatives.contains(vd) || !representatives.contains(vs)) {
            continue;
        }
        auto dual = to_string(vs, vd, -w, false);
        if (result.contains(dual)) {
            assert(w != 0);
            result.erase(dual);
            result.insert(to_string(vd, vs, w, true));
        } else {
            result.insert(to_string(vd, vs, w, false));
        }
    }

    // Intervals
    for (VertId v : g_excl.verts()) {
        const auto pvar = this->rev_map[v];
        if (!pvar || !representatives.contains(*pvar)) {
            continue;
        }
        if (!this->g.elem(0, v) && !this->g.elem(v, 0)) {
            continue;
        }
        Interval v_out{this->g.elem(v, 0) ? -Number(this->g.edge_val(v, 0)) : ExtendedNumber::minus_infinity(),
                       this->g.elem(0, v) ? Number(this->g.edge_val(0, v)) : ExtendedNumber::plus_infinity()};
        assert(!v_out.is_bottom());

        Variable variable = *pvar;

        std::stringstream elem;
        elem << variable;
        if (variable_registry->is_type(variable)) {
            auto [lb, ub] = v_out.bound(T_UNINIT, T_MAX);
            if (lb == ub) {
                if (variable_registry->is_in_stack(variable) && lb == T_NUM) {
                    // no need to show this
                    continue;
                }
                elem << "=" << lb;
            } else {
                elem << " in " << typeset_to_string(iterate_types(lb, ub));
            }
        } else {
            elem << "=";
            if (v_out.is_singleton()) {
                elem << v_out.lb();
            } else {
                elem << v_out;
            }
        }
        result.insert(elem.str());
    }

    return StringInvariant{result};
}

std::ostream& operator<<(std::ostream& o, const SplitDBM& dom) { return o << dom.to_set(); }

bool SplitDBM::eval_expression_overflow(const LinearExpression& e, Weight& out) const {
    [[maybe_unused]]
    const bool overflow = convert_NtoW_overflow(e.constant_term(), out);
    assert(!overflow);
    for (const auto& [variable, coefficient] : e.variable_terms()) {
        Weight coef;
        if (convert_NtoW_overflow(coefficient, coef)) {
            out = Weight(0);
            return true;
        }
        out += (pot_value(variable) - potential[0]) * coef;
    }
    return false;
}

Interval SplitDBM::compute_residual(const LinearExpression& e, const Variable pivot) const {
    Interval residual(-e.constant_term());
    for (const auto& [variable, coefficient] : e.variable_terms()) {
        if (variable != pivot) {
            residual = residual - (Interval(coefficient) * this->operator[](variable));
        }
    }
    return residual;
}

SplitDBM::Weight SplitDBM::pot_value(const Variable v) const {
    if (const auto y = try_at(vert_map, v)) {
        return potential[*y];
    }
    return {0};
}

Interval SplitDBM::eval_interval(const LinearExpression& e) const {
    using namespace prevail::interval_operators;
    Interval r{e.constant_term()};
    for (const auto& [variable, coefficient] : e.variable_terms()) {
        r += coefficient * operator[](variable);
    }
    return r;
}

bool SplitDBM::intersect(const LinearConstraint& cst) const {
    if (cst.is_contradiction()) {
        return false;
    }
    if (is_top() || cst.is_tautology()) {
        return true;
    }
    return intersect_aux(cst);
}

bool SplitDBM::entail(const LinearConstraint& rhs) const {
    if (rhs.is_tautology()) {
        return true;
    }
    if (rhs.is_contradiction()) {
        return false;
    }
    const Interval interval = eval_interval(rhs.expression());
    switch (rhs.kind()) {
    case ConstraintKind::EQUALS_ZERO:
        if (interval.singleton() == std::optional(Number(0))) {
            return true;
        }
        break;
    case ConstraintKind::LESS_THAN_OR_EQUALS_ZERO:
        if (interval.ub() <= Number(0)) {
            return true;
        }
        break;
    case ConstraintKind::LESS_THAN_ZERO:
        if (interval.ub() < Number(0)) {
            return true;
        }
        break;
    case ConstraintKind::NOT_ZERO:
        if (interval.ub() < Number(0) || interval.lb() > Number(0)) {
            return true;
        }
        break;
    }
    // TODO: copy the implementation from crab
    //       https://github.com/seahorn/crab/blob/master/include/crab/domains/split_dbm.hpp
    if (rhs.kind() == ConstraintKind::EQUALS_ZERO) {
        // try to convert the equality into inequalities so when it's
        // negated we do not have disequalities.
        return entail_aux(LinearConstraint(rhs.expression(), ConstraintKind::LESS_THAN_OR_EQUALS_ZERO)) &&
               entail_aux(LinearConstraint(rhs.expression().negate(), ConstraintKind::LESS_THAN_OR_EQUALS_ZERO));
    } else {
        return entail_aux(rhs);
    }

    // Note: we cannot convert rhs into SplitDBM and then use the <=
    //       operator. The problem is that we cannot know for sure
    //       whether SplitDBM can represent precisely rhs. It is not
    //       enough to do something like
    //
    //       SplitDBM dom = rhs;
    //       if (dom.is_top()) { ... }
}

void SplitDBM::diffcsts_of_assign(const Variable x, const LinearExpression& exp,
                                  std::vector<std::pair<Variable, Weight>>& lb,
                                  std::vector<std::pair<Variable, Weight>>& ub) const {
    diffcsts_of_assign(x, exp, true, ub);
    diffcsts_of_assign(x, exp, false, lb);
}

static Interval get_interval(const SplitDBM::VertMap& m, const SplitDBM::Graph& r, const Variable x,
                             const int finite_width) {
    const auto it = m.find(x);
    if (it == m.end()) {
        return Interval::top();
    }
    const SplitDBM::VertId v = it->second;
    ExtendedNumber lb = ExtendedNumber::minus_infinity();
    ExtendedNumber ub = ExtendedNumber::plus_infinity();
    if (r.elem(v, 0)) {
        lb = variable_registry->is_unsigned(x) ? (-Number(r.edge_val(v, 0))).zero_extend(finite_width)
                                               : (-Number(r.edge_val(v, 0))).sign_extend(finite_width);
    }
    if (r.elem(0, v)) {
        ub = variable_registry->is_unsigned(x) ? Number(r.edge_val(0, v)).zero_extend(finite_width)
                                               : Number(r.edge_val(0, v)).sign_extend(finite_width);
    }
    return {lb, ub};
}

Interval SplitDBM::get_interval(const Variable x, const int finite_width) const {
    return prevail::get_interval(vert_map, g, x, finite_width);
}

Interval SplitDBM::operator[](const Variable x) const { return prevail::get_interval(vert_map, g, x, 0); }

} // namespace prevail

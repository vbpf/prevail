// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0

#include "crab/splitdbm/definitions.hpp"
#include "crab/splitdbm/core_dbm.hpp"

namespace splitdbm {

GraphOps::PotentialFunction CoreDBM::pot_func(const std::vector<Weight>& p) {
    return [&p](const VertId v) -> Weight { return p[v]; };
}

CoreDBM::CoreDBM() {
    g_.growTo(1); // Allocate the zero vertex
    potential_.emplace_back(0);
}

CoreDBM::CoreDBM(Graph&& g, std::vector<Weight>&& pot, VertSet&& unstable)
    : g_(std::move(g)), potential_(std::move(pot)), unstable_(std::move(unstable)) {
    normalize();
}

bool CoreDBM::is_top() const { return g_.is_empty(); }

prevail::ExtendedNumber CoreDBM::get_bound(const VertId v, const Side side) const {
    if (side == Side::LEFT) {
        return g_.elem(v, 0) ? -prevail::Number(g_.edge_val(v, 0)) : prevail::MINUS_INFINITY;
    } else {
        return g_.elem(0, v) ? prevail::Number(g_.edge_val(0, v)) : prevail::PLUS_INFINITY;
    }
}

void CoreDBM::set_bound(const VertId v, const Side side, const Weight& bound_value) {
    if (side == Side::LEFT) {
        g_.set_edge(v, -bound_value, 0);
    } else {
        g_.set_edge(0, bound_value, v);
    }
    potential_[v] = potential_[0] + bound_value;
}

VertId CoreDBM::new_vertex() {
    const VertId vert = g_.new_vertex();
    if (vert >= potential_.size()) {
        potential_.emplace_back(0);
    } else {
        potential_[vert] = Weight(0);
    }
    return vert;
}

void CoreDBM::forget(const VertId v) {
    g_.forget(v);
}

const Graph& CoreDBM::graph() const { return g_; }

bool CoreDBM::repair_potential(const VertId src, const VertId dest) {
    return GraphOps::repair_potential(g_, potential_, src, dest);
}

bool CoreDBM::update_bound_if_tighter(const VertId v, const Side side, const Weight& new_bound) {
    if (side == Side::LEFT) {
        if (const auto w = g_.lookup(v, 0)) {
            if (*w <= -new_bound) {
                return true;
            }
        }
        g_.set_edge(v, -new_bound, 0);
        return repair_potential(v, 0);
    } else {
        if (const auto w = g_.lookup(0, v)) {
            if (*w <= new_bound) {
                return true;
            }
        }
        g_.set_edge(0, new_bound, v);
        return repair_potential(0, v);
    }
}

bool CoreDBM::add_difference_constraint(const VertId src, const VertId dest, const Weight& k) {
    g_.update_edge(src, k, dest);
    if (!repair_potential(src, dest)) {
        return false;
    }
    GraphOps::close_over_edge(g_, src, dest);
    return true;
}

void CoreDBM::close_after_bound_updates() {
    GraphOps::apply_delta(g_, GraphOps::close_after_assign(g_, pot_func(potential_), 0));
}

void CoreDBM::apply_delta(const GraphOps::EdgeVector& delta) {
    GraphOps::apply_delta(g_, delta);
}

void CoreDBM::close_after_assign_vertex(const VertId v) {
    GraphOps::apply_delta(g_, GraphOps::close_after_assign(SubGraph(g_, 0), pot_func(potential_), v));
}

void CoreDBM::set_potential(const VertId v, const Weight& val) {
    potential_[v] = val;
}

Weight CoreDBM::potential_at(const VertId v) const {
    return potential_[v];
}

Weight CoreDBM::potential_at_zero() const {
    return potential_[0];
}

std::size_t CoreDBM::graph_size() const { return g_.size(); }
std::size_t CoreDBM::num_edges() const { return g_.num_edges(); }

bool CoreDBM::vertex_has_edges(const VertId v) const {
    return g_.succs(v).size() > 0 || g_.preds(v).size() > 0;
}

std::vector<VertId> CoreDBM::get_disconnected_vertices() const {
    std::vector<VertId> result;
    for (VertId v : g_.verts()) {
        if (v == 0) {
            continue;
        }
        if (!vertex_has_edges(v)) {
            result.push_back(v);
        }
    }
    return result;
}

void CoreDBM::update_edge(const VertId src, const Weight& w, const VertId dest) {
    g_.update_edge(src, w, dest);
}

bool CoreDBM::strengthen_bound_with_propagation(const VertId v, const Side side, const Weight& new_bound) {
    if (side == Side::LEFT) {
        const auto w = g_.lookup(v, 0);
        if (!w || new_bound >= *w) {
            return true;
        }
        g_.set_edge(v, new_bound, 0);
        if (!repair_potential(v, 0)) {
            return false;
        }
        for (const auto e : g_.e_preds(v)) {
            if (e.vert == 0) {
                continue;
            }
            g_.update_edge(e.vert, e.val + new_bound, 0);
            if (!repair_potential(e.vert, 0)) {
                return false;
            }
        }
    } else {
        const auto w = g_.lookup(0, v);
        if (!w || new_bound >= *w) {
            return true;
        }
        g_.set_edge(0, new_bound, v);
        if (!repair_potential(0, v)) {
            return false;
        }
        for (const auto e : g_.e_succs(v)) {
            if (e.vert == 0) {
                continue;
            }
            g_.update_edge(0, e.val + new_bound, e.vert);
            if (!repair_potential(0, e.vert)) {
                return false;
            }
        }
    }
    return true;
}

void CoreDBM::normalize() {
    if (unstable_.empty()) {
        return;
    }

    struct UnstableWrap {
        const VertSet& vs;
        explicit UnstableWrap(const VertSet& s) : vs(s) {}
        bool operator[](const VertId v) const { return vs.contains(v); }
    };

    const auto p = pot_func(potential_);
    GraphOps::apply_delta(g_, GraphOps::close_after_widen(SubGraph(g_, 0), p, UnstableWrap(unstable_)));
    GraphOps::apply_delta(g_, GraphOps::close_after_assign(g_, p, 0));

    unstable_.clear();
}

// =============================================================================
// CoreDBM static lattice method implementations
// =============================================================================

bool CoreDBM::is_subsumed_by(const CoreDBM& left, const CoreDBM& right, const std::vector<VertId>& perm) {
    const Graph& g = left.g_;
    const Graph& og = right.g_;

    for (const VertId ox : og.verts()) {
        if (og.succs(ox).size() == 0) {
            continue;
        }

        const VertId x = perm[ox];
        for (const auto edge : og.e_succs(ox)) {
            const VertId oy = edge.vert;
            const VertId y = perm[oy];
            Weight ow = edge.val;

            if (const auto w = g.lookup(x, y)) {
                if (*w <= ow) {
                    continue;
                }
            }

            if (const auto wx = g.lookup(x, 0)) {
                if (const auto wy = g.lookup(0, y)) {
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

CoreDBM CoreDBM::join(const AlignedPair& aligned) {
    const auto& perm_x = aligned.left_perm;
    const auto& perm_y = aligned.right_perm;
    const auto& left = aligned.left;
    const auto& right = aligned.right;
    const size_t sz = aligned.size();

    // Build potentials for the aligned vertices
    std::vector<Weight> pot_left, pot_right;
    pot_left.reserve(sz);
    pot_right.reserve(sz);
    for (size_t i = 0; i < sz; ++i) {
        pot_left.push_back(left.potential_[perm_x[i]] - left.potential_[0]);
        pot_right.push_back(right.potential_[perm_y[i]] - right.potential_[0]);
    }
    pot_left[0] = 0;
    pot_right[0] = 0;

    // Build aligned views of the graphs
    GraphPerm gx(perm_x, left.g_);
    GraphPerm gy(perm_y, right.g_);

    // Compute deferred relations: bounds from left applied to relations from right
    Graph g_deferred_right;
    g_deferred_right.growTo(sz);
    SubGraph gy_excl(gy, 0);
    for (VertId s : gy_excl.verts()) {
        for (VertId d : gy_excl.succs(s)) {
            if (auto ws = gx.lookup(s, 0)) {
                if (auto wd = gx.lookup(0, d)) {
                    g_deferred_right.add_edge(s, *ws + *wd, d);
                }
            }
        }
    }

    // Apply deferred relations to right and re-close
    bool is_closed;
    Graph g_closed_left(GraphOps::meet(gx, g_deferred_right, is_closed));
    if (!is_closed) {
        GraphOps::apply_delta(g_closed_left,
            GraphOps::close_after_meet(SubGraph(g_closed_left, 0), pot_func(pot_left), gx, g_deferred_right));
    }

    // Compute deferred relations: bounds from right applied to relations from left
    Graph g_deferred_left;
    g_deferred_left.growTo(sz);
    SubGraph gx_excl(gx, 0);
    for (VertId s : gx_excl.verts()) {
        for (VertId d : gx_excl.succs(s)) {
            if (auto ws = gy.lookup(s, 0)) {
                if (auto wd = gy.lookup(0, d)) {
                    g_deferred_left.add_edge(s, *ws + *wd, d);
                }
            }
        }
    }

    Graph g_closed_right(GraphOps::meet(gy, g_deferred_left, is_closed));
    if (!is_closed) {
        GraphOps::apply_delta(g_closed_right,
            GraphOps::close_after_meet(SubGraph(g_closed_right, 0), pot_func(pot_right), gy, g_deferred_left));
    }

    // Syntactic join of the closed graphs
    Graph result_g(GraphOps::join(g_closed_left, g_closed_right));

    // Reapply missing independent relations
    std::vector<VertId> lb_up, lb_down, ub_up, ub_down;
    for (VertId v : gx_excl.verts()) {
        if (auto wx = gx.lookup(0, v)) {
            if (auto wy = gy.lookup(0, v)) {
                if (*wx < *wy) ub_up.push_back(v);
                if (*wy < *wx) ub_down.push_back(v);
            }
        }
        if (auto wx = gx.lookup(v, 0)) {
            if (auto wy = gy.lookup(v, 0)) {
                if (*wx < *wy) lb_down.push_back(v);
                if (*wy < *wx) lb_up.push_back(v);
            }
        }
    }

    for (VertId s : lb_up) {
        Weight left_lb = gx.edge_val(s, 0);
        Weight right_lb = gy.edge_val(s, 0);
        for (VertId d : ub_up) {
            if (s != d) {
                result_g.update_edge(s, std::max(left_lb + gx.edge_val(0, d), right_lb + gy.edge_val(0, d)), d);
            }
        }
    }

    for (VertId s : lb_down) {
        Weight left_lb = gx.edge_val(s, 0);
        Weight right_lb = gy.edge_val(s, 0);
        for (VertId d : ub_down) {
            if (s != d) {
                result_g.update_edge(s, std::max(left_lb + gx.edge_val(0, d), right_lb + gy.edge_val(0, d)), d);
            }
        }
    }

    return CoreDBM(std::move(result_g), std::move(pot_left), VertSet{});
}

CoreDBM CoreDBM::widen(const AlignedPair& aligned) {
    const auto& perm_left = aligned.left_perm;
    const auto& perm_right = aligned.right_perm;
    const auto& left = aligned.left;
    const auto& right = aligned.right;
    const size_t sz = aligned.size();

    // Build potentials from left (widen uses left's potentials)
    std::vector<Weight> result_pot;
    result_pot.reserve(sz);
    for (size_t i = 0; i < sz; ++i) {
        result_pot.push_back(left.potential_[perm_left[i]] - left.potential_[0]);
    }
    result_pot[0] = 0;

    // Build aligned views
    const GraphPerm gx(perm_left, left.g_);
    const GraphPerm gy(perm_right, right.g_);

    // Perform the widening
    VertSet result_unstable(left.unstable_);
    Graph result_g(GraphOps::widen(gx, gy, result_unstable));

    return CoreDBM(std::move(result_g), std::move(result_pot), std::move(result_unstable));
}

std::optional<CoreDBM> CoreDBM::meet(AlignedPair& aligned) {
    const auto& perm_left = aligned.left_perm;
    const auto& perm_right = aligned.right_perm;
    const auto& left = aligned.left;
    const auto& right = aligned.right;

    // Build aligned views
    const GraphPerm gx(perm_left, left.g_);
    const GraphPerm gy(perm_right, right.g_);

    // Compute the syntactic meet of the aligned graphs
    bool is_closed{};
    Graph result_g(GraphOps::meet(gx, gy, is_closed));

    // Select valid potentials using Bellman-Ford (updates initial_potentials in place)
    auto& result_pot = aligned.initial_potentials;
    if (!GraphOps::select_potentials(result_g, result_pot)) {
        return std::nullopt;  // Infeasible
    }

    if (!is_closed) {
        const auto potential_func = pot_func(result_pot);
        GraphOps::apply_delta(result_g, GraphOps::close_after_meet(SubGraph(result_g, 0), potential_func, gx, gy));
        GraphOps::apply_delta(result_g, GraphOps::close_after_assign(result_g, potential_func, 0));
    }

    return CoreDBM(std::move(result_g), std::move(result_pot), VertSet{});
}

} // namespace splitdbm

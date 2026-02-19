// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0

#include "crab/splitdbm/split_dbm.hpp"
#include "crab/splitdbm/definitions.hpp"

namespace splitdbm {

namespace {

// Compute deferred relations: bounds from bound_source applied to relations from rel_source.
Graph compute_deferred(const ReadableGraph auto& bound_source, ReadableGraph auto& rel_source, const size_t sz) {
    Graph deferred;
    deferred.growTo(sz);
    SubGraph rel_excl(rel_source, 0);
    for (VertId s : rel_excl.verts()) {
        for (VertId d : rel_excl.succs(s)) {
            if (auto ws = bound_source.lookup(s, 0)) {
                if (auto wd = bound_source.lookup(0, d)) {
                    deferred.add_edge(s, *ws + *wd, d);
                }
            }
        }
    }
    return deferred;
}

// Meet deferred relations into base graph and re-close.
Graph close_deferred(ScratchSpace& scratch, const ReadableGraph auto& base, const Graph& deferred,
                     const std::vector<Weight>& pot) {
    bool is_closed;
    Graph closed(graph_meet(base, deferred, is_closed));
    if (!is_closed) {
        const auto p = [&pot](const VertId v) -> Weight { return pot[v]; };
        splitdbm::apply_delta(closed, close_after_meet(scratch, SubGraph(closed, 0), p, base, deferred));
    }
    return closed;
}

} // anonymous namespace

SplitDBM::SplitDBM() {
    g_.growTo(1); // Allocate the zero vertex
    potential_.emplace_back(0);
}

SplitDBM::SplitDBM(Graph&& g, std::vector<Weight>&& pot, VertSet&& unstable)
    : g_(std::move(g)), potential_(std::move(pot)), unstable_(std::move(unstable)) {
    normalize();
}

bool SplitDBM::is_top() const { return g_.is_empty(); }

prevail::ExtendedNumber SplitDBM::get_bound(const VertId v, const Side side) const {
    if (side == Side::LEFT) {
        return g_.elem(v, 0) ? -prevail::Number(g_.edge_val(v, 0)) : prevail::MINUS_INFINITY;
    } else {
        return g_.elem(0, v) ? prevail::Number(g_.edge_val(0, v)) : prevail::PLUS_INFINITY;
    }
}

// Callers must call normalize() after set_bound() to restore closure.
void SplitDBM::set_bound(const VertId v, const Side side, const Weight& bound_value) {
    if (side == Side::LEFT) {
        g_.set_edge(v, -bound_value, 0);
    } else {
        g_.set_edge(0, bound_value, v);
    }
    potential_[v] = potential_[0] + bound_value;
}

VertId SplitDBM::new_vertex() {
    const VertId vert = g_.new_vertex();
    if (vert >= potential_.size()) {
        potential_.emplace_back(0);
    } else {
        potential_[vert] = Weight(0);
    }
    return vert;
}

void SplitDBM::forget(const VertId v) { g_.forget(v); }

const Graph& SplitDBM::graph() const { return g_; }

bool SplitDBM::repair_potential(const VertId src, const VertId dest) {
    return splitdbm::repair_potential(*scratch_, g_, potential_, src, dest);
}

bool SplitDBM::update_bound_if_tighter(const VertId v, const Side side, const Weight& new_bound) {
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

bool SplitDBM::add_difference_constraint(const VertId src, const VertId dest, const Weight& k) {
    g_.update_edge(src, k, dest);
    if (!repair_potential(src, dest)) {
        return false;
    }
    close_over_edge(g_, src, dest);
    return true;
}

void SplitDBM::close_after_bound_updates() {
    apply_delta(close_after_assign(*scratch_, g_, [this](const VertId v) { return potential_[v]; }, 0));
}

void SplitDBM::apply_delta(const EdgeVector& delta) { splitdbm::apply_delta(g_, delta); }

void SplitDBM::close_after_assign_vertex(const VertId v) {
    apply_delta(close_after_assign(*scratch_, SubGraph(g_, 0), [this](const VertId u) { return potential_[u]; }, v));
}

VertId SplitDBM::assign_vertex(const Weight& potential_value,
                               const std::span<const std::pair<VertId, Weight>> diffs_from,
                               const std::span<const std::pair<VertId, Weight>> diffs_to,
                               const std::optional<Weight>& lb_edge, const std::optional<Weight>& ub_edge) {
    const VertId vert = new_vertex();
    potential_[vert] = potential_value;

    EdgeVector delta;
    delta.reserve(diffs_from.size() + diffs_to.size());
    for (const auto& [dest, w] : diffs_from) {
        delta.emplace_back(vert, dest, w);
    }
    for (const auto& [src, w] : diffs_to) {
        delta.emplace_back(src, vert, w);
    }
    apply_delta(delta);
    close_after_assign_vertex(vert);

    if (lb_edge) {
        g_.update_edge(vert, *lb_edge, 0);
    }
    if (ub_edge) {
        g_.update_edge(0, *ub_edge, vert);
    }
    return vert;
}

Weight SplitDBM::potential_at(const VertId v) const { return potential_[v]; }

Weight SplitDBM::potential_at_zero() const { return potential_[0]; }

std::size_t SplitDBM::graph_size() const { return g_.size(); }
std::size_t SplitDBM::num_edges() const { return g_.num_edges(); }

bool SplitDBM::vertex_has_edges(const VertId v) const { return g_.succs(v).size() > 0 || g_.preds(v).size() > 0; }

std::vector<VertId> SplitDBM::get_disconnected_vertices() const {
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

bool SplitDBM::strengthen_bound(const VertId v, const Side side, const Weight& bound_value) {
    if (side == Side::LEFT) {
        const Weight edge_weight = -bound_value;
        const auto w = g_.lookup(v, 0);
        if (!w || edge_weight >= *w) {
            return true;
        }
        g_.set_edge(v, edge_weight, 0);
        if (!repair_potential(v, 0)) {
            return false;
        }
        for (const auto e : g_.e_preds(v)) {
            if (e.vert == 0) {
                continue;
            }
            g_.update_edge(e.vert, e.val + edge_weight, 0);
            if (!repair_potential(e.vert, 0)) {
                return false;
            }
        }
    } else {
        const auto w = g_.lookup(0, v);
        if (!w || bound_value >= *w) {
            return true;
        }
        g_.set_edge(0, bound_value, v);
        if (!repair_potential(0, v)) {
            return false;
        }
        for (const auto e : g_.e_succs(v)) {
            if (e.vert == 0) {
                continue;
            }
            g_.update_edge(0, e.val + bound_value, e.vert);
            if (!repair_potential(0, e.vert)) {
                return false;
            }
        }
    }
    return true;
}

void SplitDBM::normalize() {
    if (unstable_.empty()) {
        return;
    }

    // close_after_widen expects an is_stable predicate: returns true iff v is stable.
    // Vertices in unstable_ are NOT stable, so we negate the membership test.
    struct IsStable {
        const VertSet& unstable;
        explicit IsStable(const VertSet& s) : unstable(s) {}
        bool operator[](const VertId v) const { return !unstable.contains(v); }
    };

    const auto p = [this](const VertId v) { return potential_[v]; };
    apply_delta(close_after_widen(*scratch_, SubGraph(g_, 0), p, IsStable(unstable_)));
    apply_delta(close_after_assign(*scratch_, g_, p, 0));

    unstable_.clear();
}

void SplitDBM::clear_thread_local_state() { scratch_.clear(); }

bool SplitDBM::is_subsumed_by(const SplitDBM& left, const SplitDBM& right, const std::vector<VertId>& perm) {
    const Graph& g = left.g_;
    const Graph& og = right.g_;

    for (const VertId ox : og.verts()) {
        if (og.succs(ox).size() == 0) {
            continue;
        }

        const VertId x = perm[ox];
        for (const auto& edge : og.e_succs(ox)) {
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

SplitDBM SplitDBM::join(const AlignedPair& aligned) {
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

    // Compute deferred relations and close
    auto g_deferred_right = compute_deferred(gx, gy, sz);
    auto g_closed_left = close_deferred(*scratch_, gx, g_deferred_right, pot_left);
    auto g_deferred_left = compute_deferred(gy, gx, sz);
    auto g_closed_right = close_deferred(*scratch_, gy, g_deferred_left, pot_right);

    // Syntactic join of the closed graphs
    Graph result_g(graph_join(g_closed_left, g_closed_right));

    // Reapply missing independent relations
    SubGraph gx_excl(gx, 0);
    std::vector<VertId> lb_up, lb_down, ub_up, ub_down;
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

    return {std::move(result_g), std::move(pot_left), VertSet{}};
}

SplitDBM SplitDBM::widen(const AlignedPair& aligned) {
    const size_t sz = aligned.size();

    // Build potentials from left (widen uses left's potentials)
    std::vector<Weight> result_pot;
    result_pot.reserve(sz);
    for (size_t i = 0; i < sz; ++i) {
        result_pot.push_back(aligned.left.potential_[aligned.left_perm[i]] - aligned.left.potential_[0]);
    }
    result_pot[0] = 0;

    // Build aligned views
    const GraphPerm gx(aligned.left_perm, aligned.left.g_);
    const GraphPerm gy(aligned.right_perm, aligned.right.g_);

    // Perform the widening
    VertSet result_unstable(aligned.left.unstable_);
    Graph result_g(graph_widen(gx, gy, result_unstable));

    return {std::move(result_g), std::move(result_pot), std::move(result_unstable)};
}

std::optional<SplitDBM> SplitDBM::meet(AlignedPair& aligned) {
    // Build aligned views
    const GraphPerm gx(aligned.left_perm, aligned.left.g_);
    const GraphPerm gy(aligned.right_perm, aligned.right.g_);

    // Compute the syntactic meet of the aligned graphs
    bool is_closed{};
    Graph result_g(graph_meet(gx, gy, is_closed));

    // Select valid potentials using Bellman-Ford (updates initial_potentials in place)
    auto& result_pot = aligned.initial_potentials;
    if (!select_potentials(*scratch_, result_g, result_pot)) {
        return std::nullopt; // Infeasible
    }

    if (!is_closed) {
        const auto p = [&result_pot](const VertId v) { return result_pot[v]; };
        splitdbm::apply_delta(result_g, close_after_meet(*scratch_, SubGraph(result_g, 0), p, gx, gy));
        splitdbm::apply_delta(result_g, close_after_assign(*scratch_, result_g, p, 0));
    }

    return SplitDBM(std::move(result_g), std::move(result_pot), VertSet{});
}

} // namespace splitdbm

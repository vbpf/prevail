// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

// Graph view wrappers: present an existing graph differently without copying it.
// Each view satisfies the same interface as AdaptGraph (verts, succs, preds,
// e_succs, e_preds, lookup, elem, edge_val, size) so they can be used as
// template arguments to graph algorithms.

#include <concepts>
#include <ranges>

#include "crab/splitdbm/adapt_sgraph.hpp"

namespace splitdbm {

// Processing a graph under a (possibly incomplete) permutation of vertices.
// We assume perm[x] is unique; otherwise, we'd have to introduce edges for induced equivalence classes.
// Only used with AdaptGraph (the sole graph implementation).
class GraphPerm {
  public:
    constexpr static VertId invalid_vert = std::numeric_limits<VertId>::max();

    GraphPerm(const std::vector<VertId>& _perm, const Graph& _g) : g{_g}, perm{_perm}, inv(_g.size(), invalid_vert) {
        assert(perm.size() <= std::numeric_limits<VertId>::max());
        for (VertId vi = 0; static_cast<size_t>(vi) < perm.size(); vi++) {
            if (perm[vi] == invalid_vert) {
                continue;
            }
            assert(perm[vi] < g.size());
            assert(inv[perm[vi]] == invalid_vert);
            inv[perm[vi]] = vi;
        }
    }

    // Check whether an edge is live
    [[nodiscard]]
    bool elem(const VertId x, const VertId y) const {
        if (perm[x] >= g.size() || perm[y] >= g.size()) {
            return false;
        }
        return g.elem(perm[x], perm[y]);
    }

    [[nodiscard]]
    const Weight* lookup(const VertId x, const VertId y) const {
        if (perm[x] >= g.size() || perm[y] >= g.size()) {
            return nullptr;
        }
        return g.lookup(perm[x], perm[y]);
    }

    // Precondition: elem(x, y) is true.
    [[nodiscard]]
    Weight edge_val(const VertId x, const VertId y) const {
        assert(perm[x] < g.size() && perm[y] < g.size());
        return g.edge_val(perm[x], perm[y]);
    }

    // Number of allocated vertices
    [[nodiscard]]
    size_t size() const {
        return perm.size();
    }

    [[nodiscard]]
    auto verts() const {
        return std::views::iota(VertId{0}, gsl::narrow_cast<VertId>(perm.size()));
    }

    [[nodiscard]]
    auto succs(const VertId v) const {
        auto base = (perm[v] == invalid_vert) ? empty_adj() : g.succs(perm[v]);
        return base | std::views::filter([this](const VertId u) { return inv[u] != invalid_vert; }) |
               std::views::transform([this](const VertId u) { return inv[u]; });
    }
    [[nodiscard]]
    auto preds(const VertId v) const {
        auto base = (perm[v] == invalid_vert) ? empty_adj() : g.preds(perm[v]);
        return base | std::views::filter([this](const VertId u) { return inv[u] != invalid_vert; }) |
               std::views::transform([this](const VertId u) { return inv[u]; });
    }

    [[nodiscard]]
    auto e_succs(const VertId v) const {
        using EdgeRef = Graph::EdgeConstIterator::EdgeRef;
        auto base = perm[v] == invalid_vert ? empty_e_adj() : g.e_succs(perm[v]);
        return base | std::views::filter([this](auto e) { return inv[e.vert] != invalid_vert; }) |
               std::views::transform([this](auto e) -> EdgeRef { return {inv[e.vert], e.val}; });
    }
    [[nodiscard]]
    auto e_preds(const VertId v) const {
        using EdgeRef = Graph::EdgeConstIterator::EdgeRef;
        auto base = perm[v] == invalid_vert ? empty_e_adj() : g.e_preds(perm[v]);
        return base | std::views::filter([this](auto e) { return inv[e.vert] != invalid_vert; }) |
               std::views::transform([this](auto e) -> EdgeRef { return {inv[e.vert], e.val}; });
    }

  private:
    // Default-constructed ranges are safe (backed by static empties),
    // so both ternary branches produce the same concrete type.
    static TreeSMap::KeyConstRange empty_adj() { return {}; }
    static Graph::EdgeConstRange empty_e_adj() { return {}; }

    const Graph& g;
    std::vector<VertId> perm;
    std::vector<VertId> inv;
};

// ReadableGraph is a read-only graph interface required by graph algorithms.
// All graph types (AdaptGraph, GraphPerm, SubGraph, GraphRev) satisfy this concept.
template <typename G>
concept ReadableGraph = requires(const G& g, VertId v, VertId u) {
    { g.size() } -> std::convertible_to<size_t>;
    { g.elem(v, u) } -> std::convertible_to<bool>;
    { g.edge_val(v, u) } -> std::convertible_to<Weight>;
    { g.lookup(v, u) } -> std::same_as<const Weight*>;
    g.verts();
    g.succs(v);
    g.preds(v);
    g.e_succs(v);
    g.e_preds(v);
};

// View of a graph, omitting a given vertex
template <ReadableGraph G>
class SubGraph {
  public:
    SubGraph(G& _g, const VertId _v_ex) : g(_g), v_ex(_v_ex) {}

    [[nodiscard]]
    bool elem(VertId x, VertId y) const {
        return x != v_ex && y != v_ex && g.elem(x, y);
    }

    Weight* lookup(VertId x, VertId y) {
        if (x == v_ex || y == v_ex) {
            return nullptr;
        }
        return g.lookup(x, y);
    }

    [[nodiscard]]
    const Weight* lookup(VertId x, VertId y) const {
        if (x == v_ex || y == v_ex) {
            return nullptr;
        }
        return g.lookup(x, y);
    }

    [[nodiscard]]
    Weight edge_val(VertId x, VertId y) const {
        assert(x != v_ex && y != v_ex);
        return g.edge_val(x, y);
    }

    void clear_edges() { g.clear_edges(); }

    // Number of allocated vertices
    [[nodiscard]]
    size_t size() const {
        return g.size();
    }

    // Assumption: (x, y) not in mtx
    void add_edge(VertId x, Weight wt, VertId y) {
        assert(x != v_ex && y != v_ex);
        g.add_edge(x, wt, y);
    }

    void set_edge(VertId s, Weight w, VertId d) {
        assert(s != v_ex && d != v_ex);
        g.set_edge(s, w, d);
    }

    auto verts() const {
        return g.verts() | std::views::filter([this](const VertId v) { return v != v_ex; });
    }
    auto succs(VertId v) const {
        assert(v != v_ex);
        return g.succs(v) | std::views::filter([this](const VertId d) { return d != v_ex; });
    }
    auto preds(VertId v) const {
        assert(v != v_ex);
        return g.preds(v) | std::views::filter([this](const VertId d) { return d != v_ex; });
    }
    auto e_succs(VertId v) const {
        assert(v != v_ex);
        return g.e_succs(v) | std::views::filter([this](auto e) { return e.vert != v_ex; });
    }
    auto e_preds(VertId v) const {
        assert(v != v_ex);
        return g.e_preds(v) | std::views::filter([this](auto e) { return e.vert != v_ex; });
    }

  private:
    G& g;
    VertId v_ex;
};

// Viewing a graph with all edges reversed.
// Useful if we want to run single-dest shortest paths,
// for updating bounds and incremental closure.
template <ReadableGraph G>
class GraphRev {
  public:
    explicit GraphRev(G& _g) : g(_g) {}

    // Check whether an edge is live
    [[nodiscard]]
    bool elem(VertId x, VertId y) const {
        return g.elem(y, x);
    }

    Weight* lookup(VertId x, VertId y) { return g.lookup(y, x); }
    [[nodiscard]]
    const Weight* lookup(VertId x, VertId y) const {
        return g.lookup(y, x);
    }

    // Precondition: elem(x, y) is true.
    [[nodiscard]]
    Weight edge_val(VertId x, VertId y) const {
        return g.edge_val(y, x);
    }

    // Number of allocated vertices
    [[nodiscard]]
    size_t size() const {
        return g.size();
    }

    auto verts() const { return g.verts(); }
    auto succs(VertId v) const { return g.preds(v); }
    auto preds(VertId v) const { return g.succs(v); }
    auto e_succs(VertId v) const { return g.e_preds(v); }
    auto e_preds(VertId v) const { return g.e_succs(v); }

  private:
    G& g;
};

} // namespace splitdbm

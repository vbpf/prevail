// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

// Graph view wrappers: present an existing graph differently without copying it.
// Each view satisfies the same interface as AdaptGraph (verts, succs, preds,
// e_succs, e_preds, lookup, elem, edge_val, size) so they can be used as
// template arguments to graph algorithms.

#include <concepts>
#include <optional>

#include "crab/splitdbm/definitions.hpp"

namespace splitdbm {

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

// Processing a graph under a (possibly incomplete) permutation of vertices.
// We assume perm[x] is unique; otherwise, we'd have to introduce edges for induced equivalence classes.
template <class G>
class GraphPerm {
  public:
    constexpr static VertId invalid_vert = std::numeric_limits<VertId>::max();

    GraphPerm(const std::vector<VertId>& _perm, const G& _g) : g{_g}, perm{_perm}, inv(_g.size(), invalid_vert) {
        for (VertId vi = 0; vi < perm.size(); vi++) {
            if (perm[vi] == invalid_vert) {
                continue;
            }
            assert(inv[perm[vi]] == invalid_vert);
            inv[perm[vi]] = vi;
        }
    }

    // Check whether an edge is live
    bool elem(const VertId x, const VertId y) const {
        if (perm[x] > g.size() || perm[y] > g.size()) {
            return false;
        }
        return g.elem(perm[x], perm[y]);
    }

    const Weight* lookup(const VertId x, const VertId y) const {
        if (perm[x] > g.size() || perm[y] > g.size()) {
            return nullptr;
        }
        return g.lookup(perm[x], perm[y]);
    }

    // Precondition: elem(x, y) is true.
    Weight edge_val(const VertId x, const VertId y) const {
        //      assert(perm[x] < g.size() && perm[y] < g.size());
        return g.edge_val(perm[x], perm[y]);
    }

    // Precondition: elem(x, y) is true.
    Weight operator()(const VertId x, const VertId y) const {
        //      assert(perm[x] < g.size() && perm[y] < g.size());
        return g(perm[x], perm[y]);
    }

    // Number of allocated vertices
    [[nodiscard]]
    size_t size() const {
        return perm.size();
    }

    class VertConstRange final {
      public:
        class iterator final {
          public:
            explicit iterator(const VertId _v) : v{_v} {}
            VertId operator*() const { return v; }
            iterator& operator++() {
                ++v;
                return *this;
            }
            iterator& operator--() {
                --v;
                return *this;
            }
            bool operator!=(const iterator& o) const { return v < o.v; }

          private:
            VertId v;
        };
        explicit VertConstRange(const VertId _after) : after{_after} {}

        iterator begin() const { return iterator{0}; }
        iterator end() const { return iterator{after}; }

      private:
        VertId after;
    };
    using VertConstIterator = VertConstRange::iterator;

    VertConstRange verts() const { return VertConstRange(gsl::narrow<VertId>(perm.size())); }

    // GKG: Should probably modify this to handle cases where
    // the vertex iterator isn't just a VertId*.
    template <class ItG>
    class AdjConstIterator final {
      public:
        AdjConstIterator(const std::vector<VertId>& _inv, const ItG& _v) : inv(_inv), v(_v) {}

        VertId operator*() const { return inv[*v]; }

        AdjConstIterator& operator++() {
            ++v;
            return *this;
        }

        bool operator!=(const AdjConstIterator& other) {
            while (v != other.v && inv[*v] == invalid_vert) {
                ++v;
            }
            return v != other.v;
        }

      private:
        const std::vector<VertId>& inv;
        ItG v;
    };

    template <class ItG>
    class EAdjConstIterator final {
      public:
        using EdgeRef = ItG::EdgeRef;

        EAdjConstIterator(const std::vector<VertId>& _inv, const ItG& _v) : inv(_inv), v(_v) {}

        EdgeRef operator*() const { return EdgeRef{inv[(*v).vert], (*v).val}; }

        EAdjConstIterator& operator++() {
            ++v;
            return *this;
        }

        bool operator!=(const EAdjConstIterator& other) {
            while (v != other.v && inv[(*v).vert] == invalid_vert) {
                ++v;
            }
            return v != other.v;
        }

      private:
        const std::vector<VertId>& inv;
        ItG v;
    };

    template <class RG, class It>
    class ConstAdjList final {
      public:
        using ItG = RG::iterator;

        using iterator = It;

        ConstAdjList(const std::vector<VertId>& _perm, const std::vector<VertId>& _inv, const RG& _adj)
            : perm(_perm), inv(_inv), adj(_adj) {}

        ConstAdjList(const std::vector<VertId>& _perm, const std::vector<VertId>& _inv)
            : perm(_perm), inv(_inv), adj() {}

        iterator begin() const {
            if (adj) {
                return iterator(inv, (*adj).begin());
            }
            return iterator(inv, ItG::empty_iterator());
        }
        iterator end() const {
            if (adj) {
                return iterator(inv, (*adj).end());
            }
            return iterator(inv, ItG::empty_iterator());
        }

        [[nodiscard]]
        bool mem(const VertId v) const {
            if (!adj || perm[v] == invalid_vert) {
                return false;
            }
            return (*adj).mem(perm[v]);
        }

      private:
        const std::vector<VertId>& perm;
        const std::vector<VertId>& inv;
        std::optional<RG> adj;
    };

    using NeighbourConstRange =
        ConstAdjList<typename G::NeighbourConstRange, AdjConstIterator<typename G::NeighbourConstRange::iterator>>;
    using ENeighbourConstRange =
        ConstAdjList<typename G::ENeighbourConstRange, EAdjConstIterator<typename G::ENeighbourConstRange::iterator>>;

    NeighbourConstRange succs(const VertId v) const {
        if (perm[v] == invalid_vert) {
            return NeighbourConstRange(perm, inv);
        }
        return NeighbourConstRange(perm, inv, g.succs(perm[v]));
    }
    NeighbourConstRange preds(const VertId v) const {
        if (perm[v] == invalid_vert) {
            return NeighbourConstRange(perm, inv);
        }
        return NeighbourConstRange(perm, inv, g.preds(perm[v]));
    }

    ENeighbourConstRange e_succs(const VertId v) const {
        if (perm[v] == invalid_vert) {
            return ENeighbourConstRange(perm, inv);
        }
        return ENeighbourConstRange(perm, inv, g.e_succs(perm[v]));
    }
    ENeighbourConstRange e_preds(const VertId v) const {
        if (perm[v] == invalid_vert) {
            return ENeighbourConstRange(perm, inv);
        }
        return ENeighbourConstRange(perm, inv, g.e_preds(perm[v]));
    }

  private:
    const G& g;
    std::vector<VertId> perm;
    std::vector<VertId> inv;
};

// View of a graph, omitting a given vertex
template <class G>
class SubGraph {
  public:
    using GNeighbourConstRange = G::NeighbourConstRange;
    using GENeighbourConstRange = G::ENeighbourConstRange;

    SubGraph(G& _g, const VertId _v_ex) : g(_g), v_ex(_v_ex) {}

    bool elem(VertId x, VertId y) const { return x != v_ex && y != v_ex && g.elem(x, y); }

    Weight* lookup(VertId x, VertId y) {
        if (x == v_ex || y == v_ex) {
            return nullptr;
        }
        return g.lookup(x, y);
    }

    const Weight* lookup(VertId x, VertId y) const {
        if (x == v_ex || y == v_ex) {
            return nullptr;
        }
        return g.lookup(x, y);
    }

    Weight edge_val(VertId x, VertId y) const { return g.edge_val(x, y); }

    // Precondition: elem(x, y) is true.
    Weight operator()(VertId x, VertId y) const { return g(x, y); }

    void clear_edges() { g.clear_edges(); }

    // Number of allocated vertices
    [[nodiscard]]
    size_t size() const {
        return g.size();
    }

    // Assumption: (x, y) not in mtx
    void add_edge(VertId x, Weight wt, VertId y) {
        //      assert(x != v_ex && y != v_ex);
        g.add_edge(x, wt, y);
    }

    void set_edge(VertId s, Weight w, VertId d) {
        //      assert(s != v_ex && d != v_ex);
        g.set_edge(s, w, d);
    }

    struct VertConstIterator {
        VertConstIterator(const G::VertConstIterator& _iG, const VertId _v_ex) : v_ex(_v_ex), iG(_iG) {}

        // Skipping of v_ex is done entirely by !=.
        // So we _MUST_ test it != verts.end() before dereferencing.
        VertId operator*() { return *iG; }
        VertConstIterator operator++() {
            ++iG;
            return *this;
        }
        bool operator!=(const VertConstIterator& o) {
            if (iG != o.iG && (*iG) == v_ex) {
                ++iG;
            }
            return iG != o.iG;
        }

        VertId v_ex;
        G::VertConstIterator iG;
    };

    struct VertConstRange {
        VertConstRange(const G::VertConstRange& _rG, const VertId _v_ex) : rG(_rG), v_ex(_v_ex) {}

        VertConstIterator begin() const { return VertConstIterator(rG.begin(), v_ex); }
        VertConstIterator end() const { return VertConstIterator(rG.end(), v_ex); }

        G::VertConstRange rG;
        VertId v_ex;
    };

    VertConstRange verts() const { return VertConstRange(g.verts(), v_ex); }

    template <class It>
    struct AdjIterator {
        AdjIterator(const It& _iG, const VertId _v_ex) : iG(_iG), v_ex(_v_ex) {}
        VertId operator*() const { return *iG; }
        AdjIterator& operator++() {
            ++iG;
            return *this;
        }
        bool operator!=(const AdjIterator& o) {
            if (iG != o.iG && (*iG) == v_ex) {
                ++iG;
            }
            return iG != o.iG;
        }

        It iG;
        VertId v_ex;
    };

    template <class It>
    struct EAdjIterator {
        using EdgeRef = It::EdgeRef;

        EAdjIterator(const It& _iG, const VertId _v_ex) : iG(_iG), v_ex(_v_ex) {}
        EdgeRef operator*() const { return *iG; }
        EAdjIterator& operator++() {
            ++iG;
            return *this;
        }
        bool operator!=(const EAdjIterator& o) {
            if (iG != o.iG && (*iG).vert == v_ex) {
                ++iG;
            }
            return iG != o.iG;
        }

        It iG;
        VertId v_ex;
    };

    template <class R, class It>
    class AdjList {
      public:
        using iterator = It;

        AdjList(const R& _rG, const VertId _v_ex) : rG(_rG), v_ex(_v_ex) {}
        iterator begin() const { return iterator(rG.begin(), v_ex); }
        iterator end() const { return iterator(rG.end(), v_ex); }

      private:
        R rG;
        VertId v_ex;
    };
    using NeighbourConstRange = AdjList<GNeighbourConstRange, AdjIterator<typename GNeighbourConstRange::iterator>>;
    using ENeighbourConstRange = AdjList<GENeighbourConstRange, EAdjIterator<typename GENeighbourConstRange::iterator>>;

    NeighbourConstRange succs(VertId v) const {
        //      assert(v != v_ex);
        return NeighbourConstRange(g.succs(v), v_ex);
    }
    NeighbourConstRange preds(VertId v) const {
        //      assert(v != v_ex);
        return NeighbourConstRange(g.preds(v), v_ex);
    }
    ENeighbourConstRange e_succs(VertId v) const { return ENeighbourConstRange(g.e_succs(v), v_ex); }
    ENeighbourConstRange e_preds(VertId v) const { return ENeighbourConstRange(g.e_preds(v), v_ex); }

  private:
    G& g;
    VertId v_ex;
};

// Viewing a graph with all edges reversed.
// Useful if we want to run single-dest shortest paths,
// for updating bounds and incremental closure.
template <class G>
class GraphRev {
  public:
    explicit GraphRev(G& _g) : g(_g) {}

    // Check whether an edge is live
    bool elem(VertId x, VertId y) const { return g.elem(y, x); }

    Weight* lookup(VertId x, VertId y) { return g.lookup(y, x); }
    const Weight* lookup(VertId x, VertId y) const { return g.lookup(y, x); }

    // Precondition: elem(x, y) is true.
    Weight edge_val(VertId x, VertId y) const { return g.edge_val(y, x); }

    // Precondition: elem(x, y) is true.
    Weight operator()(VertId x, VertId y) const { return g(y, x); }

    // Number of allocated vertices
    [[nodiscard]]
    size_t size() const {
        return g.size();
    }

    using NeighbourConstRange = G::NeighbourConstRange;
    using ENeighbourConstRange = G::ENeighbourConstRange;

    G::VertConstRange verts() const { return g.verts(); }

    NeighbourConstRange succs(VertId v) const { return g.preds(v); }
    NeighbourConstRange preds(VertId v) const { return g.succs(v); }

    ENeighbourConstRange e_succs(VertId v) const { return g.e_preds(v); }
    ENeighbourConstRange e_preds(VertId v) const { return g.e_succs(v); }

  private:
    G& g;
};

} // namespace splitdbm

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

// A set of utility algorithms for manipulating graphs.

#include <algorithm>
#include <optional>
#include <unordered_set>

#include "crab_utils/adapt_sgraph.hpp"
#include "crab_utils/heap.hpp"
#include "crab_utils/lazy_allocator.hpp"
#include "crab_utils/num_safety.hpp"

namespace prevail {
// Graph views - for when we want to traverse some mutation
// of the graph without actually constructing it.
// ============

// Processing a graph under a (possibly incomplete) permutation of vertices.
// We assume perm[x] is unique; otherwise, we'd have to introduce edges for induced equivalence classes.
template <class G>
class GraphPerm {
  public:
    using vert_id = typename G::vert_id;
    constexpr static vert_id invalid_vert = std::numeric_limits<vert_id>::max();
    using Weight = typename G::Weight;
    using mut_val_ref_t = typename G::mut_val_ref_t;

    GraphPerm(const std::vector<vert_id>& _perm, G& _g) : g{_g}, perm{_perm}, inv(_g.size(), invalid_vert) {
        for (unsigned int vi = 0; vi < perm.size(); vi++) {
            if (perm[vi] == invalid_vert) {
                continue;
            }
            assert(inv[perm[vi]] == invalid_vert);
            inv[perm[vi]] = vi;
        }
    }

    // Check whether an edge is live
    bool elem(vert_id x, vert_id y) const {
        if (perm[x] > g.size() || perm[y] > g.size()) {
            return false;
        }
        return g.elem(perm[x], perm[y]);
    }

    bool lookup(vert_id x, vert_id y, mut_val_ref_t* w) {
        if (perm[x] > g.size() || perm[y] > g.size()) {
            return false;
        }
        return g.lookup(perm[x], perm[y], w);
    }

    std::optional<Weight> lookup(vert_id x, vert_id y) const {
        if (perm[x] > g.size() || perm[y] > g.size()) {
            return {};
        }
        return g.lookup(perm[x], perm[y]);
    }

    // Precondition: elem(x, y) is true.
    Weight edge_val(vert_id x, vert_id y) const {
        //      assert(perm[x] < g.size() && perm[y] < g.size());
        return g.edge_val(perm[x], perm[y]);
    }

    // Precondition: elem(x, y) is true.
    Weight operator()(vert_id x, vert_id y) const {
        //      assert(perm[x] < g.size() && perm[y] < g.size());
        return g(perm[x], perm[y]);
    }

    // Number of allocated vertices
    [[nodiscard]]
    size_t size() const {
        return perm.size();
    }

    class vert_const_range final {
      public:
        class iterator final {
          public:
            explicit iterator(const vert_id _v) : v{_v} {}
            vert_id operator*() const { return v; }
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
            vert_id v;
        };
        explicit vert_const_range(const vert_id _after) : after{_after} {}

        iterator begin() const { return iterator{0}; }
        iterator end() const { return iterator{after}; }

      private:
        vert_id after;
    };
    using vert_const_iterator = typename vert_const_range::iterator;

    vert_const_range verts() const { return vert_const_range(gsl::narrow<vert_id>(perm.size())); }

    // GKG: Should probably modify this to handle cases where
    // the vertex iterator isn't just a vert_id*.
    template <class ItG>
    class adj_const_iterator final {
      public:
        adj_const_iterator(const std::vector<vert_id>& _inv, const ItG& _v) : inv(_inv), v(_v) {}

        vert_id operator*() const { return inv[*v]; }

        adj_const_iterator& operator++() {
            ++v;
            return *this;
        }

        bool operator!=(const adj_const_iterator& other) {
            while (v != other.v && inv[*v] == invalid_vert) {
                ++v;
            }
            return v != other.v;
        }

      private:
        const std::vector<vert_id>& inv;
        ItG v;
    };

    template <class ItG>
    class e_adj_const_iterator final {
      public:
        using edge_ref = typename ItG::edge_ref;

        e_adj_const_iterator(const std::vector<vert_id>& _inv, const ItG& _v) : inv(_inv), v(_v) {}

        edge_ref operator*() const { return edge_ref{inv[(*v).vert], (*v).val}; }

        e_adj_const_iterator& operator++() {
            ++v;
            return *this;
        }

        bool operator!=(const e_adj_const_iterator& other) {
            while (v != other.v && inv[(*v).vert] == invalid_vert) {
                ++v;
            }
            return v != other.v;
        }

      private:
        const std::vector<vert_id>& inv;
        ItG v;
    };

    template <class RG, class It>
    class adj_list final {
      public:
        using ItG = typename RG::iterator;

        using iterator = It;

        adj_list(const std::vector<vert_id>& _perm, const std::vector<vert_id>& _inv, const RG& _adj)
            : perm(_perm), inv(_inv), adj(_adj) {}

        adj_list(const std::vector<vert_id>& _perm, const std::vector<vert_id>& _inv) : perm(_perm), inv(_inv), adj() {}

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
        bool mem(unsigned int v) const {
            if (!adj || perm[v] == invalid_vert) {
                return false;
            }
            return (*adj).mem(perm[v]);
        }

      private:
        const std::vector<vert_id>& perm;
        const std::vector<vert_id>& inv;
        std::optional<RG> adj;
    };

    template <class RG, class It>
    class const_adj_list final {
      public:
        using ItG = typename RG::iterator;

        using iterator = It;

        const_adj_list(const std::vector<vert_id>& _perm, const std::vector<vert_id>& _inv, const RG& _adj)
            : perm(_perm), inv(_inv), adj(_adj) {}

        const_adj_list(const std::vector<vert_id>& _perm, const std::vector<vert_id>& _inv)
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
        bool mem(unsigned int v) const {
            if (!adj || perm[v] == invalid_vert) {
                return false;
            }
            return (*adj).mem(perm[v]);
        }

      private:
        const std::vector<vert_id>& perm;
        const std::vector<vert_id>& inv;
        std::optional<RG> adj;
    };

    using neighbour_const_range = const_adj_list<typename G::neighbour_const_range,
                                                 adj_const_iterator<typename G::neighbour_const_range::iterator>>;
    using e_neighbour_const_range = const_adj_list<typename G::e_neighbour_const_range,
                                                   e_adj_const_iterator<typename G::e_neighbour_const_range::iterator>>;

    neighbour_const_range succs(vert_id v) const {
        if (perm[v] == invalid_vert) {
            return neighbour_const_range(perm, inv);
        }
        return neighbour_const_range(perm, inv, g.succs(perm[v]));
    }
    neighbour_const_range preds(vert_id v) const {
        if (perm[v] == invalid_vert) {
            return neighbour_const_range(perm, inv);
        }
        return neighbour_const_range(perm, inv, g.preds(perm[v]));
    }

    e_neighbour_const_range e_succs(vert_id v) const {
        if (perm[v] == invalid_vert) {
            return e_neighbour_const_range(perm, inv);
        }
        return e_neighbour_const_range(perm, inv, g.e_succs(perm[v]));
    }
    e_neighbour_const_range e_preds(vert_id v) const {
        if (perm[v] == invalid_vert) {
            return e_neighbour_const_range(perm, inv);
        }
        return e_neighbour_const_range(perm, inv, g.e_preds(perm[v]));
    }

    const G& g;
    std::vector<vert_id> perm;
    std::vector<vert_id> inv;
};

// View of a graph, omitting a given vertex
template <class G>
class SubGraph {
  public:
    using vert_id = typename G::vert_id;
    using Weight = typename G::Weight;

    using g_neighbour_const_range = typename G::neighbour_const_range;
    using g_e_neighbour_const_range = typename G::e_neighbour_const_range;

    using mut_val_ref_t = typename G::mut_val_ref_t;

    SubGraph(G& _g, vert_id _v_ex) : g(_g), v_ex(_v_ex) {}

    bool elem(vert_id x, vert_id y) const { return x != v_ex && y != v_ex && g.elem(x, y); }

    bool lookup(vert_id x, vert_id y, mut_val_ref_t* w) { return x != v_ex && y != v_ex && g.lookup(x, y, w); }

    std::optional<Weight> lookup(vert_id x, vert_id y) const {
        return (x != v_ex && y != v_ex) ? g.lookup(x, y) : std::optional<Weight>{};
    }

    Weight edge_val(vert_id x, vert_id y) const { return g.edge_val(x, y); }

    // Precondition: elem(x, y) is true.
    Weight operator()(vert_id x, vert_id y) const { return g(x, y); }

    void clear_edges() { g.clear_edges(); }

    // Number of allocated vertices
    [[nodiscard]]
    size_t size() const {
        return g.size();
    }

    // Assumption: (x, y) not in mtx
    void add_edge(vert_id x, Weight wt, vert_id y) {
        //      assert(x != v_ex && y != v_ex);
        g.add_edge(x, wt, y);
    }

    void set_edge(vert_id s, Weight w, vert_id d) {
        //      assert(s != v_ex && d != v_ex);
        g.set_edge(s, w, d);
    }

    template <class Op>
    void update_edge(vert_id s, Weight w, vert_id d, Op& op) {
        //      assert(s != v_ex && d != v_ex);
        g.update_edge(s, w, d, op);
    }

    class vert_const_iterator {
      public:
        vert_const_iterator(const typename G::vert_const_iterator& _iG, vert_id _v_ex) : v_ex(_v_ex), iG(_iG) {}

        // Skipping of v_ex is done entirely by !=.
        // So we _MUST_ test it != verts.end() before dereferencing.
        vert_id operator*() { return *iG; }
        vert_const_iterator operator++() {
            ++iG;
            return *this;
        }
        bool operator!=(const vert_const_iterator& o) {
            if (iG != o.iG && (*iG) == v_ex) {
                ++iG;
            }
            return iG != o.iG;
        }

        vert_id v_ex;
        typename G::vert_const_iterator iG;
    };
    class vert_const_range {
      public:
        vert_const_range(const typename G::vert_const_range& _rG, vert_id _v_ex) : rG(_rG), v_ex(_v_ex) {}

        vert_const_iterator begin() const { return vert_const_iterator(rG.begin(), v_ex); }
        vert_const_iterator end() const { return vert_const_iterator(rG.end(), v_ex); }

        typename G::vert_const_range rG;
        vert_id v_ex;
    };
    vert_const_range verts() const { return vert_const_range(g.verts(), v_ex); }

    template <class It>
    class adj_iterator {
      public:
        adj_iterator(const It& _iG, vert_id _v_ex) : iG(_iG), v_ex(_v_ex) {}
        vert_id operator*() const { return *iG; }
        adj_iterator& operator++() {
            ++iG;
            return *this;
        }
        bool operator!=(const adj_iterator& o) {
            if (iG != o.iG && (*iG) == v_ex) {
                ++iG;
            }
            return iG != o.iG;
        }

        It iG;
        vert_id v_ex;
    };

    template <class It>
    class e_adj_iterator {
      public:
        using edge_ref = typename It::edge_ref;

        e_adj_iterator(const It& _iG, vert_id _v_ex) : iG(_iG), v_ex(_v_ex) {}
        edge_ref operator*() const { return *iG; }
        e_adj_iterator& operator++() {
            ++iG;
            return *this;
        }
        bool operator!=(const e_adj_iterator& o) {
            if (iG != o.iG && (*iG).vert == v_ex) {
                ++iG;
            }
            return iG != o.iG;
        }

        It iG;
        vert_id v_ex;
    };

    template <class R, class It>
    class adj_list {
      public:
        using iterator = It;

        adj_list(const R& _rG, vert_id _v_ex) : rG(_rG), v_ex(_v_ex) {}
        iterator begin() const { return iterator(rG.begin(), v_ex); }
        iterator end() const { return iterator(rG.end(), v_ex); }

      private:
        R rG;
        vert_id v_ex;
    };
    using neighbour_const_range =
        adj_list<g_neighbour_const_range, adj_iterator<typename g_neighbour_const_range::iterator>>;
    using e_neighbour_const_range =
        adj_list<g_e_neighbour_const_range, e_adj_iterator<typename g_e_neighbour_const_range::iterator>>;

    neighbour_const_range succs(vert_id v) const {
        //      assert(v != v_ex);
        return neighbour_const_range(g.succs(v), v_ex);
    }
    neighbour_const_range preds(vert_id v) const {
        //      assert(v != v_ex);
        return neighbour_const_range(g.preds(v), v_ex);
    }
    e_neighbour_const_range e_succs(vert_id v) const { return e_neighbour_const_range(g.e_succs(v), v_ex); }
    e_neighbour_const_range e_preds(vert_id v) const { return e_neighbour_const_range(g.e_preds(v), v_ex); }

    G& g;
    vert_id v_ex;
};

// Viewing a graph with all edges reversed.
// Useful if we want to run single-dest shortest paths,
// for updating bounds and incremental closure.
template <class G>
class GraphRev {
  public:
    using vert_id = typename G::vert_id;
    using Weight = typename G::Weight;
    using mut_val_ref_t = typename G::mut_val_ref_t;

    explicit GraphRev(G& _g) : g(_g) {}

    // Check whether an edge is live
    bool elem(vert_id x, vert_id y) const { return g.elem(y, x); }

    bool lookup(vert_id x, vert_id y, mut_val_ref_t* w) { return g.lookup(y, x, w); }
    std::optional<Weight> lookup(vert_id x, vert_id y) const { return g.lookup(y, x); }

    // Precondition: elem(x, y) is true.
    Weight edge_val(vert_id x, vert_id y) const { return g.edge_val(y, x); }

    // Precondition: elem(x, y) is true.
    Weight operator()(vert_id x, vert_id y) const { return g(y, x); }

    // Number of allocated vertices
    [[nodiscard]]
    int size() const {
        return g.size();
    }

    using neighbour_const_range = typename G::neighbour_const_range;
    using e_neighbour_const_range = typename G::e_neighbour_const_range;

    typename G::vert_const_range verts() const { return g.verts(); }

    neighbour_const_range succs(vert_id v) const { return g.preds(v); }
    neighbour_const_range preds(vert_id v) const { return g.succs(v); }

    e_neighbour_const_range e_succs(vert_id v) const { return g.e_preds(v); }
    e_neighbour_const_range e_preds(vert_id v) const { return g.e_succs(v); }
    G& g;
};

// GKG - What's the best way to split this out?
class GraphOps {
  public:
    // The following code assumes vert_id is an integer.
    using graph_t = AdaptGraph;
    using Weight = typename graph_t::Weight;
    using vert_id = typename graph_t::vert_id;
    using WeightVector = std::vector<Weight>;

    using PotentialFunction = std::function<Weight(vert_id)>;
    using mut_val_ref_t = typename graph_t::mut_val_ref_t;

    using edge_vector = std::vector<std::tuple<vert_id, vert_id, Weight>>;

    //===========================================
    // Enums used to mark vertices/edges during algorithms
    //===========================================
    // Edge colour during chromatic Dijkstra
    enum CMarkT { E_NONE = 0, E_LEFT = 1, E_RIGHT = 2, E_BOTH = 3 };
    // Whether a vertex is 'stable' during widening
    enum SMarkT { V_UNSTABLE = 0, V_STABLE = 1 };
    // Whether a vertex is in the current SCC/queue for Bellman-Ford.
    enum QMarkT { BF_NONE = 0, BF_SCC = 1, BF_QUEUED = 2 };

  private:
    // Scratch space needed by the graph algorithms.
    // Should really switch to some kind of arena allocator, rather
    // than having all these static structures.
    static inline thread_local lazy_allocator<std::vector<char>> edge_marks;

    // Used for Bellman-Ford queueing
    static inline thread_local lazy_allocator<std::vector<vert_id>> dual_queue;
    static inline thread_local lazy_allocator<std::vector<int>> vert_marks;
    static inline thread_local size_t scratch_sz;

    // For locality, should combine dists & dist_ts.
    // Weight must have an empty constructor, but does _not_ need a top or infty element.
    // dist_ts tells us which distances are current, and ts_idx prevents wraparound problems,
    // in the unlikely circumstance that we have more than 2^sizeof(uint) iterations.
    static inline thread_local lazy_allocator<std::vector<Weight>> dists;
    static inline thread_local lazy_allocator<std::vector<Weight>> dists_alt;
    static inline thread_local lazy_allocator<std::vector<unsigned int>> dist_ts;
    static inline thread_local unsigned int ts;
    static inline thread_local unsigned int ts_idx;

  public:
    static void clear_thread_local_state() {
        dists.clear();
        dists_alt.clear();
        dist_ts.clear();
        edge_marks.clear();
        dual_queue.clear();
        vert_marks.clear();
        scratch_sz = 0;
        ts = 0;
        ts_idx = 0;
    }

  private:
    static void grow_scratch(const size_t sz) {
        if (sz <= scratch_sz) {
            return;
        }

        size_t new_sz = scratch_sz;
        if (new_sz == 0) {
            new_sz = 10; // TODO: Introduce enums for init_sz and growth_factor
        }
        while (new_sz < sz) {
            new_sz *= 2;
        }

        edge_marks->resize(new_sz * new_sz);
        dual_queue->resize(2 * new_sz);
        vert_marks->resize(new_sz);

        scratch_sz = new_sz;

        // Initialize new elements as necessary.
        while (dists->size() < scratch_sz) {
            dists->emplace_back();
            dists_alt->emplace_back();
            dist_ts->push_back(ts - 1);
        }
    }

  public:
    // Syntactic join.
    static graph_t join(auto& l, auto& r) {
        // For the join, potentials are preserved
        assert(l.size() == r.size());
        const size_t sz = l.size();

        graph_t g;
        g.growTo(sz);

        mut_val_ref_t wr;
        for (const vert_id s : l.verts()) {
            for (const auto e : l.e_succs(s)) {
                const vert_id d = e.vert;
                if (r.lookup(s, d, &wr)) {
                    g.add_edge(s, std::max(e.val, static_cast<Weight>(wr)), d);
                }
            }
        }
        return g;
    }

    // Syntactic meet
    static graph_t meet(const auto& l, const auto& r, bool& is_closed) {
        assert(l.size() == r.size());
        graph_t g(graph_t::copy(l));

        mut_val_ref_t wg;
        for (vert_id s : r.verts()) {
            for (const auto e : r.e_succs(s)) {
                if (!g.lookup(s, e.vert, &wg)) {
                    g.add_edge(s, e.val, e.vert);
                } else {
                    if (e.val < wg) {
                        wg = e.val;
                    }
                }
            }
        }
        is_closed = false;
        return g;
    }

    static graph_t widen(const auto& l, const auto& r, std::unordered_set<vert_id>& unstable) {
        assert(l.size() == r.size());
        const size_t sz = l.size();
        graph_t g;
        g.growTo(sz);
        for (const vert_id s : r.verts()) {
            for (const auto e : r.e_succs(s)) {
                const vert_id d = e.vert;
                if (auto wl = l.lookup(s, d)) {
                    if (e.val <= *wl) {
                        g.add_edge(s, *wl, d);
                    }
                }
            }

            // Check if this vertex is stable
            for (const vert_id d : l.succs(s)) {
                if (!g.elem(s, d)) {
                    unstable.insert(s);
                    break;
                }
            }
        }

        return g;
    }

  private:
    // Compute the strongly connected components.
    // Duped pretty much verbatim from Wikipedia.
    // Abuses 'dual_queue' to store indices.
    static void strong_connect(const auto& x, std::vector<vert_id>& stack, int& index, vert_id v,
                               std::vector<std::vector<vert_id>>& sccs) {
        vert_marks->at(v) = (index << 1) | 1;
        // assert(vert_marks->at(v)&1);
        dual_queue->at(v) = index;
        index++;

        stack.push_back(v);

        // Consider successors of v
        for (const vert_id w : x.succs(v)) {
            if (!vert_marks->at(w)) {
                strong_connect(x, stack, index, w, sccs);
                dual_queue->at(v) = std::min(dual_queue->at(v), dual_queue->at(w));
            } else if (vert_marks->at(w) & 1) {
                // W is on the stack
                dual_queue->at(v) = std::min(dual_queue->at(v), gsl::narrow<vert_id>(vert_marks->at(w) >> 1));
            }
        }

        // If v is a root node, pop the stack and generate an SCC
        if (dual_queue->at(v) == gsl::narrow<vert_id>(vert_marks->at(v) >> 1)) {
            sccs.emplace_back();
            std::vector<vert_id>& scc(sccs.back());
            vert_id w;
            do {
                w = stack.back();
                stack.pop_back();
                vert_marks->at(w) &= ~1;
                scc.push_back(w);
            } while (v != w);
        }
    }

    static void compute_sccs(const auto& x, std::vector<std::vector<vert_id>>& out_scc) {
        const size_t sz = x.size();
        grow_scratch(sz);

        for (vert_id v : x.verts()) {
            vert_marks->at(v) = 0;
        }
        for (vert_id v : x.verts()) {
            if (!vert_marks->at(v)) {
                std::vector<vert_id> stack;
                int index = 1;
                strong_connect(x, stack, index, v, out_scc);
            }
        }

        for (vert_id v : x.verts()) {
            vert_marks->at(v) = 0;
        }
    }

  public:
    // Run Bellman-Ford to compute a valid model of a set of difference constraints.
    // Returns false if there is some negative cycle.
    static bool select_potentials(const auto& g, WeightVector& potentials) {
        const size_t sz = g.size();
        assert(potentials.size() >= sz);
        grow_scratch(sz);

        std::vector<std::vector<vert_id>> sccs;
        compute_sccs(g, sccs);

        // Currently trusting the call-site to select reasonable initial values.
        if constexpr (false) {
            // Zero existing potentials.
            // Not strictly necessary, but means we're less likely to run into over/underflow.
            // Though this hurts our chances of early cutoff.
            for (vert_id v : g.verts()) {
                potentials[v] = 0;
            }
        }

        // Run Bellman-ford on each SCC.
        // Current implementation returns sccs in reverse topological order.
        for (const std::vector<vert_id>& scc : sccs) {

            auto qhead = dual_queue->begin();
            auto qtail = qhead;

            auto next_head = dual_queue->begin() + sz;
            auto next_tail = next_head;

            for (vert_id v : scc) {
                *qtail = v;
                vert_marks->at(v) = BF_SCC | BF_QUEUED;
                ++qtail;
            }

            for ([[maybe_unused]]
                 vert_id _ : scc) {
                while (qtail != qhead) {
                    vert_id s = *--qtail;
                    // If it _was_ on the queue, it must be in the SCC
                    vert_marks->at(s) = BF_SCC;

                    Weight s_pot = potentials[s];

                    for (const auto e : g.e_succs(s)) {
                        vert_id d = e.vert;
                        Weight sd_pot = s_pot + e.val;
                        if (sd_pot < potentials[d]) {
                            potentials[d] = sd_pot;
                            if (vert_marks->at(d) == BF_SCC) {
                                *next_tail = d;
                                vert_marks->at(d) = (BF_SCC | BF_QUEUED);
                                ++next_tail;
                            }
                        }
                    }
                }
                // Prepare for the next iteration
                std::swap(qhead, next_head);
                qtail = next_tail;
                next_tail = next_head;
                if (qhead == qtail) {
                    break;
                }
            }
            // Check if the SCC is feasible.
            while (qtail != qhead) {
                vert_id s = *--qtail;
                Weight s_pot = potentials[s];
                for (const auto e : g.e_succs(s)) {
                    vert_id d = e.vert;
                    if (s_pot + e.val < potentials[d]) {
                        // Cleanup vertex marks
                        for (vert_id v : g.verts()) {
                            vert_marks->at(v) = BF_NONE;
                        }
                        return false;
                    }
                }
            }
        }
        return true;
    }

    template <class G, class G1, class G2>
    static edge_vector close_after_meet(const G& g, const PotentialFunction& pots, const G1& l, const G2& r) {
        // We assume the syntactic meet has already been computed, and potentials have been initialized.
        // We just want to restore closure.
        assert(l.size() == r.size());
        const size_t sz = l.size();
        grow_scratch(sz);

        std::vector<std::vector<vert_id>> colour_succs(2 * sz);

        // Partition edges into r-only/rb/b-only.
        for (vert_id s : g.verts()) {
            for (const auto e : g.e_succs(s)) {
                unsigned char mark = 0;
                const vert_id d = e.vert;
                if (const auto w = l.lookup(s, d)) {
                    if (*w == e.val) {
                        mark |= E_LEFT;
                    }
                }
                if (const auto w = r.lookup(s, d)) {
                    if (*w == e.val) {
                        mark |= E_RIGHT;
                    }
                }
                // Add them to the appropriate coloured successor list
                // Could do it inline, but this'll do.
                assert(mark != 0);
                switch (mark) {
                case E_LEFT: colour_succs[2 * s].push_back(d); break;
                case E_RIGHT: colour_succs[2 * s + 1].push_back(d); break;
                default: break;
                }
                edge_marks->at(sz * s + d) = mark;
            }
        }

        // We can run the chromatic Dijkstra variant on each source.
        std::vector<std::tuple<vert_id, Weight>> adjs;
        edge_vector delta;
        for (vert_id v : g.verts()) {
            adjs.clear();
            chrome_dijkstra(g, pots, colour_succs, v, adjs);

            for (const auto& [d, w] : adjs) {
                delta.emplace_back(v, d, w);
            }
        }
        return delta;
    }

    static void apply_delta(graph_t& g, const edge_vector& delta) {
        for (const auto& [s, d, w] : delta) {
            //        assert(s != d);
            //        assert(s < g.size());
            //        assert(d < g.size());
            g.set_edge(s, w, d);
        }
    }

  private:
    static bool dists_compare(int x, int y) { return (*dists)[x] < (*dists)[y]; }

    // P is some vector-alike holding a valid system of potentials.
    // Don't need to clear/initialize
    template <class G>
    static void chrome_dijkstra(const G& g, const PotentialFunction& p, std::vector<std::vector<vert_id>>& colour_succs,
                                vert_id src, std::vector<std::tuple<vert_id, Weight>>& out) {
        const size_t sz = g.size();
        if (sz == 0) {
            return;
        }
        grow_scratch(sz);

        // Reset all vertices to infty.
        dist_ts->at(ts_idx) = ts++;
        ts_idx = (ts_idx + 1) % dists->size();

        dists->at(src) = Weight(0);
        dist_ts->at(src) = ts;

        Heap heap(dists_compare);

        for (const auto e : g.e_succs(src)) {
            const vert_id dest = e.vert;
            dists->at(dest) = p(src) + e.val - p(dest);
            dist_ts->at(dest) = ts;

            vert_marks->at(dest) = edge_marks->at(sz * src + dest);
            heap.insert(dest);
        }

        while (!heap.empty()) {
            const int es = heap.removeMin();
            const Weight es_cost = dists->at(es) + p(es); // If it's on the queue, distance is not infinite.
            {
                const Weight es_val = es_cost - p(src);
                const auto w = g.lookup(src, es);
                if (!w || *w > es_val) {
                    out.emplace_back(es, es_val);
                }
            }

            if (vert_marks->at(es) == (E_LEFT | E_RIGHT)) {
                continue;
            }

            // Pick the appropriate set of successors
            const std::vector<vert_id>& es_succs =
                (vert_marks->at(es) == E_LEFT) ? colour_succs[2 * es + 1] : colour_succs[2 * es];
            for (vert_id ed : es_succs) {
                const Weight v = es_cost + g.edge_val(es, ed) - p(ed);
                if (dist_ts->at(ed) != ts || v < dists->at(ed)) {
                    dists->at(ed) = v;
                    dist_ts->at(ed) = ts;
                    vert_marks->at(ed) = edge_marks->at(sz * es + ed);

                    if (heap.inHeap(ed)) {
                        heap.decrease(ed);
                    } else {
                        heap.insert(ed);
                    }
                } else if (v == dists->at(ed)) {
                    vert_marks->at(ed) |= edge_marks->at(sz * es + ed);
                }
            }
        }
    }

    // Run Dijkstra's algorithm, but similar to the chromatic algorithm, avoid expanding anything that _was_ stable.
    // GKG: Factor out common elements of this & the previous algorithm.
    template <class G, class S>
    static void dijkstra_recover(const G& g, const PotentialFunction& p, const S& is_stable, vert_id src,
                                 edge_vector& delta) {
        const size_t sz = g.size();
        if (sz == 0) {
            return;
        }
        if (is_stable[src]) {
            return;
        }

        grow_scratch(sz);

        // Reset all vertices to infty.
        dist_ts->at(ts_idx) = ts++;
        ts_idx = (ts_idx + 1) % dists->size();

        dists->at(src) = Weight(0);
        dist_ts->at(src) = ts;

        Heap heap(dists_compare);

        for (const auto e : g.e_succs(src)) {
            const vert_id dest = e.vert;
            dists->at(dest) = p(src) + e.val - p(dest);
            dist_ts->at(dest) = ts;

            vert_marks->at(dest) = V_UNSTABLE;
            heap.insert(dest);
        }

        while (!heap.empty()) {
            const int es = heap.removeMin();
            const Weight es_cost = dists->at(es) + p(es); // If it's on the queue, distance is not infinite.
            {
                Weight es_val = es_cost - p(src);
                auto w = g.lookup(src, es);
                if (!w || *w > es_val) {
                    delta.emplace_back(src, es, es_val);
                }
            }
            if (vert_marks->at(es) == V_STABLE) {
                continue;
            }

            const char es_mark = is_stable[es] ? V_STABLE : V_UNSTABLE;

            // Pick the appropriate set of successors
            for (const auto e : g.e_succs(es)) {
                const vert_id ed = e.vert;
                const Weight v = es_cost + e.val - p(ed);
                if (dist_ts->at(ed) != ts || v < dists->at(ed)) {
                    dists->at(ed) = v;
                    dist_ts->at(ed) = ts;
                    vert_marks->at(ed) = es_mark;

                    if (heap.inHeap(ed)) {
                        heap.decrease(ed);
                    } else {
                        heap.insert(ed);
                    }
                } else if (v == dists->at(ed)) {
                    vert_marks->at(ed) |= es_mark;
                }
            }
        }
    }

  public:
    template <class G>
    static bool repair_potential(const G& g, WeightVector& p, vert_id ii, vert_id jj) {
        // Ensure there's enough scratch space.
        const size_t sz = g.size();
        // assert(src < (int) sz && dest < (int) sz);
        grow_scratch(sz);

        for (vert_id vi : g.verts()) {
            dists->at(vi) = Weight(0);
            dists_alt->at(vi) = p[vi];
        }
        dists->at(jj) = p[ii] + g.edge_val(ii, jj) - p[jj];

        if (dists->at(jj) >= Weight(0)) {
            return true;
        }

        Heap heap(dists_compare);

        heap.insert(jj);

        while (!heap.empty()) {
            int es = heap.removeMin();

            dists_alt->at(es) = p[es] + dists->at(es);

            for (const auto e : g.e_succs(es)) {
                vert_id ed = e.vert;
                if (dists_alt->at(ed) == p[ed]) {
                    Weight gnext_ed = dists_alt->at(es) + e.val - dists_alt->at(ed);
                    if (gnext_ed < dists->at(ed)) {
                        dists->at(ed) = gnext_ed;
                        if (heap.inHeap(ed)) {
                            heap.decrease(ed);
                        } else {
                            heap.insert(ed);
                        }
                    }
                }
            }
        }
        if (dists->at(ii) < Weight(0)) {
            return false;
        }

        for (vert_id v : g.verts()) {
            p[v] = dists_alt->at(v);
        }

        return true;
    }

    template <class G, class V>
    static edge_vector close_after_widen(const G& g, const PotentialFunction& p, const V& is_stable) {
        const size_t sz = g.size();
        grow_scratch(sz);
        //      assert(orig.size() == sz);

        for (vert_id v : g.verts()) {
            // We're abusing edge_marks to store _vertex_ flags.
            // Should really just switch this to allocating types of a fixed-size buffer.
            edge_marks->at(v) = is_stable[v] ? V_STABLE : V_UNSTABLE;
        }
        edge_vector delta;
        for (vert_id v : g.verts()) {
            if (!edge_marks->at(v)) {
                dijkstra_recover(g, p, *edge_marks, v, delta);
            }
        }
        return delta;
    }

  private:
    // Compute the transitive closure of edges reachable from v, assuming
    // (1) the subgraph G \ {v} is closed, and
    // (2) P is a valid model of G.
    static void close_after_assign_fwd(const auto& g, const PotentialFunction& p, vert_id v,
                                       std::vector<std::tuple<vert_id, Weight>>& aux) {
        // Initialize the queue and distances.
        for (vert_id u : g.verts()) {
            vert_marks->at(u) = 0;
        }

        vert_marks->at(v) = BF_QUEUED;
        dists->at(v) = Weight(0);
        auto adj_head = dual_queue->begin();
        auto adj_tail = adj_head;
        for (const auto e : g.e_succs(v)) {
            vert_id d = e.vert;
            vert_marks->at(d) = BF_QUEUED;
            dists->at(d) = e.val;
            //        assert(p(v) + dists->at(d) - p(d) >= Weight(0));
            *adj_tail = d;
            ++adj_tail;
        }

        // Sort the immediate edges by increasing slack.
        std::sort(adj_head, adj_tail,
                  [&p](vert_id d1, vert_id d2) { return dists->at(d1) - p(d1) < dists->at(d2) - p(d2); });

        auto reach_tail = adj_tail;
        for (; adj_head < adj_tail; ++adj_head) {
            vert_id d = *adj_head;

            Weight d_wt = dists->at(d);
            for (const auto edge : g.e_succs(d)) {
                vert_id e = edge.vert;
                Weight e_wt = d_wt + edge.val;
                if (!vert_marks->at(e)) {
                    dists->at(e) = e_wt;
                    vert_marks->at(e) = BF_QUEUED;
                    *reach_tail = e;
                    ++reach_tail;
                } else {
                    dists->at(e) = std::min(e_wt, dists->at(e));
                }
            }
        }

        // Now collect the adjacencies, and clear vertex flags
        // FIXME: This collects _all_ edges from x, not just new ones.
        for (adj_head = dual_queue->begin(); adj_head < reach_tail; ++adj_head) {
            aux.emplace_back(*adj_head, dists->at(*adj_head));
            vert_marks->at(*adj_head) = 0;
        }
    }

  public:
    static void close_over_edge(graph_t& g, vert_id ii, vert_id jj) {
        assert(ii != 0 && jj != 0);
        SubGraph<graph_t> g_excl(g, 0);

        Weight c = g_excl.edge_val(ii, jj);

        std::vector<std::pair<vert_id, Weight>> src_dec;
        for (const auto edge : g_excl.e_preds(ii)) {
            vert_id se = edge.vert;
            Weight wt_sij = edge.val + c;

            assert(g_excl.succs(se).begin() != g_excl.succs(se).end());
            if (se != jj) {
                typename graph_t::mut_val_ref_t w;
                if (g_excl.lookup(se, jj, &w)) {
                    if (w.get() <= wt_sij) {
                        continue;
                    }
                    w = wt_sij;
                } else {
                    g_excl.add_edge(se, wt_sij, jj);
                }
                src_dec.emplace_back(se, edge.val);
            }
        }

        std::vector<std::pair<vert_id, Weight>> dest_dec;
        for (const auto edge : g_excl.e_succs(jj)) {
            vert_id de = edge.vert;
            Weight wt_ijd = edge.val + c;
            if (de != ii) {
                typename graph_t::mut_val_ref_t w;
                if (g_excl.lookup(ii, de, &w)) {
                    if (w.get() <= wt_ijd) {
                        continue;
                    }
                    w = wt_ijd;
                } else {
                    g_excl.add_edge(ii, wt_ijd, de);
                }
                dest_dec.emplace_back(de, edge.val);
            }
        }

        for (const auto& [se, p1] : src_dec) {
            Weight wt_sij = c + p1;
            for (const auto& [de, p2] : dest_dec) {
                Weight wt_sijd = wt_sij + p2;
                typename graph_t::mut_val_ref_t w;
                if (g.lookup(se, de, &w)) {
                    if (w.get() <= wt_sijd) {
                        continue;
                    }
                    w = wt_sijd;
                } else {
                    g.add_edge(se, wt_sijd, de);
                }
            }
        }

        // Closure is now updated.
    }

    static edge_vector close_after_assign(const auto& g, const PotentialFunction& p, vert_id v) {
        const size_t sz = g.size();
        grow_scratch(sz);
        edge_vector delta;
        {
            std::vector<std::tuple<vert_id, Weight>> aux;
            close_after_assign_fwd(g, p, v, aux);
            for (const auto& [vid, wt] : aux) {
                delta.emplace_back(v, vid, wt);
            }
        }
        {
            std::vector<std::tuple<vert_id, Weight>> aux;
            GraphRev g_rev{g};

            close_after_assign_fwd(g_rev, [&](vert_id v) { return -(p(v)); }, v, aux);
            for (const auto& [vid, wt] : aux) {
                delta.emplace_back(vid, v, wt);
            }
        }
        return delta;
    }
};

} // namespace prevail

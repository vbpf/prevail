// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

// Graph algorithms: closure, shortest paths, Bellman-Ford, SCC.
// All algorithms are free functions in namespace splitdbm.
// Functions that need temporary storage take a ScratchSpace& parameter.

#include <algorithm>
#include <unordered_set>

#include "crab/splitdbm/graph_views.hpp"
#include "crab/splitdbm/heap.hpp"

namespace splitdbm {

using PotentialFunction = std::function<Weight(VertId)>;
using EdgeVector = std::vector<std::tuple<VertId, VertId, Weight>>;

// Enums used to mark vertices/edges during algorithms.
// Edge colour during chromatic Dijkstra.
enum CMarkT { E_NONE = 0, E_LEFT = 1, E_RIGHT = 2, E_BOTH = 3 };
// Whether a vertex is 'stable' during widening.
enum SMarkT { V_UNSTABLE = 0, V_STABLE = 1 };
// Whether a vertex is in the current SCC/queue for Bellman-Ford.
enum QMarkT { BF_NONE = 0, BF_SCC = 1, BF_QUEUED = 2 };

inline auto make_heap(const std::vector<Weight>& dists) {
    return Heap{
        [&dists](const int x, const int y) -> bool { return dists[x] < dists[y]; }
    };
}

// Scratch space needed by graph algorithms. Lazily grows on demand.
// Intended to be wrapped in a single LazyAllocator<ScratchSpace> at the call site.
struct ScratchSpace {
    std::vector<char> edge_marks;
    std::vector<VertId> dual_queue;
    std::vector<int> vert_marks;
    size_t scratch_sz = 0;

    std::vector<Weight> dists;
    std::vector<Weight> dists_alt;
    std::vector<unsigned int> dist_ts;
    unsigned int ts = 0;
    unsigned int ts_idx = 0;

    void grow(const size_t sz) {
        if (sz <= scratch_sz) {
            return;
        }
        size_t new_sz = scratch_sz;
        if (new_sz == 0) {
            new_sz = 10;
        }
        while (new_sz < sz) {
            new_sz *= 2;
        }

        edge_marks.resize(new_sz * new_sz);
        dual_queue.resize(2 * new_sz);
        vert_marks.resize(new_sz);

        scratch_sz = new_sz;

        while (dists.size() < scratch_sz) {
            dists.emplace_back();
            dists_alt.emplace_back();
            dist_ts.push_back(ts - 1);
        }
    }
};

// ============================================================================
// Pure graph construction operations (no scratch needed)
// ============================================================================

// Syntactic join.
Graph graph_join(const ReadableGraph auto& l, const ReadableGraph auto& r) {
    assert(l.size() == r.size());
    const size_t sz = l.size();

    Graph g;
    g.growTo(sz);

    for (const VertId s : l.verts()) {
        for (const auto e : l.e_succs(s)) {
            const VertId d = e.vert;
            if (const auto pw = r.lookup(s, d)) {
                g.add_edge(s, std::max(e.val, *pw), d);
            }
        }
    }
    return g;
}

// Syntactic meet.
Graph graph_meet(const ReadableGraph auto& l, const ReadableGraph auto& r, bool& is_closed) {
    assert(l.size() == r.size());
    Graph g(Graph::copy(l));

    for (VertId s : r.verts()) {
        for (const auto e : r.e_succs(s)) {
            if (Weight* pw = g.lookup(s, e.vert)) {
                if (e.val < *pw) {
                    *pw = e.val;
                }
            } else {
                g.add_edge(s, e.val, e.vert);
            }
        }
    }
    is_closed = false;
    return g;
}

// Syntactic widening.
Graph graph_widen(const ReadableGraph auto& l, const ReadableGraph auto& r, std::unordered_set<VertId>& unstable) {
    assert(l.size() == r.size());
    const size_t sz = l.size();
    Graph g;
    g.growTo(sz);
    for (const VertId s : r.verts()) {
        for (const auto e : r.e_succs(s)) {
            const VertId d = e.vert;
            if (auto wl = l.lookup(s, d)) {
                if (e.val <= *wl) {
                    g.add_edge(s, *wl, d);
                }
            }
        }

        // Check if this vertex is stable
        for (const VertId d : l.succs(s)) {
            if (!g.elem(s, d)) {
                unstable.insert(s);
                break;
            }
        }
    }

    return g;
}

inline void apply_delta(Graph& g, const EdgeVector& delta) {
    for (const auto& [s, d, w] : delta) {
        g.set_edge(s, w, d);
    }
}

inline void close_over_edge(Graph& g, VertId ii, VertId jj) {
    assert(ii != 0 && jj != 0);
    SubGraph g_excl(g, 0);

    Weight c = g_excl.edge_val(ii, jj);

    std::vector<std::pair<VertId, Weight>> src_dec;
    for (const auto edge : g_excl.e_preds(ii)) {
        VertId se = edge.vert;
        Weight wt_sij = edge.val + c;

        assert(g_excl.succs(se).begin() != g_excl.succs(se).end());
        if (se != jj) {
            if (Weight* pw = g_excl.lookup(se, jj)) {
                if (*pw <= wt_sij) {
                    continue;
                }
                *pw = wt_sij;
            } else {
                g_excl.add_edge(se, wt_sij, jj);
            }
            src_dec.emplace_back(se, edge.val);
        }
    }

    std::vector<std::pair<VertId, Weight>> dest_dec;
    for (const auto edge : g_excl.e_succs(jj)) {
        VertId de = edge.vert;
        Weight wt_ijd = edge.val + c;
        if (de != ii) {
            if (Weight* pw = g_excl.lookup(ii, de)) {
                if (*pw <= wt_ijd) {
                    continue;
                }
                *pw = wt_ijd;
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
            if (Weight* pw = g.lookup(se, de)) {
                if (*pw <= wt_sijd) {
                    continue;
                }
                *pw = wt_sijd;
            } else {
                g.add_edge(se, wt_sijd, de);
            }
        }
    }
}

// ============================================================================
// Internal helpers (used by the public scratch-based algorithms below)
// ============================================================================
namespace detail {

// Compute the strongly connected components (Tarjan's algorithm).
void strong_connect(ScratchSpace& scratch, const ReadableGraph auto& x,
                           std::vector<VertId>& stack, int& index, VertId v,
                           std::vector<std::vector<VertId>>& sccs) {
    scratch.vert_marks.at(v) = (index << 1) | 1;
    scratch.dual_queue.at(v) = index;
    index++;

    stack.push_back(v);

    for (const VertId w : x.succs(v)) {
        if (!scratch.vert_marks.at(w)) {
            strong_connect(scratch, x, stack, index, w, sccs);
            scratch.dual_queue.at(v) = std::min(scratch.dual_queue.at(v), scratch.dual_queue.at(w));
        } else if (scratch.vert_marks.at(w) & 1) {
            scratch.dual_queue.at(v) = std::min(scratch.dual_queue.at(v), gsl::narrow<VertId>(scratch.vert_marks.at(w) >> 1));
        }
    }

    if (scratch.dual_queue.at(v) == gsl::narrow<VertId>(scratch.vert_marks.at(v) >> 1)) {
        sccs.emplace_back();
        std::vector<VertId>& scc(sccs.back());
        VertId w;
        do {
            w = stack.back();
            stack.pop_back();
            scratch.vert_marks.at(w) &= ~1;
            scc.push_back(w);
        } while (v != w);
    }
}

void compute_sccs(ScratchSpace& scratch, const ReadableGraph auto& x,
                          std::vector<std::vector<VertId>>& out_scc) {
    scratch.grow(x.size());

    for (const VertId v : x.verts()) {
        scratch.vert_marks.at(v) = 0;
    }
    for (VertId v : x.verts()) {
        if (!scratch.vert_marks.at(v)) {
            std::vector<VertId> stack;
            int index = 1;
            strong_connect(scratch, x, stack, index, v, out_scc);
        }
    }

    for (const VertId v : x.verts()) {
        scratch.vert_marks.at(v) = 0;
    }
}

// Chromatic Dijkstra for close_after_meet.
void chrome_dijkstra(ScratchSpace& scratch, const ReadableGraph auto& g, const PotentialFunction& p,
                            std::vector<std::vector<VertId>>& colour_succs,
                            VertId src, std::vector<std::tuple<VertId, Weight>>& out) {
    const size_t sz = g.size();
    if (sz == 0) {
        return;
    }
    scratch.grow(sz);

    // Reset all vertices to infty.
    scratch.dist_ts.at(scratch.ts_idx) = scratch.ts++;
    scratch.ts_idx = (scratch.ts_idx + 1) % scratch.dists.size();

    scratch.dists.at(src) = Weight(0);
    scratch.dist_ts.at(src) = scratch.ts;

    Heap heap = make_heap(scratch.dists);

    for (const auto e : g.e_succs(src)) {
        const VertId dest = e.vert;
        scratch.dists.at(dest) = p(src) + e.val - p(dest);
        scratch.dist_ts.at(dest) = scratch.ts;

        scratch.vert_marks.at(dest) = scratch.edge_marks.at(sz * src + dest);
        heap.insert(dest);
    }

    while (!heap.empty()) {
        const int es = heap.removeMin();
        const Weight es_cost = scratch.dists.at(es) + p(es);
        {
            const Weight es_val = es_cost - p(src);
            const auto w = g.lookup(src, es);
            if (!w || *w > es_val) {
                out.emplace_back(es, es_val);
            }
        }

        if (scratch.vert_marks.at(es) == (E_LEFT | E_RIGHT)) {
            continue;
        }

        const std::vector<VertId>& es_succs =
            (scratch.vert_marks.at(es) == E_LEFT) ? colour_succs[2 * es + 1] : colour_succs[2 * es];
        for (VertId ed : es_succs) {
            const Weight v = es_cost + g.edge_val(es, ed) - p(ed);
            if (scratch.dist_ts.at(ed) != scratch.ts || v < scratch.dists.at(ed)) {
                scratch.dists.at(ed) = v;
                scratch.dist_ts.at(ed) = scratch.ts;
                scratch.vert_marks.at(ed) = scratch.edge_marks.at(sz * es + ed);

                if (heap.inHeap(ed)) {
                    heap.decrease(ed);
                } else {
                    heap.insert(ed);
                }
            } else if (v == scratch.dists.at(ed)) {
                scratch.vert_marks.at(ed) |= scratch.edge_marks.at(sz * es + ed);
            }
        }
    }
}

// Dijkstra recovery for close_after_widen.
void dijkstra_recover(ScratchSpace& scratch, const ReadableGraph auto& g, const PotentialFunction& p,
                             const auto& is_stable, VertId src, EdgeVector& delta) {
    const size_t sz = g.size();
    if (sz == 0) {
        return;
    }
    if (is_stable[src]) {
        return;
    }

    scratch.grow(sz);

    scratch.dist_ts.at(scratch.ts_idx) = scratch.ts++;
    scratch.ts_idx = (scratch.ts_idx + 1) % scratch.dists.size();

    scratch.dists.at(src) = Weight(0);
    scratch.dist_ts.at(src) = scratch.ts;

    Heap heap = make_heap(scratch.dists);

    for (const auto e : g.e_succs(src)) {
        const VertId dest = e.vert;
        scratch.dists.at(dest) = p(src) + e.val - p(dest);
        scratch.dist_ts.at(dest) = scratch.ts;

        scratch.vert_marks.at(dest) = V_UNSTABLE;
        heap.insert(dest);
    }

    while (!heap.empty()) {
        const int es = heap.removeMin();
        const Weight es_cost = scratch.dists.at(es) + p(es);
        {
            Weight es_val = es_cost - p(src);
            auto w = g.lookup(src, es);
            if (!w || *w > es_val) {
                delta.emplace_back(src, es, es_val);
            }
        }
        if (scratch.vert_marks.at(es) == V_STABLE) {
            continue;
        }

        const char es_mark = is_stable[es] ? V_STABLE : V_UNSTABLE;

        for (const auto e : g.e_succs(es)) {
            const VertId ed = e.vert;
            const Weight v = es_cost + e.val - p(ed);
            if (scratch.dist_ts.at(ed) != scratch.ts || v < scratch.dists.at(ed)) {
                scratch.dists.at(ed) = v;
                scratch.dist_ts.at(ed) = scratch.ts;
                scratch.vert_marks.at(ed) = es_mark;

                if (heap.inHeap(ed)) {
                    heap.decrease(ed);
                } else {
                    heap.insert(ed);
                }
            } else if (v == scratch.dists.at(ed)) {
                scratch.vert_marks.at(ed) |= es_mark;
            }
        }
    }
}

// Forward closure for close_after_assign.
// Assumes scratch has already been grown to g.size().
void close_after_assign_fwd(ScratchSpace& scratch, const ReadableGraph auto& g, const PotentialFunction& p,
                                   VertId v, std::vector<std::tuple<VertId, Weight>>& aux) {
    for (const VertId u : g.verts()) {
        scratch.vert_marks.at(u) = 0;
    }

    scratch.vert_marks.at(v) = BF_QUEUED;
    scratch.dists.at(v) = Weight(0);
    auto adj_head = scratch.dual_queue.begin();
    auto adj_tail = adj_head;
    for (const auto e : g.e_succs(v)) {
        const VertId d = e.vert;
        scratch.vert_marks.at(d) = BF_QUEUED;
        scratch.dists.at(d) = e.val;
        *adj_tail = d;
        ++adj_tail;
    }

    // Sort the immediate edges by increasing slack.
    std::sort(adj_head, adj_tail,
              [&scratch, &p](const VertId d1, const VertId d2) { return scratch.dists[d1] - p(d1) < scratch.dists[d2] - p(d2); });

    auto reach_tail = adj_tail;
    for (; adj_head < adj_tail; ++adj_head) {
        VertId d = *adj_head;

        Weight d_wt = scratch.dists.at(d);
        for (const auto edge : g.e_succs(d)) {
            const VertId e = edge.vert;
            Weight e_wt = d_wt + edge.val;
            if (!scratch.vert_marks.at(e)) {
                scratch.dists.at(e) = e_wt;
                scratch.vert_marks.at(e) = BF_QUEUED;
                *reach_tail = e;
                ++reach_tail;
            } else {
                scratch.dists.at(e) = std::min(e_wt, scratch.dists.at(e));
            }
        }
    }

    // Collect the adjacencies and clear vertex flags.
    // FIXME: This collects _all_ edges from x, not just new ones.
    for (adj_head = scratch.dual_queue.begin(); adj_head < reach_tail; ++adj_head) {
        aux.emplace_back(*adj_head, scratch.dists.at(*adj_head));
        scratch.vert_marks.at(*adj_head) = 0;
    }
}

} // namespace detail

// ============================================================================
// Public algorithms requiring scratch space
// ============================================================================

// Run Bellman-Ford to compute a valid model of a set of difference constraints.
// Returns false if there is some negative cycle.
bool select_potentials(ScratchSpace& scratch, const ReadableGraph auto& g, std::vector<Weight>& potentials) {
    const size_t sz = g.size();
    assert(potentials.size() >= sz);
    scratch.grow(sz);

    std::vector<std::vector<VertId>> sccs;
    detail::compute_sccs(scratch, g, sccs);

    // Currently trusting the call-site to select reasonable initial values.
    if constexpr (false) {
        for (VertId v : g.verts()) {
            potentials[v] = 0;
        }
    }

    // Run Bellman-Ford on each SCC.
    for (const std::vector<VertId>& scc : sccs) {

        auto qhead = scratch.dual_queue.begin();
        auto qtail = qhead;

        auto next_head = scratch.dual_queue.begin() + sz;
        auto next_tail = next_head;

        for (const VertId v : scc) {
            *qtail = v;
            scratch.vert_marks.at(v) = BF_SCC | BF_QUEUED;
            ++qtail;
        }

        for ([[maybe_unused]]
             VertId _ : scc) {
            while (qtail != qhead) {
                VertId s = *--qtail;
                scratch.vert_marks.at(s) = BF_SCC;

                Weight s_pot = potentials[s];

                for (const auto e : g.e_succs(s)) {
                    const VertId d = e.vert;
                    Weight sd_pot = s_pot + e.val;
                    if (sd_pot < potentials[d]) {
                        potentials[d] = sd_pot;
                        if (scratch.vert_marks.at(d) == BF_SCC) {
                            *next_tail = d;
                            scratch.vert_marks.at(d) = (BF_SCC | BF_QUEUED);
                            ++next_tail;
                        }
                    }
                }
            }
            std::swap(qhead, next_head);
            qtail = next_tail;
            next_tail = next_head;
            if (qhead == qtail) {
                break;
            }
        }
        // Check if the SCC is feasible.
        while (qtail != qhead) {
            VertId s = *--qtail;
            Weight s_pot = potentials[s];
            for (const auto e : g.e_succs(s)) {
                const VertId d = e.vert;
                if (s_pot + e.val < potentials[d]) {
                    for (const VertId v : g.verts()) {
                        scratch.vert_marks.at(v) = BF_NONE;
                    }
                    return false;
                }
            }
        }
    }
    return true;
}

EdgeVector close_after_meet(ScratchSpace& scratch, const ReadableGraph auto& g, const PotentialFunction& pots,
                                   const ReadableGraph auto& l, const ReadableGraph auto& r) {
    assert(l.size() == r.size());
    const size_t sz = l.size();
    scratch.grow(sz);

    std::vector<std::vector<VertId>> colour_succs(2 * sz);

    for (VertId s : g.verts()) {
        for (const auto e : g.e_succs(s)) {
            unsigned char mark = 0;
            const VertId d = e.vert;
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
            assert(mark != 0);
            switch (mark) {
            case E_LEFT: colour_succs[2 * s].push_back(d); break;
            case E_RIGHT: colour_succs[2 * s + 1].push_back(d); break;
            default: break;
            }
            scratch.edge_marks.at(sz * s + d) = mark;
        }
    }

    std::vector<std::tuple<VertId, Weight>> adjs;
    EdgeVector delta;
    for (VertId v : g.verts()) {
        adjs.clear();
        detail::chrome_dijkstra(scratch, g, pots, colour_succs, v, adjs);

        for (const auto& [d, w] : adjs) {
            delta.emplace_back(v, d, w);
        }
    }
    return delta;
}

EdgeVector close_after_widen(ScratchSpace& scratch, const ReadableGraph auto& g, const PotentialFunction& p,
                                   const auto& is_stable) {
    const size_t sz = g.size();
    scratch.grow(sz);

    for (VertId v : g.verts()) {
        scratch.edge_marks.at(v) = is_stable[v] ? V_STABLE : V_UNSTABLE;
    }
    EdgeVector delta;
    for (VertId v : g.verts()) {
        if (!scratch.edge_marks.at(v)) {
            detail::dijkstra_recover(scratch, g, p, scratch.edge_marks, v, delta);
        }
    }
    return delta;
}

EdgeVector close_after_assign(ScratchSpace& scratch, const ReadableGraph auto& g,
                                     const PotentialFunction& p, VertId v) {
    scratch.grow(g.size());
    EdgeVector delta;
    {
        std::vector<std::tuple<VertId, Weight>> aux;
        detail::close_after_assign_fwd(scratch, g, p, v, aux);
        for (const auto& [vid, wt] : aux) {
            delta.emplace_back(v, vid, wt);
        }
    }
    {
        std::vector<std::tuple<VertId, Weight>> aux;
        GraphRev g_rev{g};

        detail::close_after_assign_fwd(scratch, g_rev, [&p](const VertId u) { return -(p(u)); }, v, aux);
        for (const auto& [vid, wt] : aux) {
            delta.emplace_back(vid, v, wt);
        }
    }
    return delta;
}

bool repair_potential(ScratchSpace& scratch, const ReadableGraph auto& g, std::vector<Weight>& p,
                             VertId ii, VertId jj) {
    const size_t sz = g.size();
    scratch.grow(sz);

    for (const VertId vi : g.verts()) {
        scratch.dists[vi] = Weight(0);
        scratch.dists_alt[vi] = p[vi];
    }
    scratch.dists[jj] = p[ii] + g.edge_val(ii, jj) - p[jj];

    if (scratch.dists[jj] >= Weight(0)) {
        return true;
    }

    Heap heap = make_heap(scratch.dists);

    heap.insert(jj);

    while (!heap.empty()) {
        int es = heap.removeMin();

        scratch.dists_alt[es] = p[es] + scratch.dists[es];

        for (const auto e : g.e_succs(es)) {
            const VertId ed = e.vert;
            if (scratch.dists_alt[ed] == p[ed]) {
                Weight gnext_ed = scratch.dists_alt[es] + e.val - scratch.dists_alt[ed];
                if (gnext_ed < scratch.dists[ed]) {
                    scratch.dists[ed] = gnext_ed;
                    if (heap.inHeap(ed)) {
                        heap.decrease(ed);
                    } else {
                        heap.insert(ed);
                    }
                }
            }
        }
    }
    if (scratch.dists[ii] < Weight(0)) {
        return false;
    }

    for (const VertId v : g.verts()) {
        p[v] = scratch.dists_alt[v];
    }

    return true;
}

} // namespace splitdbm

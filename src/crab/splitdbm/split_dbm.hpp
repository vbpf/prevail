// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <optional>
#include <vector>

#include "arith/num_extended.hpp"
#include "crab/splitdbm/definitions.hpp"
#include "crab/splitdbm/adapt_sgraph.hpp"
#include "crab/splitdbm/graph_ops.hpp"
#include "crab_utils/lazy_allocator.hpp"

namespace splitdbm {

// =============================================================================
// Side enum: Indicates edge direction relative to vertex 0
// =============================================================================
// In a DBM graph, each vertex v has TWO bounds via edge direction:
// - Edge v → 0 (LEFT side): weight w means v >= -w (lower bound)
// - Edge 0 → v (RIGHT side): weight w means v <= w (upper bound)

enum class Side : bool {
    LEFT = false,  // Edge v → 0: lower bound = -weight
    RIGHT = true   // Edge 0 → v: upper bound = weight
};

// Forward declaration for SplitDBM's static methods
struct AlignedPair;

// =============================================================================
// SplitDBM: The Split Difference Bound Matrix implementation.
// =============================================================================
// Maintains a sparse weighted graph with a potential function for efficient
// constraint propagation. Operates on vertices and sides (edge directions
// relative to vertex 0). Has no concept of Variable — only VertId and Side.

class SplitDBM {
    Graph g_;
    std::vector<Weight> potential_;
    VertSet unstable_;

    static inline thread_local prevail::LazyAllocator<ScratchSpace> scratch_;

    static PotentialFunction pot_func(const std::vector<Weight>& p);

    void apply_delta(const EdgeVector& delta);
    void close_after_assign_vertex(VertId v);

  public:
    SplitDBM();

    SplitDBM(Graph&& g, std::vector<Weight>&& pot, VertSet&& unstable);

    SplitDBM(const SplitDBM&) = default;
    SplitDBM(SplitDBM&&) = default;
    SplitDBM& operator=(const SplitDBM&) = default;
    SplitDBM& operator=(SplitDBM&&) = default;

    [[nodiscard]] bool is_top() const;

    // ==========================================================================
    // Core one-sided bound operations - the primitive API
    // ==========================================================================

    // Get the bound value for vertex v on the given side.
    // LEFT (v→0): returns lower bound (-edge_weight), or MINUS_INFINITY if no edge
    // RIGHT (0→v): returns upper bound (edge_weight), or PLUS_INFINITY if no edge
    [[nodiscard]] prevail::ExtendedNumber get_bound(VertId v, Side side) const;

    // Set the bound value for vertex v on the given side.
    // LEFT: sets edge v→0 with weight = -bound_value
    // RIGHT: sets edge 0→v with weight = bound_value
    void set_bound(VertId v, Side side, const Weight& bound_value);

    // ==========================================================================
    // Vertex management
    // ==========================================================================

    VertId new_vertex();
    void forget(VertId v);

    // ==========================================================================
    // Graph access for SplitDBM's read-only operations (e.g. to_set)
    // ==========================================================================

    [[nodiscard]] const Graph& graph() const;

    // Restore potential after an edge addition
    bool repair_potential(VertId src, VertId dest);

    // ==========================================================================
    // High-level constraint operations
    // ==========================================================================

    // Update bound only if new value is tighter. Returns false if infeasible.
    bool update_bound_if_tighter(VertId v, Side side, const Weight& new_bound);

    // Add a difference constraint: dest - src <= k
    bool add_difference_constraint(VertId src, VertId dest, const Weight& k);

    // Apply final closure after bound updates
    void close_after_bound_updates();

    // Assign a fresh vertex with difference constraints and optional bounds.
    // Returns the new VertId. The caller manages Variable↔VertId mapping.
    // diffs_from: edges new_vert → dest with given weight
    // diffs_to: edges src → new_vert with given weight
    // lb_edge/ub_edge are raw edge weights (lb_edge = -lower_bound, ub_edge = upper_bound).
    VertId assign_vertex(const Weight& potential_value,
                         std::span<const std::pair<VertId, Weight>> diffs_from,
                         std::span<const std::pair<VertId, Weight>> diffs_to, const std::optional<Weight>& lb_edge,
                         const std::optional<Weight>& ub_edge);

    // Get potential at a specific vertex
    [[nodiscard]] Weight potential_at(VertId v) const;

    // Get potential at vertex 0 (for computing relative potentials)
    [[nodiscard]] Weight potential_at_zero() const;

    // ==========================================================================
    // Size and edge accessors
    // ==========================================================================

    [[nodiscard]] std::size_t graph_size() const;
    [[nodiscard]] std::size_t num_edges() const;

    // Check if a vertex has any edges
    [[nodiscard]] bool vertex_has_edges(VertId v) const;

    // Get all vertices with no edges (excluding vertex 0) for garbage collection
    [[nodiscard]] std::vector<VertId> get_disconnected_vertices() const;

    // Strengthen a bound and propagate to neighboring edges.
    // Like update_bound_if_tighter, takes a bound value (not raw edge weight).
    // Difference: also propagates tighter bound transitively to neighbor bounds.
    bool strengthen_bound(VertId v, Side side, const Weight& bound_value);

    // WARNING: Known bug — eager normalization defeats widening convergence.
    // normalize() runs close_after_widen + close_after_assign and clears unstable_.
    // In the original CRAB, normalization was lazy — triggered only at query points
    // (operator<=, get_interval), not after every mutation. Widened results stayed
    // non-normalized until needed.
    //
    // A proper fix requires lazy normalization (e.g., mutable on SplitDBM internals
    // or a normalized_ flag checked by const methods). This is non-trivial.
    void normalize();

    // Clear the thread-local scratch space used by graph algorithms.
    static void clear_thread_local_state();

    // =========================================================================
    // Static lattice operations on permuted vertices
    // =========================================================================

    static SplitDBM join(const AlignedPair& aligned);
    static SplitDBM widen(const AlignedPair& aligned);
    static std::optional<SplitDBM> meet(AlignedPair& aligned);
    static bool is_subsumed_by(const SplitDBM& left, const SplitDBM& right, const std::vector<VertId>& perm);
};

// =============================================================================
// AlignedPair: Two SplitDBMs viewed in a common vertex space
// =============================================================================
// When performing binary operations (join, widen, meet), we need to align
// two SplitDBMs so that same-named variables occupy the same vertex index.

struct AlignedPair {
    [[nodiscard]] size_t size() const { return left_perm.size(); }

    const SplitDBM& left;
    const SplitDBM& right;
    std::vector<VertId> left_perm;
    std::vector<VertId> right_perm;
    std::vector<Weight> initial_potentials;
};

} // namespace splitdbm

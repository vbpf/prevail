// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <optional>
#include <vector>

#include "arith/num_extended.hpp"
#include "crab/splitdbm/definitions.hpp"
#include "crab/splitdbm/adapt_sgraph.hpp"
#include "crab/splitdbm/graph_ops.hpp"

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

// Forward declaration for CoreDBM's static methods
struct AlignedPair;

// =============================================================================
// CoreDBM: Low-level DBM operations using (VertId, Side)
// =============================================================================
// This class owns the graph and provides one-sided operations.
// It has NO concept of Variable - only vertices and sides.

class CoreDBM {
    Graph g_;
    std::vector<Weight> potential_;
    VertSet unstable_;

    static GraphOps::PotentialFunction pot_func(const std::vector<Weight>& p);

  public:
    CoreDBM();

    CoreDBM(Graph&& g, std::vector<Weight>&& pot, VertSet&& unstable);

    CoreDBM(const CoreDBM&) = default;
    CoreDBM(CoreDBM&&) = default;
    CoreDBM& operator=(const CoreDBM&) = default;
    CoreDBM& operator=(CoreDBM&&) = default;

    void set_to_top();

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

    // Apply edges from a delta vector
    void apply_delta(const GraphOps::EdgeVector& delta);

    // Close after assignment to a specific vertex (excludes vertex 0 from subgraph)
    void close_after_assign_vertex(VertId v);

    // Set potential for a vertex
    void set_potential(VertId v, const Weight& val);

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

    // Unconditional edge update
    void update_edge(VertId src, const Weight& w, VertId dest);

    // Strengthen a bound and propagate to neighbors.
    bool strengthen_bound_with_propagation(VertId v, Side side, const Weight& new_bound);

    void normalize();

    // =========================================================================
    // Static lattice operations on permuted vertices
    // =========================================================================

    static CoreDBM join(const AlignedPair& aligned);
    static CoreDBM widen(const AlignedPair& aligned);
    static std::optional<CoreDBM> meet(AlignedPair& aligned);
    static bool is_subsumed_by(const CoreDBM& left, const CoreDBM& right, const std::vector<VertId>& perm);
};

// =============================================================================
// AlignedPair: Two CoreDBMs viewed in a common vertex space
// =============================================================================
// When performing binary operations (join, widen, meet), we need to align
// two CoreDBMs so that same-named variables occupy the same vertex index.

struct AlignedPair {
    [[nodiscard]] size_t size() const { return left_perm.size(); }

    const CoreDBM& left;
    const CoreDBM& right;
    std::vector<VertId> left_perm;
    std::vector<VertId> right_perm;
    std::vector<Weight> initial_potentials;
};

} // namespace splitdbm

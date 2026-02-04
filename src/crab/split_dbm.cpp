// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include <cassert>
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
class AlignedPair;

// =============================================================================
// CoreDBM: Low-level DBM operations using (VertId, Side)
// =============================================================================
// This class owns the graph and provides one-sided operations.
// It has NO concept of Variable - only vertices and sides.
// SplitDBM maintains the Variable ↔ VertId mapping.

class SplitDBM::CoreDBM {
  public:
    using Graph = AdaptGraph;
    using Weight = Graph::Weight;
    using VertId = Graph::VertId;
    using VertSet = std::unordered_set<VertId>;

  private:
    Graph g_;
    std::vector<Weight> potential_;
    VertSet unstable_;

    static GraphOps::PotentialFunction pot_func(const std::vector<Weight>& p) {
        return [&p](VertId v) -> Weight { return p[v]; };
    }

  public:
    CoreDBM() {
        g_.growTo(1); // Allocate the zero vertex
        potential_.emplace_back(0);
    }

    CoreDBM(Graph&& g, std::vector<Weight>&& pot, VertSet&& unstable)
        : g_(std::move(g)), potential_(std::move(pot)), unstable_(std::move(unstable)) {
        normalize();
    }

    CoreDBM(const CoreDBM&) = default;
    CoreDBM(CoreDBM&&) = default;
    CoreDBM& operator=(const CoreDBM&) = default;
    CoreDBM& operator=(CoreDBM&&) = default;

    void set_to_top() {
        this->~CoreDBM();
        new (this) CoreDBM();
    }

    [[nodiscard]] bool is_top() const { return g_.is_empty(); }

    // ==========================================================================
    // Core one-sided bound operations - the primitive API
    // ==========================================================================

    // Get the bound value for vertex v on the given side.
    // LEFT (v→0): returns lower bound (-edge_weight), or MINUS_INFINITY if no edge
    // RIGHT (0→v): returns upper bound (edge_weight), or PLUS_INFINITY if no edge
    [[nodiscard]] Bound get_bound(VertId v, Side side) const {
        if (side == Side::LEFT) {
            return g_.elem(v, 0) ? -Number(g_.edge_val(v, 0)) : MINUS_INFINITY;
        } else {
            return g_.elem(0, v) ? Number(g_.edge_val(0, v)) : PLUS_INFINITY;
        }
    }

    // Set the bound value for vertex v on the given side.
    // LEFT: sets edge v→0 with weight = -bound_value
    // RIGHT: sets edge 0→v with weight = bound_value
    void set_bound(VertId v, Side side, Weight bound_value) {
        if (side == Side::LEFT) {
            g_.set_edge(v, -bound_value, 0);
        } else {
            g_.set_edge(0, bound_value, v);
        }
        potential_[v] = potential_[0] + bound_value;
    }

    // ==========================================================================
    // Vertex management
    // ==========================================================================

    VertId new_vertex() {
        VertId vert = g_.new_vertex();
        if (vert >= potential_.size()) {
            potential_.emplace_back(0);
        } else {
            potential_[vert] = Weight(0);
        }
        return vert;
    }

    void forget(VertId v) {
        g_.forget(v);
    }

    // ==========================================================================
    // Graph and potential access for SplitDBM's complex operations
    // ==========================================================================

    [[nodiscard]] const Graph& graph() const { return g_; }
    [[nodiscard]] Graph& graph() { return g_; }
    [[nodiscard]] const std::vector<Weight>& potential() const { return potential_; }
    [[nodiscard]] std::vector<Weight>& potential() { return potential_; }
    [[nodiscard]] const VertSet& unstable() const { return unstable_; }
    [[nodiscard]] VertSet& unstable() { return unstable_; }

    // Restore potential after an edge addition
    bool repair_potential(VertId src, VertId dest) {
        return GraphOps::repair_potential(g_, potential_, src, dest);
    }

    // ==========================================================================
    // High-level constraint operations
    // ==========================================================================

    // Update bound only if new value is tighter. Returns false if infeasible.
    // For LEFT (lower bound): new value is tighter if -new_bound < current edge weight
    // For RIGHT (upper bound): new value is tighter if new_bound < current edge weight
    bool update_bound_if_tighter(VertId v, Side side, Weight new_bound) {
        if (side == Side::LEFT) {
            // Lower bound: edge v → 0 with weight -bound
            // Tighter means smaller weight (more negative = higher lower bound)
            if (auto w = g_.lookup(v, 0)) {
                if (*w <= -new_bound) {
                    return true;  // Current is already tighter
                }
            }
            g_.set_edge(v, -new_bound, 0);
            return repair_potential(v, 0);
        } else {
            // Upper bound: edge 0 → v with weight bound
            // Tighter means smaller weight (smaller upper bound)
            if (auto w = g_.lookup(0, v)) {
                if (*w <= new_bound) {
                    return true;  // Current is already tighter
                }
            }
            g_.set_edge(0, new_bound, v);
            return repair_potential(0, v);
        }
    }

    // Add a difference constraint: dest - src <= k
    // Updates edge, repairs potential, and closes over the edge.
    // Returns false if infeasible.
    bool add_difference_constraint(VertId src, VertId dest, Weight k) {
        g_.update_edge(src, k, dest);
        if (!repair_potential(src, dest)) {
            return false;
        }
        GraphOps::close_over_edge(g_, src, dest);
        return true;
    }

    // Apply final closure after bound updates (typically called at end of add_linear_leq)
    void close_after_bound_updates() {
        GraphOps::apply_delta(g_, GraphOps::close_after_assign(g_, pot_func(potential_), 0));
    }

    // Apply edges from a delta vector
    void apply_delta(const GraphOps::EdgeVector& delta) {
        GraphOps::apply_delta(g_, delta);
    }

    // Close after assignment to a specific vertex (excludes vertex 0 from subgraph)
    void close_after_assign_vertex(VertId v) {
        GraphOps::apply_delta(g_, GraphOps::close_after_assign(SubGraph(g_, 0), pot_func(potential_), v));
    }

    // Set potential for a vertex
    void set_potential(VertId v, Weight val) {
        potential_[v] = val;
    }

    // Get potential at vertex 0 (for computing relative potentials)
    [[nodiscard]] Weight potential_at_zero() const {
        return potential_[0];
    }

    // ==========================================================================
    // Size and edge accessors
    // ==========================================================================

    [[nodiscard]] std::size_t graph_size() const { return g_.size(); }
    [[nodiscard]] std::size_t num_edges() const { return g_.num_edges(); }

    // Check if a vertex has any edges (for subsumption check permutation building)
    [[nodiscard]] bool vertex_has_edges(VertId v) const {
        return g_.succs(v).size() > 0 || g_.preds(v).size() > 0;
    }

    // Get all vertices with no edges (excluding vertex 0) for garbage collection
    [[nodiscard]] std::vector<VertId> get_disconnected_vertices() const {
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

    // Unconditional edge update (used in assign after closure)
    void update_edge(VertId src, Weight w, VertId dest) {
        g_.update_edge(src, w, dest);
    }

    // Strengthen a bound and propagate to neighbors.
    // For LEFT (lower bound v→0): propagates to predecessors
    // For RIGHT (upper bound 0→v): propagates to successors
    // Returns false if infeasible, true otherwise.
    // Note: new_bound is the EDGE weight (-lb for LEFT, ub for RIGHT)
    bool strengthen_bound_with_propagation(VertId v, Side side, Weight new_bound) {
        if (side == Side::LEFT) {
            // Lower bound: edge v → 0
            auto w = g_.lookup(v, 0);
            if (!w || new_bound >= *w) {
                return true;  // No existing bound or new bound is not tighter
            }
            g_.set_edge(v, new_bound, 0);
            if (!repair_potential(v, 0)) {
                return false;
            }
            // Propagate to predecessors: for each edge pred→v, update pred→0
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
            // Upper bound: edge 0 → v
            auto w = g_.lookup(0, v);
            if (!w || new_bound >= *w) {
                return true;  // No existing bound or new bound is not tighter
            }
            g_.set_edge(0, new_bound, v);
            if (!repair_potential(0, v)) {
                return false;
            }
            // Propagate to successors: for each edge v→succ, update 0→succ
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

    void normalize() {
        CrabStats::count("CoreDBM.count.normalize");
        ScopedCrabStats __st__("CoreDBM.normalize");

        if (unstable_.empty()) {
            return;
        }

        // Wrapper to provide operator[] for the unstable set
        struct UnstableWrap {
            const VertSet& vs;
            explicit UnstableWrap(const VertSet& s) : vs(s) {}
            bool operator[](VertId v) const { return vs.contains(v); }
        };

        const auto p = pot_func(potential_);
        GraphOps::apply_delta(g_, GraphOps::close_after_widen(SubGraph(g_, 0), p, UnstableWrap(unstable_)));
        GraphOps::apply_delta(g_, GraphOps::close_after_assign(g_, p, 0));

        unstable_.clear();
    }

    // =========================================================================
    // Static lattice operations on permuted vertices
    // (Implementations follow AlignedPair class definition)
    // =========================================================================

    // Join two CoreDBMs using an aligned pair
    static CoreDBM join(const AlignedPair& aligned);

    // Widen two CoreDBMs using an aligned pair
    static CoreDBM widen(const AlignedPair& aligned);

    // Meet two CoreDBMs using an aligned pair (with initial potentials)
    // Returns nullopt if the meet is infeasible.
    static std::optional<CoreDBM> meet(AlignedPair& aligned);

    // Check if left is subsumed by right (i.e., left <= right in the lattice).
    // perm[ox] = vertex in left corresponding to vertex ox in right.
    // INVALID_VERT means vertex ox has no edges in right and should be skipped.
    // Returns true if all edges in right are covered by left.
    static bool is_subsumed_by(const CoreDBM& left, const CoreDBM& right, const std::vector<VertId>& perm) {
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

                // Check direct edge
                if (const auto w = g.lookup(x, y)) {
                    if (*w <= ow) {
                        continue;
                    }
                }

                // Check via vertex 0
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
};

// =============================================================================
// SplitDBM constructors and assignment operators
// =============================================================================

SplitDBM::SplitDBM() : core_(std::make_unique<CoreDBM>()) {
    rev_map_.emplace_back(std::nullopt);
}

SplitDBM::~SplitDBM() = default;

SplitDBM::SplitDBM(const SplitDBM& o)
    : core_(std::make_unique<CoreDBM>(*o.core_)),
      vert_map_(o.vert_map_),
      rev_map_(o.rev_map_) {}

SplitDBM::SplitDBM(SplitDBM&& o) noexcept = default;

SplitDBM& SplitDBM::operator=(const SplitDBM& o) {
    if (this != &o) {
        core_ = std::make_unique<CoreDBM>(*o.core_);
        vert_map_ = o.vert_map_;
        rev_map_ = o.rev_map_;
    }
    return *this;
}

SplitDBM& SplitDBM::operator=(SplitDBM&& o) noexcept = default;

SplitDBM::SplitDBM(VertMap&& vert_map, RevMap&& rev_map, std::unique_ptr<CoreDBM> core)
    : core_(std::move(core)),
      vert_map_(std::move(vert_map)),
      rev_map_(std::move(rev_map)) {
    normalize();
}

void SplitDBM::set_to_top() {
    core_ = std::make_unique<CoreDBM>();
    vert_map_.clear();
    rev_map_.clear();
    rev_map_.emplace_back(std::nullopt);
}

bool SplitDBM::is_top() const {
    return core_->is_top();
}

std::pair<std::size_t, std::size_t> SplitDBM::size() const {
    return {core_->graph_size(), core_->num_edges()};
}

// =============================================================================
// End of CoreDBM and SplitDBM basics
// =============================================================================

std::optional<SplitDBM::VertId> SplitDBM::get_vertid(const Variable x) const {
    const auto it = vert_map_.find(x);
    if (it == vert_map_.end()) {
        return {};
    }
    return it->second;
}

Bound SplitDBM::get_lb(const std::optional<VertId>& v) const {
    return v ? core_->get_bound(*v, Side::LEFT) : MINUS_INFINITY;
}

Bound SplitDBM::get_ub(const std::optional<VertId>& v) const {
    return v ? core_->get_bound(*v, Side::RIGHT) : PLUS_INFINITY;
}

Bound SplitDBM::get_lb(const Variable x) const { return get_lb(get_vertid(x)); }

Bound SplitDBM::get_ub(const Variable x) const {
    if (variable_registry->is_min_only(x)) {
        return PLUS_INFINITY;
    }
    return get_ub(get_vertid(x));
}

Interval SplitDBM::get_interval(const Variable x) const {
    const auto& v = get_vertid(x);
    return {get_lb(v), get_ub(v)};
}

static std::optional<SplitDBM::VertId> try_at(const SplitDBM::VertMap& map, const Variable v) {
    const auto it = map.find(v);
    if (it == map.end()) {
        return std::nullopt;
    }
    return it->second;
}

SplitDBM::VertId SplitDBM::get_vert(Variable v) {
    if (const auto y = try_at(vert_map_, v)) {
        return *y;
    }

    VertId vert = core_->new_vertex();
    vert_map_.emplace(v, vert);
    // Initialize rev_map
    assert(vert <= rev_map_.size());
    if (vert < rev_map_.size()) {
        rev_map_[vert] = v;
    } else {
        rev_map_.push_back(v);
    }

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

void SplitDBM::diffcsts_of_assign(const LinearExpression& exp, std::vector<std::pair<Variable, Weight>>& lb,
                                  std::vector<std::pair<Variable, Weight>>& ub) const {
    diffcsts_of_assign(exp, true, ub);
    diffcsts_of_assign(exp, false, lb);
}

void SplitDBM::diffcsts_of_assign(const LinearExpression& exp,
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
            auto y_val = extract_upper_bounds ? get_lb(y) : get_ub(y);

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
            auto y_val = extract_upper_bounds ? get_ub(y) : get_lb(y);

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
            auto y_lb = get_lb(y);
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
            auto y_ub = get_interval(y).ub();
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

bool SplitDBM::add_linear_leq(const LinearExpression& exp) {
    std::vector<std::pair<Variable, Weight>> lbs, ubs;
    std::vector<diffcst_t> csts;
    diffcsts_of_lin_leq(exp, csts, lbs, ubs);

    // Apply lower bounds
    for (const auto& [var, n] : lbs) {
        CRAB_LOG("zones-split", std::cout << var << ">=" << n << "\n");
        const VertId vert = get_vert(var);
        if (!core_->update_bound_if_tighter(vert, Side::LEFT, n)) {
            return false;
        }
    }

    // Apply upper bounds
    for (const auto& [var, n] : ubs) {
        if (variable_registry->is_min_only(var)) {
            continue;
        }
        CRAB_LOG("zones-split", std::cout << var << "<=" << n << "\n");
        const VertId vert = get_vert(var);
        if (!core_->update_bound_if_tighter(vert, Side::RIGHT, n)) {
            return false;
        }
    }

    // Apply difference constraints
    for (const auto& [diff, k] : csts) {
        CRAB_LOG("zones-split", std::cout << diff.first << "-" << diff.second << "<=" << k << "\n");
        const VertId src = get_vert(diff.second);
        const VertId dest = get_vert(diff.first);
        if (!core_->add_difference_constraint(src, dest, k)) {
            return false;
        }
    }

    core_->close_after_bound_updates();
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
    Interval i = get_interval(x);
    Interval new_i = trim_interval(i, n);
    if (new_i.is_bottom()) {
        return false;
    }
    if (new_i.is_top() || !(new_i <= i)) {
        return true;
    }

    VertId v = get_vert(x);
    if (new_i.lb().is_finite()) {
        // strengthen lb: edge weight is -lb
        Weight lb_val;
        if (convert_NtoW_overflow(-*new_i.lb().number(), lb_val)) {
            return true;
        }
        if (!core_->strengthen_bound_with_propagation(v, Side::LEFT, lb_val)) {
            return false;
        }
    }
    if (new_i.ub().is_finite() && !variable_registry->is_min_only(x)) {
        // strengthen ub: edge weight is ub
        Weight ub_val;
        if (convert_NtoW_overflow(*new_i.ub().number(), ub_val)) {
            return true;
        }
        if (!core_->strengthen_bound_with_propagation(v, Side::RIGHT, ub_val)) {
            return false;
        }
    }
    normalize();
    return true;
}

bool SplitDBM::operator<=(const SplitDBM& o) const {
    // cover all trivial cases to avoid allocating a dbm matrix
    if (o.is_top()) {
        return true;
    }
    if (is_top()) {
        return false;
    }

    if (vert_map_.size() < o.vert_map_.size()) {
        return false;
    }

    // Build permutation mapping from o's vertices to this's vertices
    constexpr VertId INVALID_VERT = std::numeric_limits<VertId>::max();
    std::vector<VertId> perm(o.core_->graph_size(), INVALID_VERT);
    perm[0] = 0;
    for (const auto& [v, n] : o.vert_map_) {
        if (!o.core_->vertex_has_edges(n)) {
            continue;
        }

        // We can't have this <= o if we're missing some vertex.
        if (auto y = try_at(vert_map_, v)) {
            perm[n] = *y;
        } else {
            return false;
        }
    }

    return CoreDBM::is_subsumed_by(*core_, *o.core_, perm);
}

// =============================================================================
// AlignedPair: Two SplitDBMs viewed in a common vertex space
// =============================================================================
// When performing binary operations (join, widen, meet), we need to align
// two SplitDBMs so that same-named variables occupy the same vertex index.
// This class encapsulates that alignment.
//
// Terminology:
// - "aligned vertex": index in the common space (0, 1, 2, ...)
// - "left/right vertex": index in the respective operand's space
// - perm_left_[aligned] = left_vertex (maps aligned -> left)
// - perm_right_[aligned] = right_vertex (maps aligned -> right)

class AlignedPair {
  public:
    using VertId = SplitDBM::VertId;
    using VertMap = SplitDBM::VertMap;
    using RevMap = SplitDBM::RevMap;
    using Weight = SplitDBM::Weight;
    using CoreDBM = SplitDBM::CoreDBM;

    // Create alignment from intersection of variables (for join/widen)
    static AlignedPair make_intersection(const SplitDBM& left, const SplitDBM& right) {
        std::vector<VertId> perm_left = {0};
        std::vector<VertId> perm_right = {0};
        RevMap aligned_vars = {std::nullopt};  // aligned_vars[i] = variable at aligned vertex i

        for (const auto& [var, left_vert] : left.vert_map_) {
            if (auto right_vert = try_at(right.vert_map_, var)) {
                perm_left.push_back(left_vert);
                perm_right.push_back(*right_vert);
                aligned_vars.push_back(var);
            }
        }

        return AlignedPair(*left.core_, *right.core_,
                           std::move(perm_left), std::move(perm_right),
                           std::move(aligned_vars));
    }

    // Create alignment from union of variables (for meet)
    // Also computes initial potentials since meet needs them from both operands
    static AlignedPair make_union(const SplitDBM& left, const SplitDBM& right) {
        constexpr VertId NOT_PRESENT = static_cast<VertId>(-1);

        std::vector<VertId> perm_left = {0};
        std::vector<VertId> perm_right = {0};
        RevMap aligned_vars = {std::nullopt};
        std::vector<Weight> initial_potentials = {Weight(0)};

        const auto& pot_left = left.core_->potential();
        const auto& pot_right = right.core_->potential();

        // Add all variables from left
        for (const auto& [var, left_vert] : left.vert_map_) {
            perm_left.push_back(left_vert);
            perm_right.push_back(NOT_PRESENT);  // May be updated below
            aligned_vars.push_back(var);
            initial_potentials.push_back(pot_left[left_vert] - pot_left[0]);
        }

        // Add missing variables from right, or update perm_right for common ones
        for (const auto& [var, right_vert] : right.vert_map_) {
            // Check if already added from left
            bool found = false;
            for (size_t i = 1; i < aligned_vars.size(); ++i) {
                if (aligned_vars[i] == var) {
                    perm_right[i] = right_vert;
                    found = true;
                    break;
                }
            }
            if (!found) {
                // Variable only in right
                perm_left.push_back(NOT_PRESENT);
                perm_right.push_back(right_vert);
                aligned_vars.push_back(var);
                initial_potentials.push_back(pot_right[right_vert] - pot_right[0]);
            }
        }

        return AlignedPair(*left.core_, *right.core_,
                           std::move(perm_left), std::move(perm_right),
                           std::move(aligned_vars), std::move(initial_potentials));
    }

    // Accessors
    [[nodiscard]] size_t size() const { return perm_left_.size(); }
    [[nodiscard]] const std::vector<VertId>& left_perm() const { return perm_left_; }
    [[nodiscard]] const std::vector<VertId>& right_perm() const { return perm_right_; }
    [[nodiscard]] const CoreDBM& left_core() const { return left_; }
    [[nodiscard]] const CoreDBM& right_core() const { return right_; }

    // Get initial potentials (only valid for union alignment)
    [[nodiscard]] std::vector<Weight>& initial_potentials() { return initial_potentials_; }

    // Build result's variable mappings from the alignment
    [[nodiscard]] std::pair<VertMap, RevMap> result_mappings() const {
        VertMap vmap;
        RevMap revmap = aligned_vars_;  // Copy: aligned vertex -> variable

        for (size_t i = 1; i < aligned_vars_.size(); ++i) {
            if (aligned_vars_[i]) {
                vmap.emplace(*aligned_vars_[i], gsl::narrow<VertId>(i));
            }
        }
        return {std::move(vmap), std::move(revmap)};
    }

  private:
    AlignedPair(const CoreDBM& left, const CoreDBM& right,
                std::vector<VertId> perm_left, std::vector<VertId> perm_right,
                RevMap aligned_vars, std::vector<Weight> initial_potentials = {})
        : left_(left), right_(right),
          perm_left_(std::move(perm_left)), perm_right_(std::move(perm_right)),
          aligned_vars_(std::move(aligned_vars)),
          initial_potentials_(std::move(initial_potentials)) {}

    const CoreDBM& left_;
    const CoreDBM& right_;
    std::vector<VertId> perm_left_;
    std::vector<VertId> perm_right_;
    RevMap aligned_vars_;
    std::vector<Weight> initial_potentials_;  // Only used for union (meet)
};

// =============================================================================
// CoreDBM static method implementations (depend on AlignedPair)
// =============================================================================

SplitDBM::CoreDBM SplitDBM::CoreDBM::join(const AlignedPair& aligned) {
    const auto& perm_x = aligned.left_perm();
    const auto& perm_y = aligned.right_perm();
    const auto& left = aligned.left_core();
    const auto& right = aligned.right_core();
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

SplitDBM::CoreDBM SplitDBM::CoreDBM::widen(const AlignedPair& aligned) {
    const auto& perm_left = aligned.left_perm();
    const auto& perm_right = aligned.right_perm();
    const auto& left = aligned.left_core();
    const auto& right = aligned.right_core();
    const size_t sz = aligned.size();

    // Build potentials from left (widen uses left's potentials)
    std::vector<Weight> result_pot;
    result_pot.reserve(sz);
    for (size_t i = 0; i < sz; ++i) {
        result_pot.push_back(left.potential_[perm_left[i]] - left.potential_[0]);
    }
    result_pot[0] = 0;

    // Build aligned views
    GraphPerm gx(perm_left, left.g_);
    GraphPerm gy(perm_right, right.g_);

    // Perform the widening
    VertSet result_unstable(left.unstable_);
    Graph result_g(GraphOps::widen(gx, gy, result_unstable));

    return CoreDBM(std::move(result_g), std::move(result_pot), std::move(result_unstable));
}

std::optional<SplitDBM::CoreDBM> SplitDBM::CoreDBM::meet(AlignedPair& aligned) {
    const auto& perm_left = aligned.left_perm();
    const auto& perm_right = aligned.right_perm();
    const auto& left = aligned.left_core();
    const auto& right = aligned.right_core();

    // Build aligned views
    GraphPerm gx(perm_left, left.g_);
    GraphPerm gy(perm_right, right.g_);

    // Compute the syntactic meet of the aligned graphs
    bool is_closed{};
    Graph result_g(GraphOps::meet(gx, gy, is_closed));

    // Select valid potentials using Bellman-Ford (updates initial_potentials in place)
    auto& result_pot = aligned.initial_potentials();
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

// =============================================================================
// SplitDBM join/widen/meet operations using AlignedPair
// =============================================================================

SplitDBM do_join(const SplitDBM& left, const SplitDBM& right) {
    using CoreDBM = SplitDBM::CoreDBM;

    if (right.is_top()) {
        return right;
    }
    if (left.is_top()) {
        return left;
    }

    // 1. Build alignment (intersection of variables)
    AlignedPair aligned = AlignedPair::make_intersection(left, right);

    // 2. Execute graph join
    CoreDBM joined = CoreDBM::join(aligned);

    // 3. Build result mappings and garbage collect
    auto [out_vmap, out_revmap] = aligned.result_mappings();
    for (SplitDBM::VertId v : joined.get_disconnected_vertices()) {
        joined.forget(v);
        if (out_revmap[v]) {
            out_vmap.erase(*out_revmap[v]);
            out_revmap[v] = std::nullopt;
        }
    }

    return SplitDBM(std::move(out_vmap), std::move(out_revmap),
                    std::make_unique<CoreDBM>(std::move(joined)));
}

void SplitDBM::operator|=(const SplitDBM& right) { *this = do_join(*this, right); }

SplitDBM SplitDBM::operator|(const SplitDBM& right) const { return do_join(*this, right); }

SplitDBM SplitDBM::widen(const SplitDBM& o) const {
    // 1. Build alignment (intersection of variables)
    AlignedPair aligned = AlignedPair::make_intersection(*this, o);

    // 2. Execute graph widen
    auto result_core = std::make_unique<CoreDBM>(CoreDBM::widen(aligned));

    // 3. Build result mappings
    auto [out_vmap, out_revmap] = aligned.result_mappings();

    return SplitDBM(std::move(out_vmap), std::move(out_revmap), std::move(result_core));
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

    // 1. Build alignment (union of variables, with initial potentials)
    AlignedPair aligned = AlignedPair::make_union(*this, o);

    // 2. Execute graph meet
    auto meet_result = CoreDBM::meet(aligned);
    if (!meet_result) {
        return std::nullopt;  // Infeasible
    }

    // 3. Build result mappings
    auto [out_vmap, out_revmap] = aligned.result_mappings();

    SplitDBM res(std::move(out_vmap), std::move(out_revmap),
                 std::make_unique<CoreDBM>(std::move(*meet_result)));
    CRAB_LOG("zones-split", std::cout << "Result meet:\n" << res << "\n");
    return res;
}

void SplitDBM::havoc(const Variable v) {
    if (const auto y = try_at(vert_map_, v)) {
        core_->forget(*y);
        rev_map_[*y] = std::nullopt;
        vert_map_.erase(v);
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
    diffcsts_of_assign(e, diffs_lb, diffs_ub);
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
    VertId vert = core_->new_vertex();
    assert(vert <= rev_map_.size());
    if (vert == rev_map_.size()) {
        rev_map_.push_back(lhs);
    } else {
        rev_map_[vert] = lhs;
    }
    core_->set_potential(vert, core_->potential_at_zero() + e_val);

    {
        GraphOps::EdgeVector delta;
        for (const auto& [var, n] : diffs_lb) {
            delta.emplace_back(vert, get_vert(var), -n);
        }

        for (const auto& [var, n] : diffs_ub) {
            delta.emplace_back(get_vert(var), vert, n);
        }

        // apply_delta should be safe here, as x has no edges in G.
        core_->apply_delta(delta);
    }
    core_->close_after_assign_vertex(vert);

    if (lb_w) {
        core_->update_edge(vert, *lb_w, 0);
    }
    if (ub_w && !variable_registry->is_min_only(lhs)) {
        core_->update_edge(0, *ub_w, vert);
    }
    // Clear the old x vertex
    havoc(lhs);
    vert_map_.emplace(lhs, vert);

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


bool SplitDBM::repair_potential(const VertId src, const VertId dest) {
    return core_->repair_potential(src, dest);
}

void SplitDBM::clear_thread_local_state() { GraphOps::clear_thread_local_state(); }

void SplitDBM::normalize() {
    core_->normalize();
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
    if (intv.ub().is_finite() && !variable_registry->is_min_only(x)) {
        Weight ub;
        if (convert_NtoW_overflow(*intv.ub().number(), ub)) {
            normalize();
            return;
        }
        core_->set_bound(v, Side::RIGHT, ub);
    }
    if (intv.lb().is_finite()) {
        Weight lb;
        if (convert_NtoW_overflow(*intv.lb().number(), lb)) {
            normalize();
            return;
        }
        core_->set_bound(v, Side::LEFT, lb);
    }
    normalize();
}

void SplitDBM::apply(const ArithBinOp op, const Variable x, const Variable y, const Variable z) {
    switch (op) {
    case ArithBinOp::ADD: assign(x, LinearExpression(y).plus(z)); break;
    case ArithBinOp::SUB: assign(x, LinearExpression(y).subtract(z)); break;
    // For the rest of operations, we fall back on intervals.
    case ArithBinOp::MUL: set(x, get_interval(y) * get_interval(z)); break;
    default: CRAB_ERROR("DBM: unreachable");
    }
    normalize();
}

void SplitDBM::apply(const ArithBinOp op, const Variable x, const Variable y, const Number& k) {
    switch (op) {
    case ArithBinOp::ADD: assign(x, LinearExpression(y).plus(k)); break;
    case ArithBinOp::SUB: assign(x, LinearExpression(y).subtract(k)); break;
    case ArithBinOp::MUL: assign(x, LinearExpression(k, y)); break;
    }
    normalize();
}

void SplitDBM::forget(const VariableVector& variables) {
    if (is_top()) {
        return;
    }

    for (const auto v : variables) {
        if (vert_map_.contains(v)) {
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

    const Graph& g = core_->graph();

    // Extract all the edges
    SubGraph g_excl{g, 0};

    std::map<Variable, Variable> equivalence_classes;
    std::set<std::tuple<Variable, Variable, Weight>> diff_csts;
    for (const VertId s : g_excl.verts()) {
        const Variable vs = *rev_map_.at(s);
        Variable least = vs;
        for (const VertId d : g_excl.succs(s)) {
            const Variable vd = *rev_map_.at(d);
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
        const auto pvar = this->rev_map_[v];
        if (!pvar || !representatives.contains(*pvar)) {
            continue;
        }
        const bool has_lb = g.elem(v, 0);
        const bool has_ub = g.elem(0, v) && !variable_registry->is_min_only(*pvar);
        if (!has_lb && !has_ub) {
            continue;
        }
        Interval v_out{has_lb ? -Number(g.edge_val(v, 0)) : MINUS_INFINITY,
                       has_ub ? Number(g.edge_val(0, v)) : PLUS_INFINITY};
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
        } else if (variable_registry->is_min_only(variable)) {
            // One-sided variables: display just the lower bound
            elem << "=" << v_out.lb();
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

    return StringInvariant{std::move(result)};
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
        out += (pot_value(variable) - core_->potential()[0]) * coef;
    }
    return false;
}

Interval SplitDBM::compute_residual(const LinearExpression& e, const Variable pivot) const {
    Interval residual(-e.constant_term());
    for (const auto& [variable, coefficient] : e.variable_terms()) {
        if (variable != pivot) {
            residual = residual - Interval(coefficient) * get_interval(variable);
        }
    }
    return residual;
}

SplitDBM::Weight SplitDBM::pot_value(const Variable v) const {
    if (const auto y = try_at(vert_map_, v)) {
        return core_->potential()[*y];
    }
    return {0};
}

Interval SplitDBM::eval_interval(const LinearExpression& e) const {
    using namespace prevail::interval_operators;
    Interval r{e.constant_term()};
    for (const auto& [variable, coefficient] : e.variable_terms()) {
        r += coefficient * get_interval(variable);
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

} // namespace prevail

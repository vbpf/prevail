// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include <cassert>
#include <utility>

#include "crab/var_registry.hpp"
#include "crab/zone_domain.hpp"
#include "string_constraints.hpp"

using namespace splitdbm;

namespace prevail {

ZoneDomain::ZoneDomain() : core_(std::make_unique<SplitDBM>()) { rev_map_.emplace_back(std::nullopt); }

ZoneDomain::~ZoneDomain() = default;

ZoneDomain::ZoneDomain(const ZoneDomain& o)
    : core_(std::make_unique<SplitDBM>(*o.core_)), vert_map_(o.vert_map_), rev_map_(o.rev_map_) {}

ZoneDomain::ZoneDomain(ZoneDomain&& o) noexcept = default;

ZoneDomain& ZoneDomain::operator=(const ZoneDomain& o) {
    if (this != &o) {
        core_ = std::make_unique<SplitDBM>(*o.core_);
        vert_map_ = o.vert_map_;
        rev_map_ = o.rev_map_;
    }
    return *this;
}

ZoneDomain& ZoneDomain::operator=(ZoneDomain&& o) noexcept = default;

ZoneDomain::ZoneDomain(VertMap&& vert_map, RevMap&& rev_map, std::unique_ptr<SplitDBM> core)
    : core_(std::move(core)), vert_map_(std::move(vert_map)), rev_map_(std::move(rev_map)) {
    normalize();
}

void ZoneDomain::set_to_top() {
    core_ = std::make_unique<SplitDBM>();
    vert_map_.clear();
    rev_map_.clear();
    rev_map_.emplace_back(std::nullopt);
}

bool ZoneDomain::is_top() const { return core_->is_top(); }

std::pair<std::size_t, std::size_t> ZoneDomain::size() const { return {core_->graph_size(), core_->num_edges()}; }

std::optional<VertId> ZoneDomain::get_vertid(const Variable x) const {
    const auto it = vert_map_.find(x);
    if (it == vert_map_.end()) {
        return {};
    }
    return it->second;
}

Bound ZoneDomain::get_lb(const std::optional<VertId>& v) const {
    return v ? core_->get_bound(*v, Side::LEFT) : MINUS_INFINITY;
}

Bound ZoneDomain::get_ub(const std::optional<VertId>& v) const {
    return v ? core_->get_bound(*v, Side::RIGHT) : PLUS_INFINITY;
}

Bound ZoneDomain::get_lb(const Variable x) const { return get_lb(get_vertid(x)); }

Bound ZoneDomain::get_ub(const Variable x) const {
    if (variable_registry->is_min_only(x)) {
        return PLUS_INFINITY;
    }
    return get_ub(get_vertid(x));
}

Interval ZoneDomain::get_interval(const Variable x) const { return {get_lb(x), get_ub(x)}; }

static std::optional<VertId> try_at(const ZoneDomain::VertMap& map, const Variable v) {
    const auto it = map.find(v);
    if (it == map.end()) {
        return std::nullopt;
    }
    return it->second;
}

VertId ZoneDomain::get_vert(Variable v) {
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
        rev_map_.emplace_back(v);
    }

    assert(vert != 0);

    return vert;
}

void ZoneDomain::diffcsts_of_assign(const LinearExpression& exp, std::vector<std::pair<Variable, Weight>>& lb,
                                    std::vector<std::pair<Variable, Weight>>& ub) const {
    diffcsts_of_assign(exp, true, ub);
    diffcsts_of_assign(exp, false, lb);
}

void ZoneDomain::diffcsts_of_assign(const LinearExpression& exp,
                                    /* if true then process the upper
                                       bounds, else the lower bounds */
                                    bool extract_upper_bounds,
                                    /* foreach {v, k} \in diff_csts we have
                                       the difference constraint v - k <= k */
                                    std::vector<std::pair<Variable, Weight>>& diff_csts) const {

    std::optional<Variable> unbounded_var;
    std::vector<std::pair<Variable, Weight>> terms;

    Weight residual = exp.constant_term();

    for (const auto& [y, n] : exp.variable_terms()) {
        const Weight coeff = n;

        if (coeff < Weight(0)) {
            // Can't do anything with negative coefficients.
            auto y_val = extract_upper_bounds ? get_lb(y) : get_ub(y);

            if (y_val.is_infinite()) {
                return;
            }
            const Weight ymax = *y_val.number();
            residual += ymax * coeff;
        } else {
            auto y_val = extract_upper_bounds ? get_ub(y) : get_lb(y);

            if (y_val.is_infinite()) {
                if (unbounded_var || coeff != Weight(1)) {
                    return;
                }
                unbounded_var = y;
            } else {
                const Weight ymax = *y_val.number();
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

void ZoneDomain::diffcsts_of_lin_leq(const LinearExpression& exp,
                                     /* difference contraints */
                                     std::vector<diffcst_t>& csts,
                                     /* x >= lb for each {x,lb} in lbs */
                                     std::vector<std::pair<Variable, Weight>>& lbs,
                                     /* x <= ub for each {x,ub} in ubs */
                                     std::vector<std::pair<Variable, Weight>>& ubs) const {
    Weight exp_ub = -Weight{exp.constant_term()};

    Weight unbounded_lbcoeff;
    Weight unbounded_ubcoeff;
    std::optional<Variable> unbounded_lbvar;
    std::optional<Variable> unbounded_ubvar;

    std::vector<std::pair<std::pair<Weight, Variable>, Weight>> pos_terms, neg_terms;
    for (const auto& [y, n] : exp.variable_terms()) {
        const Weight coeff = n;
        if (coeff > Weight(0)) {
            auto y_lb = get_lb(y);
            if (y_lb.is_infinite()) {
                if (unbounded_lbvar) {
                    return;
                }
                unbounded_lbvar = y;
                unbounded_lbcoeff = coeff;
            } else {
                const Weight ymin = *y_lb.number();
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
                const Weight ymax = *y_ub.number();
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

bool ZoneDomain::add_linear_leq(const LinearExpression& exp) {
    std::vector<std::pair<Variable, Weight>> lbs, ubs;
    std::vector<diffcst_t> csts;
    diffcsts_of_lin_leq(exp, csts, lbs, ubs);

    // Apply lower bounds
    for (const auto& [var, n] : lbs) {
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
        const VertId vert = get_vert(var);
        if (!core_->update_bound_if_tighter(vert, Side::RIGHT, n)) {
            return false;
        }
    }

    // Apply difference constraints
    for (const auto& [diff, k] : csts) {
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

bool ZoneDomain::add_univar_disequation(Variable x, const Number& n) {
    const Interval i = get_interval(x);
    const Interval new_i = trim_interval(i, n);
    if (new_i.is_bottom()) {
        return false;
    }
    if (new_i.is_top() || !(new_i <= i)) {
        return true;
    }

    const VertId v = get_vert(x);
    if (new_i.lb().is_finite()) {
        if (!core_->strengthen_bound(v, Side::LEFT, Weight{*new_i.lb().number()})) {
            return false;
        }
    }
    if (new_i.ub().is_finite() && !variable_registry->is_min_only(x)) {
        if (!core_->strengthen_bound(v, Side::RIGHT, Weight{*new_i.ub().number()})) {
            return false;
        }
    }
    normalize();
    return true;
}

bool ZoneDomain::operator<=(const ZoneDomain& o) const {
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
    std::vector perm(o.core_->graph_size(), INVALID_VERT);
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

    return SplitDBM::is_subsumed_by(*core_, *o.core_, perm);
}

using RevMap = std::vector<std::optional<Variable>>;
using VertMap = boost::container::flat_map<Variable, VertId>;

[[nodiscard]]
std::pair<VertMap, RevMap> result_mappings(const RevMap&& aligned_vars) {
    VertMap vmap;
    RevMap revmap = aligned_vars;

    for (size_t i = 1; i < aligned_vars.size(); ++i) {
        if (aligned_vars[i]) {
            vmap.emplace(*aligned_vars[i], gsl::narrow<VertId>(i));
        }
    }
    return {std::move(vmap), std::move(revmap)};
}

// Build alignment from intersection of variables (for join/widen)
std::tuple<AlignedPair, RevMap> ZoneDomain::make_intersection_alignment(const ZoneDomain& left,
                                                                        const ZoneDomain& right) {
    std::vector<VertId> perm_left = {0};
    std::vector<VertId> perm_right = {0};
    RevMap aligned_vars = {std::nullopt};

    for (const auto& [var, left_vert] : left.vert_map_) {
        if (auto right_vert = try_at(right.vert_map_, var)) {
            perm_left.push_back(left_vert);
            perm_right.push_back(*right_vert);
            aligned_vars.emplace_back(var);
        }
    }

    return std::make_tuple(AlignedPair{*left.core_, *right.core_, std::move(perm_left), std::move(perm_right)},
                           std::move(aligned_vars));
}

// Build alignment from union of variables (for meet)
std::tuple<AlignedPair, RevMap> ZoneDomain::make_union_alignment(const ZoneDomain& left, const ZoneDomain& right) {
    constexpr VertId NOT_PRESENT = static_cast<VertId>(-1);

    std::vector<VertId> perm_left = {0};
    std::vector<VertId> perm_right = {0};
    RevMap aligned_vars = {std::nullopt};
    std::vector initial_potentials = {Weight(0)};

    boost::container::flat_map<Variable, size_t> var_to_index;
    for (const auto& [var, left_vert] : left.vert_map_) {
        var_to_index.emplace(var, perm_left.size());
        perm_left.push_back(left_vert);
        perm_right.push_back(NOT_PRESENT);
        aligned_vars.emplace_back(var);
        initial_potentials.push_back(left.core_->potential_at(left_vert) - left.core_->potential_at_zero());
    }

    for (const auto& [var, right_vert] : right.vert_map_) {
        if (const auto it = var_to_index.find(var); it != var_to_index.end()) {
            perm_right[it->second] = right_vert;
        } else {
            perm_left.push_back(NOT_PRESENT);
            perm_right.push_back(right_vert);
            aligned_vars.emplace_back(var);
            initial_potentials.push_back(right.core_->potential_at(right_vert) - right.core_->potential_at_zero());
        }
    }

    return std::make_tuple(AlignedPair{*left.core_, *right.core_, std::move(perm_left), std::move(perm_right),
                                       std::move(initial_potentials)},
                           std::move(aligned_vars));
}

ZoneDomain do_join(const ZoneDomain& left, const ZoneDomain& right) {
    if (right.is_top()) {
        return right;
    }
    if (left.is_top()) {
        return left;
    }

    // 1. Build alignment (intersection of variables)
    auto [aligned_pair, aligned_vars] = ZoneDomain::make_intersection_alignment(left, right);

    // 2. Execute graph join
    SplitDBM joined = SplitDBM::join(aligned_pair);

    // 3. Build result mappings and garbage collect
    auto [out_vmap, out_revmap] = result_mappings(std::move(aligned_vars));
    for (const VertId v : joined.get_disconnected_vertices()) {
        joined.forget(v);
        if (out_revmap[v]) {
            out_vmap.erase(*out_revmap[v]);
            out_revmap[v] = std::nullopt;
        }
    }

    return ZoneDomain(std::move(out_vmap), std::move(out_revmap), std::make_unique<SplitDBM>(std::move(joined)));
}

void ZoneDomain::operator|=(const ZoneDomain& right) { *this = do_join(*this, right); }

ZoneDomain ZoneDomain::operator|(const ZoneDomain& right) const { return do_join(*this, right); }

ZoneDomain ZoneDomain::widen(const ZoneDomain& o) const {
    // 1. Build alignment (intersection of variables)
    auto [aligned_pair, aligned_vars] = make_intersection_alignment(*this, o);

    // 2. Execute graph widen
    auto result_core = std::make_unique<SplitDBM>(SplitDBM::widen(aligned_pair));

    // 3. Build result mappings
    auto [out_vmap, out_revmap] = result_mappings(std::move(aligned_vars));

    return ZoneDomain(std::move(out_vmap), std::move(out_revmap), std::move(result_core));
}

std::optional<ZoneDomain> ZoneDomain::meet(const ZoneDomain& o) const {
    if (is_top()) {
        return o;
    }
    if (o.is_top()) {
        return *this;
    }

    // 1. Build alignment (union of variables, with initial potentials)
    auto [aligned_pair, aligned_vars] = make_union_alignment(*this, o);

    // 2. Execute graph meet
    auto meet_result = SplitDBM::meet(aligned_pair);
    if (!meet_result) {
        return std::nullopt; // Infeasible
    }

    // 3. Build result mappings
    auto [out_vmap, out_revmap] = result_mappings(std::move(aligned_vars));

    return ZoneDomain(std::move(out_vmap), std::move(out_revmap), std::make_unique<SplitDBM>(std::move(*meet_result)));
}

void ZoneDomain::havoc(const Variable v) {
    if (const auto y = try_at(vert_map_, v)) {
        core_->forget(*y);
        rev_map_[*y] = std::nullopt;
        vert_map_.erase(v);
        normalize();
    }
}

// return false if it becomes bottom
bool ZoneDomain::add_constraint(const LinearConstraint& cst) {
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
        break;
    }
    case ConstraintKind::LESS_THAN_ZERO: {
        // We try to convert a strict to non-strict.
        // e < 0 --> e <= -1
        const auto nc = LinearConstraint(cst.expression().plus(1), ConstraintKind::LESS_THAN_OR_EQUALS_ZERO);
        if (!add_linear_leq(nc.expression())) {
            return false;
        }
        break;
    }
    case ConstraintKind::EQUALS_ZERO: {
        const LinearExpression& exp = cst.expression();
        if (!add_linear_leq(exp) || !add_linear_leq(exp.negate())) {
            return false;
        }
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
    return true;
}

void ZoneDomain::assign(Variable lhs, const LinearExpression& e) {
    const Interval value_interval = eval_interval(e);

    std::optional<Weight> lb_w, ub_w;
    if (value_interval.lb().is_finite()) {
        lb_w = Weight{-*value_interval.lb().number()};
    }
    if (value_interval.ub().is_finite()) {
        ub_w = Weight{*value_interval.ub().number()};
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

    const Weight e_val = eval_expression(e);

    std::vector<std::pair<VertId, Weight>> diffs_from, diffs_to;
    for (const auto& [var, n] : diffs_lb) {
        diffs_from.emplace_back(get_vert(var), -n);
    }
    for (const auto& [var, n] : diffs_ub) {
        diffs_to.emplace_back(get_vert(var), n);
    }

    VertId vert = core_->assign_vertex(core_->potential_at_zero() + e_val, diffs_from, diffs_to, lb_w,
                                       (ub_w && !variable_registry->is_min_only(lhs)) ? ub_w : std::nullopt);

    assert(vert <= rev_map_.size());
    if (vert == rev_map_.size()) {
        rev_map_.emplace_back(lhs);
    } else {
        rev_map_[vert] = lhs;
    }
    // Clear the old x vertex
    havoc(lhs);
    vert_map_.emplace(lhs, vert);

    normalize();
}

ZoneDomain ZoneDomain::narrow(const ZoneDomain& o) const {
    if (is_top()) {
        return o;
    }
    // FIXME: Implement properly
    // Narrowing as a no-op should be sound.
    return {*this};
}

void ZoneDomain::clear_thread_local_state() { SplitDBM::clear_thread_local_state(); }

void ZoneDomain::normalize() { core_->normalize(); }

void ZoneDomain::set(const Variable x, const Interval& intv) {
    assert(!intv.is_bottom());

    havoc(x);

    if (intv.is_top()) {
        return;
    }

    const VertId v = get_vert(x);
    if (intv.ub().is_finite() && !variable_registry->is_min_only(x)) {
        core_->set_bound(v, Side::RIGHT, Weight{*intv.ub().number()});
    }
    if (intv.lb().is_finite()) {
        core_->set_bound(v, Side::LEFT, Weight{*intv.lb().number()});
    }
    normalize();
}

void ZoneDomain::apply(const ArithBinOp op, const Variable x, const Variable y, const Variable z) {
    switch (op) {
    case ArithBinOp::ADD: assign(x, LinearExpression(y).plus(z)); break;
    case ArithBinOp::SUB: assign(x, LinearExpression(y).subtract(z)); break;
    // For the rest of operations, we fall back on intervals.
    case ArithBinOp::MUL: set(x, get_interval(y) * get_interval(z)); break;
    default: CRAB_ERROR("DBM: unreachable");
    }
    normalize();
}

void ZoneDomain::apply(const ArithBinOp op, const Variable x, const Variable y, const Number& k) {
    switch (op) {
    case ArithBinOp::ADD: assign(x, LinearExpression(y).plus(k)); break;
    case ArithBinOp::SUB: assign(x, LinearExpression(y).subtract(k)); break;
    case ArithBinOp::MUL: assign(x, LinearExpression(k, y)); break;
    }
    normalize();
}

void ZoneDomain::forget(const VariableVector& variables) {
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

static std::string to_string(const Variable vd, const Variable vs, const Weight& w, const bool eq) {
    std::stringstream elem;
    if (eq) {
        if (w.operator>(0)) {
            elem << vd << "=" << vs << "+" << w;
        } else if (w.operator<(0)) {
            elem << vs << "=" << vd << "+" << -w;
        } else {
            const auto [left, right] = std::minmax(vs, vd, VariableRegistry::printing_order);
            elem << left << "=" << right;
        }
    } else {
        elem << vd << "-" << vs << "<=" << w;
    }
    return elem.str();
}

StringInvariant ZoneDomain::to_set() const {
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
                least = std::min(least, vd, VariableRegistry::printing_order);
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
        if (variable_registry->is_min_only(variable)) {
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

std::ostream& operator<<(std::ostream& o, const ZoneDomain& dom) { return o << dom.to_set(); }

Weight ZoneDomain::eval_expression(const LinearExpression& e) const {
    Weight res = e.constant_term();
    for (const auto& [variable, coefficient] : e.variable_terms()) {
        res += (pot_value(variable) - core_->potential_at_zero()) * Weight{coefficient};
    }
    return res;
}

Interval ZoneDomain::compute_residual(const LinearExpression& e, const Variable pivot) const {
    Interval residual(-e.constant_term());
    for (const auto& [variable, coefficient] : e.variable_terms()) {
        if (variable != pivot) {
            residual = residual - Interval(coefficient) * get_interval(variable);
        }
    }
    return residual;
}

Weight ZoneDomain::pot_value(const Variable v) const {
    if (const auto y = try_at(vert_map_, v)) {
        return core_->potential_at(*y);
    }
    return {0};
}

Interval ZoneDomain::eval_interval(const LinearExpression& e) const {
    using namespace prevail::interval_operators;
    Interval r{e.constant_term()};
    for (const auto& [variable, coefficient] : e.variable_terms()) {
        r += coefficient * get_interval(variable);
    }
    return r;
}

bool ZoneDomain::intersect(const LinearConstraint& cst) const {
    if (cst.is_contradiction()) {
        return false;
    }
    if (is_top() || cst.is_tautology()) {
        return true;
    }
    return intersect_aux(cst);
}

bool ZoneDomain::entail(const LinearConstraint& rhs) const {
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

    // Note: we cannot convert rhs into ZoneDomain and then use the <=
    //       operator. The problem is that we cannot know for sure
    //       whether ZoneDomain can represent precisely rhs. It is not
    //       enough to do something like
    //
    //       ZoneDomain dom = rhs;
    //       if (dom.is_top()) { ... }
}

} // namespace prevail

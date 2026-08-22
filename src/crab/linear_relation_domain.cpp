// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <array>
#include <set>

#include "arith/dsl_syntax.hpp"
#include "crab/linear_relation_domain.hpp"
#include "crab/var_registry.hpp"

namespace prevail {

namespace {

// The fallback is a proof search over must-equalities. Exhausting any budget must
// fail closed: returning false can reject a safe program, but cannot admit an
// unsafe one. The identity limit bounds each state's mask; the state and
// transition limits bound the combinatorial search itself.
constexpr size_t MAX_REWRITE_IDENTITIES = 32;
constexpr size_t MAX_REWRITE_STATES = 512;
constexpr size_t MAX_REWRITE_TRANSITIONS = 4096;

} // namespace

void LinearRelationDomain::derive_bound(const NumAbsDomain& values, const Variable compared_var,
                                        const LinearExpression& bound_le_zero) {
    using namespace dsl_syntax;
    // On bottom, entail() is vacuously true, so canonicalization would equate every
    // variable to a global and store a garbage bound.
    if (values.is_bottom()) {
        return;
    }
    const auto [eq_first, eq_last] = equalities.equal_range(compared_var);
    if (eq_first == eq_last) {
        return;
    }
    const auto& terms = bound_le_zero.variable_terms();
    const auto q_it = terms.find(compared_var);
    if (q_it == terms.end() || q_it->second == 0) {
        return;
    }
    for (auto eq_it = eq_first; eq_it != eq_last; ++eq_it) {
        // q*(expr - compared_var) is zero under the equality, and cancels compared_var.
        LinearExpression derived = bound_le_zero.plus(eq_it->second.subtract(compared_var).multiply(q_it->second));

        // Rewrite each variable to a write-stable global the DBM proves it equal to, so the
        // bound outlives the compared registers. The target set is fixed but the equality is
        // always discovered via entail(eq(...)) -- no symbol is hardcoded as a match target.
        const std::array<Variable, 2> stable{variable_registry.packet_size(), variable_registry.meta_offset()};
        std::vector<Variable> vars;
        for (const auto& [v, c] : derived.variable_terms()) {
            vars.push_back(v);
        }
        for (const Variable v : vars) {
            for (const Variable s : stable) {
                if (v != s && values.entail(eq(v, s))) {
                    const auto it = derived.variable_terms().find(v);
                    if (it != derived.variable_terms().end() && it->second != 0) {
                        derived = derived.plus((LinearExpression{s}.subtract(v)).multiply(it->second));
                    }
                    break;
                }
            }
        }
        add_bound(std::move(derived));
    }
}

bool LinearRelationDomain::entails(const NumAbsDomain& values, const LinearConstraint& query) const {
    using namespace dsl_syntax;
    if (values.entail(query)) {
        return true;
    }
    if (empty()) {
        return false;
    }
    const auto try_entail = [&](const LinearExpression& e) { return values.entail(LinearConstraint{e, query.kind()}); };

    // (a) Canonicalize: rewrite each query variable to a DBM-proven-equal variable that
    // appears in some stored fact. Replacing v (coeff q) with w adds q*(w - v); sound
    // because the DBM proves v == w. This bridges register copies (e.g. the call passes
    // r2 where a fact is phrased over the register r2 was copied from).
    std::set<Variable> fact_vars;
    for (const auto& [key, expr] : equalities) {
        fact_vars.insert(key);
        for (const auto& [v, c] : expr.variable_terms()) {
            fact_vars.insert(v);
        }
    }
    for (const LinearExpression& b : bounds) {
        for (const auto& [v, c] : b.variable_terms()) {
            fact_vars.insert(v);
        }
    }
    LinearExpression current = query.expression();
    for (const auto& [v, q] : query.expression().variable_terms()) {
        if (fact_vars.contains(v)) {
            continue;
        }
        for (const Variable w : fact_vars) {
            if (v != w && values.entail(eq(v, w))) {
                current = current.plus((LinearExpression{w}.subtract(v)).multiply(q));
                break;
            }
        }
    }

    // (b) Use derived bounds. For a `<= 0` query Q and a stored bound `D <= 0`, Q holds
    // if `Q - D <= 0` is DBM-provable (D <= 0 and Q <= D imply Q <= 0). Only valid for
    // the LESS_THAN_OR_EQUALS_ZERO kind.
    const auto expression_is_proved = [&](const LinearExpression& expression) {
        if (try_entail(expression)) {
            return true;
        }
        if (query.kind() == ConstraintKind::LESS_THAN_OR_EQUALS_ZERO) {
            for (const LinearExpression& d : bounds) {
                if (try_entail(expression.subtract(d))) {
                    return true;
                }
            }
        }
        return false;
    };
    if (expression_is_proved(current)) {
        return true;
    }

    // (c) Eliminate variables via stored equalities. Each `key == expr` is the identity
    // `key - expr == 0`; adding -(q/d)*(key - expr) cancels a shared variable v when q/d
    // is integral. Explore alternatives instead of mutating one greedy chain: an unrelated
    // earlier equality must not prevent a later applicable equality from being tried.
    // Every path uses each equality at most once, so the worklist is finite. This restriction
    // can only lose proofs; every enqueued rewrite still adds a multiple of a known zero.
    // An identity disconnected from the query cannot become applicable: rewrites
    // introduce only variables from an identity already sharing a variable with
    // the current expression. Compute that connected component before enforcing
    // the identity budget so unrelated must-facts do not suppress valid proofs.
    std::set<Variable> connected_variables;
    for (const auto& [v, q] : current.variable_terms()) {
        connected_variables.insert(v);
    }
    std::set<const EqualityStore::value_type*> selected_equalities;
    std::vector<LinearExpression> identities;
    bool component_grew = true;
    while (component_grew) {
        component_grew = false;
        for (const auto& equality : equalities) {
            if (selected_equalities.contains(&equality)) {
                continue;
            }
            LinearExpression identity = LinearExpression{equality.first}.subtract(equality.second);
            const bool connected = std::ranges::any_of(
                identity.variable_terms(), [&](const auto& term) { return connected_variables.contains(term.first); });
            if (!connected) {
                continue;
            }
            if (identities.size() >= MAX_REWRITE_IDENTITIES) {
                return false;
            }
            selected_equalities.insert(&equality);
            for (const auto& [v, c] : identity.variable_terms()) {
                connected_variables.insert(v);
            }
            identities.push_back(std::move(identity));
            component_grew = true;
        }
    }
    struct RewriteState {
        LinearExpression expression;
        std::vector<bool> used_equalities;
    };
    const auto used_subset = [](const std::vector<bool>& a, const std::vector<bool>& b) {
        for (size_t i = 0; i < a.size(); ++i) {
            if (a[i] && !b[i]) {
                return false;
            }
        }
        return true;
    };
    std::vector<RewriteState> worklist{{current, std::vector<bool>(identities.size())}};
    std::vector<RewriteState> seen = worklist;
    size_t transitions = 0;
    for (size_t cursor = 0; cursor < worklist.size(); ++cursor) {
        const RewriteState state = worklist[cursor];
        for (size_t i = 0; i < identities.size(); ++i) {
            if (state.used_equalities[i]) {
                continue;
            }
            const LinearExpression& identity = identities[i];
            for (const auto& [v, q] : state.expression.variable_terms()) {
                const auto d_it = identity.variable_terms().find(v);
                if (d_it == identity.variable_terms().end() || d_it->second == 0 || q % d_it->second != 0) {
                    continue;
                }
                if (transitions >= MAX_REWRITE_TRANSITIONS) {
                    return false;
                }
                ++transitions;
                LinearExpression candidate = state.expression.plus(identity.multiply(-(q / d_it->second)));
                if (expression_is_proved(candidate)) {
                    return true;
                }
                std::vector<bool> used = state.used_equalities;
                used[i] = true;
                const bool dominated = std::any_of(seen.begin(), seen.end(), [&](const RewriteState& prior) {
                    return expressions_equal(prior.expression, candidate) && used_subset(prior.used_equalities, used);
                });
                if (!dominated) {
                    if (worklist.size() >= MAX_REWRITE_STATES) {
                        return false;
                    }
                    RewriteState next{std::move(candidate), std::move(used)};
                    seen.push_back(next);
                    worklist.push_back(std::move(next));
                }
            }
        }
    }
    return false;
}

} // namespace prevail

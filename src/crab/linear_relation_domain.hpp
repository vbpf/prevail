// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <algorithm>
#include <map>
#include <vector>

#include "arith/linear_constraint.hpp"
#include "arith/linear_expression.hpp"
#include "arith/variable.hpp"

namespace prevail {

// Holds linear must-facts the numeric domain (a DBM) cannot represent because they
// relate three or more variables:
//   equalities: `key == value`   (recorded when a pointer advances by a scalar)
//   bounds:     `expr <= 0`       (derived at a pointer comparison)
//
// Motivating case: `mid = ptr + len; if (mid <= end) ...; use(ptr, len)`. The check
// leaves the DBM knowing `mid.offset <= end`, but the later access is phrased over
// `ptr.offset + len`, a three-variable sum the DBM cannot hold. Recording
// `mid.offset == ptr.offset + len` lets the checker substitute it back and discharge
// the access against the two-variable bound the DBM already has. Facts are dropped
// whenever a variable they mention is written (invalidate_for). Joins and widening
// intersect facts; meet and narrowing combine them as a conjunction.
struct LinearRelationDomain {
    // Transfers keep at most one equality per key. Meet/narrow may retain multiple
    // equalities for the same key because their conjunction is more precise than
    // either operand and must remain below both operands in the lattice.
    using EqualityStore = std::multimap<Variable, LinearExpression>;
    EqualityStore equalities;
    std::vector<LinearExpression> bounds;

    // Not operator==: dsl_syntax overloads that to build a LinearConstraint. Equal
    // expressions have identical constant term and (zero-dropped) variable-term map.
    [[nodiscard]]
    static bool expressions_equal(const LinearExpression& a, const LinearExpression& b) {
        return a.constant_term() == b.constant_term() && a.variable_terms() == b.variable_terms();
    }

    [[nodiscard]]
    static bool contains_equality(const EqualityStore& store, const Variable key, const LinearExpression& value) {
        const auto [first, last] = store.equal_range(key);
        return std::any_of(first, last, [&](const auto& entry) { return expressions_equal(entry.second, value); });
    }

    [[nodiscard]]
    bool empty() const {
        return equalities.empty() && bounds.empty();
    }
    void clear() {
        equalities.clear();
        bounds.clear();
    }
    void set_equality(const Variable key, LinearExpression value) {
        equalities.erase(key);
        equalities.emplace(key, std::move(value));
    }
    void add_bound(LinearExpression le_zero) {
        for (const LinearExpression& b : bounds) {
            if (expressions_equal(b, le_zero)) {
                return;
            }
        }
        bounds.push_back(std::move(le_zero));
    }

    // Drop every fact mentioning `v` (as an equality key, in an equality value, or in a
    // bound). The soundness lever: called wherever `v` is written or havoced.
    void invalidate_for(const Variable v) {
        std::erase_if(equalities, [v](const auto& kv) {
            const auto& [key, value] = kv;
            return key == v || value.variable_terms().contains(v);
        });
        std::erase_if(bounds, [v](const LinearExpression& b) { return b.variable_terms().contains(v); });
    }

    [[nodiscard]]
    static LinearRelationDomain intersect(const LinearRelationDomain& a, const LinearRelationDomain& b) {
        LinearRelationDomain result;
        // Join/widen keep a fact only if both sides carry it identically.
        const auto& small = a.equalities.size() <= b.equalities.size() ? a.equalities : b.equalities;
        const auto& large = a.equalities.size() <= b.equalities.size() ? b.equalities : a.equalities;
        for (const auto& [key, expr] : small) {
            if (contains_equality(large, key, expr) && !contains_equality(result.equalities, key, expr)) {
                result.equalities.emplace(key, expr);
            }
        }
        for (const LinearExpression& ba : a.bounds) {
            for (const LinearExpression& bb : b.bounds) {
                if (expressions_equal(ba, bb)) {
                    result.bounds.push_back(ba);
                    break;
                }
            }
        }
        return result;
    }

    [[nodiscard]]
    static LinearRelationDomain combine(const LinearRelationDomain& a, const LinearRelationDomain& b) {
        LinearRelationDomain result = a;
        // Meet is conjunction for must-facts: every fact from either operand remains
        // true in their concrete intersection. Deduplication keeps the representation
        // idempotent without discarding distinct facts that happen to share a key.
        for (const auto& [key, expr] : b.equalities) {
            if (!contains_equality(result.equalities, key, expr)) {
                result.equalities.emplace(key, expr);
            }
        }
        for (const LinearExpression& bound : b.bounds) {
            result.add_bound(bound);
        }
        return result;
    }

    [[nodiscard]]
    bool has_all_facts_of(const LinearRelationDomain& other) const {
        for (const auto& [key, expr] : other.equalities) {
            if (!contains_equality(equalities, key, expr)) {
                return false;
            }
        }
        for (const LinearExpression& ob : other.bounds) {
            const bool present = std::any_of(bounds.begin(), bounds.end(),
                                             [&](const LinearExpression& b) { return expressions_equal(b, ob); });
            if (!present) {
                return false;
            }
        }
        return true;
    }
};

} // namespace prevail

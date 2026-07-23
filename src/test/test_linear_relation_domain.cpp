// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "arith/dsl_syntax.hpp"
#include "crab/linear_relation_domain.hpp"
#include "crab/var_registry.hpp"

using namespace prevail;

TEST_CASE("LinearRelationDomain stores and clears facts", "[relations]") {
    const Variable a = variable_registry.reg(DataKind::svalues, 1);
    const Variable b = variable_registry.reg(DataKind::svalues, 2);
    LinearRelationDomain d;
    REQUIRE(d.empty());
    d.set_equality(a, LinearExpression{b}.plus(4));
    REQUIRE_FALSE(d.empty());
    d.add_bound(LinearExpression{a}.subtract(b));
    REQUIRE_FALSE(d.empty());
    d.clear();
    REQUIRE(d.empty());
}

TEST_CASE("LinearRelationDomain::invalidate_for drops by any mention", "[relations]") {
    const Variable a = variable_registry.reg(DataKind::svalues, 1);
    const Variable b = variable_registry.reg(DataKind::svalues, 2);
    const Variable c = variable_registry.reg(DataKind::svalues, 3);
    LinearRelationDomain d;
    d.set_equality(a, LinearExpression{b}.plus(c)); // a == b + c
    d.add_bound(LinearExpression{b}.subtract(c));   // b - c <= 0

    d.invalidate_for(b);           // mentions b as key? no; in expr/bound? yes both
    REQUIRE(d.equalities.empty()); // a==b+c dropped (b in value)
    REQUIRE(d.bounds.empty());     // b-c<=0 dropped (b in bound)
}

TEST_CASE("LinearRelationDomain::invalidate_for drops equality by key", "[relations]") {
    const Variable a = variable_registry.reg(DataKind::svalues, 1);
    const Variable b = variable_registry.reg(DataKind::svalues, 2);
    LinearRelationDomain d;
    d.set_equality(a, LinearExpression{b});
    d.invalidate_for(a);
    REQUIRE(d.equalities.empty());
}

// Retention: invalidation must drop only facts mentioning the variable and must
// leave every unrelated fact intact. This rules out over-erasure.
TEST_CASE("LinearRelationDomain::invalidate_for retains unrelated facts", "[relations]") {
    const Variable a = variable_registry.reg(DataKind::svalues, 1);
    const Variable b = variable_registry.reg(DataKind::svalues, 2);
    const Variable c = variable_registry.reg(DataKind::svalues, 3);
    LinearRelationDomain d;
    d.set_equality(a, LinearExpression{b}); // a == b   (mentions b)
    d.set_equality(c, LinearExpression{7}); // c == 7   (constant only, no b)

    d.invalidate_for(b);
    REQUIRE(d.equalities.size() == 1);   // only a == b dropped
    REQUIRE(d.equalities.count(c) == 1); // c == 7 survives untouched
}

// expressions_equal is order-insensitive on the canonical form: a + 4 built two
// different ways compares equal, and a genuinely different expression does not.
TEST_CASE("expressions_equal compares canonical form", "[relations]") {
    const Variable a = variable_registry.reg(DataKind::svalues, 1);
    const LinearExpression a_plus_4 = LinearExpression{a}.plus(4);    // a + 4
    const LinearExpression four_plus_a = LinearExpression{4}.plus(a); // 4 + a
    REQUIRE(LinearRelationDomain::expressions_equal(a_plus_4, four_plus_a));
    REQUIRE_FALSE(LinearRelationDomain::expressions_equal(a_plus_4, LinearExpression{a}.plus(5)));
}

TEST_CASE("LinearRelationDomain::intersect keeps only shared, identical facts", "[relations]") {
    const Variable a = variable_registry.reg(DataKind::svalues, 1);
    const Variable b = variable_registry.reg(DataKind::svalues, 2);
    const Variable c = variable_registry.reg(DataKind::svalues, 3);
    LinearRelationDomain x, y;
    x.set_equality(a, LinearExpression{b}); // a == b   (both)
    y.set_equality(a, LinearExpression{b});
    x.set_equality(c, LinearExpression{b});       // c == b   (x only)
    x.add_bound(LinearExpression{a}.subtract(b)); // a-b<=0   (both)
    y.add_bound(LinearExpression{a}.subtract(b));
    y.add_bound(LinearExpression{c}); // c<=0     (y only)

    const LinearRelationDomain r = LinearRelationDomain::intersect(x, y);
    REQUIRE(r.equalities.size() == 1);
    REQUIRE(r.equalities.count(a) == 1);
    REQUIRE(r.bounds.size() == 1);
}

TEST_CASE("LinearRelationDomain::combine retains facts from both operands", "[relations]") {
    const Variable key = variable_registry.reg(DataKind::packet_offsets, 8);
    const Variable left_base = variable_registry.reg(DataKind::packet_offsets, 6);
    const Variable right_base = variable_registry.reg(DataKind::packet_offsets, 7);
    const Variable len = variable_registry.reg(DataKind::svalues, 4);
    LinearRelationDomain left, right;
    left.set_equality(key, LinearExpression{left_base}.plus(len));
    left.add_bound(LinearExpression{left_base}.plus(len));
    right.set_equality(key, LinearExpression{right_base}.plus(len));
    right.add_bound(LinearExpression{right_base}.plus(len));

    const LinearRelationDomain combined = LinearRelationDomain::combine(left, right);

    // Both same-key equalities are conjuncts of the concrete meet. Keeping only
    // one would make the result fail to be below the other operand.
    REQUIRE(combined.equalities.count(key) == 2);
    REQUIRE(combined.bounds.size() == 2);
    REQUIRE(combined.has_all_facts_of(left));
    REQUIRE(combined.has_all_facts_of(right));
}

TEST_CASE("LinearRelationDomain::has_all_facts_of", "[relations]") {
    const Variable a = variable_registry.reg(DataKind::svalues, 1);
    const Variable b = variable_registry.reg(DataKind::svalues, 2);
    LinearRelationDomain more, less;
    more.set_equality(a, LinearExpression{b});
    more.add_bound(LinearExpression{a});
    less.set_equality(a, LinearExpression{b});
    REQUIRE(more.has_all_facts_of(less));       // more >= less's facts
    REQUIRE_FALSE(less.has_all_facts_of(more)); // less lacks the bound
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "arith/dsl_syntax.hpp"
#include "crab/linear_relation_domain.hpp"
#include "crab/type_to_num.hpp" // for NumAbsDomain alias
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

TEST_CASE("LinearRelationDomain::entails proves a 3-var query via a stored equality", "[relations]") {
    using namespace dsl_syntax;
    const Variable mid = variable_registry.reg(DataKind::packet_offsets, 8);
    const Variable base = variable_registry.reg(DataKind::packet_offsets, 6);
    const Variable len = variable_registry.reg(DataKind::svalues, 4);
    const Variable ceiling = variable_registry.packet_size();

    NumAbsDomain values = NumAbsDomain::top();
    // DBM knows the 2-var bound on the intermediate: mid <= ceiling.
    values.add_constraint(mid - ceiling <= 0);

    LinearRelationDomain d;
    // Equality: mid == base + len.
    d.set_equality(mid, LinearExpression{base}.plus(len));

    // Query is the 3-var form the DBM alone cannot prove: base + len <= ceiling.
    const LinearConstraint query = (LinearExpression{base}.plus(len)) <= LinearExpression{ceiling};
    REQUIRE_FALSE(values.entail(query)); // DBM alone: no
    REQUIRE(d.entails(values, query));   // with equality substitution: yes
}

TEST_CASE("LinearRelationDomain::entails tries alternative equalities", "[relations]") {
    using namespace dsl_syntax;
    const Variable base = variable_registry.reg(DataKind::packet_offsets, 6);
    const Variable unrelated_mid = variable_registry.reg(DataKind::packet_offsets, 8);
    const Variable needed_mid = variable_registry.reg(DataKind::packet_offsets, 9);
    const Variable unrelated_len = variable_registry.reg(DataKind::svalues, 3);
    const Variable needed_len = variable_registry.reg(DataKind::svalues, 4);
    const Variable ceiling = variable_registry.packet_size();

    NumAbsDomain values = NumAbsDomain::top();
    values.add_constraint(needed_mid - ceiling <= 0);

    LinearRelationDomain d;
    // The lower-keyed equality is considered first and shares `base` with the
    // query, but substituting it cannot prove the query.
    d.set_equality(unrelated_mid, LinearExpression{base}.plus(unrelated_len));
    d.set_equality(needed_mid, LinearExpression{base}.plus(needed_len));

    const LinearConstraint query = (LinearExpression{base}.plus(needed_len)) <= LinearExpression{ceiling};
    REQUIRE_FALSE(values.entail(query));
    REQUIRE(d.entails(values, query));
}

TEST_CASE("LinearRelationDomain::entails rejects an unprovable query", "[relations]") {
    using namespace dsl_syntax;
    const Variable base = variable_registry.reg(DataKind::packet_offsets, 6);
    const Variable len = variable_registry.reg(DataKind::svalues, 4);
    const Variable ceiling = variable_registry.packet_size();
    NumAbsDomain values = NumAbsDomain::top(); // knows nothing
    LinearRelationDomain d;
    const LinearConstraint query = (LinearExpression{base}.plus(len)) <= LinearExpression{ceiling};
    REQUIRE_FALSE(d.entails(values, query));
}

// Isolates step (a), canonicalization. The DBM proves copy == orig but does NOT
// know orig's value; the only stored fact (orig == 5) is phrased over orig. The
// query is phrased over copy and shares no variable with the fact, so step (b)
// cannot latch onto any shared variable without first rewriting copy -> orig.
// Thus the proof exists ONLY if canonicalization fires.
TEST_CASE("LinearRelationDomain::entails proves a query via DBM canonicalization (step a)", "[relations]") {
    using namespace dsl_syntax;
    const Variable orig = variable_registry.reg(DataKind::packet_offsets, 10);
    const Variable copy = variable_registry.reg(DataKind::packet_offsets, 11);

    NumAbsDomain values = NumAbsDomain::top();
    values.add_constraint(copy - orig == 0); // DBM proves copy == orig (register copy)

    LinearRelationDomain d;
    d.set_equality(orig, LinearExpression{5}); // fact phrased over orig: orig == 5

    // Query phrased over copy: copy <= 5. The DBM knows copy == orig but not orig's
    // value, and step (b) has no shared variable to eliminate (the fact never mentions
    // copy). Only canonicalizing copy -> orig lets the stored equality collapse it.
    const LinearConstraint query = LinearExpression{copy} <= LinearExpression{5};
    REQUIRE_FALSE(values.entail(query)); // DBM alone: no
    REQUIRE(d.entails(values, query));   // canonicalize copy->orig, then eliminate: yes
}

// Isolates step (c), bound subtraction. No equalities are stored (so step (b) never
// runs and step (a) has nothing to canonicalize against a copy), and the DBM is top.
// The weaker query a + b <= c + 5 follows only by subtracting the stored bound
// a + b - c <= 0, leaving the constant -5 <= 0 for the DBM to discharge.
TEST_CASE("LinearRelationDomain::entails proves a <=0 query via a stored bound (step c)", "[relations]") {
    using namespace dsl_syntax;
    const Variable a = variable_registry.reg(DataKind::packet_offsets, 12);
    const Variable b = variable_registry.reg(DataKind::svalues, 13);
    const Variable c = variable_registry.packet_size();

    NumAbsDomain values = NumAbsDomain::top(); // no numeric facts

    LinearRelationDomain d;
    // Stored derived bound: a + b - c <= 0  (i.e. a + b <= c).
    d.add_bound(LinearExpression{a}.plus(b).subtract(c));

    // Weaker query: a + b <= c + 5. Provable only by subtracting the stored bound:
    // (a + b - c - 5) - (a + b - c) = -5 <= 0. No equalities exist to prove it otherwise.
    const LinearConstraint query = (LinearExpression{a}.plus(b)) <= (LinearExpression{c}.plus(5));
    REQUIRE_FALSE(values.entail(query)); // DBM alone: no
    REQUIRE(d.entails(values, query));   // via stored bound: yes
}

// Facts AND DBM constraints are present, but the query is genuinely false. The facts
// yield base + len <= ceiling (non-strict); the STRICT form base + len < ceiling does
// not follow, and step (c) is gated to LESS_THAN_OR_EQUALS_ZERO so it cannot apply.
// This proves the rewrite machinery cannot fabricate a proof of a false query.
TEST_CASE("LinearRelationDomain::entails rejects a false query despite present facts", "[relations]") {
    using namespace dsl_syntax;
    const Variable mid = variable_registry.reg(DataKind::packet_offsets, 14);
    const Variable base = variable_registry.reg(DataKind::packet_offsets, 15);
    const Variable len = variable_registry.reg(DataKind::svalues, 16);
    const Variable ceiling = variable_registry.packet_size();

    NumAbsDomain values = NumAbsDomain::top();
    values.add_constraint(mid - ceiling <= 0); // mid <= ceiling

    LinearRelationDomain d;
    d.set_equality(mid, LinearExpression{base}.plus(len)); // mid == base + len
    d.add_bound(LinearExpression{mid}.subtract(ceiling));  // mid - ceiling <= 0

    // base + len <= ceiling holds, but the strict inequality does not.
    const LinearConstraint query = (LinearExpression{base}.plus(len)) < LinearExpression{ceiling};
    REQUIRE_FALSE(values.entail(query));
    REQUIRE_FALSE(d.entails(values, query)); // rewrite machinery cannot fabricate `< 0`
}

// add_bound is dedup-on-add: adding a structurally-equal bound twice keeps one copy,
// but a genuinely different bound is stored separately. Keeps the vector small so the
// intersect/has_all_facts_of quadratic scans stay cheap across loop fixpoints.
TEST_CASE("LinearRelationDomain::add_bound deduplicates structurally-equal bounds", "[relations]") {
    const Variable a = variable_registry.reg(DataKind::svalues, 1);
    const Variable b = variable_registry.reg(DataKind::svalues, 2);
    LinearRelationDomain d;
    d.add_bound(LinearExpression{a}.subtract(b)); // a - b <= 0
    d.add_bound(LinearExpression{a}.subtract(b)); // same bound again
    REQUIRE(d.bounds.size() == 1);
    d.add_bound(LinearExpression{b}.subtract(a)); // b - a <= 0 (different)
    REQUIRE(d.bounds.size() == 2);
}

TEST_CASE("LinearRelationDomain::derive_bound substitutes equality into a bound", "[relations]") {
    const Variable mid = variable_registry.reg(DataKind::packet_offsets, 8);
    const Variable base = variable_registry.reg(DataKind::packet_offsets, 6);
    const Variable len = variable_registry.reg(DataKind::svalues, 4);
    const Variable end = variable_registry.reg(DataKind::packet_offsets, 7);
    LinearRelationDomain d;
    d.set_equality(mid, LinearExpression{base}.plus(len)); // mid == base + len
    // Comparison established: mid - end <= 0. With a top() DBM no equality is proven,
    // so canonicalization is a no-op and only the equality substitution applies.
    d.derive_bound(NumAbsDomain::top(), mid, LinearExpression{mid}.subtract(end));
    // Expect a stored bound equivalent to base + len - end <= 0 (no `mid`).
    REQUIRE(d.bounds.size() == 1);
    REQUIRE_FALSE(d.bounds[0].variable_terms().contains(mid));
    // base, len, end all present.
    REQUIRE(d.bounds[0].variable_terms().contains(base));
    REQUIRE(d.bounds[0].variable_terms().contains(len));
    REQUIRE(d.bounds[0].variable_terms().contains(end));
}

TEST_CASE("LinearRelationDomain::derive_bound is a no-op without a matching equality", "[relations]") {
    const Variable mid = variable_registry.reg(DataKind::packet_offsets, 8);
    const Variable end = variable_registry.reg(DataKind::packet_offsets, 7);
    LinearRelationDomain d;
    d.derive_bound(NumAbsDomain::top(), mid, LinearExpression{mid}.subtract(end));
    REQUIRE(d.bounds.empty());
}

// Derivation-time canonicalization: after substituting the equality, each variable of
// the derived bound is rewritten to a write-stable global the DBM currently proves it
// equal to. Here the ceiling `ceil` is proven equal to packet_size; the stored bound
// must be phrased over packet_size (which outlives `ceil` being recycled) and must not
// mention `ceil` (canonicalized away) nor `mid` (substituted away).
TEST_CASE("LinearRelationDomain::derive_bound canonicalizes to a stable global", "[relations]") {
    using namespace dsl_syntax;
    const Variable mid = variable_registry.reg(DataKind::packet_offsets, 8);
    const Variable base = variable_registry.reg(DataKind::packet_offsets, 6);
    const Variable len = variable_registry.reg(DataKind::svalues, 4);
    const Variable ceil = variable_registry.reg(DataKind::packet_offsets, 7);
    const Variable pkt = variable_registry.packet_size();

    NumAbsDomain values = NumAbsDomain::top();
    values.add_constraint(ceil - pkt == 0); // DBM proves ceil == packet_size

    LinearRelationDomain d;
    d.set_equality(mid, LinearExpression{base}.plus(len)); // mid == base + len
    // Comparison established: mid - ceil <= 0.
    d.derive_bound(values, mid, LinearExpression{mid}.subtract(ceil));

    REQUIRE(d.bounds.size() == 1);
    REQUIRE_FALSE(d.bounds[0].variable_terms().contains(mid));  // substituted away
    REQUIRE_FALSE(d.bounds[0].variable_terms().contains(ceil)); // canonicalized away
    REQUIRE(d.bounds[0].variable_terms().contains(pkt));        // rewritten to stable global
    REQUIRE(d.bounds[0].variable_terms().contains(base));
    REQUIRE(d.bounds[0].variable_terms().contains(len));
}

// Companion to the packet_size canonicalization test: meta_offset is the OTHER
// write-stable global in the canonicalization target set, so a bound variable the
// DBM proves equal to meta_offset must be rewritten to meta_offset. Guards against
// hardcoding packet_size as the sole target.
TEST_CASE("LinearRelationDomain::derive_bound canonicalizes to meta_offset", "[relations]") {
    using namespace dsl_syntax;
    const Variable mid = variable_registry.reg(DataKind::packet_offsets, 8);
    const Variable base = variable_registry.reg(DataKind::packet_offsets, 6);
    const Variable len = variable_registry.reg(DataKind::svalues, 4);
    const Variable floor = variable_registry.reg(DataKind::packet_offsets, 7);
    const Variable meta = variable_registry.meta_offset();

    NumAbsDomain values = NumAbsDomain::top();
    values.add_constraint(floor - meta == 0); // DBM proves floor == meta_offset

    LinearRelationDomain d;
    d.set_equality(mid, LinearExpression{base}.plus(len)); // mid == base + len
    // Comparison established: mid - floor <= 0.
    d.derive_bound(values, mid, LinearExpression{mid}.subtract(floor));

    REQUIRE(d.bounds.size() == 1);
    REQUIRE_FALSE(d.bounds[0].variable_terms().contains(mid));   // substituted away
    REQUIRE_FALSE(d.bounds[0].variable_terms().contains(floor)); // canonicalized away
    REQUIRE(d.bounds[0].variable_terms().contains(meta));        // rewritten to stable global
    REQUIRE(d.bounds[0].variable_terms().contains(base));
    REQUIRE(d.bounds[0].variable_terms().contains(len));
}

// Coefficient accumulation: two DISTINCT bound variables both proven equal to the
// SAME stable global must collapse into a single term whose coefficient is the sum.
// Start with `a + b - c <= 0` where the DBM proves a == packet_size and b ==
// packet_size (and derive over a trivial equality that leaves a,b,c untouched). The
// canonicalized bound must carry packet_size with coefficient 2 (1 from a, 1 from b),
// -1 for c, and neither a nor b.
TEST_CASE("LinearRelationDomain::derive_bound accumulates coefficients on a shared global", "[relations]") {
    using namespace dsl_syntax;
    const Variable mid = variable_registry.reg(DataKind::packet_offsets, 20);
    const Variable a = variable_registry.reg(DataKind::packet_offsets, 21);
    const Variable b = variable_registry.reg(DataKind::packet_offsets, 22);
    const Variable c = variable_registry.reg(DataKind::packet_offsets, 23);
    const Variable pkt = variable_registry.packet_size();

    NumAbsDomain values = NumAbsDomain::top();
    values.add_constraint(a - pkt == 0); // DBM proves a == packet_size
    values.add_constraint(b - pkt == 0); // DBM proves b == packet_size

    LinearRelationDomain d;
    d.set_equality(mid, LinearExpression{a}.plus(b)); // mid == a + b
    // Comparison established: mid - c <= 0. Substituting mid yields a + b - c <= 0;
    // then a and b are each proven == packet_size, so both collapse onto pkt.
    d.derive_bound(values, mid, LinearExpression{mid}.subtract(c));

    REQUIRE(d.bounds.size() == 1);
    const LinearExpression& bound = d.bounds[0];
    REQUIRE_FALSE(bound.variable_terms().contains(mid)); // substituted away
    REQUIRE_FALSE(bound.variable_terms().contains(a));   // canonicalized to pkt
    REQUIRE_FALSE(bound.variable_terms().contains(b));   // canonicalized to pkt
    REQUIRE(bound.variable_terms().contains(pkt));
    REQUIRE(bound.variable_terms().at(pkt) == 2); // 1 (from a) + 1 (from b)
    REQUIRE(bound.variable_terms().at(c) == -1);  // c left untouched
    REQUIRE(bound.variable_terms().size() == 2);  // exactly {pkt, c}
}

// Pins Fix 2: on a bottom `values`, AddBottom::entail returns true vacuously, which
// would otherwise make the canonicalization believe the compared var equals
// packet_size and store a garbage bound. The is_bottom() guard must make derive_bound
// a no-op instead.
TEST_CASE("LinearRelationDomain::derive_bound is a no-op on bottom values", "[relations]") {
    using namespace dsl_syntax;
    const Variable mid = variable_registry.reg(DataKind::packet_offsets, 8);
    const Variable end = variable_registry.reg(DataKind::packet_offsets, 7);

    const NumAbsDomain values = NumAbsDomain::bottom();

    LinearRelationDomain d;
    d.set_equality(mid, LinearExpression{end}); // a matching equality exists for mid
    // Without the guard, canonicalization on a bottom domain would fire and store a
    // bound; the guard must short-circuit before any bound is added.
    d.derive_bound(values, mid, LinearExpression{mid}.subtract(end));
    REQUIRE(d.bounds.empty());
}

TEST_CASE("TypeToNumDomain meet and narrow conjoin relation facts", "[relations][lattice]") {
    const Variable mid = variable_registry.reg(DataKind::packet_offsets, 8);
    const Variable base = variable_registry.reg(DataKind::packet_offsets, 6);
    const Variable len = variable_registry.reg(DataKind::svalues, 4);

    TypeToNumDomain with_fact = TypeToNumDomain::top();
    with_fact.record_equality(mid, LinearExpression{base}.plus(len));
    TypeToNumDomain without_fact = TypeToNumDomain::top();

    const TypeToNumDomain meet = with_fact & without_fact;
    REQUIRE(meet.relations.has_all_facts_of(with_fact.relations));
    REQUIRE(meet <= with_fact);
    REQUIRE(meet <= without_fact);

    const TypeToNumDomain narrowed = without_fact.narrow(with_fact);
    REQUIRE(narrowed.relations.has_all_facts_of(with_fact.relations));
    REQUIRE(narrowed <= with_fact);
    REQUIRE(narrowed <= without_fact);
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// Unit tests for the DSU-based TypeDomain.

#include <catch2/catch_all.hpp>

#include "arith/dsl_syntax.hpp"
#include "crab/type_domain.hpp"
#include "crab/type_encoding.hpp"
#include "crab/var_registry.hpp"

using namespace prevail;

static constexpr Reg r0{0};
static constexpr Reg r1{1};
static constexpr Reg r2{2};
static constexpr Reg r3{3};

// ============================================================================
// Basic top / bottom
// ============================================================================

TEST_CASE("TypeDomain top is not bottom", "[type_domain]") {
    const TypeDomain td;
    REQUIRE(!td.is_bottom());
}

TEST_CASE("TypeDomain bottom is bottom", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    td.assign_type(r0, T_CTX);
    td.add_constraint(reg_type(r0) == T_NUM); // intersect {ctx} & {num} = empty
    REQUIRE(td.is_bottom());
}

// ============================================================================
// Assignment and query
// ============================================================================

TEST_CASE("assign type encoding and get", "[type_domain]") {
    TypeDomain td;
    td.assign_type(r0, T_NUM);
    REQUIRE(td.get_type(r0) == T_NUM);
}

TEST_CASE("assign type from register copies type and tracks equality", "[type_domain]") {
    TypeDomain td;
    td.assign_type(r0, T_STACK);
    td.assign_type(r1, r0);
    REQUIRE(td.get_type(r1) == T_STACK);
    REQUIRE(td.same_type(r0, r1));
}

TEST_CASE("havoc makes type unknown", "[type_domain]") {
    TypeDomain td;
    td.assign_type(r0, T_CTX);
    td.havoc_type(r0);
    // After havoc, type is top (all types) — not a singleton.
    REQUIRE(!td.get_type(r0).has_value()); // non-singleton returns nullopt
    // All types are possible.
    REQUIRE(td.may_have_type(r0, T_NUM));
    REQUIRE(td.may_have_type(r0, T_CTX));
    REQUIRE(td.may_have_type(r0, T_SHARED));
}

TEST_CASE("havoc detaches from equality class", "[type_domain]") {
    TypeDomain td;
    td.assign_type(r0, T_CTX);
    td.assign_type(r1, r0);
    REQUIRE(td.same_type(r0, r1));
    td.havoc_type(r1);
    REQUIRE(!td.same_type(r0, r1));
    REQUIRE(td.get_type(r0) == T_CTX); // r0 unchanged
}

// ============================================================================
// iterate_types
// ============================================================================

TEST_CASE("iterate_types returns singleton", "[type_domain]") {
    TypeDomain td;
    td.assign_type(r0, T_CTX);
    const auto types = td.iterate_types(r0);
    REQUIRE(types.size() == 1);
    REQUIRE(types[0] == T_CTX);
}

TEST_CASE("iterate_types returns exact non-convex set", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    // Restrict to {map_fd, shared} — non-adjacent types.
    const Variable v = reg_type(r0);
    td.restrict_to(v, TypeSet::singleton(T_MAP) | TypeSet::singleton(T_SHARED));
    const auto types = td.iterate_types(r0);
    // Must return exactly {map_fd, shared}, not the convex hull.
    REQUIRE(types.size() == 2);
    REQUIRE(std::find(types.begin(), types.end(), T_MAP) != types.end());
    REQUIRE(std::find(types.begin(), types.end(), T_SHARED) != types.end());
    // Must NOT contain spurious types from the interval.
    REQUIRE(std::find(types.begin(), types.end(), T_NUM) == types.end());
    REQUIRE(std::find(types.begin(), types.end(), T_CTX) == types.end());
}

TEST_CASE("get_type returns nullopt for non-singleton set", "[type_domain]") {
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_STACK));
    REQUIRE(!td.get_type(r0).has_value());
}

// ============================================================================
// Type group checks
// ============================================================================

TEST_CASE("is_in_group checks subset of group", "[type_domain]") {
    TypeDomain td;
    td.assign_type(r0, T_CTX);
    REQUIRE(td.is_in_group(r0, TypeGroup::pointer));
    REQUIRE(td.is_in_group(r0, TypeGroup::ctx));
    REQUIRE(td.is_in_group(r0, TypeGroup::singleton_ptr));
    REQUIRE(!td.is_in_group(r0, TypeGroup::number));
    REQUIRE(!td.is_in_group(r0, TypeGroup::mem));
}

TEST_CASE("type query predicates", "[type_domain]") {
    TypeDomain td;
    td.assign_type(r0, T_NUM);
    td.assign_type(r1, T_CTX);
    REQUIRE(td.type_is_number(r0));
    REQUIRE(!td.type_is_number(r1));
    REQUIRE(td.type_is_pointer(r1));
    REQUIRE(!td.type_is_pointer(r0));
    REQUIRE(td.type_is_not_stack(r0));
    REQUIRE(td.type_is_not_stack(r1));
    REQUIRE(td.type_is_not_number(r1));
    REQUIRE(!td.type_is_not_number(r0));
}

// ============================================================================
// Constraint handling
// ============================================================================

TEST_CASE("add_constraint restricts to singleton", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    td.add_constraint(reg_type(r0) == T_PACKET);
    REQUIRE(td.get_type(r0) == T_PACKET);
}

TEST_CASE("add_constraint removes a type via !=", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_NUM) | TypeSet::singleton(T_CTX));
    td.add_constraint(reg_type(r0) != T_NUM);
    REQUIRE(td.get_type(r0) == T_CTX);
}

TEST_CASE("add_constraint unifies variables via ==", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_MAP) | TypeSet::singleton(T_CTX));
    td.restrict_to(reg_type(r1), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_SHARED));
    td.add_constraint(eq(reg_type(r0), reg_type(r1)));
    // Intersection: {ctx}
    REQUIRE(td.get_type(r0) == T_CTX);
    REQUIRE(td.get_type(r1) == T_CTX);
    REQUIRE(td.same_type(r0, r1));
}

TEST_CASE("add_constraint conflicting singleton goes to bottom", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    td.assign_type(r0, T_MAP);
    td.add_constraint(reg_type(r0) == T_SHARED);
    REQUIRE(td.is_bottom());
}

// ============================================================================
// Unify
// ============================================================================

TEST_CASE("unify intersects TypeSets", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_MAP) | TypeSet::singleton(T_CTX) | TypeSet::singleton(T_STACK));
    td.restrict_to(reg_type(r1), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_PACKET) | TypeSet::singleton(T_STACK));
    td.add_constraint(eq(reg_type(r0), reg_type(r1)));
    // Intersection: {ctx, stack}
    const auto types = td.iterate_types(r0);
    REQUIRE(types.size() == 2);
    REQUIRE(std::find(types.begin(), types.end(), T_CTX) != types.end());
    REQUIRE(std::find(types.begin(), types.end(), T_STACK) != types.end());
    REQUIRE(td.same_type(r0, r1));
}

TEST_CASE("unify disjoint TypeSets goes to bottom", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_MAP) | TypeSet::singleton(T_CTX));
    td.restrict_to(reg_type(r1), TypeSet::singleton(T_PACKET) | TypeSet::singleton(T_SHARED));
    td.add_constraint(eq(reg_type(r0), reg_type(r1)));
    REQUIRE(td.is_bottom());
}

TEST_CASE("unify transitive chain progressively narrows", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_MAP) | TypeSet::singleton(T_CTX) | TypeSet::singleton(T_STACK));
    td.restrict_to(reg_type(r1), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_STACK) | TypeSet::singleton(T_SHARED));
    td.restrict_to(reg_type(r2), TypeSet::singleton(T_STACK) | TypeSet::singleton(T_SHARED) | TypeSet::singleton(T_PACKET));

    td.add_constraint(eq(reg_type(r0), reg_type(r1))); // r0,r1 → {ctx, stack}
    REQUIRE(!td.is_bottom());
    {
        const auto types = td.iterate_types(r0);
        REQUIRE(types.size() == 2);
    }

    td.add_constraint(eq(reg_type(r1), reg_type(r2))); // r0,r1,r2 → {stack}
    REQUIRE(!td.is_bottom());
    REQUIRE(td.get_type(r0) == T_STACK);
    REQUIRE(td.get_type(r1) == T_STACK);
    REQUIRE(td.get_type(r2) == T_STACK);
    REQUIRE(td.same_type(r0, r2));
}

// ============================================================================
// Restrict affects entire equivalence class
// ============================================================================

TEST_CASE("restrict narrows the whole equivalence class", "[type_domain]") {
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_STACK));
    td.assign_type(r1, r0); // r1 unified with r0
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_CTX));
    // Both must be narrowed.
    REQUIRE(td.get_type(r0) == T_CTX);
    REQUIRE(td.get_type(r1) == T_CTX);
}

// ============================================================================
// Join
// ============================================================================

TEST_CASE("join widens TypeSets to union", "[type_domain][join]") {
    TypeDomain a, b;
    a.assign_type(r0, T_CTX);
    b.assign_type(r0, T_STACK);
    const TypeDomain j = a | b;
    REQUIRE(!j.is_bottom());
    const auto types = j.iterate_types(r0);
    REQUIRE(types.size() == 2);
    REQUIRE(std::find(types.begin(), types.end(), T_CTX) != types.end());
    REQUIRE(std::find(types.begin(), types.end(), T_STACK) != types.end());
}

TEST_CASE("join preserves common explicit equality", "[type_domain][join]") {
    TypeDomain a, b;
    // In both: r0=r1=ctx
    a.assign_type(r0, T_CTX);
    a.assign_type(r1, r0);
    b.assign_type(r0, T_CTX);
    b.assign_type(r1, r0);
    const TypeDomain j = a | b;
    REQUIRE(j.same_type(r0, r1));
    REQUIRE(j.get_type(r0) == T_CTX);
}

TEST_CASE("join drops one-sided equality", "[type_domain][join]") {
    TypeDomain a, b;
    // A: r0=r1=ctx; B: r0=ctx, r1=stack
    a.assign_type(r0, T_CTX);
    a.assign_type(r1, r0);
    b.assign_type(r0, T_CTX);
    b.assign_type(r1, T_STACK);
    const TypeDomain j = a | b;
    REQUIRE(!j.same_type(r0, r1));
    REQUIRE(j.get_type(r0) == T_CTX);
    const auto types = j.iterate_types(r1);
    REQUIRE(types.size() == 2);
}

TEST_CASE("singleton-aware join detects implicit equality", "[type_domain][join]") {
    // Key precision feature: r0 and r1 are independently {num} in A and {ctx} in B.
    // The join should detect they must be equal.
    TypeDomain a, b;
    a.assign_type(r0, T_NUM);
    a.assign_type(r1, T_NUM);
    b.assign_type(r0, T_CTX);
    b.assign_type(r1, T_CTX);
    const TypeDomain j = a | b;
    REQUIRE(j.same_type(r0, r1));
    const auto types = j.iterate_types(r0);
    REQUIRE(types.size() == 2);
    REQUIRE(std::find(types.begin(), types.end(), T_NUM) != types.end());
    REQUIRE(std::find(types.begin(), types.end(), T_CTX) != types.end());
}

TEST_CASE("singleton-aware join does not falsely unify different singletons", "[type_domain][join]") {
    // A: r0={num}, r1={ctx}; B: r0={ctx}, r1={num}
    // They should NOT be unified (different key pairs).
    TypeDomain a, b;
    a.assign_type(r0, T_NUM);
    a.assign_type(r1, T_CTX);
    b.assign_type(r0, T_CTX);
    b.assign_type(r1, T_NUM);
    const TypeDomain j = a | b;
    REQUIRE(!j.same_type(r0, r1));
}

TEST_CASE("join with bottom is identity", "[type_domain][join]") {
    using namespace dsl_syntax;
    TypeDomain a;
    a.assign_type(r0, T_CTX);
    TypeDomain bot;
    bot.assign_type(r0, T_CTX);
    bot.add_constraint(reg_type(r0) == T_NUM); // force bottom
    REQUIRE(bot.is_bottom());

    const TypeDomain j = a | bot;
    REQUIRE(!j.is_bottom());
    REQUIRE(j.get_type(r0) == T_CTX);
}

// ============================================================================
// Meet
// ============================================================================

TEST_CASE("meet intersects TypeSets", "[type_domain]") {
    TypeDomain a, b;
    a.restrict_to(reg_type(r0), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_STACK) | TypeSet::singleton(T_PACKET));
    b.restrict_to(reg_type(r0), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_SHARED));
    const auto m = a.meet(b);
    REQUIRE(m.has_value());
    REQUIRE(m->get_type(r0) == T_CTX);
}

TEST_CASE("meet merges equalities transitively", "[type_domain]") {
    TypeDomain a, b;
    // A: r0=r1=ctx; B: r1=r2=ctx
    a.assign_type(r0, T_CTX);
    a.assign_type(r1, r0);
    b.assign_type(r1, T_CTX);
    b.assign_type(r2, r1);
    const auto m = a.meet(b);
    REQUIRE(m.has_value());
    REQUIRE(m->same_type(r0, r2));
}

TEST_CASE("meet with incompatible equalities goes to bottom", "[type_domain]") {
    TypeDomain a, b;
    a.assign_type(r0, T_CTX);
    b.assign_type(r0, T_STACK);
    b.assign_type(r1, r0); // r0=r1={stack}
    // meet: r0 must be {ctx} (from a) and in same class as r1 with {stack} (from b)
    // intersection of r0's class with {stack} = {ctx} & {stack} = empty → bottom
    const auto m = a.meet(b);
    REQUIRE(!m.has_value());
}

// ============================================================================
// operator<= (subsumption) — correctness regression tests
// ============================================================================

TEST_CASE("top is not subsumed by a constrained domain", "[type_domain][subsumption]") {
    // Regression: this caught a bug where operator<= only iterated self.var_to_id,
    // missing variables present in other but absent in self.
    TypeDomain top_td;
    TypeDomain constrained;
    constrained.assign_type(r0, T_NUM);
    REQUIRE(!(top_td <= constrained));
}

TEST_CASE("constrained is subsumed by top", "[type_domain][subsumption]") {
    TypeDomain td;
    td.assign_type(r0, T_NUM);
    const TypeDomain top_td;
    REQUIRE(td <= top_td);
}

TEST_CASE("bottom is subsumed by everything", "[type_domain][subsumption]") {
    using namespace dsl_syntax;
    TypeDomain bot;
    bot.assign_type(r0, T_CTX);
    bot.add_constraint(reg_type(r0) == T_NUM);
    REQUIRE(bot.is_bottom());
    const TypeDomain td;
    REQUIRE(bot <= td);
}

TEST_CASE("subsumption respects TypeSet refinement", "[type_domain][subsumption]") {
    TypeDomain narrow_td, wide_td;
    narrow_td.assign_type(r0, T_CTX);
    wide_td.restrict_to(reg_type(r0), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_STACK));
    REQUIRE(narrow_td <= wide_td);
    REQUIRE(!(wide_td <= narrow_td));
}

TEST_CASE("subsumption with implicit singleton equality", "[type_domain][subsumption]") {
    // Regression: this caught a bug where operator<= required strict DSU equality
    // for variables in the same class in other, even when both had the same singleton.
    //
    // Scenario: a has r0={num} and r1={num} in separate DSU classes.
    // b (the join) has r0=r1 unified in one class with {num}.
    // a <= b must be true because r0 and r1 are implicitly equal.
    TypeDomain a;
    a.assign_type(r0, T_NUM);
    a.assign_type(r1, T_NUM);
    // a: r0 and r1 both {num} but in separate DSU classes.

    // Build b where r0 and r1 are explicitly unified.
    TypeDomain b;
    b.assign_type(r0, T_NUM);
    b.assign_type(r1, r0); // r0=r1 in same class

    REQUIRE(a <= b);
}

TEST_CASE("subsumption fails when singletons differ", "[type_domain][subsumption]") {
    TypeDomain a;
    a.assign_type(r0, T_NUM);
    a.assign_type(r1, T_CTX);

    TypeDomain b;
    b.assign_type(r0, T_NUM);
    b.assign_type(r1, r0); // r0=r1 in same class with {num}

    // a has r1={ctx} which is not {num}, so equality in b is not satisfied.
    REQUIRE(!(a <= b));
}

TEST_CASE("join result subsumes both operands", "[type_domain][subsumption][join]") {
    // Soundness check: a <= a|b and b <= a|b.
    TypeDomain a, b;
    a.assign_type(r0, T_NUM);
    a.assign_type(r1, T_NUM);
    b.assign_type(r0, T_CTX);
    b.assign_type(r1, T_CTX);
    const TypeDomain j = a | b;
    REQUIRE(a <= j);
    REQUIRE(b <= j);
}

TEST_CASE("join result subsumes operands with mixed equalities", "[type_domain][subsumption][join]") {
    TypeDomain a, b;
    // A: r0=r1=ctx, r2=stack
    a.assign_type(r0, T_CTX);
    a.assign_type(r1, r0);
    a.assign_type(r2, T_STACK);
    // B: r0=stack, r1=stack, r2=ctx
    b.assign_type(r0, T_STACK);
    b.assign_type(r1, T_STACK);
    b.assign_type(r2, T_CTX);
    const TypeDomain j = a | b;
    REQUIRE(a <= j);
    REQUIRE(b <= j);
}

// ============================================================================
// entail
// ============================================================================

TEST_CASE("entail checks singleton", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    td.assign_type(r0, T_CTX);
    REQUIRE(td.entail(reg_type(r0) == T_CTX));
    REQUIRE(!td.entail(reg_type(r0) == T_NUM));
    REQUIRE(td.entail(reg_type(r0) != T_NUM));
    REQUIRE(!td.entail(reg_type(r0) != T_CTX));
}

TEST_CASE("entail checks equality through singleton", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    td.assign_type(r0, T_NUM);
    td.assign_type(r1, T_NUM);
    // Not explicitly unified, but both singleton {num} → implicitly equal.
    REQUIRE(td.entail(eq(reg_type(r0), reg_type(r1))));
}

TEST_CASE("entail checks equality through DSU", "[type_domain]") {
    using namespace dsl_syntax;
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_STACK));
    td.assign_type(r1, r0);
    // Unified but not singleton — entail should still confirm equality.
    REQUIRE(td.entail(eq(reg_type(r0), reg_type(r1))));
}

// ============================================================================
// implies
// ============================================================================

TEST_CASE("implies_group checks conditional type constraint", "[type_domain]") {
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_NUM));

    // If r0 is a pointer, then r0 must be ctx.
    REQUIRE(td.implies_group(r0, TypeGroup::pointer, r0, TypeSet::singleton(T_CTX)));
}

TEST_CASE("implies_not_type checks conditional type constraint", "[type_domain]") {
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_NUM));

    // If r0 is not stack, then r0 is in {ctx, num} (trivially true here).
    REQUIRE(td.implies_not_type(r0, T_STACK, r0, TypeSet::singleton(T_CTX) | TypeSet::singleton(T_NUM)));
}

// ============================================================================
// initialized
// ============================================================================

TEST_CASE("is_initialized checks T_UNINIT membership", "[type_domain]") {
    TypeDomain td;
    // Top includes T_UNINIT.
    REQUIRE(!td.is_initialized(r0));
    td.assign_type(r0, T_NUM);
    REQUIRE(td.is_initialized(r0));
}

// ============================================================================
// to_set serialization
// ============================================================================

TEST_CASE("to_set outputs singleton types", "[type_domain][serialization]") {
    TypeDomain td;
    td.assign_type(r0, T_CTX);
    const auto inv = td.to_set();
    REQUIRE(!inv.is_bottom());
    REQUIRE(inv.contains("r0.type=ctx"));
}

TEST_CASE("to_set outputs multi-valued TypeSet as 'in' notation", "[type_domain][serialization]") {
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_STACK));
    const auto inv = td.to_set();
    REQUIRE(!inv.is_bottom());
    REQUIRE(inv.contains("r0.type in {ctx, stack}"));
}

TEST_CASE("to_set shows equality for unified variables", "[type_domain][serialization]") {
    TypeDomain td;
    td.restrict_to(reg_type(r0), TypeSet::singleton(T_CTX) | TypeSet::singleton(T_STACK));
    td.assign_type(r1, r0);
    const auto inv = td.to_set();
    REQUIRE(!inv.is_bottom());
    // First member gets the type set, rest get equality.
    REQUIRE(inv.contains("r0.type in {ctx, stack}"));
    REQUIRE(inv.contains("r1.type=r0.type"));
}

TEST_CASE("to_set groups same-singleton variables via sentinel invariant", "[type_domain][serialization]") {
    // Singleton-merging invariant: both r0 and r1 are {ctx}, so they share the
    // ctx sentinel DSU element and are in the same equivalence class.
    TypeDomain td;
    td.assign_type(r0, T_CTX);
    td.assign_type(r1, T_CTX);
    const auto inv = td.to_set();
    REQUIRE(!inv.is_bottom());
    // Both should appear: one as concrete type, the other as equality.
    REQUIRE(inv.contains("r0.type=ctx"));
    REQUIRE(inv.contains("r1.type=ctx"));
}

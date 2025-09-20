// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "arith/dsl_syntax.hpp"
#include "crab/ebpf_domain.hpp"

using namespace prevail;
using namespace dsl_syntax;

// Assert that the domain defined by `specific_csts` is subsumed by the one from `general_csts`.
// (i.e., specific <= general)
static void require_subsumes(const std::vector<LinearConstraint>& specific_csts,
                             const std::vector<LinearConstraint>& general_csts) {
    const EbpfDomain specific = EbpfDomain::from_constraints(specific_csts);
    const EbpfDomain general = EbpfDomain::from_constraints(general_csts);
    REQUIRE(specific <= general);
}

// Assert that the domain defined by `a_csts` is NOT subsumed by the one from `b_csts`.
static void require_not_subsumes(const std::vector<LinearConstraint>& a_csts,
                                 const std::vector<LinearConstraint>& b_csts) {
    const EbpfDomain a = EbpfDomain::from_constraints(a_csts);
    const EbpfDomain b = EbpfDomain::from_constraints(b_csts);
    REQUIRE(!(a <= b));
}

static const RegPack r0 = reg_pack(0);
static const RegPack r1 = reg_pack(1);

TEST_CASE("Basic subsumption properties", "[subsumption][lattice]") {
    // Identical domains subsume each other.
    require_subsumes({r0.type == T_NUM}, {r0.type == T_NUM});

    // Anything is subsumed by top.
    require_subsumes({r0.type == T_NUM, r0.svalue == 5}, {});

    // Top is not subsumed by anything but top.
    require_not_subsumes({}, {r0.type == T_NUM});
}

TEST_CASE("Straightforward value and type subsumption", "[subsumption][lattice]") {
    // A specific value is subsumed by a range containing it.
    require_subsumes({r0.type == T_NUM, r0.svalue == 5}, {r0.type == T_NUM, r0.svalue >= 0, r0.svalue <= 10});
    require_not_subsumes({r0.type == T_NUM, r0.svalue >= 0, r0.svalue <= 10}, {r0.type == T_NUM, r0.svalue == 5});

    // A sub-range is subsumed by a super-range.
    require_subsumes({r0.type == T_NUM, r0.svalue >= 2, r0.svalue <= 8},
                     {r0.type == T_NUM, r0.svalue >= 0, r0.svalue <= 10});

    // A specific type is subsumed by a type range containing it.
    require_subsumes({r0.type == T_PACKET}, {r0.type >= T_NUM, r0.type <= T_STACK});
    require_not_subsumes({r0.type >= T_NUM, r0.type <= T_STACK}, {r0.type == T_PACKET});

    // Relational constraints must also hold.
    require_subsumes({r0.type == T_NUM, r1.type == T_NUM, eq(r0.svalue, r1.svalue), r0.svalue == 5},
                     {r0.type == T_NUM, r1.type == T_NUM, eq(r0.svalue, r1.svalue)});
    require_not_subsumes({r0.type == T_NUM, r1.type == T_NUM, eq(r0.svalue, r1.svalue)},
                         {r0.type == T_NUM, r1.type == T_NUM, r0.svalue >= 0});
}

TEST_CASE("Subsumption of unrelated or disjoint domains", "[subsumption][lattice]") {
    require_not_subsumes({r0.type == T_NUM, r0.svalue == 1}, {r0.type == T_NUM, r0.svalue == 2});
    require_not_subsumes({r0.type == T_PACKET}, {r0.type == T_STACK});
    require_not_subsumes({r0.type == T_NUM, r0.svalue >= 0, r0.svalue <= 5},
                         {r0.type == T_NUM, r0.svalue >= 3, r0.svalue <= 8});
}

TEST_CASE("Subsumption with absent type-specific variables", "[subsumption][lattice]") {
    // This is the core of the bug fix.
    // The specific domain has type T_NUM. For this type, `packet_offset` is an irrelevant (bottom) variable.
    // The general domain includes T_PACKET and has a constraint on `packet_offset`.
    // The check `specific <= general` should pass because bottom is subsumed by any constraint.
    require_subsumes({r0.type == T_NUM}, {r0.type >= T_NUM, r0.type <= T_PACKET, r0.packet_offset == 5});

    // The reverse must not be true. The `general` domain has a non-bottom `packet_offset`, which
    // is not subsumed by the `specific` domain's bottom `packet_offset`.
    require_not_subsumes({r0.type >= T_NUM, r0.type <= T_PACKET, r0.packet_offset == 5}, {r0.type == T_NUM});

    // Same test with stack-related variables.
    require_subsumes({r0.type == T_NUM},
                     {r0.type >= T_NUM, r0.type <= T_STACK, r0.stack_offset == 128, r0.stack_numeric_size == 8});
    require_not_subsumes({r0.type >= T_NUM, r0.type <= T_STACK, r0.stack_offset == 128, r0.stack_numeric_size == 8},
                         {r0.type == T_NUM});
}

TEST_CASE("Subsumption with present type-specific variables", "[subsumption][lattice]") {
    // Standard subsumption check when the relevant type-specific variables are active in both domains.
    require_subsumes({r0.type == T_PACKET, r0.packet_offset == 8},
                     {r0.type == T_PACKET, r0.packet_offset >= 0, r0.packet_offset <= 16});
    require_not_subsumes({r0.type == T_PACKET, r0.packet_offset >= 0, r0.packet_offset <= 16},
                         {r0.type == T_PACKET, r0.packet_offset == 8});

    // Check with multiple active type-specific variables.
    const auto general_domain = {r0.type >= T_PACKET, r0.type <= T_STACK, r0.packet_offset >= 0, r0.stack_offset >= 0};
    // The specific domain has only T_PACKET, so stack_offset is bottom and is subsumed.
    require_subsumes({r0.type == T_PACKET, r0.packet_offset == 8}, general_domain);
    // The reverse is not true, as `general_domain` has a non-bottom `stack_offset`.
    require_not_subsumes(general_domain, {r0.type == T_PACKET, r0.packet_offset == 8});
}

TEST_CASE("Edge case subsumption with bottom and mixed types", "[subsumption][lattice]") {
    // Bottom is subsumed by anything.
    require_subsumes({r0.svalue > 0, r0.svalue < 0}, {r0.type == T_NUM});
    require_subsumes({r0.svalue > 0, r0.svalue < 0}, {});

    // Nothing (except bottom) is subsumed by bottom.
    require_not_subsumes({r0.type == T_NUM}, {r0.svalue > 0, r0.svalue < 0});

    // A single, specific type should be subsumed by a wider type range.
    require_subsumes({r0.type == T_SHARED, r0.shared_offset == 16}, {r0.type >= T_NUM, r0.type <= T_SHARED});

    // A wider type range is not subsumed by a single type, even if the offset is unconstrained.
    require_not_subsumes({r0.type >= T_NUM, r0.type <= T_SHARED}, {r0.type == T_SHARED});
}

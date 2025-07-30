// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "arith/dsl_syntax.hpp"
#include "crab/ebpf_domain.hpp"

using namespace prevail;
using namespace dsl_syntax;

static const Variable r0 = reg_pack(0).svalue;
static const Variable r1 = reg_pack(1).svalue;
static const Variable r0_type = reg_pack(0).type;
static const Variable r1_type = reg_pack(1).type;

TEST_CASE("ebpf_domain basic join", "[ebpf][join]") {
    EbpfDomain a, b;
    a.set_to_top();
    b.set_to_top();
    EbpfDomain j = a | b;
    REQUIRE(j.is_top());
    REQUIRE(a <= j);
    REQUIRE(b <= j);
}

TEST_CASE("ebpf_domain disjoint value join", "[ebpf][join]") {
    EbpfDomain a = EbpfDomain::from_constraints({r0_type == T_NUM, r0 == 0});
    EbpfDomain b = EbpfDomain::from_constraints({r0_type == T_NUM, r0 == 5});
    EbpfDomain j = a | b;
    REQUIRE(a <= j);
    REQUIRE(b <= j);

    EbpfDomain over_approx = EbpfDomain::from_constraints({
        r0_type == T_NUM,
        r0 >= 0,
        r0 <= 5,
    });
    REQUIRE_FALSE(over_approx.is_top());
    REQUIRE(j <= over_approx);
}

TEST_CASE("ebpf_domain join respects partial order", "[ebpf][join]") {
    EbpfDomain a = EbpfDomain::from_constraints({r0_type == T_NUM, r0 == 1});
    EbpfDomain b = EbpfDomain::from_constraints({r0_type == T_NUM, r0 == 2});
    EbpfDomain j = a | b;
    REQUIRE(a <= j);
    REQUIRE(b <= j);
    REQUIRE_FALSE(j <= a);
    REQUIRE_FALSE(j <= b);

    EbpfDomain over_approx = EbpfDomain::from_constraints({
        r0_type == T_NUM,
        r0 >= 1,
        r0 <= 2,
    });
    REQUIRE_FALSE(over_approx.is_top());
    REQUIRE(j <= over_approx);
}

TEST_CASE("ebpf_domain join with matching map types", "[ebpf][join][type]") {
    EbpfDomain a = EbpfDomain::from_constraints({r0_type == T_MAP, r0 == 1});
    EbpfDomain b = EbpfDomain::from_constraints({r0_type == T_MAP, r0 == 3});
    EbpfDomain j = a | b;
    REQUIRE(a <= j);
    REQUIRE(b <= j);

    EbpfDomain over_approx = EbpfDomain::from_constraints({
        r0_type == T_MAP,
        r0 >= 1,
        r0 <= 3,
    });
    REQUIRE_FALSE(over_approx.is_top());
    REQUIRE(j <= over_approx);
}

TEST_CASE("ebpf_domain join with matching memory types but different offsets", "[ebpf][join][type]") {
    EbpfDomain a = EbpfDomain::from_constraints({r0_type == T_PACKET, r0 == 1, reg_pack(0).packet_offset == 0});
    EbpfDomain b = EbpfDomain::from_constraints({r0_type == T_PACKET, r0 == 3, reg_pack(0).packet_offset == 4});
    EbpfDomain j = a | b;
    REQUIRE(a <= j);
    REQUIRE(b <= j);

    EbpfDomain over_approx = EbpfDomain::from_constraints({
        r0_type == T_PACKET,
        r0 >= 1,
        r0 <= 3,
        reg_pack(0).packet_offset >= 0,
        reg_pack(0).packet_offset <= 4,
    });
    REQUIRE_FALSE(over_approx.is_top());
    REQUIRE(j <= over_approx);
}

TEST_CASE("ebpf_domain join with different types and unknown offsets", "[ebpf][join][type]") {
    EbpfDomain a = EbpfDomain::from_constraints({r0_type == T_MAP, r0 == 1});
    EbpfDomain b = EbpfDomain::from_constraints({r0_type == T_STACK, r0 == 2});
    EbpfDomain j = a | b;
    REQUIRE(a <= j);
    REQUIRE(b <= j);

    EbpfDomain over_approx = EbpfDomain::from_constraints({
        r0_type <= T_STACK,
        r0_type >= T_MAP,
        r0 >= 1,
        r0 <= 2,
    });
    REQUIRE_FALSE(over_approx.is_top());
    REQUIRE(j <= over_approx);
}

TEST_CASE("ebpf_domain join preserves type-specific offsets", "[ebpf][join][type-specific]") {
    EbpfDomain a = EbpfDomain::from_constraints({r1_type == T_STACK, r1 == 123, reg_pack(1).stack_offset == 100});
    EbpfDomain b = EbpfDomain::from_constraints({r1_type == T_PACKET, r1 == 123, reg_pack(1).packet_offset == 4});
    EbpfDomain j = a | b;
    REQUIRE(a <= j);
    REQUIRE(b <= j);

    EbpfDomain over_approx = EbpfDomain::from_constraints({
        r1 == 123,
        r1_type >= T_PACKET,
        r1_type <= T_STACK,
        reg_pack(1).stack_offset == 100,
        reg_pack(1).packet_offset == 4,
    });
    REQUIRE_FALSE(over_approx.is_top());
    REQUIRE(j <= over_approx);
}

static const Variable r6 = reg_pack(6).svalue;
static const Variable r7 = reg_pack(7).svalue;
static const Variable r10 = reg_pack(10).svalue;
static const Variable r6_type = reg_pack(6).type;
static const Variable r7_type = reg_pack(7).type;
static const Variable r10_type = reg_pack(10).type;

TEST_CASE("ebpf_domain join regression from 74+103 to 104", "[ebpf][join][regression]") {
    // distillation of running:
    // ./check --no-simplify ebpf-samples/linux/test_map_in_map_kern.o kprobe/sys_connect - v

    // Invariant from block 74
    EbpfDomain a = EbpfDomain::from_constraints({
        r0_type == T_MAP,
        r0 == 0,
        r6_type == T_MAP,
        r6 == 0,
        r7_type == T_NUM,
        r7 == 0,
        r1 == 153,
        r10_type == T_STACK,
        r10 >= 4096,
        r10 <= 2147418112,
    });

    // Invariant from block 103
    EbpfDomain b = EbpfDomain::from_constraints({
        r0_type == T_NUM,
        r6_type == T_NUM,
        r7_type == T_NUM,
        r7 >= 1,
        r1 == 146,
        r10_type == T_STACK,
        r10 >= 4096,
        r10 <= 2147418112,
    });

    EbpfDomain join = a | b;
    REQUIRE(a <= join);
    REQUIRE(b <= join);

    // Conservative overapproximation of correct join
    EbpfDomain over_approx = EbpfDomain::from_constraints({
        r0_type >= T_MAP,
        r0_type <= T_NUM,
        r6_type >= T_MAP,
        r6_type <= T_NUM,
        r7_type == T_NUM,
        r7 >= 0,
        r1 >= 146,
        r1 <= 153,
        r10_type == T_STACK,
        r10 >= 4096,
        r10 <= 2147418112,
    });
    REQUIRE(join <= over_approx);
}

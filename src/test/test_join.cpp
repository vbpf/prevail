// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "arith/dsl_syntax.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/splitdbm/split_dbm.hpp"

using namespace prevail;

using TypeRestrictions = std::vector<std::pair<Variable, TypeSet>>;

static void require_join(const TypeRestrictions& a_type, const std::vector<LinearConstraint>& a_csts,
                         const TypeRestrictions& b_type, const std::vector<LinearConstraint>& b_csts,
                         const TypeRestrictions& over_type, const std::vector<LinearConstraint>& over_csts) {
    using namespace dsl_syntax;
    EbpfDomain a = EbpfDomain::from_constraints(a_type, a_csts);
    EbpfDomain b = EbpfDomain::from_constraints(b_type, b_csts);
    EbpfDomain j = a | b;
    REQUIRE(a <= j);
    REQUIRE(b <= j);
    EbpfDomain over_approx = EbpfDomain::from_constraints(over_type, over_csts);
    REQUIRE(j <= over_approx);
}

static const RegPack r0 = reg_pack(0);
static const Variable r0_type = reg_type(Reg{0});
static const RegPack r1 = reg_pack(1);
static const Variable r1_type = reg_type(Reg{1});
static const RegPack r2 = reg_pack(2);
static const Variable r2_type = reg_type(Reg{2});
static const RegPack r6 = reg_pack(6);
static const Variable r6_type = reg_type(Reg{6});
static const RegPack r7 = reg_pack(7);
static const Variable r7_type = reg_type(Reg{7});
static const RegPack r10 = reg_pack(10);
static const Variable r10_type = reg_type(Reg{10});

using TS = TypeSet;

TEST_CASE("EbpfDomain basic join", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({}, {}, {}, {}, {}, {});
}

// 1) Type-only joins
TEST_CASE("join same precise type", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_NUM)}}, {}, {{r0_type, TS::singleton(T_NUM)}}, {},
                 {{r0_type, TS::singleton(T_NUM)}}, {});
}

TEST_CASE("join disjoint precise types gives exact union", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_MAP)}}, {}, {{r0_type, TS::singleton(T_STACK)}}, {},
                 {{r0_type, TS::of({T_MAP, T_STACK})}}, {});
}

TEST_CASE("join precise with top widens type range", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_MAP)}}, {}, {{r0_type, TS::singleton(T_NUM)}}, {},
                 {{r0_type, TS::of({T_MAP, T_NUM})}}, {});
}

TEST_CASE("EbpfDomain disjoint value join", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_NUM)}}, {r0.svalue == 0}, {{r0_type, TS::singleton(T_NUM)}},
                 {r0.svalue == 5}, {{r0_type, TS::singleton(T_NUM)}}, {r0.svalue >= 0, r0.svalue <= 5});
}

TEST_CASE("join respects partial order", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_NUM)}}, {r0.svalue == 1}, {{r0_type, TS::singleton(T_NUM)}},
                 {r0.svalue == 2}, {{r0_type, TS::singleton(T_NUM)}}, {r0.svalue >= 1, r0.svalue <= 2});
}

// 2) Value constraints with same type
TEST_CASE("join keeps equal constants", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_NUM)}}, {r0.svalue == 7}, {{r0_type, TS::singleton(T_NUM)}},
                 {r0.svalue == 7}, {{r0_type, TS::singleton(T_NUM)}}, {r0.svalue == 7});
}

TEST_CASE("join convex hull of disjoint constants", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_NUM)}}, {r0.svalue == 1}, {{r0_type, TS::singleton(T_NUM)}},
                 {r0.svalue == 3}, {{r0_type, TS::singleton(T_NUM)}}, {r0.svalue >= 1, r0.svalue <= 3});
}

TEST_CASE("join overlapping intervals", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_NUM)}}, {r0.svalue >= 0, r0.svalue <= 5}, {{r0_type, TS::singleton(T_NUM)}},
                 {r0.svalue >= 3, r0.svalue <= 10}, {{r0_type, TS::singleton(T_NUM)}},
                 {r0.svalue >= 0, r0.svalue <= 10});
}

TEST_CASE("join with one top one constrained becomes top for value", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_NUM)}}, {r0.svalue >= -5, r0.svalue <= 5},
                 {{r0_type, TS::singleton(T_NUM)}}, {}, {{r0_type, TS::singleton(T_NUM)}}, {});
}

// 3) Same memory type, offsets
TEST_CASE("join same pointer type same offset", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_PACKET)}}, {r0.svalue == 123, r0.packet_offset == 4},
                 {{r0_type, TS::singleton(T_PACKET)}}, {r0.svalue == 123, r0.packet_offset == 4},
                 {{r0_type, TS::singleton(T_PACKET)}}, {r0.svalue == 123, r0.packet_offset == 4});
}

TEST_CASE("join ranges offsets for same pointer type", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_PACKET)}}, {r0.svalue == 1, r0.packet_offset == 0},
                 {{r0_type, TS::singleton(T_PACKET)}}, {r0.svalue == 3, r0.packet_offset == 4},
                 {{r0_type, TS::singleton(T_PACKET)}},
                 {r0.svalue >= 1, r0.svalue <= 3, r0.packet_offset >= 0, r0.packet_offset <= 4});
}

// 4) Different memory types keep per-type offsets
TEST_CASE("join keeps offsets across disjoint types", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r1_type, TS::singleton(T_STACK)}}, {r1.svalue == 123, r1.stack_offset == 100},
                 {{r1_type, TS::singleton(T_PACKET)}}, {r1.svalue == 123, r1.packet_offset == 4},
                 {{r1_type, TS::of({T_PACKET, T_STACK})}},
                 {r1.svalue == 123, r1.stack_offset == 100, r1.packet_offset == 4});
}

// 5) One branch pointer, other numeric
TEST_CASE("join widens type and preserves offset from one side", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_PACKET)}}, {r0.packet_offset == 8}, {{r0_type, TS::singleton(T_NUM)}}, {},
                 {{r0_type, TS::of({T_NUM, T_PACKET})}}, {r0.packet_offset == 8});
}

TEST_CASE("join with matching map types", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_MAP)}}, {r0.svalue == 1}, {{r0_type, TS::singleton(T_MAP)}},
                 {r0.svalue == 3}, {{r0_type, TS::singleton(T_MAP)}}, {r0.svalue >= 1, r0.svalue <= 3});
}

TEST_CASE("join with matching memory types but different offsets", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_PACKET)}}, {r0.svalue == 1, r0.packet_offset == 0},
                 {{r0_type, TS::singleton(T_PACKET)}}, {r0.svalue == 3, r0.packet_offset == 4},
                 {{r0_type, TS::singleton(T_PACKET)}},
                 {r0.svalue >= 1, r0.svalue <= 3, r0.packet_offset >= 0, r0.packet_offset <= 4});
}

TEST_CASE("join with different types and unknown offsets", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_MAP)}}, {r0.svalue == 1}, {{r0_type, TS::singleton(T_STACK)}},
                 {r0.svalue == 2}, {{r0_type, TS::of({T_MAP, T_STACK})}}, {r0.svalue >= 1, r0.svalue <= 2});
}

// 6) Shared memory offsets and sizes
TEST_CASE("join shared offsets and sizes", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_SHARED)}}, {r0.shared_offset == 16, r0.shared_region_size == 64},
                 {{r0_type, TS::singleton(T_SHARED)}}, {r0.shared_offset == 32, r0.shared_region_size == 64},
                 {{r0_type, TS::singleton(T_SHARED)}},
                 {r0.shared_offset >= 16, r0.shared_offset <= 32, r0.shared_region_size == 64});
}

TEST_CASE("join preserves shared offset across type widening", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_SHARED)}}, {r0.shared_offset == 0}, {{r0_type, TS::singleton(T_NUM)}}, {},
                 {{r0_type, TS::of({T_NUM, T_SHARED})}}, {r0.shared_offset == 0});
}

// 7) Stack numeric size interactions
TEST_CASE("join stack offsets and numeric size", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_STACK)}}, {r0.stack_offset == 64, r0.stack_numeric_size == 8},
                 {{r0_type, TS::singleton(T_STACK)}}, {r0.stack_offset == 96, r0.stack_numeric_size == 8},
                 {{r0_type, TS::singleton(T_STACK)}},
                 {r0.stack_offset >= 64, r0.stack_offset <= 96, r0.stack_numeric_size == 8});
}

TEST_CASE("join preserves stack facts across type mismatch", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_STACK)}}, {r0.stack_offset == 64, r0.stack_numeric_size == 8},
                 {{r0_type, TS::singleton(T_NUM)}}, {}, {{r0_type, TS::of({T_NUM, T_STACK})}},
                 {r0.stack_offset == 64, r0.stack_numeric_size == 8});
}

// 8) Context and map-related variables
TEST_CASE("join context offsets", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_CTX)}}, {r0.ctx_offset == 0}, {{r0_type, TS::singleton(T_CTX)}},
                 {r0.ctx_offset == 16}, {{r0_type, TS::singleton(T_CTX)}}, {r0.ctx_offset >= 0, r0.ctx_offset <= 16});
}

TEST_CASE("join map fd constants", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_MAP)}}, {r0.map_fd == 10}, {{r0_type, TS::singleton(T_MAP)}},
                 {r0.map_fd == 10}, {{r0_type, TS::singleton(T_MAP)}}, {r0.map_fd == 10});
}

TEST_CASE("join map vs non-map keeps map fd", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_MAP)}}, {r0.map_fd == 7}, {{r0_type, TS::singleton(T_NUM)}}, {},
                 {{r0_type, TS::of({T_MAP, T_NUM})}}, {r0.map_fd == 7});
}

// 9) Top/Bottom edge behavior
TEST_CASE("join with bottom on one side returns other", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({}, {r2.svalue == 0, r2.svalue != 0}, {{r0_type, TS::singleton(T_NUM)}}, {r2.svalue == 5},
                 {{r0_type, TS::singleton(T_NUM)}}, {r2.svalue == 5});
}

// 10) Type range with value ranges
TEST_CASE("join of type ranges with value ranges", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::of({T_PACKET, T_STACK, T_SHARED})}}, {r0.svalue >= 0, r0.svalue <= 100},
                 {{r0_type, TS::of({T_NUM, T_CTX, T_PACKET, T_STACK})}}, {r0.svalue >= 50, r0.svalue <= 200},
                 {{r0_type, TS::of({T_NUM, T_CTX, T_PACKET, T_STACK, T_SHARED})}}, {r0.svalue >= 0, r0.svalue <= 200});
}

TEST_CASE("join regression from 74+103 to 104", "[join][lattice]") {
    using namespace dsl_syntax;
    // distillation of running:
    // ./check --no-simplify ebpf-samples/linux/test_map_in_map_kern.o kprobe/sys_connect - v

    require_join({{r0_type, TS::singleton(T_MAP)},
                  {r6_type, TS::singleton(T_MAP)},
                  {r7_type, TS::singleton(T_NUM)},
                  {r10_type, TS::singleton(T_STACK)}},
                 {
                     r0.svalue == 0,
                     r6.svalue == 0,
                     r7.svalue == 0,
                     r1.svalue == 153,
                     r10.svalue >= 4096,
                     r10.svalue <= 2147418112,
                 },
                 {{r0_type, TS::singleton(T_NUM)},
                  {r6_type, TS::singleton(T_NUM)},
                  {r7_type, TS::singleton(T_NUM)},
                  {r10_type, TS::singleton(T_STACK)}},
                 {
                     r7.svalue >= 1,
                     r1.svalue == 146,
                     r10.svalue >= 4096,
                     r10.svalue <= 2147418112,
                 },
                 // Conservative overapproximation of correct join
                 {{r0_type, TS::of({T_MAP, T_NUM})},
                  {r6_type, TS::of({T_MAP, T_NUM})},
                  {r7_type, TS::singleton(T_NUM)},
                  {r10_type, TS::singleton(T_STACK)}},
                 {
                     r7.svalue >= 0,
                     r1.svalue >= 146,
                     r1.svalue <= 153,
                     r10.svalue >= 4096,
                     r10.svalue <= 2147418112,
                 });
}

// 11) Relational domain properties
TEST_CASE("join preserves equality relation across branches", "[join][lattice]") {
    using namespace dsl_syntax;
    // Both branches assert r0.svalue == r1.svalue with different constants; after join, equality should be preserved
    require_join({{r0_type, TS::singleton(T_NUM)}, {r1_type, TS::singleton(T_NUM)}},
                 {eq(r0.svalue, r1.svalue), r0.svalue == 5, eq(r0.uvalue, r1.uvalue)},
                 {{r0_type, TS::singleton(T_NUM)}, {r1_type, TS::singleton(T_NUM)}},
                 {eq(r0.svalue, r1.svalue), r0.svalue == 7, eq(r0.uvalue, r1.uvalue)},
                 {{r0_type, TS::singleton(T_NUM)}, {r1_type, TS::singleton(T_NUM)}},
                 {r0.svalue >= 5, r0.svalue <= 7, r1.svalue >= 5, r1.svalue <= 7, eq(r0.svalue, r1.svalue),
                  eq(r0.uvalue, r1.uvalue)});
}

TEST_CASE("join drops opposing order relations but keeps per-var hulls", "[join][lattice]") {
    using namespace dsl_syntax;
    // One branch has r0.svalue <= r1.svalue, the other r1.svalue <= r0.svalue, on the same intervals.
    require_join({{r0_type, TS::singleton(T_NUM)}, {r1_type, TS::singleton(T_NUM)}},
                 {r0.svalue >= 0, r0.svalue <= 10, r1.svalue >= 5, r1.svalue <= 15, r0.svalue <= r1.svalue},
                 {{r0_type, TS::singleton(T_NUM)}, {r1_type, TS::singleton(T_NUM)}},
                 {r0.svalue >= 0, r0.svalue <= 10, r1.svalue >= 5, r1.svalue <= 15, r1.svalue <= r0.svalue},
                 {{r0_type, TS::singleton(T_NUM)}, {r1_type, TS::singleton(T_NUM)}},
                 {r0.svalue >= 0, r0.svalue <= 10, r1.svalue >= 5, r1.svalue <= 15});
}

// 12) svalue/uvalue interactions and implicit holes
TEST_CASE("join preserves svalue/uvalue-implied hole when both branches imply it", "[join][lattice]") {
    using namespace dsl_syntax;
    // Negative signed implies large unsigned (>= 2^63). Both branches keep this fact, join should too.
    const Number two63 = Number::max_int(64) + Number(1); // 2^63
    require_join({{r0_type, TS::singleton(T_NUM)}}, {r0.svalue <= -1, r0.uvalue >= two63},
                 {{r0_type, TS::singleton(T_NUM)}}, {r0.svalue <= -10, r0.uvalue >= two63},
                 {{r0_type, TS::singleton(T_NUM)}}, {r0.svalue <= -1, r0.uvalue >= two63});
}

TEST_CASE("join may lose hole if other branch allows small non-negative values", "[join][lattice]") {
    using namespace dsl_syntax;
    const Number two63 = Number::max_int(64) + Number(1); // 2^63
    // Branch A implies a hole around 0 (negative signed => u >= 2^63).
    // Branch B allows only small non-negative values.
    // The joined over-approx (convex hull on each dimension) can lose the hole.
    require_join(
        {{r0_type, TS::singleton(T_NUM)}}, {r0.svalue <= -1, r0.uvalue >= two63}, {{r0_type, TS::singleton(T_NUM)}},
        {r0.svalue >= 0, r0.svalue <= 100, r0.uvalue >= 0, r0.uvalue <= 100}, {{r0_type, TS::singleton(T_NUM)}}, {});
}

// 13) Algebraic laws: commutativity and idempotence
TEST_CASE("join is commutative and idempotent (domain-wide)", "[join][lattice]") {
    using namespace dsl_syntax;
    const TypeRestrictions TA{{r0_type, TS::singleton(T_PACKET)}};
    const std::vector A{r0.svalue >= 1, r0.svalue <= 3, r0.packet_offset == 4};

    // Idempotence
    require_join(TA, A, TA, A, TA, A);

    // Commutativity: A | B = B | A (same over-approx)
    const TypeRestrictions TB{{r0_type, TS::singleton(T_NUM)}};
    const std::vector B{r0.svalue >= 2, r0.svalue <= 5};
    const TypeRestrictions Tover{{r0_type, TS::of({T_NUM, T_PACKET})}};
    const std::vector over{r0.svalue >= 1, r0.svalue <= 5, r0.packet_offset == 4};
    require_join(TA, A, TB, B, Tover, over);
    require_join(TB, B, TA, A, Tover, over);
}

// 14) Numeric value across pointer/num join (value facts should not leak to pointer case)
TEST_CASE("join does not conflate value facts across pointer/num", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_NUM)}}, {r0.svalue == 42}, {{r0_type, TS::singleton(T_PACKET)}},
                 {r0.packet_offset == 8}, {{r0_type, TS::of({T_NUM, T_PACKET})}}, {r0.packet_offset == 8});
}

// 15) Extreme bounds (overflow safety of convex hull)
TEST_CASE("join convex hull with extreme 64-bit bounds", "[join][lattice]") {
    using namespace dsl_syntax;
    const Number min64 = Number::min_int(64);
    const Number max64 = Number::max_int(64);
    require_join({{r0_type, TS::singleton(T_NUM)}}, {r0.svalue >= min64, r0.svalue <= -1},
                 {{r0_type, TS::singleton(T_NUM)}}, {r0.svalue >= 1, r0.svalue <= max64},
                 {{r0_type, TS::singleton(T_NUM)}}, {r0.svalue >= min64, r0.svalue <= max64});
}

// 16) Disjoint intervals with a gap
TEST_CASE("join hull of disjoint intervals with gap", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_NUM)}}, {r0.svalue >= -10, r0.svalue <= -1},
                 {{r0_type, TS::singleton(T_NUM)}}, {r0.svalue >= 1, r0.svalue <= 10},
                 {{r0_type, TS::singleton(T_NUM)}}, {r0.svalue >= -10, r0.svalue <= 10});
}

// 17) Mixed per-type fields preserved under widening
TEST_CASE("join preserves multiple per-type fields across type widening", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_PACKET)}}, {r0.packet_offset == 8}, {{r0_type, TS::singleton(T_STACK)}},
                 {r0.stack_offset == 96}, {{r0_type, TS::of({T_PACKET, T_STACK})}},
                 {r0.packet_offset == 8, r0.stack_offset == 96});
}

// 18) Map FD differing constants
TEST_CASE("join map fd differing constants forms hull", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_MAP)}}, {r0.map_fd == 7}, {{r0_type, TS::singleton(T_MAP)}},
                 {r0.map_fd == 9}, {{r0_type, TS::singleton(T_MAP)}}, {r0.map_fd >= 7, r0.map_fd <= 9});
}

// 19) Shared region size differing
TEST_CASE("join shared region size differing values", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join(
        {{r0_type, TS::singleton(T_SHARED)}}, {r0.shared_offset == 0, r0.shared_region_size == 64},
        {{r0_type, TS::singleton(T_SHARED)}}, {r0.shared_offset == 32, r0.shared_region_size == 128},
        {{r0_type, TS::singleton(T_SHARED)}},
        {r0.shared_offset >= 0, r0.shared_offset <= 32, r0.shared_region_size >= 64, r0.shared_region_size <= 128});
}

// 20) Context fields vanish when resulting type excludes T_CTX
TEST_CASE("join does not retain ctx_offset if resulting type excludes T_CTX", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r0_type, TS::singleton(T_CTX)}}, {r0.ctx_offset == 16},
                 {{r0_type, TS::of({T_NUM, T_CTX, T_PACKET, T_STACK})}}, {},
                 {{r0_type, TS::of({T_NUM, T_CTX, T_PACKET, T_STACK})}}, {});
}

// 21) Multi-register per-type field preservation under mixed joins
TEST_CASE("join preserves multi-register per-type field", "[join][lattice]") {
    using namespace dsl_syntax;
    require_join({{r6_type, TS::singleton(T_PACKET)}, {r7_type, TS::singleton(T_NUM)}}, {r6.packet_offset == 4},
                 {{r6_type, TS::singleton(T_NUM)}, {r7_type, TS::singleton(T_STACK)}}, {r7.stack_offset == 128},
                 {{r6_type, TS::of({T_NUM, T_PACKET})}, {r7_type, TS::of({T_NUM, T_STACK})}},
                 {r6.packet_offset == 4, r7.stack_offset == 128});
}

// 22) SplitDBM widen closure
TEST_CASE("close_after_widen recovers transitive edge through unstable vertex", "[widen][splitdbm]") {
    using namespace splitdbm;

    // Vertices: 0 (special zero vertex), 1, 2, 3.
    //
    // Left (closed) graph:
    //   Bounds: 0->v: 100, v->0: 0 for v in {1,2,3}
    //   Relations: 1->2: 5, 2->3: 5, 1->3: 10 (closure of 1->2->3)
    //
    // Right graph (same, except 1->3 is LOOSER: 12 instead of 10):
    //   Relations: 1->2: 5, 2->3: 5, 1->3: 12
    //
    // Widening keeps edges where right <= left, using left's weight:
    //   1->2: 5 (kept), 2->3: 5 (kept), 1->3: DROPPED (12 > 10)
    //
    // Vertex 1 becomes unstable (lost outgoing edge 1->3).
    //
    // close_after_widen should run Dijkstra recovery from unstable vertex 1
    // and discover the transitive path 1->2->3 = 5+5 = 10, adding edge 1->3: 10.

    auto make_graph = [](Weight w13) {
        Graph g;
        g.growTo(4);
        g.add_edge(0, Weight(100), 1);
        g.add_edge(1, Weight(0), 0);
        g.add_edge(0, Weight(100), 2);
        g.add_edge(2, Weight(0), 0);
        g.add_edge(0, Weight(100), 3);
        g.add_edge(3, Weight(0), 0);
        g.add_edge(1, Weight(5), 2);
        g.add_edge(2, Weight(5), 3);
        g.add_edge(1, w13, 3);
        return g;
    };

    std::vector<Weight> pot = {Weight(0), Weight(0), Weight(5), Weight(10)};

    SplitDBM left(make_graph(Weight(10)), std::vector<Weight>(pot), VertSet{});
    SplitDBM right(make_graph(Weight(12)), std::vector<Weight>(pot), VertSet{});

    AlignedPair aligned{
        .left = left,
        .right = right,
        .left_perm = {0, 1, 2, 3},
        .right_perm = {0, 1, 2, 3},
        .initial_potentials = std::vector<Weight>(pot),
    };

    SplitDBM result = SplitDBM::widen(aligned);
    const Graph& rg = result.graph();

    REQUIRE(rg.elem(1, 2));
    CHECK(rg.edge_val(1, 2) == Weight(5));

    REQUIRE(rg.elem(2, 3));
    CHECK(rg.edge_val(2, 3) == Weight(5));

    // The transitive edge 1->3 should be recovered via path 1->2->3 = 5+5 = 10.
    REQUIRE(rg.elem(1, 3));
    CHECK(rg.edge_val(1, 3) == Weight(10));
}

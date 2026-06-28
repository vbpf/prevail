// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>

#include "arith/dsl_syntax.hpp"
#include "crab/type_to_num.hpp"

using namespace prevail;

static constexpr Reg r0{0};
static constexpr Reg r1{1};

TEST_CASE("forget_type_dependent_values preserves type and universal value", "[type_to_num]") {
    TypeToNumDomain dom;
    const RegPack pack = reg_pack(r0);

    dom.assign_type(r0, T_STACK);
    dom.values.assign(pack.uvalue, 512);
    dom.values.assign(pack.svalue, 512);
    dom.values.assign(pack.stack_offset, 512);

    dom.forget_type_dependent_values(r0);

    REQUIRE(dom.get_type(r0) == T_STACK);
    REQUIRE(dom.values.eval_interval(pack.uvalue) == Interval{512});
    REQUIRE(dom.values.eval_interval(pack.svalue).is_top());
    REQUIRE(dom.values.eval_interval(pack.stack_offset).is_top());
}

TEST_CASE("TypeToNumDomain register assignment clears stale destination kind values", "[type_to_num]") {
    using namespace dsl_syntax;

    TypeToNumDomain dom;
    const RegPack dst = reg_pack(r0);
    const RegPack src = reg_pack(r1);

    dom.assign_type(r0, T_NUM);
    dom.values.assign(dst.svalue, 7);
    dom.values.assign(dst.uvalue, 7);

    dom.assign_type(r1, T_SHARED);
    dom.values.assign(src.uvalue, 100);
    dom.values.assign(src.shared_offset, 4);
    dom.values.assign(src.shared_region_size, 16);

    dom.assign(r0, r1);

    REQUIRE(dom.get_type(r0) == T_SHARED);
    REQUIRE(dom.values.eval_interval(dst.uvalue) == Interval{100});
    REQUIRE(dom.values.eval_interval(dst.shared_offset) == Interval{4});
    REQUIRE(dom.values.entail(eq(dst.shared_region_size, src.shared_region_size)));
    REQUIRE(dom.values.entail(dst.shared_region_size >= 16));
    REQUIRE(dom.values.eval_interval(dst.svalue).is_top());
}

TEST_CASE("TypeToNumDomain self assignment keeps kind values", "[type_to_num]") {
    TypeToNumDomain dom;
    const RegPack pack = reg_pack(r0);

    dom.assign_type(r0, T_NUM);
    dom.values.assign(pack.svalue, -3);
    dom.values.assign(pack.uvalue, 7);

    dom.assign(r0, r0);

    REQUIRE(dom.get_type(r0) == T_NUM);
    REQUIRE(dom.values.eval_interval(pack.svalue) == Interval{-3});
    REQUIRE(dom.values.eval_interval(pack.uvalue) == Interval{7});
}

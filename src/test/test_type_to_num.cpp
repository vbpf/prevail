// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>

#include <string>

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

TEST_CASE("forget_type_dependent_values handles stack frame type variables", "[type_to_num]") {
    TypeToNumDomain dom;
    const std::string prefix = "saved";
    const Variable frame_type = variable_registry.stack_frame_var(DataKind::types, r0.v, prefix);
    const Variable frame_uvalue = variable_registry.stack_frame_var(DataKind::uvalues, r0.v, prefix);
    const Variable frame_svalue = variable_registry.stack_frame_var(DataKind::svalues, r0.v, prefix);
    const Variable frame_stack_offset = variable_registry.stack_frame_var(DataKind::stack_offsets, r0.v, prefix);

    dom.assign_type(frame_type, LinearExpression{T_STACK});
    dom.values.assign(frame_uvalue, 512);
    dom.values.assign(frame_svalue, 512);
    dom.values.assign(frame_stack_offset, 512);

    dom.forget_type_dependent_values(frame_type);

    REQUIRE(dom.types.entail_type(frame_type, T_STACK));
    REQUIRE(dom.values.eval_interval(frame_uvalue) == Interval{512});
    REQUIRE(dom.values.eval_interval(frame_svalue).is_top());
    REQUIRE(dom.values.eval_interval(frame_stack_offset).is_top());
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

// r0 is either the number 0 or a pointer to the start of the context.
static TypeToNumDomain zero_or_ctx() {
    TypeToNumDomain dom;
    dom.types.restrict_to(reg_type(r0), TypeSet{T_NUM, T_CTX});
    dom.values.assign(reg_pack(r0).svalue, 0);
    dom.values.assign(reg_pack(r0).ctx_offset, 0);
    return dom;
}

TEST_CASE("TypeToNumDomain narrow forgets kind values of removed types", "[type_to_num]") {
    const RegPack pack = reg_pack(r0);

    TypeToNumDomain ctx;
    ctx.assign_type(r0, T_CTX);
    ctx.values.assign(pack.ctx_offset, 0);

    const TypeToNumDomain res = zero_or_ctx().narrow(ctx);

    REQUIRE(res.get_type(r0) == T_CTX);
    REQUIRE(res.values.eval_interval(pack.ctx_offset) == Interval{0});
    REQUIRE(res.values.eval_interval(pack.svalue).is_top());
}

TEST_CASE("TypeToNumDomain meet forgets kind values of removed types", "[type_to_num]") {
    const RegPack pack = reg_pack(r0);

    TypeToNumDomain ctx;
    ctx.assign_type(r0, T_CTX);
    ctx.values.assign(pack.ctx_offset, 0);

    for (const TypeToNumDomain& res : {zero_or_ctx() & ctx, ctx & zero_or_ctx()}) {
        REQUIRE(res.get_type(r0) == T_CTX);
        REQUIRE(res.values.eval_interval(pack.ctx_offset) == Interval{0});
        REQUIRE(res.values.eval_interval(pack.svalue).is_top());
    }
}

TEST_CASE("TypeToNumDomain meet ignores conflicts on kind values of removed types", "[type_to_num]") {
    const RegPack pack = reg_pack(r0);

    // svalue=0 describes the number alternative only, so it does not contradict what is known about the pointer.
    TypeToNumDomain ctx;
    ctx.assign_type(r0, T_CTX);
    ctx.values.assign(pack.ctx_offset, 0);
    ctx.values.assign(pack.svalue, 4096);

    for (const TypeToNumDomain& res : {zero_or_ctx() & ctx, ctx & zero_or_ctx()}) {
        REQUIRE_FALSE(res.is_bottom());
        REQUIRE(res.get_type(r0) == T_CTX);
        REQUIRE(res.values.eval_interval(pack.ctx_offset) == Interval{0});
    }
}

TEST_CASE("TypeToNumDomain join_over_types forgets kind values of all registers sharing the type", "[type_to_num]") {
    const RegPack pack = reg_pack(r1);

    TypeToNumDomain dom = zero_or_ctx();
    dom.assign(r1, r0);
    REQUIRE(dom.same_type(r0, r1));

    const TypeToNumDomain res = dom.join_over_types(r0, [&](TypeToNumDomain& state, const TypeEncoding type) {
        REQUIRE(state.get_type(r1) == type);
        REQUIRE(state.values.eval_interval(pack.svalue).is_top() == (type != T_NUM));
        REQUIRE(state.values.eval_interval(pack.ctx_offset).is_top() == (type != T_CTX));
        if (type == T_NUM) {
            state.set_to_bottom();
        }
    });

    REQUIRE(res.get_type(r1) == T_CTX);
    REQUIRE(res.values.eval_interval(pack.ctx_offset) == Interval{0});
    REQUIRE(res.values.eval_interval(pack.svalue).is_top());
}

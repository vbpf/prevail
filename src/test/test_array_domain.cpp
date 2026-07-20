// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "crab/array_domain.hpp"

using namespace prevail;

TEST_CASE("numeric byte queries outside the stack window fail closed", "[array_domain]") {
    ArrayDomain stack{8};
    stack.initialize_numbers(0, 8);

    REQUIRE(stack.all_num_width(Interval{0}, Interval{8}));
    REQUIRE_FALSE(stack.all_num_width(Interval{8}, Interval{4}));
    REQUIRE_FALSE(stack.all_num_width(Interval{16}, Interval{4}));
    REQUIRE_FALSE(stack.all_num_width(Interval{-8}, Interval{4}));
    REQUIRE_FALSE(stack.all_num_lb_ub(Interval{8}, Interval{12}));
    REQUIRE_FALSE(stack.all_num_lb_ub(Interval{16}, Interval{20}));
    REQUIRE_FALSE(stack.all_num_lb_ub(Interval{-8}, Interval{-4}));
}

TEST_CASE("weak type store outside the stack window is a no-op", "[array_domain]") {
    ArrayDomain stack{8};
    TypeDomain types;
    stack.initialize_numbers(0, 8);

    REQUIRE_NOTHROW((void)stack.store_type(types, Interval{16}, Interval{4}, false));
    REQUIRE(stack.all_num_width(Interval{0}, Interval{8}));
}

TEST_CASE("weak type store havoc spans the byte width, not the upper bound", "[array_domain]") {
    ArrayDomain stack{64};
    TypeDomain types;
    stack.initialize_numbers(0, 64);

    // Weak update (non-singleton index) of a non-numeric value over bytes
    // [8, 20). Only that range must become non-numeric; the bug passed the
    // upper bound (20) as the width and clobbered [8, 28) instead.
    (void)stack.store_type(types, Interval{8, 16}, Interval{4}, /*is_num=*/false);

    REQUIRE_FALSE(stack.all_num_width(Interval{8}, Interval{4})); // [8, 12): targeted, non-numeric
    REQUIRE(stack.all_num_width(Interval{20}, Interval{4}));      // [20, 24): untouched, still numeric
    REQUIRE(stack.all_num_width(Interval{24}, Interval{4}));      // [24, 28): untouched, still numeric
}

TEST_CASE("stack access at a negative singleton offset does not throw", "[array_domain]") {
    // Regression for an InternalError thrown when a stack pointer is walked out of
    // bounds (below the frame) across loop iterations: the resulting negative constant
    // offset reached Number::narrow<Index>() (an unsigned type) and threw, crashing the
    // analysis instead of letting the assertion checker reject the out-of-bounds access.
    // The array domain must handle such offsets gracefully (there is no cell there).
    ArrayDomain stack{8};
    TypeDomain types;
    NumAbsDomain values = NumAbsDomain::top();
    stack.initialize_numbers(0, 8);

    const Interval neg{-8};
    const Interval width{8};

    REQUIRE_NOTHROW((void)stack.store_type(types, neg, width, /*is_num=*/false));
    REQUIRE_NOTHROW(stack.havoc_type(types, neg, width));
    REQUIRE_NOTHROW(stack.havoc(values, DataKind::svalues, neg, width, /*big_endian=*/false));
    REQUIRE_NOTHROW((void)stack.store(values, DataKind::svalues, neg, width, /*big_endian=*/false));

    // The in-bounds numeric cell must be untouched by the out-of-bounds operations.
    REQUIRE(stack.all_num_width(Interval{0}, Interval{8}));
}

TEST_CASE("out-of-bounds negative offset kill preserves the in-bounds cell value", "[array_domain]") {
    // A negative constant offset must not be routed through the symbolic kill path:
    // the inclusive range `[-8] | ([-8] + [8]) = [-8, 0]` overlaps the tracked cell
    // [0, 8) and would erase its value. The offset-0 access at [-8, 8) covers bytes
    // [-8, 0), which does not include byte 0, so the cell must survive intact.
    ArrayDomain stack{8};
    NumAbsDomain values = NumAbsDomain::top();
    stack.initialize_numbers(0, 8);

    // Store a known value in the in-bounds 8-byte cell at offset 0.
    const std::optional<Variable> cell = stack.store(values, DataKind::svalues, Interval{0}, Interval{8},
                                                     /*big_endian=*/false);
    REQUIRE(cell.has_value());
    values.assign(*cell, LinearExpression{Number{42}});

    // An out-of-bounds havoc/store at a negative offset must leave the offset-0 cell alone.
    stack.havoc(values, DataKind::svalues, Interval{-8}, Interval{8}, /*big_endian=*/false);
    (void)stack.store(values, DataKind::svalues, Interval{-8}, Interval{8}, /*big_endian=*/false);

    const std::optional<LinearExpression> reloaded =
        stack.load(values, DataKind::svalues, Interval{0}, 8, /*big_endian=*/false);
    REQUIRE(reloaded.has_value());
    REQUIRE(values.eval_interval(*reloaded).singleton() == Number{42});
}

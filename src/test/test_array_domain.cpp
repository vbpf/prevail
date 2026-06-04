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

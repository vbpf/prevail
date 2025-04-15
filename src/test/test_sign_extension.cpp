// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include <algorithm>
#include <cstdint>

#include "crab/interval.hpp"

using namespace prevail;

TEST_CASE("sign_extend 1 bit positive-positive", "[sign_extension]") {
    // no actual sign extension needed
    REQUIRE(interval_t{0b0'0, 0b0'0}.sign_extend(1) == interval_t{0, 0});
}

TEST_CASE("sign_extend 1 bit negative-negative", "[sign_extension]") {
    // straight-forward sign extension on both ends; order is preserved
    REQUIRE(interval_t{0b0'1, 0b0'1}.sign_extend(1) == interval_t{-1, -1});
}

TEST_CASE("sign_extend 1 bit positive-negative", "[sign_extension]") {
    // 0b1 is in the range (<=ub)
    // 0b0 is in the range (>=lb)
    // so the convex hull is [-1, 0]
    REQUIRE(interval_t{0b0'0, 0b0'1}.sign_extend(1) == interval_t{-1, 0});
}

// === 2 bits ===

TEST_CASE("sign_extend 2 bits positive-positive", "[sign_extension]") {
    // no actual sign extension needed
    REQUIRE(interval_t{0b0'00, 0b0'00}.sign_extend(2) == interval_t{0, 0});
    REQUIRE(interval_t{0b0'00, 0b0'01}.sign_extend(2) == interval_t{0, 1});

    REQUIRE(interval_t{0b0'01, 0b0'01}.sign_extend(2) == interval_t{1, 1});
}

TEST_CASE("sign_extend 2 bits negative-negative", "[sign_extension]") {
    // straight-forward sign extension on both ends; order is preserved
    REQUIRE(interval_t{0b0'10, 0b0'10}.sign_extend(2) == interval_t{-2, -2});
    REQUIRE(interval_t{0b0'10, 0b0'11}.sign_extend(2) == interval_t{-2, -1});

    REQUIRE(interval_t{0b0'11, 0b0'11}.sign_extend(2) == interval_t{-1, -1});
}

TEST_CASE("sign_extend 2 bits positive-negative", "[sign_extension]") {
    // 0b10 is in the range (<=ub)
    // 0b01 is in the range (>=lb)
    // so the convex hull is [-2, 1]
    REQUIRE(interval_t{0b0'00, 0b0'10}.sign_extend(2) == interval_t{-2, 1});
    REQUIRE(interval_t{0b0'00, 0b0'11}.sign_extend(2) == interval_t{-2, 1});

    REQUIRE(interval_t{0b0'01, 0b0'10}.sign_extend(2) == interval_t{-2, 1});
    REQUIRE(interval_t{0b0'01, 0b0'11}.sign_extend(2) == interval_t{-2, 1});
}
// === 3 bits ===

TEST_CASE("sign_extend 3 bits positive-positive", "[sign_extension]") {
    // no actual sign extension needed
    REQUIRE(interval_t{0b0'000, 0b0'000}.sign_extend(3) == interval_t{0, 0});
    REQUIRE(interval_t{0b0'000, 0b0'001}.sign_extend(3) == interval_t{0, 1});
    REQUIRE(interval_t{0b0'000, 0b0'010}.sign_extend(3) == interval_t{0, 2});
    REQUIRE(interval_t{0b0'000, 0b0'011}.sign_extend(3) == interval_t{0, 3});

    REQUIRE(interval_t{0b0'001, 0b0'001}.sign_extend(3) == interval_t{1, 1});
    REQUIRE(interval_t{0b0'001, 0b0'010}.sign_extend(3) == interval_t{1, 2});
    REQUIRE(interval_t{0b0'001, 0b0'011}.sign_extend(3) == interval_t{1, 3});

    REQUIRE(interval_t{0b0'010, 0b0'010}.sign_extend(3) == interval_t{2, 2});
    REQUIRE(interval_t{0b0'010, 0b0'011}.sign_extend(3) == interval_t{2, 3});

    REQUIRE(interval_t{0b0'011, 0b0'011}.sign_extend(3) == interval_t{3, 3});
}

TEST_CASE("sign_extend 3 bits negative-negative", "[sign_extension]") {
    // straight-forward sign extension on both ends; order is preserved
    REQUIRE(interval_t{0b0'100, 0b0'100}.sign_extend(3) == interval_t{-4, -4});
    REQUIRE(interval_t{0b0'100, 0b0'101}.sign_extend(3) == interval_t{-4, -3});
    REQUIRE(interval_t{0b0'100, 0b0'110}.sign_extend(3) == interval_t{-4, -2});
    REQUIRE(interval_t{0b0'100, 0b0'111}.sign_extend(3) == interval_t{-4, -1});

    REQUIRE(interval_t{0b0'101, 0b0'101}.sign_extend(3) == interval_t{-3, -3});
    REQUIRE(interval_t{0b0'101, 0b0'110}.sign_extend(3) == interval_t{-3, -2});
    REQUIRE(interval_t{0b0'101, 0b0'111}.sign_extend(3) == interval_t{-3, -1});

    REQUIRE(interval_t{0b0'110, 0b0'110}.sign_extend(3) == interval_t{-2, -2});
    REQUIRE(interval_t{0b0'110, 0b0'111}.sign_extend(3) == interval_t{-2, -1});

    REQUIRE(interval_t{0b0'111, 0b0'111}.sign_extend(3) == interval_t{-1, -1});
}

TEST_CASE("sign_extend 3 bits positive-negative", "[sign_extension]") {
    // 0b100 is in the range (<=ub)
    // 0b011 is in the range (>=lb)
    // so the convex hull is [-4, 3]
    REQUIRE(interval_t{0b0'000, 0b0'100}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'000, 0b0'101}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'000, 0b0'110}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'000, 0b0'111}.sign_extend(3) == interval_t{-4, 3});

    REQUIRE(interval_t{0b0'001, 0b0'100}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'001, 0b0'101}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'001, 0b0'110}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'001, 0b0'111}.sign_extend(3) == interval_t{-4, 3});

    REQUIRE(interval_t{0b0'010, 0b0'100}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'010, 0b0'101}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'010, 0b0'110}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'010, 0b0'111}.sign_extend(3) == interval_t{-4, 3});

    REQUIRE(interval_t{0b0'011, 0b0'100}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'011, 0b0'101}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'011, 0b0'110}.sign_extend(3) == interval_t{-4, 3});
    REQUIRE(interval_t{0b0'011, 0b0'111}.sign_extend(3) == interval_t{-4, 3});
}

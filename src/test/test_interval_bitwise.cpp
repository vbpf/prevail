// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include <cstdint>
#include <limits>

#include "crab/interval.hpp"

using namespace prevail;

TEST_CASE("bitwise_and with singleton all-ones preserves lhs modulo width", "[interval][bitwise]") {
    const Interval left{5, 100};
    const Interval right{std::numeric_limits<uint64_t>::max()};
    REQUIRE(left.bitwise_and(right) == Interval{5, 100});
}

TEST_CASE("bitwise_and with non-singleton containing all-ones includes zero", "[interval][bitwise]") {
    const Interval left{5, 100};
    const Interval anomalous_right{-5, 5};
    REQUIRE(left.bitwise_and(anomalous_right) == Interval{0, 100});
}

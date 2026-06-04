// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include <cstdint>
#include <limits>

#include "crab/finite_domain.hpp"
#include "crab/interval.hpp"
#include "crab/type_to_num.hpp"

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

TEST_CASE("signed division by a negative singleton preserves interval order", "[interval][arithmetic]") {
    REQUIRE(Interval{-8, -4}.sdiv(Interval{-1}) == Interval{4, 8});
    REQUIRE(Interval{4, 8}.sdiv(Interval{-2}) == Interval{-4, -2});
    REQUIRE(Interval::top().sdiv(Interval{-1}) == Interval::top());
    REQUIRE((Interval::top() / Interval{-1}) == Interval::top());
}

TEST_CASE("finite domain left shift by zero preserves 64-bit interval", "[finite_domain][bitwise]") {
    FiniteDomain::clear_thread_local_state();
    const auto r1 = reg_pack(1);
    FiniteDomain domain;
    domain.set(r1.svalue, Interval{1, 5});
    domain.set(r1.uvalue, Interval{1, 5});

    domain.shl(r1.svalue, r1.uvalue, 0, 64);

    REQUIRE(domain.eval_interval(r1.uvalue) == Interval{1, 5});
    REQUIRE(domain.eval_interval(r1.svalue) == Interval{1, 5});
}

TEST_CASE("finite domain 32-bit left shift by zero widens when high operand bits differ", "[finite_domain][bitwise]") {
    FiniteDomain::clear_thread_local_state();
    const auto r2 = reg_pack(2);
    FiniteDomain domain;
    const Number uint32_max{std::numeric_limits<uint32_t>::max()};
    domain.set(r2.svalue, Interval{uint32_max, uint32_max + 1});
    domain.set(r2.uvalue, Interval{uint32_max, uint32_max + 1});

    domain.shl(r2.svalue, r2.uvalue, 0, 32);

    REQUIRE(domain.eval_interval(r2.uvalue) == Interval::top());
    REQUIRE(domain.eval_interval(r2.svalue) == Interval::top());
}

TEST_CASE("finite domain left shift widens when high operand bits differ", "[finite_domain][bitwise]") {
    FiniteDomain::clear_thread_local_state();
    const auto r2 = reg_pack(2);
    FiniteDomain domain;
    const Number top_bit{uint64_t{1} << 63};
    domain.set(r2.svalue, Interval{top_bit - 1, top_bit});
    domain.set(r2.uvalue, Interval{top_bit - 1, top_bit});

    domain.shl(r2.svalue, r2.uvalue, 1, 64);

    REQUIRE(domain.eval_interval(r2.uvalue) == Interval{0, std::numeric_limits<uint64_t>::max() - 1});
    REQUIRE(domain.eval_interval(r2.svalue) == Interval::top());
}

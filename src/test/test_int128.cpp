// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// Validates the Boost-free 128-bit integers in arith/num_int128.hpp against the compiler's
// native __int128 as an oracle. Only meaningful where __int128 exists (GCC/Clang), which is
// where the test suite runs; the custom types are what MSVC uses in production.

#include <catch2/catch_all.hpp>

#include <cstdint>
#include <limits>
#include <vector>

#include "arith/num_int128.hpp"

#ifdef __GNUC__

using prevail::detail::Int128Custom;
using prevail::detail::UInt128Custom;

namespace {
using i128 = __int128;
using u128 = unsigned __int128;

constexpr UInt128Custom to_cu(const u128 x) {
    return UInt128Custom{static_cast<uint64_t>(x >> 64), static_cast<uint64_t>(x)};
}
constexpr Int128Custom to_ci(const i128 x) { return Int128Custom{to_cu(static_cast<u128>(x))}; }
constexpr u128 from_cu(const UInt128Custom c) { return (static_cast<u128>(c.hi) << 64) | c.lo; }
constexpr u128 from_ci(const Int128Custom c) { return from_cu(c.u); }

// Interesting 128-bit bit patterns (used for both signed and unsigned interpretations).
std::vector<u128> sample_values() {
    std::vector<u128> v;
    const std::vector<uint64_t> limbs = {
        0, 1, 2, 3, 7, 0xff, 0x8000000000000000ULL, ~0ULL, 0x123456789abcdefULL, 0x7fffffffffffffffULL, 1000000007ULL};
    for (const uint64_t hi : limbs) {
        for (const uint64_t lo : limbs) {
            v.push_back((static_cast<u128>(hi) << 64) | lo);
        }
    }
    v.push_back(static_cast<u128>(-1));
    v.push_back(static_cast<u128>(std::numeric_limits<int64_t>::min()));
    v.push_back(~static_cast<u128>(0) >> 1);       // int128 max
    v.push_back((~static_cast<u128>(0) >> 1) + 1); // int128 min
    return v;
}
} // namespace

TEST_CASE("custom uint128 matches native unsigned __int128", "[int128]") {
    const auto vals = sample_values();
    for (const u128 a : vals) {
        const UInt128Custom ca = to_cu(a);
        CHECK(from_cu(~ca) == static_cast<u128>(~a));
        CHECK(from_cu(-ca) == static_cast<u128>(-a));
        for (int s = 0; s < 128; ++s) {
            CHECK(from_cu(ca << s) == static_cast<u128>(a << s));
            CHECK(from_cu(ca >> s) == (a >> s));
        }
        for (const u128 b : vals) {
            const UInt128Custom cb = to_cu(b);
            CHECK(from_cu(ca + cb) == static_cast<u128>(a + b));
            CHECK(from_cu(ca - cb) == static_cast<u128>(a - b));
            CHECK(from_cu(ca * cb) == static_cast<u128>(a * b));
            CHECK(from_cu(ca & cb) == (a & b));
            CHECK(from_cu(ca | cb) == (a | b));
            CHECK(from_cu(ca ^ cb) == (a ^ b));
            CHECK((ca == cb) == (a == b));
            CHECK((ca < cb) == (a < b));
            CHECK((ca <= cb) == (a <= b));
            CHECK((ca > cb) == (a > b));
            if (b != 0) {
                CHECK(from_cu(ca / cb) == (a / b));
                CHECK(from_cu(ca % cb) == (a % b));
            }
        }
    }
}

TEST_CASE("custom int128 matches native signed __int128", "[int128]") {
    const auto vals = sample_values();
    constexpr i128 int128_min = static_cast<i128>(static_cast<u128>(1) << 127);
    for (const u128 ua : vals) {
        const auto a = static_cast<i128>(ua);
        const Int128Custom ca = to_ci(a);
        CHECK(from_ci(-ca) == static_cast<u128>(-a));
        CHECK(static_cast<int64_t>(ca) == static_cast<int64_t>(a));
        CHECK(static_cast<uint64_t>(ca) == static_cast<uint64_t>(a));
        CHECK(static_cast<int32_t>(ca) == static_cast<int32_t>(a));
        for (int s = 0; s < 128; ++s) {
            CHECK(from_ci(ca << s) == static_cast<u128>(a << s));
            CHECK(from_ci(ca >> s) == static_cast<u128>(a >> s)); // arithmetic shift
        }
        for (const u128 ub : vals) {
            const auto b = static_cast<i128>(ub);
            const Int128Custom cb = to_ci(b);
            CHECK(from_ci(ca + cb) == static_cast<u128>(a + b));
            CHECK(from_ci(ca - cb) == static_cast<u128>(a - b));
            CHECK(from_ci(ca * cb) == static_cast<u128>(a * b));
            CHECK((ca == cb) == (a == b));
            CHECK((ca < cb) == (a < b));
            CHECK((ca <= cb) == (a <= b));
            CHECK((ca > cb) == (a > b));
            CHECK((ca >= cb) == (a >= b));
            // Skip the one case that is UB for native __int128 too (INT128_MIN / -1).
            if (b != 0 && !(a == int128_min && b == -1)) {
                CHECK(from_ci(ca / cb) == static_cast<u128>(a / b));
                CHECK(from_ci(ca % cb) == static_cast<u128>(a % b));
            }
        }
    }
}

#endif // __GNUC__

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include <algorithm>
#include <iterator>
#include <set>
#include <string>

#include "string_constraints.hpp"

using namespace prevail;

namespace {
// Mirror of the line-set difference the YAML harness uses to build its
// "unexpected"/"unseen" diffs, so this test exercises the same operation.
std::set<std::string> line_difference(const std::set<std::string>& a, const std::set<std::string>& b) {
    std::set<std::string> res;
    std::ranges::set_difference(a, b, std::inserter(res, res.begin()));
    return res;
}
} // namespace

// to_lines renders an invariant as the set of text lines the YAML harness diffs
// on. Bottom must render as the single line "_|_" -- the exact form the harness
// parses back into a bottom invariant -- so that the diff is an ordinary
// set-difference over lines with no special-casing of bottom.
TEST_CASE("StringInvariant::to_lines renders bottom as the \"_|_\" line", "[string_constraints]") {
    CHECK(StringInvariant::bottom().to_lines() == std::set<std::string>{"_|_"});
    CHECK(StringInvariant::top().to_lines() == std::set<std::string>{});
    CHECK(StringInvariant{std::set<std::string>{"r0.type=number"}}.to_lines() ==
          std::set<std::string>{"r0.type=number"});
}

// The harness diffs two invariants by line-set difference. A matching
// `_|_`-vs-`_|_` comparison must produce empty diffs in both directions (so it
// no longer reports the same `_|_` under both "unexpected" and "unseen"), while
// a genuine mismatch still surfaces the differing lines.
TEST_CASE("Line-set diff of invariants handles bottom uniformly", "[string_constraints]") {
    const std::set<std::string> bottom = StringInvariant::bottom().to_lines();
    const std::set<std::string> concrete = StringInvariant{std::set<std::string>{"r0.type=number"}}.to_lines();

    SECTION("bottom vs bottom is empty in both directions") { CHECK(line_difference(bottom, bottom).empty()); }

    SECTION("bottom vs concrete surfaces the difference on each side") {
        CHECK(line_difference(bottom, concrete) == std::set<std::string>{"_|_"});
        CHECK(line_difference(concrete, bottom) == std::set<std::string>{"r0.type=number"});
    }
}

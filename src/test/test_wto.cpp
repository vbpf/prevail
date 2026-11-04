// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "cfg/cfg.hpp"
#include "cfg/wto.hpp"

using namespace prevail;

static Wto make_figure1_wto() {
    return Wto(cfg_from_adjacency_list({{Label::entry, {Label{1}}},
                                        {Label{1}, {Label{2}}},
                                        {Label{2}, {Label{3}}},
                                        {Label{3}, {Label{4}}},
                                        {Label{4}, {Label{5}, Label{7}}},
                                        {Label{5}, {Label{6}}},
                                        {Label{6}, {Label{5}, Label{7}}},
                                        {Label{7}, {Label{3}, Label{8}}},
                                        {Label{8}, {Label::exit}}}));
}

TEST_CASE("wto figure 1", "[wto]") {
    // Construct the example graph in figure 1 of Bourdoncle,
    // "Efficient chaotic iteration strategies with widenings", 1993.
    const Wto wto = make_figure1_wto();

    std::ostringstream os;
    os << wto;
    REQUIRE(os.str() == "entry 1 2 ( 3 4 ( 5 6 ) 7 ) 8 exit \n");
}

TEST_CASE("wto figure 2a", "[wto]") {
    // Construct the example graph in figure 2a of Bourdoncle,
    // "Efficient chaotic iteration strategies with widenings", 1993.
    const Wto wto(cfg_from_adjacency_list({{Label::entry, {Label{1}}},
                                           {Label{1}, {Label{2}, Label{4}}},
                                           {Label{2}, {Label{3}}},
                                           {Label{3}, {Label::exit}},
                                           {Label{4}, {Label{3}, Label{5}}},
                                           {Label{5}, {Label{4}}}}));

    std::ostringstream os;
    os << wto;
    REQUIRE(os.str() == "entry 1 ( 4 5 ) 2 3 exit \n");
}

TEST_CASE("wto figure 2b", "[wto]") {
    // Construct the example graph in figure 2b of Bourdoncle,
    // "Efficient chaotic iteration strategies with widenings", 1993.
    const Wto wto(cfg_from_adjacency_list({{Label::entry, {Label{1}}},
                                           {Label{1}, {Label{2}, Label{4}}},
                                           {Label{2}, {Label{3}}},
                                           {Label{3}, {Label{1}, Label::exit}},
                                           {Label{4}, {Label{3}}}}));

    std::ostringstream os;
    os << wto;
    REQUIRE(os.str() == "entry ( 1 4 2 3 ) exit \n");
}

TEST_CASE("wto nesting outermost head tracks maximal SCC", "[wto]") {
    const Wto wto = make_figure1_wto();

    REQUIRE(wto.nesting(Label{2}).outermost_head() == std::optional<Label>{});
    REQUIRE(wto.nesting(Label{1}).outermost_head() == std::optional<Label>{});
    REQUIRE(wto.nesting(Label{3}).outermost_head() == std::optional<Label>{});
    REQUIRE(wto.nesting(Label{4}).outermost_head() == std::optional<Label>{Label{3}});
    REQUIRE(wto.nesting(Label{5}).outermost_head() == std::optional<Label>{Label{3}});
    REQUIRE(wto.nesting(Label{6}).outermost_head() == std::optional<Label>{Label{3}});
    REQUIRE(wto.nesting(Label{7}).outermost_head() == std::optional<Label>{Label{3}});
    REQUIRE(wto.nesting(Label{8}).outermost_head() == std::optional<Label>{});
}

// `depth` cycles nested in one another: 1 -> 2 -> ... -> depth, with a back edge from the last
// vertex to every vertex (itself included).
static Cfg make_nested_cycles_cfg(const int depth) {
    std::map<Label, std::vector<Label>> adjacency{{Label::entry, {Label{1}}}};
    for (int i = 1; i < depth; i++) {
        adjacency[Label{i}] = {Label{i + 1}};
    }
    for (int i = 1; i <= depth; i++) {
        adjacency[Label{depth}].push_back(Label{i});
    }
    adjacency[Label{depth}].push_back(Label::exit);
    return cfg_from_adjacency_list(adjacency);
}

TEST_CASE("wto nesting depth is bounded", "[wto]") {
    constexpr int limit = Wto::max_nesting_depth;

    const Wto wto(make_nested_cycles_cfg(limit));
    int heads = 0;
    wto.for_each_loop_head([&](const Label&) { heads++; });
    REQUIRE(heads == limit);

    REQUIRE_THROWS_WITH(Wto(make_nested_cycles_cfg(limit + 1)),
                        Catch::Matchers::ContainsSubstring("loop nesting depth exceeds " + std::to_string(limit)));
    // Deep enough to overflow the C++ stack in any consumer that recurses on nesting depth.
    REQUIRE_THROWS_AS(Wto(make_nested_cycles_cfg(20000)), RuntimeInputError);
}

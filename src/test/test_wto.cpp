// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "cfg/cfg.hpp"
#include "cfg/wto.hpp"

using namespace prevail;

TEST_CASE("wto figure 1", "[wto]") {
    // Construct the example graph in figure 1 of Bourdoncle,
    // "Efficient chaotic iteration strategies with widenings", 1993.
    const Wto wto(cfg_from_adjacency_list({{Label::entry, {Label{1}}},
                                           {Label{1}, {Label{2}}},
                                           {Label{2}, {Label{3}}},
                                           {Label{3}, {Label{4}}},
                                           {Label{4}, {Label{5}, Label{7}}},
                                           {Label{5}, {Label{6}}},
                                           {Label{6}, {Label{5}, Label{7}}},
                                           {Label{7}, {Label{3}, Label{8}}},
                                           {Label{8}, {Label::exit}}}));

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
    const Wto wto(cfg_from_adjacency_list({{Label::entry, {Label{1}}},
                                           {Label{1}, {Label{2}}},
                                           {Label{2}, {Label{3}}},
                                           {Label{3}, {Label{4}}},
                                           {Label{4}, {Label{5}, Label{7}}},
                                           {Label{5}, {Label{6}}},
                                           {Label{6}, {Label{5}, Label{7}}},
                                           {Label{7}, {Label{3}, Label{8}}},
                                           {Label{8}, {Label::exit}}}));

    REQUIRE(wto.nesting(Label{1}).outermost_head() == std::optional<Label>{});
    REQUIRE(wto.nesting(Label{3}).outermost_head() == std::optional<Label>{});
    REQUIRE(wto.nesting(Label{4}).outermost_head() == std::optional<Label>{Label{3}});
    REQUIRE(wto.nesting(Label{5}).outermost_head() == std::optional<Label>{Label{3}});
    REQUIRE(wto.nesting(Label{6}).outermost_head() == std::optional<Label>{Label{3}});
    REQUIRE(wto.nesting(Label{7}).outermost_head() == std::optional<Label>{Label{3}});
}

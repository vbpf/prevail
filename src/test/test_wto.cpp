// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "cfg/cfg.hpp"
#include "cfg/wto.hpp"

using prevail::label_t;
using prevail::wto_t;

TEST_CASE("wto figure 1", "[wto]") {
    // Construct the example graph in figure 1 of Bourdoncle,
    // "Efficient chaotic iteration strategies with widenings", 1993.
    const wto_t wto(prevail::cfg_from_adjacency_list({{label_t::entry, {label_t{1}}},
                                                      {label_t{1}, {label_t{2}}},
                                                      {label_t{2}, {label_t{3}}},
                                                      {label_t{3}, {label_t{4}}},
                                                      {label_t{4}, {label_t{5}, label_t{7}}},
                                                      {label_t{5}, {label_t{6}}},
                                                      {label_t{6}, {label_t{5}, label_t{7}}},
                                                      {label_t{7}, {label_t{3}, label_t{8}}},
                                                      {label_t{8}, {label_t::exit}}}));

    std::ostringstream os;
    os << wto;
    REQUIRE(os.str() == "entry 1 2 ( 3 4 ( 5 6 ) 7 ) 8 exit \n");
}

TEST_CASE("wto figure 2a", "[wto]") {
    // Construct the example graph in figure 2a of Bourdoncle,
    // "Efficient chaotic iteration strategies with widenings", 1993.
    const wto_t wto(prevail::cfg_from_adjacency_list({{label_t::entry, {label_t{1}}},
                                                      {label_t{1}, {label_t{2}, label_t{4}}},
                                                      {label_t{2}, {label_t{3}}},
                                                      {label_t{3}, {label_t::exit}},
                                                      {label_t{4}, {label_t{3}, label_t{5}}},
                                                      {label_t{5}, {label_t{4}}}}));

    std::ostringstream os;
    os << wto;
    REQUIRE(os.str() == "entry 1 ( 4 5 ) 2 3 exit \n");
}

TEST_CASE("wto figure 2b", "[wto]") {
    // Construct the example graph in figure 2b of Bourdoncle,
    // "Efficient chaotic iteration strategies with widenings", 1993.
    const wto_t wto(prevail::cfg_from_adjacency_list({{label_t::entry, {label_t{1}}},
                                                      {label_t{1}, {label_t{2}, label_t{4}}},
                                                      {label_t{2}, {label_t{3}}},
                                                      {label_t{3}, {label_t{1}, label_t::exit}},
                                                      {label_t{4}, {label_t{3}}}}));

    std::ostringstream os;
    os << wto;
    REQUIRE(os.str() == "entry ( 1 4 2 3 ) exit \n");
}

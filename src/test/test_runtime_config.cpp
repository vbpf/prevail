// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>

#include "config.hpp"

using namespace prevail;

TEST_CASE("RuntimeConfig defaults are accepted", "[config][runtime]") {
    RuntimeConfig cfg{};
    REQUIRE_NOTHROW(cfg.validate());
    CHECK(cfg.subprogram_stack_size == 512);
    CHECK(cfg.max_call_stack_frames == 8);
    CHECK(cfg.max_packet_size == 0xffff);
    CHECK(cfg.total_stack_size() == 512 * 8);
}

TEST_CASE("RuntimeConfig::total_stack_size is the product", "[config][runtime]") {
    RuntimeConfig cfg{};
    cfg.subprogram_stack_size = 1024;
    cfg.max_call_stack_frames = 16;
    CHECK(cfg.total_stack_size() == 1024 * 16);
}

TEST_CASE("RuntimeConfig::validate rejects out-of-range subprogram_stack_size", "[config][runtime]") {
    RuntimeConfig cfg{};

    cfg.subprogram_stack_size = 0;
    CHECK_THROWS_AS(cfg.validate(), std::invalid_argument);

    cfg.subprogram_stack_size = -1;
    CHECK_THROWS_AS(cfg.validate(), std::invalid_argument);

    cfg.subprogram_stack_size = RuntimeConfig::MAX_SUBPROGRAM_STACK_SIZE + 1;
    CHECK_THROWS_AS(cfg.validate(), std::invalid_argument);

    cfg.subprogram_stack_size = RuntimeConfig::MAX_SUBPROGRAM_STACK_SIZE;
    CHECK_NOTHROW(cfg.validate());

    cfg.subprogram_stack_size = 1;
    CHECK_NOTHROW(cfg.validate());
}

TEST_CASE("RuntimeConfig::validate rejects out-of-range max_call_stack_frames", "[config][runtime]") {
    RuntimeConfig cfg{};

    cfg.max_call_stack_frames = 0;
    CHECK_THROWS_AS(cfg.validate(), std::invalid_argument);

    cfg.max_call_stack_frames = -1;
    CHECK_THROWS_AS(cfg.validate(), std::invalid_argument);

    cfg.max_call_stack_frames = RuntimeConfig::MAX_CALL_STACK_FRAMES_LIMIT + 1;
    CHECK_THROWS_AS(cfg.validate(), std::invalid_argument);

    cfg.max_call_stack_frames = RuntimeConfig::MAX_CALL_STACK_FRAMES_LIMIT;
    CHECK_NOTHROW(cfg.validate());

    cfg.max_call_stack_frames = 1;
    CHECK_NOTHROW(cfg.validate());
}

TEST_CASE("RuntimeConfig::validate rejects out-of-range max_packet_size", "[config][runtime]") {
    RuntimeConfig cfg{};

    cfg.max_packet_size = 0;
    CHECK_THROWS_AS(cfg.validate(), std::invalid_argument);

    cfg.max_packet_size = -1;
    CHECK_THROWS_AS(cfg.validate(), std::invalid_argument);

    cfg.max_packet_size = RuntimeConfig::MAX_PACKET_SIZE_LIMIT + 1;
    CHECK_THROWS_AS(cfg.validate(), std::invalid_argument);

    cfg.max_packet_size = RuntimeConfig::MAX_PACKET_SIZE_LIMIT;
    CHECK_NOTHROW(cfg.validate());

    cfg.max_packet_size = 1;
    CHECK_NOTHROW(cfg.validate());
}

TEST_CASE("VerifierOptions composes RuntimeConfig", "[config][runtime]") {
    VerifierOptions options{};
    static_assert(std::is_same_v<decltype(options.runtime), RuntimeConfig>);

    options.runtime.strict = true;
    options.runtime.allow_division_by_zero = false;
    CHECK(options.runtime.strict);
    CHECK_FALSE(options.runtime.allow_division_by_zero);

    REQUIRE_NOTHROW(options.runtime.validate());
}

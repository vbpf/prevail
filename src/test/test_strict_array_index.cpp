// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
//
// Strict mode requires the key passed to a map helper to be a known in-range index for
// every array map the fd register may name. These tests pin the cases where the check
// used to be skipped: an fd that may also name a non-array map, and a key that lives in
// packet or shared memory rather than on the stack.

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <catch2/catch_all.hpp>

#include "ebpf_verifier.hpp"
#include "test/parse.hpp"

using namespace prevail;

namespace {

// Linux BPF_MAP_TYPE_* values; only ARRAY has EbpfMapType::is_array set.
constexpr uint32_t HASH_MAP_TYPE = 1;
constexpr uint32_t ARRAY_MAP_TYPE = 2;

constexpr int ARRAY_MAP_FD = 1;
constexpr int HASH_MAP_FD = 2;

const EbpfMapDescriptor array_map = {.original_fd = ARRAY_MAP_FD,
                                     .type = ARRAY_MAP_TYPE,
                                     .key_size = 4,
                                     .value_size = 8,
                                     .max_entries = 1,
                                     .inner_map_fd = 0};

const EbpfMapDescriptor hash_map = {.original_fd = HASH_MAP_FD,
                                    .type = HASH_MAP_TYPE,
                                    .key_size = 4,
                                    .value_size = 8,
                                    .max_entries = 2,
                                    .inner_map_fd = 0};

ProgramInfo xdp_info() {
    return ProgramInfo{
        .platform = &g_ebpf_platform_linux,
        .map_descriptors = {array_map, hash_map},
        .type = g_ebpf_platform_linux.get_program_type("xdp", ""),
    };
}

// A line of the form "<name>:" labels the next instruction, as in the YAML fixtures;
// every other line is one instruction.
std::optional<VerificationError> first_error(const std::vector<std::string>& lines, const bool strict) {
    std::map<std::string, Label> labels;
    int index = 0;
    for (const std::string& line : lines) {
        if (line.ends_with(":")) {
            labels.emplace(line.substr(0, line.size() - 1), Label{index});
        } else {
            index++;
        }
    }

    InstructionSeq seq;
    index = 0;
    for (const std::string& line : lines) {
        if (!line.ends_with(":")) {
            seq.emplace_back(Label{index++}, parse_instruction(line, labels, {}), std::nullopt);
        }
    }

    VerifierOptions options{};
    options.runtime.strict = strict;
    const Program prog = Program::from_sequence(seq, xdp_info(), options);
    const ThreadLocalGuard guard;
    return analyze(prog, options).find_first_error();
}

// bpf_map_lookup_elem on the one-entry array, or on the hash map when ctx->ingress_ifindex is nonzero.
std::vector<std::string> array_or_hash_lookup(const int key) {
    return {
        "r3 = *(u32 *)(r1 + 12)",
        "r1 = " + std::to_string(key),
        "*(u32 *)(r10 - 4) = r1",
        "r2 = r10",
        "r2 += -4",
        "r1 = map_fd " + std::to_string(ARRAY_MAP_FD),
        "if r3 == 0 goto <lookup>",
        "r1 = map_fd " + std::to_string(HASH_MAP_FD),
        "<lookup>:",
        "call 1",
        "r0 = 0",
        "exit",
    };
}

// bpf_map_lookup_elem with the first four packet bytes as the key, passed in place.
std::vector<std::string> packet_key_lookup(const int map_fd) {
    return {
        "r2 = *(u32 *)(r1 + 0)",
        "r3 = *(u32 *)(r1 + 4)",
        "r4 = r2",
        "r4 += 4",
        "if r4 > r3 goto <done>",
        "r1 = map_fd " + std::to_string(map_fd),
        "call 1",
        "<done>:",
        "r0 = 0",
        "exit",
    };
}

// bpf_map_lookup_elem keyed by the value of a previous lookup on the same map.
std::vector<std::string> map_value_key_lookup(const int map_fd) {
    return {
        "r1 = 0",
        "*(u32 *)(r10 - 4) = r1",
        "r2 = r10",
        "r2 += -4",
        "r1 = map_fd " + std::to_string(map_fd),
        "call 1",
        "if r0 == 0 goto <done>",
        "r2 = r0",
        "r1 = map_fd " + std::to_string(map_fd),
        "call 1",
        "<done>:",
        "r0 = 0",
        "exit",
    };
}

} // namespace

TEST_CASE("strict array index check covers an fd that may name a non-array map", "[strict][map]") {
    const auto error = first_error(array_or_hash_lookup(1000), true);
    REQUIRE(error.has_value());
    CHECK_THAT(error->message, Catch::Matchers::ContainsSubstring("Array index overflow"));

    CHECK_FALSE(first_error(array_or_hash_lookup(0), true).has_value());
    CHECK_FALSE(first_error(array_or_hash_lookup(1000), false).has_value());
}

TEST_CASE("strict array index check rejects a key in packet memory", "[strict][map]") {
    const auto error = first_error(packet_key_lookup(ARRAY_MAP_FD), true);
    REQUIRE(error.has_value());
    CHECK_THAT(error->message, Catch::Matchers::ContainsSubstring("Array index must be on the stack"));

    CHECK_FALSE(first_error(packet_key_lookup(HASH_MAP_FD), true).has_value());
    CHECK_FALSE(first_error(packet_key_lookup(ARRAY_MAP_FD), false).has_value());
}

TEST_CASE("strict array index check rejects a key in shared memory", "[strict][map]") {
    const auto error = first_error(map_value_key_lookup(ARRAY_MAP_FD), true);
    REQUIRE(error.has_value());
    CHECK_THAT(error->message, Catch::Matchers::ContainsSubstring("Array index must be on the stack"));

    CHECK_FALSE(first_error(map_value_key_lookup(HASH_MAP_FD), true).has_value());
    CHECK_FALSE(first_error(map_value_key_lookup(ARRAY_MAP_FD), false).has_value());
}

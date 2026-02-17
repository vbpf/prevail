// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once
#include <functional>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "verifier.hpp"

namespace prevail {

struct TestCase {
    std::string name;
    // If set, this YAML test case is expected to throw while being loaded/parsing.
    // In that case, analysis is skipped and the exception message is compared.
    std::optional<std::string> expected_exception;
    std::optional<std::string> actual_exception;
    ebpf_verifier_options_t options{};
    StringInvariant assumed_pre_invariant;
    InstructionSeq instruction_seq;
    StringInvariant expected_post_invariant;
    std::set<std::string> expected_messages;
    struct Observation {
        Label label = Label::entry;
        InvariantPoint point = InvariantPoint::pre;
        ObservationCheckMode mode = ObservationCheckMode::consistent;
        StringInvariant constraints;
    };
    std::vector<Observation> observations;
};

void foreach_suite(const std::string& path, const std::function<void(const TestCase&)>& f);

template <typename T>
struct Diff {
    T unexpected;
    T unseen;
};

struct Failure {
    Diff<StringInvariant> invariant;
    Diff<std::set<std::string>> messages;
};

void print_failure(const Failure& failure, std::ostream& os = std::cout);

std::optional<Failure> run_yaml_test_case(TestCase test_case, bool debug = false);

struct ConformanceTestResult {
    bool success{};
    Interval r0_value = Interval::top();
    std::string error_reason{};
};

// Run verification on BPF instructions with optional input memory
ConformanceTestResult run_conformance_test_case(const std::vector<uint8_t>& memory_bytes,
                                                std::span<const EbpfInst> instructions, bool debug);

bool run_yaml(const std::string& path);
} // namespace prevail

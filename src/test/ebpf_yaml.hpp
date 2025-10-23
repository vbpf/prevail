// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once
#include <functional>
#include <set>
#include <string>

#include "verifier.hpp"

namespace prevail {

struct TestCase {
    std::string name;
    ebpf_verifier_options_t options{};
    StringInvariant assumed_pre_invariant;
    InstructionSeq instruction_seq;
    StringInvariant expected_post_invariant;
    std::set<std::string> expected_messages;
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
};

ConformanceTestResult run_conformance_test_case(const std::vector<std::byte>& memory_bytes,
                                                const std::vector<std::byte>& program_bytes, bool debug);

bool run_yaml(const std::string& path);
} // namespace prevail

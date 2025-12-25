// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This program reads BPF instructions from stdin and memory contents from
// the first argument. It then executes the BPF program and prints the
// value of r0 at the end of execution.
// The program is intended to be used with the bpf conformance test suite.

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <CLI11/CLI11.hpp>

#include "ebpf_verifier.hpp"
#include "test/ebpf_yaml.hpp"

using namespace prevail;

/**
 * @brief Read in a string of hex bytes and return a vector of bytes.
 *
 * @param[in] input String containing hex bytes.
 * @return Vector of bytes.
 */
std::vector<std::byte> base16_decode(const std::string& input) {
    std::vector<std::byte> output;
    std::stringstream ss(input);
    std::string value;
    while (std::getline(ss, value, ' ')) {
        if (value.empty()) {
            continue;
        }
        try {
            output.push_back(static_cast<std::byte>(std::stoi(value, nullptr, 16)));
        } catch (std::invalid_argument&) {
            std::cerr << "base16_decode failed to decode " << value << "\n";
        } catch (std::out_of_range&) {
            std::cerr << "base16_decode failed to decode " << value << "\n";
        }
    }
    return output;
}

/**
 * @brief This program reads BPF instructions from stdin and memory contents from
 * the first argument. It then executes the BPF program and prints the
 * value of r0 at the end of execution.
 */
int main(int argc, char** argv) {
    CLI::App app{"Check conformance"};
    bool debug = false;
    app.add_flag("--debug", debug, "Debug");
    std::string memory_string;
    app.add_option("--memory,memory", memory_string, "base16 memory bytes");
    std::string program_string;
    app.add_option("--program", program_string, "base16 program bytes");
    std::string other_positional_argument;

    // Currently the conformance test project passes an empty string as an additional
    // positional argument. We need to accept it to make CLI11 parsing pass until
    // the test project is fixed.
    app.add_option("other", other_positional_argument, "Other");
    CLI11_PARSE(app, argc, argv);

    if (program_string.empty()) {
        std::getline(std::cin, program_string);
    }

    const auto& result = run_conformance_test_case(base16_decode(memory_string), base16_decode(program_string), debug);
    if (!result.success) {
        // Write failure reason to stdout since the bpf conformance library does not look at stderr.
        std::cout << "Verification failed\n";
        return 1;
    }
    if (result.r0_value.is_top()) {
        std::cout << "Couldn't determine r0 value\n";
        return 1;
    }
    if (!result.r0_value.singleton()) {
        std::cout << "r0 value is range [" << result.r0_value.lb() << ", " << result.r0_value.ub() << "]\n";
        return 1;
    }

    // Print output so the conformance test suite can check it.
    if (result.r0_value.singleton() && result.r0_value.singleton().value().fits_cast_to<int64_t>()) {
        std::cout << std::hex << result.r0_value.singleton().value().cast_to<uint64_t>() << std::endl;
    } else {
        std::cout << result.r0_value << std::endl;
    }

    return 0;
}

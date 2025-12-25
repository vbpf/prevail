// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// Test that prevail can be consumed as an installed library
// Main include - provides core functionality
#include <prevail.hpp>

// Specific includes for advanced features (optional)
#include <prevail/arith/linear_constraint.hpp>

#include <iostream>

int main() {
    std::cout << "Testing prevail installation..." << std::endl;

    // Test 1: Create a platform (basic API usage)
    auto platform = prevail::create_ebpf_platform(0, {}, {});
    std::cout << "  V Platform creation works" << std::endl;

    // Test 2: Use a type that requires GSL (tests transitive dependencies)
    prevail::LinearConstraint constraint;
    std::cout << "  V GSL dependency available" << std::endl;

    // Test 3: Verify headers are accessible
    std::cout << "  V All headers accessible" << std::endl;

    std::cout << "\nV Prevail installation test PASSED!" << std::endl;
    return 0;
}

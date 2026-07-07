// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// Test that prevail can be consumed as an installed library.
#include <prevail.hpp>          // umbrella header (resolves via include/)
#include <prevail/platform.hpp> // a specific header (resolves via include/prevail/)

#include <iostream>

int main() {
    std::cout << "Testing prevail installation..." << std::endl;

    // Reference a symbol defined in the installed prevail library. Taking its address
    // forces the linker to resolve it from the installed archive, so this exercises the
    // full find_package(prevail) path: headers found, library linked, transitive
    // dependencies (GSL, libbtf, ...) resolved.
    const prevail::ebpf_platform_t& platform = prevail::g_ebpf_platform_linux;
    std::cout << "  prevail library linked (platform @ " << static_cast<const void*>(&platform) << ")" << std::endl;

    std::cout << "\nPrevail installation test PASSED!" << std::endl;
    return 0;
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// Auto-generated test file for project: katran
#include "test_verify.hpp"

TEST_CASE("katran/xdp_root.o", "[verify][samples][katran]") {
    static const FileEntry file = {"xdp_root.o",
                                   {
                                       {.section = "xdp"},
                                   }};
    verify_file("katran", file);
}

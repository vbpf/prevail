// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// Auto-generated test file for project: bpf_cilium_test
#include "test_verify.hpp"

TEST_CASE("bpf_cilium_test/bpf_lb-DLB_L3.o", "[verify][samples][bpf_cilium_test]") {
    static const FileEntry file = {"bpf_lb-DLB_L3.o",
                                   {
                                       {.section = "2/2"},
                                       {.section = "2/1"},
                                       {.section = "from-netdev"},
                                   }};
    verify_file("bpf_cilium_test", file);
}

TEST_CASE("bpf_cilium_test/bpf_lb-DLB_L4.o", "[verify][samples][bpf_cilium_test]") {
    static const FileEntry file = {"bpf_lb-DLB_L4.o",
                                   {
                                       {.section = "2/2"},
                                       {.section = "2/1"},
                                       {.section = "from-netdev"},
                                   }};
    verify_file("bpf_cilium_test", file);
}

TEST_CASE("bpf_cilium_test/bpf_lb-DUNKNOWN.o", "[verify][samples][bpf_cilium_test]") {
    static const FileEntry file = {"bpf_lb-DUNKNOWN.o",
                                   {
                                       {.section = "2/2"},
                                       {.section = "2/1"},
                                       {.section = "from-netdev"},
                                   }};
    verify_file("bpf_cilium_test", file);
}

TEST_CASE("bpf_cilium_test/bpf_lxc-DDROP_ALL.o", "[verify][samples][bpf_cilium_test]") {
    static const FileEntry file = {"bpf_lxc-DDROP_ALL.o",
                                   {
                                       {.section = "2/2"},
                                       {.section = "2/1"},
                                       {.section = "2/3"},
                                       {.section = "2/5"},
                                       {.section = "2/4"},
                                       {.section = "2/7"},
                                       {.section = "2/6"},
                                       {.section = "from-container"},
                                       {.section = "1/0x1010"},
                                   }};
    verify_file("bpf_cilium_test", file);
}

TEST_CASE("bpf_cilium_test/bpf_lxc-DUNKNOWN.o", "[verify][samples][bpf_cilium_test]") {
    static const FileEntry file = {"bpf_lxc-DUNKNOWN.o",
                                   {
                                       {.section = "2/2"},
                                       {.section = "2/1"},
                                       {.section = "2/3"},
                                       {.section = "2/5"},
                                       {.section = "2/4"},
                                       {.section = "2/7"},
                                       {.section = "2/6"},
                                       {.section = "from-container"},
                                       {.section = "1/0x1010"},
                                   }};
    verify_file("bpf_cilium_test", file);
}

TEST_CASE("bpf_cilium_test/bpf_lxc_jit.o", "[verify][samples][bpf_cilium_test]") {
    static const FileEntry file = {"bpf_lxc_jit.o",
                                   {
                                       {.section = "2/1"},
                                       {.section = "2/3"},
                                       {.section = "2/5"},
                                       {.section = "2/4"},
                                       {.section = "2/10"},
                                       {.section = "2/7"},
                                       {.section = "2/6"},
                                       {.section = "from-container"},
                                       {.section = "1/0xdc06"},
                                   }};
    verify_file("bpf_cilium_test", file);
}

TEST_CASE("bpf_cilium_test/bpf_netdev.o", "[verify][samples][bpf_cilium_test]") {
    static const FileEntry file = {"bpf_netdev.o",
                                   {
                                       {.section = "2/2"},
                                       {.section = "2/1"},
                                       {.section = "2/3"},
                                       {.section = "2/5"},
                                       {.section = "2/4"},
                                       {.section = "2/7"},
                                       {.section = "from-netdev"},
                                       {.section = "3/2"},
                                   }};
    verify_file("bpf_cilium_test", file);
}

TEST_CASE("bpf_cilium_test/bpf_overlay.o", "[verify][samples][bpf_cilium_test]") {
    static const FileEntry file = {"bpf_overlay.o",
                                   {
                                       {.section = "2/2"},
                                       {.section = "2/1"},
                                       {.section = "2/3"},
                                       {.section = "2/5"},
                                       {.section = "2/4"},
                                       {.section = "2/7"},
                                       {.section = "from-overlay"},
                                       {.section = "3/2"},
                                   }};
    verify_file("bpf_cilium_test", file);
}

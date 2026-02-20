// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// Auto-generated test file for project: cilium
#include "test_verify.hpp"

TEST_CASE("cilium/bpf_lb.o", "[verify][samples][cilium]") {
    static const FileEntry file = {"bpf_lb.o",
                                   {
                                       {.section = "2/1"},
                                       {.section = "from-netdev"},
                                   }};
    verify_file("cilium", file);
}

TEST_CASE("cilium/bpf_lxc.o", "[verify][samples][cilium]") {
    static const FileEntry file = {"bpf_lxc.o",
                                   {
                                       {.section = "2/1"},
                                       {.section = "2/3"},
                                       {.section = "2/5"},
                                       {.section = "2/4"},
                                       {.section = "2/10", .legacy = true},
                                       {.section = "2/7", .slow = true},
                                       {.section = "2/6"},
                                       {.section = "from-container"},
                                       {.section = "2/12", .slow = true},
                                       {.section = "2/11", .slow = true},
                                       {.section = "1/0x1010"},
                                       {.section = "2/8"},
                                       {.section = "2/9"},
                                   }};
    verify_file("cilium", file);
}

TEST_CASE("cilium/bpf_netdev.o", "[verify][samples][cilium]") {
    static const FileEntry file = {"bpf_netdev.o",
                                   {
                                       {.section = "2/1"},
                                       {.section = "2/3"},
                                       {.section = "2/5"},
                                       {.section = "2/4"},
                                       {.section = "2/7"},
                                       {.section = "from-netdev", .legacy = true},
                                   }};
    verify_file("cilium", file);
}

TEST_CASE("cilium/bpf_overlay.o", "[verify][samples][cilium]") {
    static const FileEntry file = {"bpf_overlay.o",
                                   {
                                       {.section = "2/1"},
                                       {.section = "2/3"},
                                       {.section = "2/5"},
                                       {.section = "2/4"},
                                       {.section = "2/7"},
                                       {.section = "from-overlay", .legacy = true},
                                   }};
    verify_file("cilium", file);
}

TEST_CASE("cilium/bpf_xdp.o", "[verify][samples][cilium]") {
    static const FileEntry file = {"bpf_xdp.o",
                                   {
                                       {.section = "from-netdev"},
                                   }};
    verify_file("cilium", file);
}

TEST_CASE("cilium/bpf_xdp_dsr_linux.o", "[verify][samples][cilium]") {
    static const FileEntry file = {"bpf_xdp_dsr_linux.o",
                                   {
                                       {.section = "2/1"},
                                       {.section = "2/21", .expect = Expect::Xfail},
                                       {.section = "2/16", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/18", .expect = Expect::Xfail},
                                       {.section = "2/24", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/20", .expect = Expect::Xfail},
                                       {.section = "2/15", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/17", .expect = Expect::Xfail},
                                       {.section = "2/19", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/7", .expect = Expect::Xfail},
                                       {.section = "2/10", .expect = Expect::Xfail},
                                       {.section = "from-netdev"},
                                   }};
    verify_file("cilium", file);
}

TEST_CASE("cilium/bpf_xdp_dsr_linux_v1.o", "[verify][samples][cilium]") {
    static const FileEntry file = {"bpf_xdp_dsr_linux_v1.o",
                                   {
                                       {.section = "2/1"},
                                       {.section = "2/21", .expect = Expect::Xfail},
                                       {.section = "2/16", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/18", .expect = Expect::Xfail},
                                       {.section = "2/24", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/20", .expect = Expect::Xfail},
                                       {.section = "2/15", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/17", .expect = Expect::Xfail},
                                       {.section = "2/19", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/7", .expect = Expect::Xfail},
                                       {.section = "2/10", .expect = Expect::Xfail},
                                       {.section = "from-netdev"},
                                   }};
    verify_file("cilium", file);
}

TEST_CASE("cilium/bpf_xdp_dsr_linux_v1_1.o", "[verify][samples][cilium]") {
    static const FileEntry file = {"bpf_xdp_dsr_linux_v1_1.o",
                                   {
                                       {.section = "2/1"},
                                       {.section = "2/21", .expect = Expect::Xfail},
                                       {.section = "2/16", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/18", .expect = Expect::Xfail},
                                       {.section = "2/24", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/20", .expect = Expect::Xfail},
                                       {.section = "2/15", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/17", .expect = Expect::Xfail},
                                       {.section = "2/19", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/7", .expect = Expect::Xfail},
                                       {.section = "2/10", .expect = Expect::Xfail},
                                       {.section = "from-netdev"},
                                   }};
    verify_file("cilium", file);
}

TEST_CASE("cilium/bpf_xdp_snat_linux.o", "[verify][samples][cilium]") {
    static const FileEntry file = {"bpf_xdp_snat_linux.o",
                                   {
                                       {.section = "2/1"},
                                       {.section = "2/16", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/18", .expect = Expect::Xfail},
                                       {.section = "2/24", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/15", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/17", .expect = Expect::Xfail},
                                       {.section = "2/19", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/7", .expect = Expect::Xfail},
                                       {.section = "2/10", .expect = Expect::Xfail},
                                       {.section = "from-netdev"},
                                   }};
    verify_file("cilium", file);
}

TEST_CASE("cilium/bpf_xdp_snat_linux_v1.o", "[verify][samples][cilium]") {
    static const FileEntry file = {"bpf_xdp_snat_linux_v1.o",
                                   {
                                       {.section = "2/1"},
                                       {.section = "2/16", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/18", .expect = Expect::Xfail},
                                       {.section = "2/24", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/15", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/17", .expect = Expect::Xfail},
                                       {.section = "2/19", .expect = Expect::Xfail, .slow = true},
                                       {.section = "2/7", .expect = Expect::Xfail},
                                       {.section = "2/10", .expect = Expect::Xfail},
                                       {.section = "from-netdev"},
                                   }};
    verify_file("cilium", file);
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

TEST_SECTION("cilium", "bpf_lb.o", "2/1")
TEST_SECTION("cilium", "bpf_lb.o", "from-netdev")

TEST_SECTION("cilium", "bpf_lxc.o", "1/0x1010")
TEST_SECTION("cilium", "bpf_lxc.o", "2/1")
TEST_SECTION("cilium", "bpf_lxc.o", "2/3")
TEST_SECTION("cilium", "bpf_lxc.o", "2/4")
TEST_SECTION("cilium", "bpf_lxc.o", "2/5")
TEST_SECTION("cilium", "bpf_lxc.o", "2/6")
TEST_SECTION("cilium", "bpf_lxc.o", "2/8")
TEST_SECTION("cilium", "bpf_lxc.o", "2/9")
TEST_SECTION("cilium", "bpf_lxc.o", "from-container")

TEST_SECTION("cilium", "bpf_netdev.o", "2/1")
TEST_SECTION("cilium", "bpf_netdev.o", "2/3")
TEST_SECTION("cilium", "bpf_netdev.o", "2/4")
TEST_SECTION("cilium", "bpf_netdev.o", "2/5")
TEST_SECTION("cilium", "bpf_netdev.o", "2/7")

TEST_SECTION("cilium", "bpf_overlay.o", "2/1")
TEST_SECTION("cilium", "bpf_overlay.o", "2/3")
TEST_SECTION("cilium", "bpf_overlay.o", "2/4")
TEST_SECTION("cilium", "bpf_overlay.o", "2/5")
TEST_SECTION("cilium", "bpf_overlay.o", "2/7")
TEST_SECTION_LEGACY("cilium", "bpf_overlay.o", "from-overlay")

TEST_SECTION("cilium", "bpf_xdp.o", "from-netdev")

TEST_SECTION("cilium", "bpf_xdp_dsr_linux_v1_1.o", "from-netdev")
TEST_SECTION("cilium", "bpf_xdp_dsr_linux.o", "2/1")
TEST_SECTION("cilium", "bpf_xdp_dsr_linux.o", "from-netdev")

TEST_SECTION("cilium", "bpf_xdp_snat_linux.o", "2/1")
TEST_SECTION("cilium", "bpf_xdp_snat_linux.o", "from-netdev")

// Unsupported: implications are lost in correlated branches
TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/7")

// Failure: 166:168: Upper bound must be at most packet_size (valid_access(r4.offset, width=2) for read)
// This is the result of merging two branches, one with value 0 and another with value -22,
// then checking that the result is != 0. The minor issue is not handling the int32 comparison precisely enough.
// The bigger issue is that the convexity of the numerical domain means that precise handling would still get
// [-22, -1] which is not sufficient (at most -2 is needed)
TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/10")
TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/21")
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_dsr_linux.o", "2/24")

TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_dsr_linux.o", "2/15")

TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/17")

// Failure: trying to access r4 where r4.packet_offset=[0, 255] and packet_size=[54, 65534]
// Root cause: r5.value=[0, 65535] 209: w5 >>= 8; clears r5 instead of yielding [0, 255]
TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/18")
TEST_SECTION_FAIL("cilium", "bpf_xdp_snat_linux.o", "2/10")
TEST_SECTION_FAIL("cilium", "bpf_xdp_snat_linux.o", "2/18")

TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_dsr_linux.o", "2/19")

// Failure: 230: Upper bound must be at most packet_size (valid_access(r3.offset+32, width=8) for write)
// r3.packet_offset=[0, 82] and packet_size=[34, 65534]
// looks like a combination of misunderstanding the value passed to xdp_adjust_tail()
// which is "r7.value=[0, 82]; w7 -= r9;" where r9.value where "r7.value-r9.value<=48"
TEST_SECTION_FAIL("cilium", "bpf_xdp_dsr_linux.o", "2/20")

TEST_SECTION_FAIL("cilium", "bpf_xdp_snat_linux.o", "2/7")
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_snat_linux.o", "2/15")
TEST_SECTION_FAIL("cilium", "bpf_xdp_snat_linux.o", "2/17")
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_snat_linux.o", "2/19")

// Failure (&255): assert r5.type == number; w5 &= 255;
// fails since in one branch (77) r5 is a number but in another (92:93) it is a packet
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_snat_linux.o", "2/24")
// Failure (&255): assert r3.type == number; w3 &= 255;
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_dsr_linux.o", "2/16")
TEST_SECTION_FAIL_SLOW("cilium", "bpf_xdp_snat_linux.o", "2/16")

TEST_SECTION_LEGACY("cilium", "bpf_netdev.o", "from-netdev")

TEST_SECTION_SLOW("cilium", "bpf_lxc.o", "2/7")
TEST_SECTION_LEGACY_SLOW("cilium", "bpf_lxc.o", "2/10")
TEST_SECTION_SLOW("cilium", "bpf_lxc.o", "2/11")
TEST_SECTION_SLOW("cilium", "bpf_lxc.o", "2/12")

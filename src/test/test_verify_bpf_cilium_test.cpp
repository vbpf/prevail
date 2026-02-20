// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

TEST_SECTION_SLOW("bpf_cilium_test", "bpf_lxc_jit.o", "1/0xdc06")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "2/6")
TEST_SECTION_SLOW("bpf_cilium_test", "bpf_lxc_jit.o", "2/7")
TEST_SECTION_LEGACY_SLOW("bpf_cilium_test", "bpf_lxc_jit.o", "2/10")
TEST_SECTION("bpf_cilium_test", "bpf_lxc_jit.o", "from-container")

TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "1/0x1010")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/6")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "2/7")
TEST_SECTION_LEGACY("bpf_cilium_test", "bpf_lxc-DUNKNOWN.o", "from-container")

TEST_SECTION_SLOW("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "1/0x1010")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/6")
TEST_SECTION_SLOW("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "2/7")
TEST_SECTION("bpf_cilium_test", "bpf_lxc-DDROP_ALL.o", "from-container")

TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_netdev.o", "2/7")

TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/3")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/4")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/5")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "2/7")
TEST_SECTION("bpf_cilium_test", "bpf_overlay.o", "3/2")
TEST_SECTION_LEGACY_SLOW("bpf_cilium_test", "bpf_overlay.o", "from-overlay")

TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L3.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L3.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L3.o", "from-netdev")

TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L4.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L4.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DLB_L4.o", "from-netdev")

TEST_SECTION("bpf_cilium_test", "bpf_lb-DUNKNOWN.o", "2/1")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DUNKNOWN.o", "2/2")
TEST_SECTION("bpf_cilium_test", "bpf_lb-DUNKNOWN.o", "from-netdev")

TEST_SECTION_LEGACY_SLOW("bpf_cilium_test", "bpf_netdev.o", "from-netdev")

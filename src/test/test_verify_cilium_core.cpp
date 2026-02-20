// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

// cilium-core/bpf_host.o
TEST_PROGRAM_FAIL("cilium-core", "bpf_host.o", "tc/entry", "cil_from_netdev", 5)
TEST_PROGRAM_FAIL("cilium-core", "bpf_host.o", "tc/entry", "cil_from_host", 5)
TEST_PROGRAM_FAIL("cilium-core", "bpf_host.o", "tc/entry", "cil_to_netdev", 5)
// - cil_to_host: unsupported function: skc_lookup_tcp
TEST_PROGRAM_FAIL("cilium-core", "bpf_host.o", "tc/entry", "cil_host_policy", 5)

// cilium-core/bpf_lxc.o
TEST_PROGRAM("cilium-core", "bpf_lxc.o", "tc/entry", "cil_from_container", 4)
TEST_PROGRAM("cilium-core", "bpf_lxc.o", "tc/entry", "cil_lxc_policy", 4)
TEST_PROGRAM("cilium-core", "bpf_lxc.o", "tc/entry", "cil_lxc_policy_egress", 4)
TEST_PROGRAM("cilium-core", "bpf_lxc.o", "tc/entry", "cil_to_container", 4)

// cilium-core/bpf_network.o
TEST_SECTION("cilium-core", "bpf_network.o", "tc/entry")

// cilium-core/bpf_overlay.o
TEST_PROGRAM("cilium-core", "bpf_overlay.o", "tc/entry", "cil_from_overlay", 2)
// - cil_to_overlay: CRAB_ERROR("Bound: inf / inf")

// cilium-core/bpf_sock.o
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/connect4")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/connect6")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/post_bind4")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/post_bind6")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/sendmsg4")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/sendmsg6")
TEST_SECTION("cilium-core", "bpf_sock.o", "cgroup/recvmsg4")
TEST_SECTION_FAIL("cilium-core", "bpf_sock.o", "cgroup/recvmsg6")
// - bpf_sock.o cgroup/sock_release: invalid helper function id 46

// cilium-core/bpf_wireguard.o
TEST_PROGRAM("cilium-core", "bpf_wireguard.o", "tc/entry", "cil_from_wireguard", 2)
TEST_PROGRAM("cilium-core", "bpf_wireguard.o", "tc/entry", "cil_to_wireguard", 2)

// cilium-core/bpf_xdp.o
TEST_SECTION_FAIL("cilium-core", "bpf_xdp.o", "xdp/entry")

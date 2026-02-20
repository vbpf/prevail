// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

// cilium-examples tests
TEST_SECTION("cilium-examples", "cgroup_skb_bpf_bpfel.o", "cgroup_skb/egress")
TEST_SECTION("cilium-examples", "kprobe_bpf_bpfel.o", "kprobe/sys_execve")
TEST_SECTION("cilium-examples", "kprobe_percpu_bpf_bpfel.o", "kprobe/sys_execve")
TEST_SECTION("cilium-examples", "kprobepin_bpf_bpfel.o", "kprobe/sys_execve")
TEST_SECTION("cilium-examples", "tracepoint_in_c_bpf_bpfel.o", "tracepoint/kmem/mm_page_alloc")
TEST_SECTION("cilium-examples", "xdp_bpf_bpfel.o", "xdp")
// This is TEST_SECTION_FAIL, but with a shorter filename to avoid CATCH2 test name limits.
TEST_CASE("expect failure cilium-examples/uretprobe_x86 uretprobe/bash_readline",
          "[!shouldfail][verify][samples][cilium-examples]") {
    VERIFY_SECTION("cilium-examples", "uretprobe_bpf_x86_bpfel.o", "uretprobe/bash_readline", {},
                   &g_ebpf_platform_linux, true);
}

TEST_PROGRAM("cilium-examples", "tcx_bpf_bpfel.o", "tc", "ingress_prog_func", 2)
TEST_PROGRAM("cilium-examples", "tcx_bpf_bpfel.o", "tc", "egress_prog_func", 2)

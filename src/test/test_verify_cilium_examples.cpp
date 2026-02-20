// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT-examples
#include "test_verify.hpp"

TEST_CASE("cilium-examples/cgroup_skb_bpf_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"cgroup_skb_bpf_bpfel.o",
                                   {
                                       {.section = "cgroup_skb/egress"},
                                   }};
    verify_file("cilium-examples", file);
}

TEST_CASE("cilium-examples/fentry_bpf_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"fentry_bpf_bpfel.o",
                                   {
                                       {.section = "fentry/tcp_connect", .expect = Expect::Xfail},
                                   }};
    verify_file("cilium-examples", file);
}

TEST_CASE("cilium-examples/kprobe_bpf_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"kprobe_bpf_bpfel.o",
                                   {
                                       {.section = "kprobe/sys_execve"},
                                   }};
    verify_file("cilium-examples", file);
}

TEST_CASE("cilium-examples/kprobe_percpu_bpf_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"kprobe_percpu_bpf_bpfel.o",
                                   {
                                       {.section = "kprobe/sys_execve"},
                                   }};
    verify_file("cilium-examples", file);
}

TEST_CASE("cilium-examples/kprobepin_bpf_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"kprobepin_bpf_bpfel.o",
                                   {
                                       {.section = "kprobe/sys_execve"},
                                   }};
    verify_file("cilium-examples", file);
}

TEST_CASE("cilium-examples/ringbuffer_bpf_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"ringbuffer_bpf_bpfel.o",
                                   {
                                       {.section = "kprobe/sys_execve", .expect = Expect::Xfail},
                                   }};
    verify_file("cilium-examples", file);
}

TEST_CASE("cilium-examples/tcprtt_bpf_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"tcprtt_bpf_bpfel.o",
                                   {
                                       {.section = "fentry/tcp_close", .expect = Expect::Xfail},
                                   }};
    verify_file("cilium-examples", file);
}

TEST_CASE("cilium-examples/tcprtt_sockops_bpf_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"tcprtt_sockops_bpf_bpfel.o",
                                   {
                                       {.section = "sockops", .expect = Expect::Xfail},
                                   }};
    verify_file("cilium-examples", file);
}

TEST_CASE("cilium-examples/tcx_bpf_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"tcx_bpf_bpfel.o",
                                   {
                                       {.section = "tc", .function = "ingress_prog_func", .count = 2},
                                       {.section = "tc", .function = "egress_prog_func", .count = 2},
                                   }};
    verify_file("cilium-examples", file);
}

TEST_CASE("cilium-examples/tracepoint_in_c_bpf_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"tracepoint_in_c_bpf_bpfel.o",
                                   {
                                       {.section = "tracepoint/kmem/mm_page_alloc"},
                                   }};
    verify_file("cilium-examples", file);
}

TEST_CASE("cilium-examples/uretprobe_bpf_x86_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"uretprobe_bpf_x86_bpfel.o",
                                   {
                                       {.section = "uretprobe/bash_readline", .expect = Expect::Xfail},
                                   }};
    verify_file("cilium-examples", file);
}

TEST_CASE("cilium-examples/xdp_bpf_bpfel.o", "[verify][samples][cilium-examples]") {
    static const FileEntry file = {"xdp_bpf_bpfel.o",
                                   {
                                       {.section = "xdp"},
                                   }};
    verify_file("cilium-examples", file);
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// Auto-generated test file for project: linux-selftests
#include "test_verify.hpp"

TEST_CASE("linux-selftests/atomics.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"atomics.o",
                                   {
                                       {.section = "raw_tp/sys_enter", .function = "add", .count = 7},
                                       {.section = "raw_tp/sys_enter", .function = "sub", .count = 7},
                                       {.section = "raw_tp/sys_enter", .function = "and", .count = 7},
                                       {.section = "raw_tp/sys_enter", .function = "or", .count = 7},
                                       {.section = "raw_tp/sys_enter", .function = "xor", .count = 7},
                                       {.section = "raw_tp/sys_enter", .function = "cmpxchg", .count = 7},
                                       {.section = "raw_tp/sys_enter", .function = "xchg", .count = 7},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/bloom_filter_map.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {
        "bloom_filter_map.o",
        {
            {.section = ".text", .expect = Expect::Xfail},
            {.section = "fentry/__x64_sys_getpgid", .function = "inner_map", .count = 2, .expect = Expect::Xfail},
            {.section = "fentry/__x64_sys_getpgid", .function = "check_bloom", .count = 2, .expect = Expect::Xfail},
        }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/bpf_cubic.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"bpf_cubic.o",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/bpf_dctcp.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {
        "bpf_dctcp.o",
        {
            {.section = "struct_ops", .function = "bpf_dctcp_init", .count = 7, .expect = Expect::Xfail},
            {.section = "struct_ops", .function = "bpf_dctcp_ssthresh", .count = 7, .expect = Expect::Xfail},
            {.section = "struct_ops", .function = "bpf_dctcp_update_alpha", .count = 7, .expect = Expect::Xfail},
            {.section = "struct_ops", .function = "bpf_dctcp_state", .count = 7, .expect = Expect::Xfail},
            {.section = "struct_ops", .function = "bpf_dctcp_cwnd_event", .count = 7, .expect = Expect::Xfail},
            {.section = "struct_ops", .function = "bpf_dctcp_cwnd_undo", .count = 7, .expect = Expect::Xfail},
            {.section = "struct_ops", .function = "bpf_dctcp_cong_avoid", .count = 7, .expect = Expect::Xfail},
        }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/fexit_sleep.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"fexit_sleep.o",
                                   {
                                       {.section = "fentry/__x64_sys_nanosleep"},
                                       {.section = "fexit/__x64_sys_nanosleep"},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/freplace_get_constant.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"freplace_get_constant.o",
                                   {
                                       {.section = "freplace/get_constant", .expect = Expect::Xfail},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/get_cgroup_id_kern.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"get_cgroup_id_kern.o",
                                   {
                                       {.section = "tracepoint/syscalls/sys_enter_nanosleep"},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/kfree_skb.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"kfree_skb.o",
                                   {
                                       {.section = "tp_btf/kfree_skb", .expect = Expect::Xfail},
                                       {.section = "fentry/eth_type_trans", .expect = Expect::Xfail},
                                       {.section = "fexit/eth_type_trans", .expect = Expect::Xfail},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/loop1.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"loop1.o",
                                   {
                                       {.section = "raw_tracepoint/kfree_skb"},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/loop2.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"loop2.o",
                                   {
                                       {.section = "raw_tracepoint/consume_skb"},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/loop3.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {
        "loop3.o",
        {
            {.section = "raw_tracepoint/consume_skb", .expect = Expect::Skip, .skip_reason = "hangs"},
        }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/loop4.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"loop4.o",
                                   {
                                       {.section = "socket"},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/loop5.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"loop5.o",
                                   {
                                       {.section = "socket"},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/map_ptr_kern.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {
        "map_ptr_kern.o",
        {
            {.section = ".text", .function = "check_lru_percpu_hash", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_lpm_trie", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_array_of_maps", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_hash_of_maps", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_devmap", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_sockmap", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_cpumap", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_xskmap", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_sockhash", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_cgroup_storage", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_reuseport_sockarray", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_percpu_cgroup_storage", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_queue", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_stack", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_sk_storage", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_devmap_hash", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_ringbuf", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check_default_noinline", .count = 19, .expect = Expect::Xfail},
            {.section = ".text", .function = "check", .count = 19, .expect = Expect::Xfail},
            {.section = "cgroup_skb/egress", .expect = Expect::Xfail},
        }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/socket_cookie_prog.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"socket_cookie_prog.o",
                                   {
                                       {.section = "cgroup/connect6", .expect = Expect::Xfail},
                                       {.section = "sockops", .expect = Expect::Xfail},
                                       {.section = "fexit/inet_stream_connect", .expect = Expect::Xfail},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/sockmap_parse_prog.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"sockmap_parse_prog.o",
                                   {
                                       {.section = "sk_skb1"},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/sockmap_verdict_prog.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"sockmap_verdict_prog.o",
                                   {
                                       {.section = "sk_skb2"},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/tailcall1.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"tailcall1.o",
                                   {
                                       {.section = "tc", .function = "classifier_0", .count = 4},
                                       {.section = "tc", .function = "classifier_1", .count = 4},
                                       {.section = "tc", .function = "classifier_2", .count = 4},
                                       {.section = "tc", .function = "entry", .count = 4},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/tailcall2.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"tailcall2.o",
                                   {
                                       {.section = "tc", .function = "classifier_0", .count = 6},
                                       {.section = "tc", .function = "classifier_1", .count = 6},
                                       {.section = "tc", .function = "classifier_2", .count = 6},
                                       {.section = "tc", .function = "classifier_3", .count = 6},
                                       {.section = "tc", .function = "classifier_4", .count = 6},
                                       {.section = "tc", .function = "entry", .count = 6},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/tailcall3.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"tailcall3.o",
                                   {
                                       {.section = "tc", .function = "classifier_0", .count = 2},
                                       {.section = "tc", .function = "entry", .count = 2},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/test_global_func1.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"test_global_func1.o",
                                   {
                                       {.section = ".text", .function = "f1", .count = 4, .expect = Expect::Xfail},
                                       {.section = ".text", .function = "f0", .count = 4},
                                       {.section = ".text", .function = "f2", .count = 4, .expect = Expect::Xfail},
                                       {.section = ".text", .function = "f3", .count = 4, .expect = Expect::Xfail},
                                       {.section = "tc", .expect = Expect::Xfail},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/test_global_func_args.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {"test_global_func_args.o",
                                   {
                                       {.section = ".text", .function = "foo", .count = 3, .expect = Expect::Xfail},
                                       {.section = ".text", .function = "bar", .count = 3, .expect = Expect::Xfail},
                                       {.section = ".text", .function = "baz", .count = 3},
                                       {.section = "cgroup_skb/ingress"},
                                   }};
    verify_file("linux-selftests", file);
}

TEST_CASE("linux-selftests/test_spin_lock.o", "[verify][samples][linux-selftests]") {
    static const FileEntry file = {
        "test_spin_lock.o",
        {
            {.section = ".text", .function = "static_subprog", .count = 3, .expect = Expect::Xfail},
            {.section = ".text", .function = "static_subprog_lock", .count = 3, .expect = Expect::Xfail},
            {.section = ".text", .function = "static_subprog_unlock", .count = 3, .expect = Expect::Xfail},
            {.section = "cgroup_skb/ingress", .expect = Expect::Xfail},
            {.section = "tc", .function = "lock_static_subprog_call", .count = 3, .expect = Expect::Xfail},
            {.section = "tc", .function = "lock_static_subprog_lock", .count = 3, .expect = Expect::Xfail},
            {.section = "tc", .function = "lock_static_subprog_unlock", .count = 3, .expect = Expect::Xfail},
        }};
    verify_file("linux-selftests", file);
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// Auto-generated test file for project: new_linux
#include "test_verify.hpp"

TEST_CASE("new_linux/sock_flags_kern.o", "[verify][samples][new_linux]") {
    static const FileEntry file = {"sock_flags_kern.o",
                                   {
                                       {.section = "cgroup/sock1"},
                                       {.section = "cgroup/sock2"},
                                   }};
    verify_file("new_linux", file);
}

TEST_CASE("new_linux/sockex1_kern.o", "[verify][samples][new_linux]") {
    static const FileEntry file = {"sockex1_kern.o",
                                   {
                                       {.section = "socket1"},
                                   }};
    verify_file("new_linux", file);
}

TEST_CASE("new_linux/sockex2_kern.o", "[verify][samples][new_linux]") {
    static const FileEntry file = {"sockex2_kern.o",
                                   {
                                       {.section = "socket2"},
                                   }};
    verify_file("new_linux", file);
}

TEST_CASE("new_linux/sockex3_kern.o", "[verify][samples][new_linux]") {
    static const FileEntry file = {"sockex3_kern.o",
                                   {
                                       {.section = "socket/3"},
                                       {.section = "socket/4"},
                                       {.section = "socket/1"},
                                       {.section = "socket/2"},
                                       {.section = "socket/0"},
                                   }};
    verify_file("new_linux", file);
}

TEST_CASE("new_linux/trace_output_kern.o", "[verify][samples][new_linux]") {
    static const FileEntry file = {"trace_output_kern.o",
                                   {
                                       {.section = "kprobe/__x64_sys_write"},
                                   }};
    verify_file("new_linux", file);
}

TEST_CASE("new_linux/tracex1_kern.o", "[verify][samples][new_linux]") {
    static const FileEntry file = {"tracex1_kern.o",
                                   {
                                       {.section = "kprobe/__netif_receive_skb_core"},
                                   }};
    verify_file("new_linux", file);
}

TEST_CASE("new_linux/tracex2_kern.o", "[verify][samples][new_linux]") {
    static const FileEntry file = {"tracex2_kern.o",
                                   {
                                       {.section = "kprobe/kfree_skb"},
                                       {.section = "kprobe/__x64_sys_write"},
                                   }};
    verify_file("new_linux", file);
}

TEST_CASE("new_linux/tracex3_kern.o", "[verify][samples][new_linux]") {
    static const FileEntry file = {"tracex3_kern.o",
                                   {
                                       {.section = "kprobe/blk_mq_start_request"},
                                       {.section = "kprobe/blk_account_io_done"},
                                   }};
    verify_file("new_linux", file);
}

TEST_CASE("new_linux/tracex4_kern.o", "[verify][samples][new_linux]") {
    static const FileEntry file = {"tracex4_kern.o",
                                   {
                                       {.section = "kprobe/kmem_cache_free"},
                                       {.section = "kretprobe/kmem_cache_alloc_node"},
                                   }};
    verify_file("new_linux", file);
}

TEST_CASE("new_linux/tracex6_kern.o", "[verify][samples][new_linux]") {
    static const FileEntry file = {"tracex6_kern.o",
                                   {
                                       {.section = "kprobe/htab_map_get_next_key"},
                                       {.section = "kprobe/htab_map_lookup_elem"},
                                   }};
    verify_file("new_linux", file);
}

TEST_CASE("new_linux/tracex7_kern.o", "[verify][samples][new_linux]") {
    static const FileEntry file = {"tracex7_kern.o",
                                   {
                                       {.section = "kprobe/open_ctree"},
                                   }};
    verify_file("new_linux", file);
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// Auto-generated test file for project: bcc
#include "test_verify.hpp"

TEST_CASE("bcc/bashreadline.bpf.o", "[verify][samples][bcc]") {
    static const FileEntry file = {"bashreadline.bpf.o",
                                   {
                                       {.section = "uretprobe/readline", .expect = Expect::Xfail},
                                   }};
    verify_file("bcc", file);
}

TEST_CASE("bcc/capable.bpf.o", "[verify][samples][bcc]") {
    static const FileEntry file = {"capable.bpf.o",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("bcc", file);
}

TEST_CASE("bcc/exitsnoop.bpf.o", "[verify][samples][bcc]") {
    static const FileEntry file = {"exitsnoop.bpf.o",
                                   {
                                       {.section = "tracepoint/sched/sched_process_exit"},
                                   }};
    verify_file("bcc", file);
}

TEST_CASE("bcc/filelife.bpf.o", "[verify][samples][bcc]") {
    static const FileEntry file = {"filelife.bpf.o",
                                   {
                                       {.section = "kprobe/vfs_create", .expect = Expect::Xfail},
                                       {.section = "kprobe/vfs_open", .expect = Expect::Xfail},
                                       {.section = "kprobe/security_inode_create", .expect = Expect::Xfail},
                                       {.section = "kprobe/vfs_unlink"},
                                       {.section = "kretprobe/vfs_unlink", .expect = Expect::Xfail},
                                   }};
    verify_file("bcc", file);
}

TEST_CASE("bcc/oomkill.bpf.o", "[verify][samples][bcc]") {
    static const FileEntry file = {"oomkill.bpf.o",
                                   {
                                       {.section = "kprobe/oom_kill_process", .expect = Expect::Xfail},
                                   }};
    verify_file("bcc", file);
}

TEST_CASE("bcc/tcpconnect.bpf.o", "[verify][samples][bcc]") {
    static const FileEntry file = {"tcpconnect.bpf.o",
                                   {
                                       {.section = "kprobe/tcp_v4_connect"},
                                       {.section = "kretprobe/tcp_v4_connect", .expect = Expect::Xfail},
                                       {.section = "kprobe/tcp_v6_connect"},
                                       {.section = "kretprobe/tcp_v6_connect", .expect = Expect::Xfail},
                                   }};
    verify_file("bcc", file);
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

// bcc libbpf-tools
TEST_SECTION_FAIL("bcc", "bashreadline.bpf.o", "uretprobe/readline")
TEST_SECTION("bcc", "exitsnoop.bpf.o", "tracepoint/sched/sched_process_exit")
TEST_SECTION_FAIL("bcc", "filelife.bpf.o", "kprobe/vfs_create")
TEST_SECTION_FAIL("bcc", "filelife.bpf.o", "kprobe/vfs_open")
TEST_SECTION_FAIL("bcc", "filelife.bpf.o", "kprobe/security_inode_create")
TEST_SECTION("bcc", "filelife.bpf.o", "kprobe/vfs_unlink")
TEST_SECTION_FAIL("bcc", "filelife.bpf.o", "kretprobe/vfs_unlink")
TEST_SECTION_FAIL("bcc", "oomkill.bpf.o", "kprobe/oom_kill_process")
TEST_SECTION("bcc", "tcpconnect.bpf.o", "kprobe/tcp_v4_connect")
TEST_SECTION_FAIL("bcc", "tcpconnect.bpf.o", "kretprobe/tcp_v4_connect")
TEST_SECTION("bcc", "tcpconnect.bpf.o", "kprobe/tcp_v6_connect")
TEST_SECTION_FAIL("bcc", "tcpconnect.bpf.o", "kretprobe/tcp_v6_connect")

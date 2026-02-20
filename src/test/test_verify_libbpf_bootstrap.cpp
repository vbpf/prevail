// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

// libbpf-bootstrap
TEST_SECTION_FAIL("libbpf-bootstrap", "bootstrap.bpf.o", "tp/sched/sched_process_exec")
TEST_SECTION_FAIL("libbpf-bootstrap", "bootstrap.bpf.o", "tp/sched/sched_process_exit")
TEST_SECTION_FAIL("libbpf-bootstrap", "bootstrap_legacy.bpf.o", "tp/sched/sched_process_exec")
TEST_SECTION("libbpf-bootstrap", "bootstrap_legacy.bpf.o", "tp/sched/sched_process_exit")
TEST_SECTION_FAIL("libbpf-bootstrap", "fentry.bpf.o", "fentry/do_unlinkat")
TEST_SECTION_FAIL("libbpf-bootstrap", "fentry.bpf.o", "fexit/do_unlinkat")
TEST_SECTION("libbpf-bootstrap", "kprobe.bpf.o", "kprobe/do_unlinkat")
TEST_SECTION("libbpf-bootstrap", "kprobe.bpf.o", "kretprobe/do_unlinkat")
TEST_SECTION_FAIL("libbpf-bootstrap", "lsm.bpf.o", "lsm/bpf")
TEST_SECTION("libbpf-bootstrap", "minimal.bpf.o", "tp/syscalls/sys_enter_write")
TEST_SECTION("libbpf-bootstrap", "minimal_legacy.bpf.o", "tp/syscalls/sys_enter_write")
TEST_SECTION("libbpf-bootstrap", "minimal_ns.bpf.o", "tp/syscalls/sys_enter_write")
TEST_SECTION_FAIL("libbpf-bootstrap", "profile.bpf.o", "perf_event")
TEST_SECTION_FAIL("libbpf-bootstrap", "sockfilter.bpf.o", "socket")
TEST_SECTION_FAIL("libbpf-bootstrap", "task_iter.bpf.o", "iter/task")
TEST_SECTION("libbpf-bootstrap", "tc.bpf.o", "tc")
TEST_SECTION("libbpf-bootstrap", "uprobe.bpf.o", "uprobe")
TEST_SECTION("libbpf-bootstrap", "uprobe.bpf.o", "uretprobe")
TEST_SECTION("libbpf-bootstrap", "uprobe.bpf.o", "uprobe//proc/self/exe:uprobed_sub")
TEST_SECTION("libbpf-bootstrap", "uprobe.bpf.o", "uretprobe//proc/self/exe:uprobed_sub")

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// Auto-generated test file for project: libbpf-bootstrap
#include "test_verify.hpp"

TEST_CASE("libbpf-bootstrap/bootstrap.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"bootstrap.bpf.o",
                                   {
                                       {.section = "tp/sched/sched_process_exec", .expect = Expect::Xfail},
                                       {.section = "tp/sched/sched_process_exit", .expect = Expect::Xfail},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/bootstrap_legacy.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"bootstrap_legacy.bpf.o",
                                   {
                                       {.section = "tp/sched/sched_process_exec", .expect = Expect::Xfail},
                                       {.section = "tp/sched/sched_process_exit"},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/fentry.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"fentry.bpf.o",
                                   {
                                       {.section = "fentry/do_unlinkat", .expect = Expect::Xfail},
                                       {.section = "fexit/do_unlinkat", .expect = Expect::Xfail},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/kprobe.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"kprobe.bpf.o",
                                   {
                                       {.section = "kprobe/do_unlinkat"},
                                       {.section = "kretprobe/do_unlinkat"},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/ksyscall.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"ksyscall.bpf.o",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/lsm.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"lsm.bpf.o",
                                   {
                                       {.section = "lsm/bpf", .expect = Expect::Xfail},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/minimal.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"minimal.bpf.o",
                                   {
                                       {.section = "tp/syscalls/sys_enter_write"},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/minimal_legacy.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"minimal_legacy.bpf.o",
                                   {
                                       {.section = "tp/syscalls/sys_enter_write"},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/minimal_ns.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"minimal_ns.bpf.o",
                                   {
                                       {.section = "tp/syscalls/sys_enter_write"},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/profile.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"profile.bpf.o",
                                   {
                                       {.section = "perf_event", .expect = Expect::Xfail},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/sockfilter.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"sockfilter.bpf.o",
                                   {
                                       {.section = "socket", .expect = Expect::Xfail},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/task_iter.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"task_iter.bpf.o",
                                   {
                                       {.section = "iter/task", .expect = Expect::Xfail},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/tc.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"tc.bpf.o",
                                   {
                                       {.section = "tc"},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/uprobe.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"uprobe.bpf.o",
                                   {
                                       {.section = "uprobe"},
                                       {.section = "uretprobe"},
                                       {.section = "uprobe//proc/self/exe:uprobed_sub"},
                                       {.section = "uretprobe//proc/self/exe:uprobed_sub"},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

TEST_CASE("libbpf-bootstrap/usdt.bpf.o", "[verify][samples][libbpf-bootstrap]") {
    static const FileEntry file = {"usdt.bpf.o",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("libbpf-bootstrap", file);
}

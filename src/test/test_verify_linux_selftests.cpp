// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

// linux-selftests
// multi-program section (7 progs)
// TEST_SECTION("linux-selftests", "atomics.o", "raw_tp/sys_enter") -- 7 programs in section
// multi-program section (2 progs)
// TEST_SECTION("linux-selftests", "bloom_filter_map.o", "fentry/__x64_sys_getpgid") -- 2 programs in section
TEST_SECTION("linux-selftests", "fexit_sleep.o", "fentry/__x64_sys_nanosleep")
TEST_SECTION("linux-selftests", "fexit_sleep.o", "fexit/__x64_sys_nanosleep")
TEST_SECTION_FAIL("linux-selftests", "freplace_get_constant.o", "freplace/get_constant")
TEST_SECTION("linux-selftests", "get_cgroup_id_kern.o", "tracepoint/syscalls/sys_enter_nanosleep")
// BTF-typed arguments not modeled
TEST_SECTION_FAIL("linux-selftests", "kfree_skb.o", "tp_btf/kfree_skb")
TEST_SECTION_FAIL("linux-selftests", "kfree_skb.o", "fentry/eth_type_trans")
TEST_SECTION_FAIL("linux-selftests", "kfree_skb.o", "fexit/eth_type_trans")
TEST_SECTION("linux-selftests", "loop1.o", "raw_tracepoint/kfree_skb")
TEST_SECTION("linux-selftests", "loop2.o", "raw_tracepoint/consume_skb")
// loop3 hangs (analysis does not terminate)
// TEST_SECTION("linux-selftests", "loop3.o", "raw_tracepoint/consume_skb")
TEST_SECTION("linux-selftests", "loop4.o", "socket")
TEST_SECTION("linux-selftests", "loop5.o", "socket")
TEST_SECTION_FAIL("linux-selftests", "socket_cookie_prog.o", "cgroup/connect6")
TEST_SECTION_FAIL("linux-selftests", "socket_cookie_prog.o", "sockops")
TEST_SECTION_FAIL("linux-selftests", "socket_cookie_prog.o", "fexit/inet_stream_connect")
TEST_SECTION("linux-selftests", "sockmap_parse_prog.o", "sk_skb1")
TEST_SECTION("linux-selftests", "sockmap_verdict_prog.o", "sk_skb2")
// multi-program tc sections (tailcall programs)
// TEST_SECTION("linux-selftests", "tailcall1.o", "tc") -- 4 programs in section
// TEST_SECTION("linux-selftests", "tailcall2.o", "tc") -- 6 programs in section
// TEST_SECTION("linux-selftests", "tailcall3.o", "tc") -- 2 programs in section
// global subprograms verified standalone fail (no calling context)
TEST_SECTION_FAIL("linux-selftests", "test_global_func1.o", "tc")
TEST_PROGRAM("linux-selftests", "test_global_func1.o", ".text", "f0", 4)
TEST_PROGRAM_FAIL("linux-selftests", "test_global_func1.o", ".text", "f1", 4)
TEST_PROGRAM_FAIL("linux-selftests", "test_global_func1.o", ".text", "f2", 4)
TEST_PROGRAM_FAIL("linux-selftests", "test_global_func1.o", ".text", "f3", 4)
TEST_SECTION("linux-selftests", "test_global_func_args.o", "cgroup_skb/ingress")
TEST_PROGRAM_FAIL("linux-selftests", "test_global_func_args.o", ".text", "foo", 3)
TEST_PROGRAM_FAIL("linux-selftests", "test_global_func_args.o", ".text", "bar", 3)
TEST_PROGRAM("linux-selftests", "test_global_func_args.o", ".text", "baz", 3)
TEST_SECTION_FAIL("linux-selftests", "test_spin_lock.o", "cgroup_skb/ingress")
// multi-program tc section (3 programs)
// TEST_SECTION("linux-selftests", "test_spin_lock.o", "tc") -- 3 programs in section

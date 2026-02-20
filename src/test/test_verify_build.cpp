// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

// Test some programs that should pass verification except when the strict flag is set.
TEST_SECTION_REJECT_IF_STRICT("build", "mapoverflow.o", ".text")
TEST_SECTION_REJECT_IF_STRICT("build", "mapunderflow.o", ".text")

TEST_PROGRAM("build", "bpf2bpf.o", ".text", "add1", 2);
TEST_PROGRAM("build", "bpf2bpf.o", ".text", "add2", 2);
TEST_PROGRAM("build", "bpf2bpf.o", "test", "func", 1);

TEST_SECTION("build", "byteswap.o", ".text")
TEST_SECTION("build", "stackok.o", ".text")
TEST_SECTION("build", "packet_start_ok.o", "xdp")
TEST_SECTION("build", "packet_access.o", "xdp")
TEST_SECTION("build", "tail_call.o", "xdp_prog")
TEST_SECTION("build", "map_in_map.o", ".text")
TEST_SECTION("build", "map_in_map_anonymous.o", ".text")
TEST_SECTION("build", "map_in_map_legacy.o", ".text")
TEST_SECTION("build", "store_map_value_in_map.o", ".text")
TEST_SECTION("build", "twomaps.o", ".text");
TEST_SECTION("build", "twostackvars.o", ".text");
TEST_SECTION("build", "twotypes.o", ".text");
TEST_SECTION("build", "global_variable.o", ".text")
TEST_PROGRAM("build", "prog_array.o", ".text", "func", 5);
TEST_PROGRAM("build", "prog_array.o", ".text", "func0", 5);
TEST_PROGRAM("build", "prog_array.o", ".text", "func1", 5);
TEST_PROGRAM("build", "prog_array.o", ".text", "func2", 5);
TEST_PROGRAM("build", "prog_array.o", ".text", "func3", 5);

// Test some programs that ought to fail verification.
TEST_SECTION_REJECT("build", "badmapptr.o", "test")
TEST_SECTION_REJECT("build", "badhelpercall.o", ".text")
TEST_SECTION_REJECT("build", "ctxoffset.o", "sockops")
TEST_SECTION_FAIL("build", "dependent_read.o", "xdp")
TEST_SECTION_REJECT("build", "exposeptr.o", ".text")
TEST_SECTION_REJECT("build", "exposeptr2.o", ".text")
TEST_SECTION_REJECT("build", "mapvalue-overrun.o", ".text")
TEST_SECTION_REJECT("build", "nullmapref.o", "test")
TEST_SECTION_REJECT("build", "packet_overflow.o", "xdp")
TEST_SECTION_REJECT("build", "packet_reallocate.o", "socket_filter")
TEST_SECTION_REJECT("build", "tail_call_bad.o", "xdp_prog")
TEST_SECTION_REJECT("build", "ringbuf_uninit.o", ".text");
// Intentional OOB access in else branch
TEST_SECTION_REJECT("build", "invalid_map_access.o", ".text")

TEST_SECTION("build", "twomaps_btf.o", ".text")
// bpf_loop callback not supported
TEST_SECTION_FAIL("build", "bpf_loop_helper.o", "xdp")
TEST_SECTION("build", "cpumap.o", "xdp")
TEST_SECTION("build", "devmap.o", "xdp")
TEST_SECTION("build", "hash_of_maps.o", ".text")
TEST_SECTION("build", "lpm_trie.o", "xdp")
TEST_SECTION("build", "percpu_array.o", "xdp")
TEST_SECTION("build", "percpu_hash.o", "xdp")
// perf_event_output helper not modeled
TEST_SECTION_FAIL("build", "perf_event_array.o", "xdp")
// queue/stack pop helper not modeled
TEST_SECTION_FAIL("build", "queue_stack.o", ".text")
TEST_SECTION("build", "sockmap.o", "sk_skb/stream_verdict")
TEST_SECTION("build", "global_func.o", "xdp")
// global subprograms verified standalone fail (no calling context)
TEST_PROGRAM_FAIL("build", "global_func.o", ".text", "add_and_store", 2)
TEST_PROGRAM_FAIL("build", "global_func.o", ".text", "process_entry", 2)

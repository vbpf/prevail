// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// Auto-generated test file for project: build
#include "test_verify.hpp"

TEST_CASE("build/badhelpercall.o", "[verify][samples][build]") {
    static const FileEntry file = {"badhelpercall.o",
                                   {
                                       {.section = ".text", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/badmapptr.o", "[verify][samples][build]") {
    static const FileEntry file = {"badmapptr.o",
                                   {
                                       {.section = "test", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/badrelo.o", "[verify][samples][build]") {
    static const FileEntry file = {"badrelo.o",
                                   {
                                       {.section = ".text", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/bounded_loop.o", "[verify][samples][build]") {
    static const FileEntry file = {"bounded_loop.o",
                                   {
                                       {.section = "test"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/bpf2bpf.o", "[verify][samples][build]") {
    static const FileEntry file = {"bpf2bpf.o",
                                   {
                                       {.section = ".text", .function = "add1", .count = 2},
                                       {.section = ".text", .function = "add2", .count = 2},
                                       {.section = "test"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/bpf_loop_helper.o", "[verify][samples][build]") {
    static const FileEntry file = {
        "bpf_loop_helper.o",
        {
            {.section = ".text", .expect = Expect::Skip, .skip_reason = "loop_callback can hang"},
            {.section = "xdp", .expect = Expect::Xfail},
        }};
    verify_file("build", file);
}

TEST_CASE("build/byteswap.o", "[verify][samples][build]") {
    static const FileEntry file = {"byteswap.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/correlated_branch.o", "[verify][samples][build]") {
    static const FileEntry file = {"correlated_branch.o",
                                   {
                                       {.section = "xdp", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/correlated_branch2.o", "[verify][samples][build]") {
    static const FileEntry file = {"correlated_branch2.o",
                                   {
                                       {.section = "socket_filter", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/cpumap.o", "[verify][samples][build]") {
    static const FileEntry file = {"cpumap.o",
                                   {
                                       {.section = "xdp"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/ctxoffset.o", "[verify][samples][build]") {
    static const FileEntry file = {"ctxoffset.o",
                                   {
                                       {.section = "sockops", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/dependent_read.o", "[verify][samples][build]") {
    static const FileEntry file = {"dependent_read.o",
                                   {
                                       {.section = "xdp", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/devmap.o", "[verify][samples][build]") {
    static const FileEntry file = {"devmap.o",
                                   {
                                       {.section = "xdp"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/divzero.o", "[verify][samples][build]") {
    static const FileEntry file = {"divzero.o",
                                   {
                                       {.section = "test"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/exposeptr.o", "[verify][samples][build]") {
    static const FileEntry file = {"exposeptr.o",
                                   {
                                       {.section = ".text", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/exposeptr2.o", "[verify][samples][build]") {
    static const FileEntry file = {"exposeptr2.o",
                                   {
                                       {.section = ".text", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/externalfunction.o", "[verify][samples][build]") {
    static const FileEntry file = {"externalfunction.o",
                                   {
                                       {.section = ".text", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/global_func.o", "[verify][samples][build]") {
    static const FileEntry file = {
        "global_func.o",
        {
            {.section = ".text", .function = "add_and_store", .count = 2, .expect = Expect::Xfail},
            {.section = ".text", .function = "process_entry", .count = 2, .expect = Expect::Xfail},
            {.section = "xdp"},
        }};
    verify_file("build", file);
}

TEST_CASE("build/global_variable.o", "[verify][samples][build]") {
    static const FileEntry file = {"global_variable.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/global_variable_2.o", "[verify][samples][build]") {
    static const FileEntry file = {"global_variable_2.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/hash_of_maps.o", "[verify][samples][build]") {
    static const FileEntry file = {"hash_of_maps.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/infinite_loop.o", "[verify][samples][build]") {
    static const FileEntry file = {"infinite_loop.o",
                                   {
                                       {.section = "test"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/invalid_map_access.o", "[verify][samples][build]") {
    static const FileEntry file = {"invalid_map_access.o",
                                   {
                                       {.section = ".text", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/loop.o", "[verify][samples][build]") {
    static const FileEntry file = {"loop.o",
                                   {
                                       {.section = "test_md", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/lpm_trie.o", "[verify][samples][build]") {
    static const FileEntry file = {"lpm_trie.o",
                                   {
                                       {.section = "xdp"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/map_in_map.o", "[verify][samples][build]") {
    static const FileEntry file = {"map_in_map.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/map_in_map_anonymous.o", "[verify][samples][build]") {
    static const FileEntry file = {"map_in_map_anonymous.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/map_in_map_legacy.o", "[verify][samples][build]") {
    static const FileEntry file = {"map_in_map_legacy.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/map_in_map_typedef.o", "[verify][samples][build]") {
    static const FileEntry file = {"map_in_map_typedef.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/mapoverflow.o", "[verify][samples][build]") {
    static const FileEntry file = {"mapoverflow.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/mapunderflow.o", "[verify][samples][build]") {
    static const FileEntry file = {"mapunderflow.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/mapvalue-overrun.o", "[verify][samples][build]") {
    static const FileEntry file = {"mapvalue-overrun.o",
                                   {
                                       {.section = ".text", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/nullmapref.o", "[verify][samples][build]") {
    static const FileEntry file = {"nullmapref.o",
                                   {
                                       {.section = "test", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/packet_access.o", "[verify][samples][build]") {
    static const FileEntry file = {"packet_access.o",
                                   {
                                       {.section = "xdp"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/packet_overflow.o", "[verify][samples][build]") {
    static const FileEntry file = {"packet_overflow.o",
                                   {
                                       {.section = "xdp", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/packet_reallocate.o", "[verify][samples][build]") {
    static const FileEntry file = {"packet_reallocate.o",
                                   {
                                       {.section = "socket_filter", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/packet_start_ok.o", "[verify][samples][build]") {
    static const FileEntry file = {"packet_start_ok.o",
                                   {
                                       {.section = "xdp"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/percpu_array.o", "[verify][samples][build]") {
    static const FileEntry file = {"percpu_array.o",
                                   {
                                       {.section = "xdp"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/percpu_hash.o", "[verify][samples][build]") {
    static const FileEntry file = {"percpu_hash.o",
                                   {
                                       {.section = "xdp"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/perf_event_array.o", "[verify][samples][build]") {
    static const FileEntry file = {"perf_event_array.o",
                                   {
                                       {.section = "xdp", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/prog_array.o", "[verify][samples][build]") {
    static const FileEntry file = {"prog_array.o",
                                   {
                                       {.section = ".text", .function = "func0", .count = 5},
                                       {.section = ".text", .function = "func1", .count = 5},
                                       {.section = ".text", .function = "func2", .count = 5},
                                       {.section = ".text", .function = "func3", .count = 5},
                                       {.section = ".text", .function = "func", .count = 5},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/ptr_arith.o", "[verify][samples][build]") {
    static const FileEntry file = {"ptr_arith.o",
                                   {
                                       {.section = "xdp", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/queue_stack.o", "[verify][samples][build]") {
    static const FileEntry file = {"queue_stack.o",
                                   {
                                       {.section = ".text", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/ringbuf_in_map.o", "[verify][samples][build]") {
    static const FileEntry file = {"ringbuf_in_map.o",
                                   {
                                       {.section = ".text", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/ringbuf_uninit.o", "[verify][samples][build]") {
    static const FileEntry file = {"ringbuf_uninit.o",
                                   {
                                       {.section = ".text", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/sockmap.o", "[verify][samples][build]") {
    static const FileEntry file = {"sockmap.o",
                                   {
                                       {.section = "sk_skb/stream_verdict"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/stackok.o", "[verify][samples][build]") {
    static const FileEntry file = {"stackok.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/store_map_value_in_map.o", "[verify][samples][build]") {
    static const FileEntry file = {"store_map_value_in_map.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/tail_call.o", "[verify][samples][build]") {
    static const FileEntry file = {"tail_call.o",
                                   {
                                       {.section = "xdp_prog"},
                                       {.section = "xdp_prog/0"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/tail_call_bad.o", "[verify][samples][build]") {
    static const FileEntry file = {"tail_call_bad.o",
                                   {
                                       {.section = "xdp_prog", .expect = Expect::Xfail},
                                       {.section = "xdp_prog/0"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/twomaps.o", "[verify][samples][build]") {
    static const FileEntry file = {"twomaps.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/twomaps_btf.o", "[verify][samples][build]") {
    static const FileEntry file = {"twomaps_btf.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/twostackvars.o", "[verify][samples][build]") {
    static const FileEntry file = {"twostackvars.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/twotypes.o", "[verify][samples][build]") {
    static const FileEntry file = {"twotypes.o",
                                   {
                                       {.section = ".text"},
                                   }};
    verify_file("build", file);
}

TEST_CASE("build/wronghelper.o", "[verify][samples][build]") {
    static const FileEntry file = {"wronghelper.o",
                                   {
                                       {.section = "xdp", .expect = Expect::Xfail},
                                   }};
    verify_file("build", file);
}

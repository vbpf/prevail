// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT-ebpf
#include "test_verify.hpp"

TEST_CASE("cilium-ebpf/arena-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"arena-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/btf_map_init-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"btf_map_init-el.elf",
                                   {
                                       {.section = "socket/tail"},
                                       {.section = "socket/main"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/constants-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"constants-el.elf",
                                   {
                                       {.section = "sk_lookup/"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/errors-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {
        "errors-el.elf",
        {
            {.section = "socket", .function = "poisoned_single", .count = 3, .expect = Expect::Xfail},
            {.section = "socket", .function = "poisoned_double", .count = 3, .expect = Expect::Xfail},
            {.section = "socket", .function = "poisoned_kfunc", .count = 3, .expect = Expect::Xfail},
        }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/fentry_fexit-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"fentry_fexit-el.elf",
                                   {
                                       {.section = "fentry/target"},
                                       {.section = "fexit/target"},
                                       {.section = "tc"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/freplace-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"freplace-el.elf",
                                   {
                                       {.section = ".text"},
                                       {.section = "raw_tracepoint/sched_process_exec"},
                                       {.section = "freplace/subprog"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/fwd_decl-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"fwd_decl-el.elf",
                                   {
                                       {.section = "socket", .expect = Expect::Xfail},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/invalid-kfunc-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"invalid-kfunc-el.elf",
                                   {
                                       {.section = "tc", .expect = Expect::Xfail},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/invalid_btf_map_init-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"invalid_btf_map_init-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/invalid_map-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"invalid_map-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/invalid_map_static-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"invalid_map_static-el.elf",
                                   {
                                       {.section = "xdp", .expect = Expect::Xfail},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/iproute2_map_compat-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"iproute2_map_compat-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/kconfig-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"kconfig-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/kfunc-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"kfunc-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/kfunc-kmod-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"kfunc-kmod-el.elf",
                                   {
                                       {.section = "tc", .expect = Expect::Xfail},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/ksym-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"ksym-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/linked-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"linked-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/linked1-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {
        "linked1-el.elf",
        {
            {.section = ".text", .function = "l1", .count = 4, .expect = Expect::Xfail},
            {.section = ".text", .function = "l1_w", .count = 4, .expect = Expect::Xfail},
            {.section = ".text", .function = "l1_s", .count = 4, .expect = Expect::Xfail},
            {.section = ".text", .function = "ww", .count = 4, .expect = Expect::Xfail},
            {.section = "socket", .function = "entry_l2", .count = 4, .expect = Expect::Xfail},
            {.section = "socket", .function = "entry_l1_w", .count = 4, .expect = Expect::Xfail},
            {.section = "socket", .function = "entry_l1_s", .count = 4, .expect = Expect::Xfail},
            {.section = "socket", .function = "entry_ww", .count = 4, .expect = Expect::Xfail},
        }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/linked2-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {
        "linked2-el.elf",
        {
            {.section = ".text", .function = "l2", .count = 4, .expect = Expect::Xfail},
            {.section = ".text", .function = "l1_w", .count = 4, .expect = Expect::Xfail},
            {.section = ".text", .function = "l1_s", .count = 4, .expect = Expect::Xfail},
            {.section = ".text", .function = "ww", .count = 4, .expect = Expect::Xfail},
            {.section = "socket", .function = "entry_l1", .count = 4, .expect = Expect::Xfail},
            {.section = "socket", .function = "entry_l1_w", .count = 4, .expect = Expect::Xfail},
            {.section = "socket", .function = "entry_l1_s", .count = 4, .expect = Expect::Xfail},
            {.section = "socket", .function = "entry_ww", .count = 4, .expect = Expect::Xfail},
        }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/loader-clang-14-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"loader-clang-14-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/loader-clang-17-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"loader-clang-17-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/loader-clang-20-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"loader-clang-20-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/loader-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"loader-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/loader_nobtf-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"loader_nobtf-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/manyprogs-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"manyprogs-el.elf",
                                   {
                                       {.section = "kprobe/sys_execvea0"},  {.section = "kprobe/sys_execvea1"},
                                       {.section = "kprobe/sys_execvea2"},  {.section = "kprobe/sys_execvea3"},
                                       {.section = "kprobe/sys_execvea4"},  {.section = "kprobe/sys_execvea5"},
                                       {.section = "kprobe/sys_execvea6"},  {.section = "kprobe/sys_execvea7"},
                                       {.section = "kprobe/sys_execvea8"},  {.section = "kprobe/sys_execvea9"},
                                       {.section = "kprobe/sys_execvea10"}, {.section = "kprobe/sys_execvea11"},
                                       {.section = "kprobe/sys_execvea12"}, {.section = "kprobe/sys_execvea13"},
                                       {.section = "kprobe/sys_execvea14"}, {.section = "kprobe/sys_execvea15"},
                                       {.section = "kprobe/sys_execvea16"}, {.section = "kprobe/sys_execvea17"},
                                       {.section = "kprobe/sys_execvea18"}, {.section = "kprobe/sys_execvea19"},
                                       {.section = "kprobe/sys_execvea20"}, {.section = "kprobe/sys_execvea21"},
                                       {.section = "kprobe/sys_execvea22"}, {.section = "kprobe/sys_execvea23"},
                                       {.section = "kprobe/sys_execvea24"}, {.section = "kprobe/sys_execvea25"},
                                       {.section = "kprobe/sys_execvea26"}, {.section = "kprobe/sys_execvea27"},
                                       {.section = "kprobe/sys_execvea28"}, {.section = "kprobe/sys_execvea29"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/map_spin_lock-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"map_spin_lock-el.elf",
                                   {
                                       {.section = "", .expect = Expect::Skip, .skip_reason = "failed to load"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/raw_tracepoint-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"raw_tracepoint-el.elf",
                                   {
                                       {.section = "raw_tracepoint/sched_process_exec"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/strings-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"strings-el.elf",
                                   {
                                       {.section = "xdp"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/struct_ops-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"struct_ops-el.elf",
                                   {
                                       {.section = "struct_ops/test_1"},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/subprog_reloc-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"subprog_reloc-el.elf",
                                   {
                                       {.section = ".text"},
                                       {.section = "xdp", .expect = Expect::Xfail},
                                   }};
    verify_file("cilium-ebpf", file);
}

TEST_CASE("cilium-ebpf/variables-el.elf", "[verify][samples][cilium-ebpf]") {
    static const FileEntry file = {"variables-el.elf",
                                   {
                                       {.section = "socket", .function = "set_vars", .count = 8},
                                       {.section = "socket", .function = "get_bss", .count = 8},
                                       {.section = "socket", .function = "get_data", .count = 8},
                                       {.section = "socket", .function = "get_rodata", .count = 8},
                                       {.section = "socket", .function = "check_struct", .count = 8},
                                       {.section = "socket", .function = "check_struct_pad", .count = 8},
                                       {.section = "socket", .function = "check_array", .count = 8},
                                       {.section = "socket", .function = "add_atomic", .count = 8},
                                   }};
    verify_file("cilium-ebpf", file);
}

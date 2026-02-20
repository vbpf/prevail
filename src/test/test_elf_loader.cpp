// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>
#include <stdexcept>

#include "config.hpp"
#include "elf_loader.hpp"
#include "platform.hpp"

using namespace prevail;

#define FAIL_LOAD_ELF_BASE(test_name, dirname, filename, sectionname)                                    \
    TEST_CASE(test_name, "[elf]") {                                                                      \
        try {                                                                                            \
            thread_local_options = {};                                                                   \
            read_elf("ebpf-samples/" dirname "/" filename, sectionname, "", {}, &g_ebpf_platform_linux); \
            REQUIRE(false);                                                                              \
        } catch (const std::runtime_error&) {                                                            \
        }                                                                                                \
    }

#define FAIL_LOAD_ELF(dirname, filename, sectionname) \
    FAIL_LOAD_ELF_BASE("Try loading nonexisting program: " dirname "/" filename, dirname, filename, sectionname)

// Like FAIL_LOAD_ELF, but includes sectionname in the test name to avoid collisions
// when multiple sections of the same file fail to load.
#define FAIL_LOAD_ELF_SECTION(dirname, filename, sectionname) \
    FAIL_LOAD_ELF_BASE("Try loading bad section: " dirname "/" filename " " sectionname, dirname, filename, sectionname)

// Intentional loader failures.
FAIL_LOAD_ELF("cilium", "not-found.o", "2/1")
FAIL_LOAD_ELF("cilium", "bpf_lxc.o", "not-found")
FAIL_LOAD_ELF("build", "badrelo.o", ".text")
FAIL_LOAD_ELF("invalid", "badsymsize.o", "xdp_redirect_map")
FAIL_LOAD_ELF_SECTION("bcc", "capable.bpf.o", "kprobe/cap_capable")
FAIL_LOAD_ELF_SECTION("bcc", "capable.bpf.o", "kretprobe/cap_capable")
FAIL_LOAD_ELF_SECTION("libbpf-bootstrap", "ksyscall.bpf.o", "ksyscall/tgkill")
FAIL_LOAD_ELF_SECTION("libbpf-bootstrap", "ksyscall.bpf.o", "ksyscall/kill")
FAIL_LOAD_ELF_SECTION("libbpf-bootstrap", "usdt.bpf.o", "usdt/libc.so.6:libc:setjmp")
FAIL_LOAD_ELF_SECTION("libbpf-bootstrap", "usdt.bpf.o", "usdt")
FAIL_LOAD_ELF_SECTION("linux-selftests", "bpf_cubic.o", "struct_ops")
FAIL_LOAD_ELF_SECTION("linux-selftests", "bpf_dctcp.o", "struct_ops")
FAIL_LOAD_ELF_SECTION("linux-selftests", "map_ptr_kern.o", "cgroup_skb/egress")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "errors-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "fwd_decl-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "invalid-kfunc-el.elf", "tc")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "kconfig-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "kfunc-el.elf", "tc")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "kfunc-el.elf", "fentry/bpf_fentry_test2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "kfunc-el.elf", "tp_btf/task_newtask")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "kfunc-kmod-el.elf", "tc")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "ksym-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "linked-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "linked1-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "linked2-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "static")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "other")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "xdp")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "socket/2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "socket/3")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "socket/4")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "static")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "other")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "xdp")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "socket/2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "socket/3")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "socket/4")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "static")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "other")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "xdp")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "socket/2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "socket/3")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "socket/4")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "static")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "other")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "xdp")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "socket/2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "socket/3")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "socket/4")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "static")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "other")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "xdp")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "socket")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "socket/2")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "socket/3")
FAIL_LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "socket/4")

TEST_CASE("CO-RE relocations are parsed from .BTF.ext core_relo subsection", "[elf][core]") {
    thread_local_options = {};

    constexpr auto fentry_path = "ebpf-samples/cilium-examples/tcprtt_bpf_bpfel.o";
    constexpr auto fentry_section = "fentry/tcp_close";
    const auto fentry_progs = read_elf(fentry_path, fentry_section, "", {}, &g_ebpf_platform_linux);
    REQUIRE(fentry_progs.size() == 1);
    REQUIRE(fentry_progs[0].core_relocation_count > 0);

    constexpr auto sockops_path = "ebpf-samples/cilium-examples/tcprtt_sockops_bpf_bpfel.o";
    constexpr auto sockops_section = "sockops";
    const auto sockops_progs = read_elf(sockops_path, sockops_section, "", {}, &g_ebpf_platform_linux);
    REQUIRE(sockops_progs.size() == 1);
    REQUIRE(sockops_progs[0].core_relocation_count > 0);
}

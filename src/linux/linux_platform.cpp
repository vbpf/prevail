// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <stdexcept>
#if __linux__
#include <linux/bpf.h>

#ifndef BPF_PROG_TYPE_CGROUP_SYSCTL
#define BPF_PROG_TYPE_CGROUP_SYSCTL 23
#endif
#ifndef BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
#define BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE 24
#endif
#ifndef BPF_PROG_TYPE_CGROUP_SOCKOPT
#define BPF_PROG_TYPE_CGROUP_SOCKOPT 25
#endif
#ifndef BPF_PROG_TYPE_TRACING
#define BPF_PROG_TYPE_TRACING 26
#endif
#ifndef BPF_PROG_TYPE_STRUCT_OPS
#define BPF_PROG_TYPE_STRUCT_OPS 27
#endif
#ifndef BPF_PROG_TYPE_EXT
#define BPF_PROG_TYPE_EXT 28
#endif
#ifndef BPF_PROG_TYPE_LSM
#define BPF_PROG_TYPE_LSM 29
#endif
#ifndef BPF_PROG_TYPE_SK_LOOKUP
#define BPF_PROG_TYPE_SK_LOOKUP 30
#endif
#ifndef BPF_PROG_TYPE_SYSCALL
#define BPF_PROG_TYPE_SYSCALL 31
#endif
#ifndef BPF_PROG_TYPE_NETFILTER
#define BPF_PROG_TYPE_NETFILTER 32
#endif

#ifndef BPF_MAP_TYPE_XSKMAP
#define BPF_MAP_TYPE_XSKMAP 17
#endif
#ifndef BPF_MAP_TYPE_SOCKHASH
#define BPF_MAP_TYPE_SOCKHASH 18
#endif
#ifndef BPF_MAP_TYPE_CGROUP_STORAGE
#define BPF_MAP_TYPE_CGROUP_STORAGE 19
#endif
#ifndef BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
#define BPF_MAP_TYPE_REUSEPORT_SOCKARRAY 20
#endif
#ifndef BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
#define BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE 21
#endif
#ifndef BPF_MAP_TYPE_QUEUE
#define BPF_MAP_TYPE_QUEUE 22
#endif
#ifndef BPF_MAP_TYPE_STACK
#define BPF_MAP_TYPE_STACK 23
#endif
#ifndef BPF_MAP_TYPE_SK_STORAGE
#define BPF_MAP_TYPE_SK_STORAGE 24
#endif
#ifndef BPF_MAP_TYPE_DEVMAP_HASH
#define BPF_MAP_TYPE_DEVMAP_HASH 25
#endif
#ifndef BPF_MAP_TYPE_STRUCT_OPS
#define BPF_MAP_TYPE_STRUCT_OPS 26
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
#ifndef BPF_MAP_TYPE_INODE_STORAGE
#define BPF_MAP_TYPE_INODE_STORAGE 28
#endif
#ifndef BPF_MAP_TYPE_TASK_STORAGE
#define BPF_MAP_TYPE_TASK_STORAGE 29
#endif
#ifndef BPF_MAP_TYPE_BLOOM_FILTER
#define BPF_MAP_TYPE_BLOOM_FILTER 30
#endif
#ifndef BPF_MAP_TYPE_USER_RINGBUF
#define BPF_MAP_TYPE_USER_RINGBUF 31
#endif
#ifndef BPF_MAP_TYPE_CGRP_STORAGE
#define BPF_MAP_TYPE_CGRP_STORAGE 32
#endif
#ifndef BPF_MAP_TYPE_ARENA
#define BPF_MAP_TYPE_ARENA 33
#endif

#define PTYPE(name, descr, native_type, prefixes) {name, descr, native_type, prefixes}
#define PTYPE_PRIVILEGED(name, descr, native_type, prefixes) {name, descr, native_type, prefixes, true}
#else
#define PTYPE(name, descr, native_type, prefixes) {name, descr, 0, prefixes}
#define PTYPE_PRIVILEGED(name, descr, native_type, prefixes) {name, descr, 0, prefixes, true}
#endif
#include "elf_loader.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"
#include "linux/linux_platform.hpp"
#include "platform.hpp"
#include "verifier.hpp"

namespace prevail {
// Map definitions as they appear in an ELF file, so field width matters.
struct BpfLoadMapDef {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
};

static int create_map_linux(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
                            ebpf_verifier_options_t options);

// Allow for comma as a separator between multiple prefixes, to make
// the preprocessor treat a prefix list as one macro argument.
#define COMMA ,

const EbpfProgramType linux_socket_filter_program_type =
    PTYPE("socket_filter", &g_socket_filter_descr, BPF_PROG_TYPE_SOCKET_FILTER, {"socket"});

const EbpfProgramType linux_xdp_program_type = PTYPE("xdp", &g_xdp_descr, BPF_PROG_TYPE_XDP, {"xdp"});

const EbpfProgramType cilium_lxc_program_type = PTYPE("lxc", &g_sched_descr, BPF_PROG_TYPE_SOCKET_FILTER, {});

const std::vector<EbpfProgramType> linux_program_types = {
    PTYPE("unspec", &g_unspec_descr, BPF_PROG_TYPE_UNSPEC, {}),
    linux_socket_filter_program_type,
    linux_xdp_program_type,
    PTYPE("cgroup_device", &g_cgroup_dev_descr, BPF_PROG_TYPE_CGROUP_DEVICE, {"cgroup/dev"}),
    PTYPE("cgroup_skb", &g_socket_filter_descr, BPF_PROG_TYPE_CGROUP_SKB, {"cgroup/skb"}),
    PTYPE("cgroup_sock", &g_cgroup_sock_descr, BPF_PROG_TYPE_CGROUP_SOCK, {"cgroup/sock"}),
    PTYPE_PRIVILEGED("kprobe", &g_kprobe_descr, BPF_PROG_TYPE_KPROBE, {"kprobe/" COMMA "kretprobe/"}),
    PTYPE("lwt_in", &g_lwt_inout_descr, BPF_PROG_TYPE_LWT_IN, {"lwt_in"}),
    PTYPE("lwt_out", &g_lwt_inout_descr, BPF_PROG_TYPE_LWT_OUT, {"lwt_out"}),
    PTYPE("lwt_xmit", &g_lwt_xmit_descr, BPF_PROG_TYPE_LWT_XMIT, {"lwt_xmit"}),
    PTYPE("perf_event", &g_perf_event_descr, BPF_PROG_TYPE_PERF_EVENT, {"perf_section" COMMA "perf_event"}),
    PTYPE("sched_act", &g_sched_descr, BPF_PROG_TYPE_SCHED_ACT, {"action"}),
    PTYPE("sched_cls", &g_sched_descr, BPF_PROG_TYPE_SCHED_CLS, {"classifier"}),
    PTYPE("sk_skb", &g_sk_skb_descr, BPF_PROG_TYPE_SK_SKB, {"sk_skb"}),
    PTYPE("sock_ops", &g_sock_ops_descr, BPF_PROG_TYPE_SOCK_OPS, {"sockops"}),
    PTYPE("tracepoint", &g_tracepoint_descr, BPF_PROG_TYPE_TRACEPOINT, {"tracepoint/"}),
    PTYPE("cgroup_sockopt", &g_sockopt_descr, BPF_PROG_TYPE_CGROUP_SOCKOPT,
          {"cgroup/getsockopt" COMMA "cgroup/setsockopt"}),
    PTYPE("sk_msg", &g_sk_msg_md, BPF_PROG_TYPE_SK_MSG, {"sk_msg"}),
    PTYPE("raw_tracepoint", &g_tracepoint_descr, BPF_PROG_TYPE_RAW_TRACEPOINT, {"raw_tracepoint/" COMMA "raw_tp/"}),
    PTYPE("raw_tracepoint_writable", &g_tracepoint_descr, BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
          {"raw_tracepoint.w/" COMMA "raw_tp.w/"}),
    PTYPE("cgroup_sock_addr", &g_sock_addr_descr, BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
          {"cgroup/bind" COMMA "cgroup/post_bind" COMMA "cgroup/connect" COMMA "cgroup/sendmsg" COMMA
           "cgroup/recvmsg" COMMA "cgroup/getpeername" COMMA "cgroup/getsockname"}),
    PTYPE("lwt_seg6local", &g_lwt_xmit_descr, BPF_PROG_TYPE_LWT_SEG6LOCAL, {"lwt_seg6local"}),
    PTYPE("lirc_mode2", &g_unspec_descr, BPF_PROG_TYPE_LIRC_MODE2, {"lirc_mode2"}),
    PTYPE("sk_reuseport", &g_sk_reuseport_descr, BPF_PROG_TYPE_SK_REUSEPORT, {"sk_reuseport/"}),
    PTYPE("flow_dissector", &g_flow_dissector_descr, BPF_PROG_TYPE_FLOW_DISSECTOR, {"flow_dissector"}),
    PTYPE("cgroup_sysctl", &g_cgroup_sysctl_descr, BPF_PROG_TYPE_CGROUP_SYSCTL, {"cgroup/sysctl"}),
    PTYPE("ext", &g_unspec_descr, BPF_PROG_TYPE_EXT, {"freplace/"}),
    PTYPE("tracing", &g_unspec_descr, BPF_PROG_TYPE_TRACING,
          {"fentry/" COMMA "fexit/" COMMA "fmod_ret/" COMMA "iter/" COMMA "lsm.s/" COMMA "tp_btf/"}),
    PTYPE("struct_ops", &g_unspec_descr, BPF_PROG_TYPE_STRUCT_OPS, {"struct_ops/"}),
    PTYPE("lsm", &g_unspec_descr, BPF_PROG_TYPE_LSM, {"lsm/"}),
    PTYPE("sk_lookup", &g_sk_lookup_descr, BPF_PROG_TYPE_SK_LOOKUP, {"sk_lookup/"}),
    PTYPE("syscall", &g_unspec_descr, BPF_PROG_TYPE_SYSCALL, {"syscall/"}),
    PTYPE("netfilter", &g_unspec_descr, BPF_PROG_TYPE_NETFILTER, {"netfilter/"}),
};

static EbpfProgramType get_program_type_linux(const std::string& section, const std::string& path) {
    EbpfProgramType type{};

    // linux only deduces from section, but cilium and cilium_test have this information
    // in the filename:
    // * cilium/bpf_xdp.o:from-netdev is XDP
    // * bpf_cilium_test/bpf_lb-DLB_L3.o:from-netdev is SK_SKB
    if (path.find("cilium") != std::string::npos) {
        if (path.find("xdp") != std::string::npos) {
            return linux_xdp_program_type;
        }
        if (path.find("lxc") != std::string::npos) {
            return cilium_lxc_program_type;
        }
    }

    for (const EbpfProgramType& t : linux_program_types) {
        for (const std::string& prefix : t.section_prefixes) {
            if (section.find(prefix) == 0) {
                return t;
            }
        }
    }

    return linux_socket_filter_program_type;
}

#ifdef __linux__
#define BPF_MAP_TYPE(x) BPF_MAP_TYPE_##x, #x
#else
#define BPF_MAP_TYPE(x) 0, #x
#endif

static const EbpfMapType linux_map_types[] = {
    {BPF_MAP_TYPE(UNSPEC)},
    {BPF_MAP_TYPE(HASH)},
    {BPF_MAP_TYPE(ARRAY), true},
    {BPF_MAP_TYPE(PROG_ARRAY), true, EbpfMapValueType::PROGRAM},
    {BPF_MAP_TYPE(PERF_EVENT_ARRAY), true},
    {BPF_MAP_TYPE(PERCPU_HASH)},
    {BPF_MAP_TYPE(PERCPU_ARRAY), true},
    {BPF_MAP_TYPE(STACK_TRACE)},
    {BPF_MAP_TYPE(CGROUP_ARRAY), true},
    {BPF_MAP_TYPE(LRU_HASH)},
    {BPF_MAP_TYPE(LRU_PERCPU_HASH)},
    {BPF_MAP_TYPE(LPM_TRIE)},
    {BPF_MAP_TYPE(ARRAY_OF_MAPS), true, EbpfMapValueType::MAP},
    {BPF_MAP_TYPE(HASH_OF_MAPS), false, EbpfMapValueType::MAP},
    {BPF_MAP_TYPE(DEVMAP)},
    {BPF_MAP_TYPE(SOCKMAP)},
    {BPF_MAP_TYPE(CPUMAP)},
    {BPF_MAP_TYPE(XSKMAP)},
    {BPF_MAP_TYPE(SOCKHASH)},
    {BPF_MAP_TYPE(CGROUP_STORAGE)},
    {BPF_MAP_TYPE(REUSEPORT_SOCKARRAY)},
    {BPF_MAP_TYPE(PERCPU_CGROUP_STORAGE)},
    {BPF_MAP_TYPE(QUEUE)},
    {BPF_MAP_TYPE(STACK)},
    {BPF_MAP_TYPE(SK_STORAGE)},
    {BPF_MAP_TYPE(DEVMAP_HASH)},
    {BPF_MAP_TYPE(STRUCT_OPS)},
    {BPF_MAP_TYPE(RINGBUF)},
    {BPF_MAP_TYPE(INODE_STORAGE)},
    {BPF_MAP_TYPE(TASK_STORAGE)},
    {BPF_MAP_TYPE(BLOOM_FILTER)},
    {BPF_MAP_TYPE(USER_RINGBUF)},
    {BPF_MAP_TYPE(CGRP_STORAGE)},
    {BPF_MAP_TYPE(ARENA)},
};

EbpfMapType get_map_type_linux(uint32_t platform_specific_type) {
    const uint32_t index = platform_specific_type;
    if (index == 0 || index >= std::size(linux_map_types)) {
        return linux_map_types[0];
    }
    EbpfMapType type = linux_map_types[index];
#ifdef __linux__
    assert(type.platform_specific_type == platform_specific_type);
#else
    type.platform_specific_type = platform_specific_type;
#endif
    return type;
}

void parse_maps_section_linux(std::vector<EbpfMapDescriptor>& map_descriptors, const char* data,
                              const size_t map_def_size, const int map_count, const ebpf_platform_t* platform,
                              const ebpf_verifier_options_t options) {
    // Copy map definitions from the ELF section into a local list.
    auto mapdefs = std::vector<BpfLoadMapDef>();
    for (int i = 0; i < map_count; i++) {
        BpfLoadMapDef def = {0};
        memcpy(&def, data + i * map_def_size, std::min(map_def_size, sizeof(def)));
        mapdefs.emplace_back(def);
    }

    // Add map definitions into the map_descriptors list.
    for (const auto& s : mapdefs) {
        EbpfMapType type = get_map_type_linux(s.type);
        map_descriptors.emplace_back(EbpfMapDescriptor{
            .original_fd = create_map_linux(s.type, s.key_size, s.value_size, s.max_entries, options),
            .type = s.type,
            .key_size = s.key_size,
            .value_size = s.value_size,
            .max_entries = s.max_entries,
            .inner_map_fd = gsl::narrow<int32_t>(s.inner_map_idx) // Temporarily fill in the index. This will be
                                                                  // replaced in the resolve_inner_map_references pass.
        });
    }
}

// Initialize the inner_map_fd in each map descriptor.
void resolve_inner_map_references_linux(std::vector<EbpfMapDescriptor>& map_descriptors) {
    for (size_t i = 0; i < map_descriptors.size(); i++) {
        const int inner = map_descriptors[i].inner_map_fd; // Get the inner_map_idx back.
        if (inner < 0 || inner >= gsl::narrow<int>(map_descriptors.size())) {
            throw UnmarshalError("bad inner map index " + std::to_string(inner) + " for map " + std::to_string(i));
        }
        map_descriptors[i].inner_map_fd = map_descriptors.at(inner).original_fd;
    }
}

#if __linux__
static int do_bpf(const bpf_cmd cmd, bpf_attr& attr) { return syscall(321, cmd, &attr, sizeof(attr)); }
#endif

/** Try to allocate a Linux map.
 *
 *  This function requires admin privileges.
 */
static int create_map_linux(const uint32_t map_type, const uint32_t key_size, const uint32_t value_size,
                            const uint32_t max_entries, const ebpf_verifier_options_t options) {
    if (options.mock_map_fds) {
        const EbpfMapType type = get_map_type_linux(map_type);
        return create_map_crab(type, key_size, value_size, max_entries, options);
    }

#if __linux__
    bpf_attr attr{};
    memset(&attr, '\0', sizeof(attr));
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = 20;
    attr.map_flags = map_type == BPF_MAP_TYPE_HASH ? BPF_F_NO_PREALLOC : 0;
    const int map_fd = do_bpf(BPF_MAP_CREATE, attr);
    if (map_fd < 0) {
        std::cerr << "Failed to create map, " << strerror(errno) << "\n";
        std::cerr << "Map: \n"
                  << " map_type = " << attr.map_type << "\n"
                  << " key_size = " << attr.key_size << "\n"
                  << " value_size = " << attr.value_size << "\n"
                  << " max_entries = " << attr.max_entries << "\n"
                  << " map_flags = " << attr.map_flags << "\n";
        exit(2);
    }
    return map_fd;
#else
    throw std::runtime_error(std::string("cannot create a Linux map"));
#endif
}

EbpfMapDescriptor& get_map_descriptor_linux(const int map_fd) {
    // First check if we already have the map descriptor cached.
    EbpfMapDescriptor* map = find_map_descriptor(map_fd);
    if (map != nullptr) {
        return *map;
    }

    // This fd was not created from the maps section of an ELF file,
    // but it may be an fd created by an app before calling the verifier.
    // In this case, we would like to query the map descriptor info
    // (key size, value size) from the execution context, but this is
    // not yet supported on Linux.

    throw UnmarshalError("map_fd " + std::to_string(map_fd) + " not found");
}

const ebpf_platform_t g_ebpf_platform_linux = {
    get_program_type_linux,
    get_helper_prototype_linux,
    is_helper_usable_linux,
    sizeof(BpfLoadMapDef),
    parse_maps_section_linux,
    get_map_descriptor_linux,
    get_map_type_linux,
    resolve_inner_map_references_linux,
    bpf_conformance_groups_t::default_groups | bpf_conformance_groups_t::packet,
};
} // namespace prevail

#include "linux/gpl/spec_type_descriptors.hpp"
#include "linux/linux_platform.hpp"
#include "platform.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <stdexcept>
#include <string_view>

namespace prevail {

// Map-type bitmask constants for EbpfHelperPrototype::allowed_map_types.
// Values match the BPF_MAP_TYPE_* enum in the kernel UAPI.
namespace {
constexpr uint64_t MT_HASH = map_type_bit(1);
constexpr uint64_t MT_ARRAY = map_type_bit(2);
constexpr uint64_t MT_PERF_EVENT_ARRAY = map_type_bit(4);
constexpr uint64_t MT_STACK_TRACE = map_type_bit(7);
constexpr uint64_t MT_CGROUP_ARRAY = map_type_bit(8);
constexpr uint64_t MT_LRU_HASH = map_type_bit(9);
constexpr uint64_t MT_LPM_TRIE = map_type_bit(11);
constexpr uint64_t MT_ARRAY_OF_MAPS = map_type_bit(12);
constexpr uint64_t MT_HASH_OF_MAPS = map_type_bit(13);
constexpr uint64_t MT_DEVMAP = map_type_bit(14);
constexpr uint64_t MT_SOCKMAP = map_type_bit(15);
constexpr uint64_t MT_CPUMAP = map_type_bit(16);
constexpr uint64_t MT_XSKMAP = map_type_bit(17);
constexpr uint64_t MT_SOCKHASH = map_type_bit(18);
constexpr uint64_t MT_CGROUP_STORAGE = map_type_bit(19);
constexpr uint64_t MT_REUSEPORT_SOCKARRAY = map_type_bit(20);
constexpr uint64_t MT_PERCPU_CGROUP_STORAGE = map_type_bit(21);
constexpr uint64_t MT_QUEUE = map_type_bit(22);
constexpr uint64_t MT_STACK = map_type_bit(23);
constexpr uint64_t MT_SK_STORAGE = map_type_bit(24);
constexpr uint64_t MT_DEVMAP_HASH = map_type_bit(25);
constexpr uint64_t MT_RINGBUF = map_type_bit(27);
constexpr uint64_t MT_INODE_STORAGE = map_type_bit(28);
constexpr uint64_t MT_TASK_STORAGE = map_type_bit(29);
constexpr uint64_t MT_BLOOM_FILTER = map_type_bit(30);
constexpr uint64_t MT_USER_RINGBUF = map_type_bit(31);
constexpr uint64_t MT_CGRP_STORAGE = map_type_bit(32);
constexpr uint64_t MT_PERCPU_ARRAY = map_type_bit(6);
constexpr uint64_t MT_PERCPU_HASH = map_type_bit(5);
constexpr uint64_t MT_LRU_PERCPU_HASH = map_type_bit(10);
// Map types whose elements are plain value_size-byte buffers, which is what the generic map
// helpers (lookup/update/delete) model. Every other map type either returns something else
// from a lookup (a socket, an inner map, an ERR_PTR) or has dedicated helpers.
constexpr uint64_t MT_GENERIC =
    MT_HASH | MT_ARRAY | MT_PERCPU_HASH | MT_PERCPU_ARRAY | MT_LRU_HASH | MT_LRU_PERCPU_HASH | MT_LPM_TRIE;
} // namespace

// Most ABI return/argument type constants used below are first-class enum
// members in spec/ebpf_base.h. Keep only compatibility aliases used by this
// static prototype table.

// Treat non-nullable map value return as nullable for compatibility.
#define EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL

// Allow NULL map value pointers (optional map value argument compatibility).
#define EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE_OR_NULL EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE

const ebpf_ctx_descriptor_t g_sk_buff = sk_buff;
const ebpf_ctx_descriptor_t g_sk_buff_no_meta = sk_buff_no_meta;
const ebpf_ctx_descriptor_t g_xdp_md = xdp_md;
const ebpf_ctx_descriptor_t g_sk_msg_md = sk_msg_md;
const ebpf_ctx_descriptor_t g_unspec_descr = unspec_descr;
const ebpf_ctx_descriptor_t g_tracing_descr = tracing_descr;
const ebpf_ctx_descriptor_t g_lirc_mode2_descr = lirc_mode2_descr;
const ebpf_ctx_descriptor_t g_netfilter_descr = netfilter_descr;
const ebpf_ctx_descriptor_t g_syscall_descr = syscall_descr;
const ebpf_ctx_descriptor_t g_cgroup_dev_descr = cgroup_dev_descr;
const ebpf_ctx_descriptor_t g_kprobe_descr = kprobe_descr;
const ebpf_ctx_descriptor_t g_tracepoint_descr = tracepoint_descr;
const ebpf_ctx_descriptor_t g_perf_event_descr = perf_event_descr;
const ebpf_ctx_descriptor_t g_cgroup_sock_descr = cgroup_sock_descr;
const ebpf_ctx_descriptor_t g_sock_ops_descr = sock_ops_descr;
const ebpf_ctx_descriptor_t g_sock_addr_descr = sock_addr_descr;
const ebpf_ctx_descriptor_t g_sockopt_descr = sockopt_descr;
const ebpf_ctx_descriptor_t g_sk_lookup_descr = sk_lookup_descr;
const ebpf_ctx_descriptor_t g_sk_reuseport_descr = sk_reuseport_descr;
const ebpf_ctx_descriptor_t g_cgroup_sysctl_descr = cgroup_sysctl_descr;
const ebpf_ctx_descriptor_t g_flow_dissector_descr = flow_dissector_descr;

// eBPF helpers are documented at the following links:
// https://github.com/iovisor/bpf-docs/blob/master/bpf_helpers.rst
// https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html

static constexpr EbpfHelperPrototype bpf_unspec_proto = {
    .name = "unspec",
    .return_type = EBPF_RETURN_TYPE_UNSUPPORTED,
};

// Not a function at run time (RET_VOID in the kernel): a failed tail call falls through without setting r0.
constexpr EbpfHelperPrototype bpf_tail_call_proto = {
    .name = "tail_call",
    .return_type = EBPF_RETURN_TYPE_VOID_OR_NO_RETURN_IF_SUCCEED,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    // The target of a successful tail call from a subprogram runs before control returns to the
    // subprogram's caller and may reallocate the packet; like Linux, treat the call as doing so.
    .reallocate_packet = true,
};

static constexpr EbpfHelperPrototype bpf_override_return_proto = {
    .name = "override_return",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_kprobe_descr,
};

static constexpr EbpfHelperPrototype bpf_probe_read_proto = {
    .name = "probe_read",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_probe_read_str_proto = {
    .name = "probe_read_str",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_probe_write_user_proto = {
    .name = "probe_write_user",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_trace_printk_proto = {
    .name = "trace_printk",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_perf_event_read_proto = {
    .name = "perf_event_read",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .allowed_map_types = MT_PERF_EVENT_ARRAY,
};

static constexpr EbpfHelperPrototype bpf_perf_event_read_value_proto = {
    .name = "perf_event_read_value",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .allowed_map_types = MT_PERF_EVENT_ARRAY,
};

static constexpr EbpfHelperPrototype bpf_perf_event_output_proto = {
    .name = "perf_event_output",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
    .allowed_map_types = MT_PERF_EVENT_ARRAY,
};

static constexpr EbpfHelperPrototype bpf_get_current_task_proto = {
    .name = "get_current_task",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static constexpr EbpfHelperPrototype bpf_current_task_under_cgroup_proto = {
    .name = "current_task_under_cgroup",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .allowed_map_types = MT_CGROUP_ARRAY,
};

static constexpr EbpfHelperPrototype bpf_perf_prog_read_value_proto = {
    .name = "perf_prog_read_value",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .ctx_descriptor = &g_perf_event_descr,
};

static constexpr EbpfHelperPrototype bpf_map_lookup_elem_proto = {
    .name = "map_lookup_elem",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
            EBPF_ARGUMENT_TYPE_DONTCARE,
            EBPF_ARGUMENT_TYPE_DONTCARE,
            EBPF_ARGUMENT_TYPE_DONTCARE,
        },
    // The kernel also allows SOCKMAP, SOCKHASH and XSKMAP (the lookup returns a socket) and
    // DEVMAP and DEVMAP_HASH (a read-only value); neither is the writable value_size-byte
    // buffer that the transformer models as the result of a lookup on a non-map-of-maps map.
    .allowed_map_types = MT_GENERIC | MT_ARRAY_OF_MAPS | MT_HASH_OF_MAPS,
};

static constexpr EbpfHelperPrototype bpf_map_update_elem_proto = {
    .name = "map_update_elem",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_DONTCARE,
        },
    // The kernel also allows SOCKMAP and SOCKHASH, where the value argument must be a socket.
    .allowed_map_types = MT_GENERIC,
    .modifies_map = true,
};

static constexpr EbpfHelperPrototype bpf_map_delete_elem_proto = {
    .name = "map_delete_elem",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
            EBPF_ARGUMENT_TYPE_DONTCARE,
            EBPF_ARGUMENT_TYPE_DONTCARE,
            EBPF_ARGUMENT_TYPE_DONTCARE,
        },
    // The kernel also allows SOCKMAP and SOCKHASH for some program types.
    .allowed_map_types = MT_GENERIC,
    .modifies_map = true,
};

static constexpr EbpfHelperPrototype bpf_get_prandom_u32_proto = {
    .name = "get_prandom_u32",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static constexpr EbpfHelperPrototype bpf_get_smp_processor_id_proto = {
    .name = "get_smp_processor_id",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static constexpr EbpfHelperPrototype bpf_get_numa_node_id_proto = {
    .name = "get_numa_node_id",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static constexpr EbpfHelperPrototype bpf_ktime_get_ns_proto = {
    .name = "ktime_get_ns",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static constexpr EbpfHelperPrototype bpf_get_current_pid_tgid_proto = {
    .name = "get_current_pid_tgid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static constexpr EbpfHelperPrototype bpf_get_current_uid_gid_proto = {
    .name = "get_current_uid_gid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static constexpr EbpfHelperPrototype bpf_get_current_comm_proto = {
    .name = "get_current_comm",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_get_current_cgroup_id_proto = {
    .name = "get_current_cgroup_id",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static constexpr EbpfHelperPrototype bpf_sock_map_update_proto = {
    .name = "sock_map_update",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_DONTCARE,
        },
    .ctx_descriptor = &g_sock_ops_descr,
    .allowed_map_types = MT_SOCKMAP,
};

static constexpr EbpfHelperPrototype bpf_sock_hash_update_proto = {
    .name = "sock_hash_update",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_DONTCARE,
        },
    .ctx_descriptor = &g_sock_ops_descr,
    .allowed_map_types = MT_SOCKHASH,
};

static constexpr EbpfHelperPrototype bpf_get_stackid_proto = {
    .name = "get_stackid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .allowed_map_types = MT_STACK_TRACE,
};

static constexpr EbpfHelperPrototype bpf_get_stack_proto = {
    .name = "get_stack",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_skb_store_bytes_proto = {
    .name = "skb_store_bytes",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_load_bytes_proto = {
    .name = "skb_load_bytes",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_load_bytes_relative_proto = {
    .name = "skb_load_bytes_relative",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_pull_data_proto = {
    .name = "skb_pull_data",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_l3_csum_replace_proto = {
    .name = "l3_csum_replace",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_l4_csum_replace_proto = {
    .name = "l4_csum_replace",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_csum_diff_proto = {
    .name = "csum_diff",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_csum_update_proto = {
    .name = "csum_update",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_clone_redirect_proto = {
    .name = "clone_redirect",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_redirect_proto = {
    .name = "redirect",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_sk_redirect_hash_proto = {
    .name = "sk_redirect_hash",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_buff,
    .allowed_map_types = MT_SOCKHASH,
};

static constexpr EbpfHelperPrototype bpf_sk_redirect_map_proto = {
    .name = "sk_redirect_map",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_buff,
    .allowed_map_types = MT_SOCKMAP,
};

static constexpr EbpfHelperPrototype bpf_msg_redirect_hash_proto = {
    .name = "msg_redirect_hash",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_msg_md,
    .allowed_map_types = MT_SOCKHASH,
};

static constexpr EbpfHelperPrototype bpf_msg_redirect_map_proto = {
    .name = "msg_redirect_map",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_msg_md,
    .allowed_map_types = MT_SOCKMAP,
};

static constexpr EbpfHelperPrototype bpf_msg_apply_bytes_proto = {
    .name = "msg_apply_bytes",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_msg_md,
};

static constexpr EbpfHelperPrototype bpf_msg_cork_bytes_proto = {
    .name = "msg_cork_bytes",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_msg_md,
};

static constexpr EbpfHelperPrototype bpf_msg_pull_data_proto = {
    .name = "msg_pull_data",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_msg_md,
};
static constexpr EbpfHelperPrototype bpf_get_cgroup_classid_proto = {
    .name = "get_cgroup_classid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_get_route_realm_proto = {
    .name = "get_route_realm",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_get_hash_recalc_proto = {
    .name = "get_hash_recalc",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_set_hash_invalid_proto = {
    .name = "set_hash_invalid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_set_hash_proto = {
    .name = "set_hash",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_vlan_push_proto = {
    .name = "skb_vlan_push",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_vlan_pop_proto = {
    .name = "skb_vlan_pop",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_change_proto_proto = {
    .name = "skb_change_proto",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_change_type_proto = {
    .name = "skb_change_type",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_adjust_room_proto = {
    .name = "skb_adjust_room",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_change_tail_proto = {
    .name = "skb_change_tail",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_change_head_proto = {
    .name = "skb_change_head",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_xdp_adjust_head_proto = {
    .name = "xdp_adjust_head",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_xdp_descr,
};

static constexpr EbpfHelperPrototype bpf_xdp_adjust_tail_proto = {
    .name = "xdp_adjust_tail",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_xdp_descr,
};

static constexpr EbpfHelperPrototype bpf_xdp_adjust_meta_proto = {
    .name = "xdp_adjust_meta",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_xdp_descr,
};

static constexpr EbpfHelperPrototype bpf_skb_get_tunnel_key_proto = {
    .name = "skb_get_tunnel_key",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_get_tunnel_opt_proto = {
    .name = "skb_get_tunnel_opt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_set_tunnel_key_proto = {
    .name = "skb_set_tunnel_key",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_buff,
};

/*
 * int bpf_skb_set_tunnel_opt(skb, opt, size)
 *     populate tunnel options metadata
 *     @skb: pointer to skb
 *     @opt: pointer to raw tunnel option data
 *     @size: size of @opt
 *     Return: 0 on success or negative error
 */
static constexpr EbpfHelperPrototype bpf_skb_set_tunnel_opt_proto = {
    .name = "skb_set_tunnel_opt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_under_cgroup_proto = {
    .name = "skb_under_cgroup",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_buff,
    .allowed_map_types = MT_CGROUP_ARRAY,
};

static constexpr EbpfHelperPrototype bpf_skb_cgroup_id_proto = {
    .name = "skb_cgroup_id",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_get_socket_cookie_proto = {
    .name = "get_socket_cookie",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = nullptr,
};

static constexpr EbpfHelperPrototype bpf_get_socket_uid_proto = {
    .name = "get_socket_uid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_setsockopt_proto = {
    .name = "setsockopt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_getsockopt_proto = {
    .name = "getsockopt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_sock_ops_cb_flags_set_proto = {
    .name = "sock_ops_cb_flags_set",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sock_ops_descr,
};

static constexpr EbpfHelperPrototype bpf_bind_proto = {
    .name = "bind",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .ctx_descriptor = &g_sock_addr_descr,
};

static constexpr EbpfHelperPrototype bpf_skb_get_xfrm_state_proto = {
    .name = "skb_get_xfrm_state",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_fib_lookup_proto = {
    .name = "fib_lookup",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READWRITE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_lwt_push_encap_proto = {
    .name = "lwt_push_encap",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_lwt_seg6_store_bytes_proto = {
    .name = "lwt_seg6_store_bytes",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_lwt_seg6_action_proto = {
    .name = "lwt_seg6_action",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_lwt_seg6_adjust_srh_proto = {
    .name = "lwt_seg6_adjust_srh",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_rc_repeat_proto = {
    .name = "rc_repeat",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = &g_lirc_mode2_descr,
};

static constexpr EbpfHelperPrototype bpf_rc_keydown_proto = {
    .name = "rc_keydown",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_lirc_mode2_descr,
};

static constexpr EbpfHelperPrototype bpf_get_local_storage_proto = {
    .name = "get_local_storage",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .zero_args_mask = 1 << 1,
    .allowed_map_types = MT_CGROUP_STORAGE | MT_PERCPU_CGROUP_STORAGE,
};

static constexpr EbpfHelperPrototype bpf_redirect_map_proto = {
    .name = "redirect_map",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .allowed_map_types = MT_DEVMAP | MT_DEVMAP_HASH | MT_CPUMAP | MT_XSKMAP,
};

static constexpr EbpfHelperPrototype bpf_sk_select_reuseport_proto = {
    .name = "sk_select_reuseport",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .ctx_descriptor = &g_sk_reuseport_descr,
    .allowed_map_types = MT_REUSEPORT_SOCKARRAY | MT_SOCKMAP | MT_SOCKHASH,
};

static constexpr EbpfHelperPrototype bpf_get_current_ancestor_cgroup_id_proto = {
    .name = "get_current_ancestor_cgroup_id",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

static constexpr EbpfHelperPrototype bpf_sk_lookup_tcp_proto = {
    .name = "sk_lookup_tcp",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_SOCK_COMMON_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};
static constexpr EbpfHelperPrototype bpf_sk_lookup_udp_proto = {
    .name = "sk_lookup_udp",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_SOCKET_OR_NULL,
    .argument_type{
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

static constexpr EbpfHelperPrototype bpf_sk_release_proto = {
    .name = "sk_release",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
        },
};

static constexpr EbpfHelperPrototype bpf_map_push_elem_proto = {
    .name = "map_push_elem",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .allowed_map_types = MT_QUEUE | MT_STACK | MT_BLOOM_FILTER,
    .modifies_map = true,
};

static constexpr EbpfHelperPrototype bpf_map_pop_elem_proto = {
    .name = "map_pop_elem",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MAP_VALUE,
    },
    .allowed_map_types = MT_QUEUE | MT_STACK,
    .modifies_map = true,
};

static constexpr EbpfHelperPrototype bpf_map_peek_elem_proto = {
    .name = "map_peek_elem",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_CONST_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MAP_VALUE,
    },
    .allowed_map_types = MT_QUEUE | MT_STACK | MT_BLOOM_FILTER,
};

static constexpr EbpfHelperPrototype bpf_msg_push_data_proto = {
    .name = "msg_push_data",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_msg_md,
};

static constexpr EbpfHelperPrototype bpf_msg_pop_data_proto = {
    .name = "msg_pop_data",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sk_msg_md,
};

static constexpr EbpfHelperPrototype bpf_rc_pointer_rel_proto = {
    .name = "rc_pointer_rel",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .ctx_descriptor = &g_lirc_mode2_descr,
};

static constexpr EbpfHelperPrototype bpf_spin_lock_proto = {
    .name = "spin_lock",
    .return_type = EBPF_RETURN_TYPE_INTEGER, // returns 0
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_SPIN_LOCK,
        },
};

static constexpr EbpfHelperPrototype bpf_spin_unlock_proto = {
    .name = "spin_unlock",
    .return_type = EBPF_RETURN_TYPE_INTEGER, // returns 0
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_SPIN_LOCK,
        },
};

static constexpr EbpfHelperPrototype bpf_jiffies64_proto = {
    .name = "jiffies64",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static constexpr EbpfHelperPrototype bpf_sk_fullsock_proto = {
    .name = "sk_fullsock",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_SOCKET_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_SOCK_COMMON,
        },
};

static constexpr EbpfHelperPrototype bpf_tcp_sock_proto = {
    .name = "tcp_sock",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_TCP_SOCKET_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_SOCK_COMMON,
        },
};

static constexpr EbpfHelperPrototype bpf_skb_ecn_set_ce_proto = {
    .name = "skb_ecn_set_ce",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_tcp_check_syncookie_proto = {
    .name = "tcp_check_syncookie",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_get_listener_sock_proto = {
    .name = "get_listener_sock",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_TCP_SOCKET_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_SOCK_COMMON,
        },
};

static constexpr EbpfHelperPrototype bpf_skc_lookup_tcp_proto = {
    .name = "skc_lookup_tcp",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_SOCK_COMMON_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_sysctl_get_name_proto = {
    .name = "sysctl_get_name",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READWRITE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_cgroup_sysctl_descr,
};

static constexpr EbpfHelperPrototype bpf_sysctl_get_current_value_proto = {
    .name = "sysctl_get_current_value",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .ctx_descriptor = &g_cgroup_sysctl_descr,
};

static constexpr EbpfHelperPrototype bpf_sysctl_get_new_value_proto = {
    .name = "sysctl_get_new_value",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .ctx_descriptor = &g_cgroup_sysctl_descr,
};

static constexpr EbpfHelperPrototype bpf_sysctl_set_new_value_proto = {
    .name = "sysctl_set_new_value",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .ctx_descriptor = &g_cgroup_sysctl_descr,
};

static constexpr EbpfHelperPrototype bpf_strtol_proto = {
    .name = "strtol",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_LONG,
        },
};

static constexpr EbpfHelperPrototype bpf_strtoul_proto = {
    .name = "strtoul",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_LONG,
        },
};

static constexpr EbpfHelperPrototype bpf_strncmp_proto = {
    .name = "strncmp",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_PTR_TO_CONST_STR,
        },
};

static constexpr EbpfHelperPrototype bpf_sk_storage_get_proto = {
    .name = "sk_storage_get",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .allowed_map_types = MT_SK_STORAGE,
};

static constexpr EbpfHelperPrototype bpf_sk_storage_delete_proto = {
    .name = "sk_storage_delete",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
        },
    .allowed_map_types = MT_SK_STORAGE,
};

static constexpr EbpfHelperPrototype bpf_send_signal_proto = {
    .name = "send_signal",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_send_signal_thread_proto = {
    .name = "send_signal_thread",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_tcp_gen_syncookie_proto = {
    .name = "tcp_gen_syncookie",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_skb_output_proto = {
    .name = "skb_event_output",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP, // originally const
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
    //.arg1_btf_id = &bpf_skb_output_btf_ids[0],
    .allowed_map_types = MT_PERF_EVENT_ARRAY,
};

static constexpr EbpfHelperPrototype bpf_probe_read_user_proto = {
    .name = "probe_read_user",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_probe_read_user_str_proto = {
    .name = "probe_read_user_str",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_probe_read_kernel_proto = {
    .name = "probe_read_kernel",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_probe_read_kernel_str_proto = {
    .name = "probe_read_kernel_str",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_tcp_send_ack_proto = {
    .name = "tcp_send_ack",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    //.arg1_btf_id = &tcp_sock_id[0],
};

static constexpr EbpfHelperPrototype bpf_read_branch_records_proto = {
    .name = "read_branch_records",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READWRITE_MEM_OR_NULL,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_perf_event_descr,
};

static constexpr EbpfHelperPrototype bpf_get_ns_current_pid_tgid_proto = {
    .name = "get_ns_current_pid_tgid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL, // TODO: or null
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_xdp_output_proto = {
    .name = "xdp_event_output",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
    // .arg1_btf_id = &bpf_xdp_output_btf_ids[0],
    .allowed_map_types = MT_PERF_EVENT_ARRAY,
};

static constexpr EbpfHelperPrototype bpf_sk_assign_proto = {
    .name = "sk_assign",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_ktime_get_boot_ns_proto = {
    .name = "ktime_get_boot_ns",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static constexpr EbpfHelperPrototype bpf_seq_printf_proto = {
    .name = "seq_printf",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
    // .arg1_btf_id = &btf_seq_file_ids[0],
};

static constexpr EbpfHelperPrototype bpf_seq_write_proto = {
    .name = "seq_write",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
};

static constexpr EbpfHelperPrototype bpf_sk_cgroup_id_proto = {
    .name = "sk_cgroup_id",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
        },
};

static constexpr EbpfHelperPrototype bpf_sk_ancestor_cgroup_id_proto = {
    .name = "sk_ancestor_cgroup_id",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_ringbuf_reserve_proto = {
    .name = "ringbuf_reserve",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_ALLOC_MEM_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_CONST_ALLOC_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .allowed_map_types = MT_RINGBUF,
};

static constexpr EbpfHelperPrototype bpf_ringbuf_submit_proto = {
    .name = "ringbuf_submit",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_ALLOC_MEM,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_ringbuf_discard_proto = {
    .name = "ringbuf_discard",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_ALLOC_MEM,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_ringbuf_output_proto = {
    .name = "ringbuf_output",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .allowed_map_types = MT_RINGBUF,
};

constexpr EbpfHelperPrototype bpf_ringbuf_query_proto = {
    .name = "ringbuf_query",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_CONST_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .allowed_map_types = MT_RINGBUF,
};

static constexpr EbpfHelperPrototype bpf_csum_level_proto = {
    .name = "csum_level",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skc_to_tcp6_sock_proto = {
    .name = "skc_to_tcp6_sock",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
        },
    //.ret_btf_id  = &btf_sock_ids[BTF_SOCK_TYPE_TCP6],
};

static constexpr EbpfHelperPrototype bpf_skc_to_tcp_sock_proto = {
    .name = "skc_to_tcp_sock",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
        },
    //.ret_btf_id  = &btf_sock_ids[BTF_SOCK_TYPE_TCP],
};

static constexpr EbpfHelperPrototype bpf_skc_to_tcp_timewait_sock_proto = {
    .name = "skc_to_tcp_timewait_sock",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
        },
    //.ret_btf_id  = &btf_sock_ids[BTF_SOCK_TYPE_TCP_TW],
};

static constexpr EbpfHelperPrototype bpf_skc_to_tcp_request_sock_proto = {
    .name = "skc_to_tcp_request_sock",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
        },
    //.ret_btf_id  = &btf_sock_ids[BTF_SOCK_TYPE_TCP_REQ],
};

static constexpr EbpfHelperPrototype bpf_skc_to_udp6_sock_proto = {
    .name = "skc_to_udp6_sock",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
        },
    //.ret_btf_id  = &btf_sock_ids[BTF_SOCK_TYPE_UDP6],
};

static constexpr EbpfHelperPrototype bpf_sock_from_file_proto = {
    .name = "sock_from_file",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
        },
    //.ret_btf_id = &bpf_sock_from_file_btf_ids[0],
    //.arg1_btf_id = &bpf_sock_from_file_btf_ids[1],
};

static constexpr EbpfHelperPrototype bpf_get_task_stack_proto = {
    .name = "get_task_stack",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    // .arg1_btf_id = &bpf_get_task_stack_btf_ids[0],
};

static constexpr EbpfHelperPrototype bpf_inode_storage_get_proto = {
    .name = "inode_storage_get",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    //.arg2_btf_id = &bpf_inode_storage_btf_ids[0],
    .allowed_map_types = MT_INODE_STORAGE,
};

static constexpr EbpfHelperPrototype bpf_inode_storage_delete_proto = {
    .name = "inode_storage_delete",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
        },
    //.arg2_btf_id = &bpf_inode_storage_btf_ids[0],
    .allowed_map_types = MT_INODE_STORAGE,
};

static constexpr EbpfHelperPrototype bpf_d_path_proto = {
    .name = "d_path",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_READWRITE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
    // .allowed = bpf_d_path_allowed,
    // .arg1_btf_id = &bpf_d_path_btf_ids[0],
    .might_sleep = true,
};

static constexpr EbpfHelperPrototype bpf_copy_from_user_proto = {
    .name = "copy_from_user",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .might_sleep = true,
};

static constexpr EbpfHelperPrototype bpf_per_cpu_ptr_proto = {
    .name = "per_cpu_ptr",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MEM_OR_BTF_ID_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_PERCPU_BTF_ID,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_this_cpu_ptr_proto = {
    .name = "this_cpu_ptr",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MEM_OR_BTF_ID,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_PERCPU_BTF_ID,
        },
};

static constexpr EbpfHelperPrototype bpf_snprintf_btf_proto = {
    .name = "snprintf_btf",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READWRITE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_seq_printf_btf_proto = {
    .name = "seq_printf_btf",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    // .arg1_btf_id	= &btf_seq_file_ids[0],
};

static constexpr EbpfHelperPrototype bpf_skb_cgroup_classid_proto = {
    .name = "skb_cgroup_classid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_redirect_neigh_proto = {
    .name = "redirect_neigh",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_redirect_peer_proto = {
    .name = "redirect_peer",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_task_storage_get_proto = {
    .name = "task_storage_get",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    // .arg2_btf_id = &bpf_task_storage_btf_ids[0],
    .allowed_map_types = MT_TASK_STORAGE,
};

static constexpr EbpfHelperPrototype bpf_task_storage_delete_proto = {
    .name = "task_storage_delete",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
        },
    // .arg2_btf_id = &bpf_task_storage_btf_ids[0],
    .allowed_map_types = MT_TASK_STORAGE,
};

static constexpr EbpfHelperPrototype bpf_get_current_task_btf_proto = {
    .name = "get_current_task_btf",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID,
    // .ret_btf_id = &bpf_get_current_btf_ids[0],
};

static constexpr EbpfHelperPrototype bpf_bprm_opts_set_proto = {
    .name = "bprm_opts_set",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        }
    // .arg1_btf_id	= &bpf_bprm_opts_set_btf_ids[0],
};

static constexpr EbpfHelperPrototype bpf_ima_inode_hash_proto = {
    .name = "ima_inode_hash",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    //    .allowed	= bpf_ima_inode_hash_allowed,
    //    .arg1_btf_id	= &bpf_ima_inode_hash_btf_ids[0],
    .might_sleep = true,
};

static constexpr EbpfHelperPrototype bpf_ktime_get_coarse_ns_proto = {
    .name = "ktime_get_coarse_ns",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

// bpf_skb_check_mtu_proto/bpf_xdp_check_mtu_proto
static constexpr EbpfHelperPrototype bpf_check_mtu_proto = {
    .name = "check_mtu",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_INT,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_for_each_map_elem_proto = {
    .name = "for_each_map_elem",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_FUNC,
            EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    // LPM_TRIE does not implement map_for_each_callback.
    .allowed_map_types = MT_GENERIC & ~MT_LPM_TRIE,
};

static constexpr EbpfHelperPrototype bpf_snprintf_proto = {
    .name = "snprintf",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READWRITE_MEM_OR_NULL,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_PTR_TO_CONST_STR,
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM_OR_NULL,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
};

static constexpr EbpfHelperPrototype bpf_sys_bpf_proto = {
    .name = "sys_bpf",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READWRITE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_btf_find_by_name_kind_proto = {
    .name = "btf_find_by_name_kind",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_sys_close_proto = {
    .name = "sys_close",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_kallsyms_lookup_name_proto = {
    .name = "kallsyms_lookup_name",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_LONG,
        },
};

static constexpr EbpfHelperPrototype bpf_timer_init_proto = {
    .name = "timer_init",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_TIMER,
            EBPF_ARGUMENT_TYPE_CONST_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    // Only these map types may hold a bpf_timer in their value.
    .allowed_map_types = MT_HASH | MT_ARRAY | MT_LRU_HASH,
};

static constexpr EbpfHelperPrototype bpf_timer_set_callback_proto = {
    .name = "timer_set_callback",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_TIMER,
            EBPF_ARGUMENT_TYPE_PTR_TO_FUNC,
        },
};

static constexpr EbpfHelperPrototype bpf_timer_start_proto = {
    .name = "timer_start",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_TIMER,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_timer_cancel_proto = {
    .name = "timer_cancel",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_TIMER,
        },
};

// same signature for bpf_get_func_ip_proto_kprobe/bpf_get_func_ip_proto_tracing
static constexpr EbpfHelperPrototype bpf_get_func_ip_proto = {
    .name = "get_func_ip",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
};

static constexpr EbpfHelperPrototype bpf_get_attach_cookie_proto = {
    .name = "get_attach_cookie",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
};

static constexpr EbpfHelperPrototype bpf_task_pt_regs_proto = {
    .name = "task_pt_regs",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
        },
    //    .arg1_btf_id	= &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
    //    .ret_btf_id	= &bpf_task_pt_regs_ids[0],
};

static constexpr EbpfHelperPrototype bpf_get_branch_snapshot_proto = {
    .name = "get_branch_snapshot",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
};

static constexpr EbpfHelperPrototype bpf_get_func_arg_proto = {
    .name = "get_func_arg",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_LONG,
        },
    .ctx_descriptor = &g_tracing_descr,
};

static constexpr EbpfHelperPrototype bpf_get_func_ret_proto = {
    .name = "get_func_ret",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_LONG,
        },
    .ctx_descriptor = &g_tracing_descr,
};

static constexpr EbpfHelperPrototype bpf_get_func_arg_cnt_proto = {
    .name = "get_func_arg_cnt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = &g_tracing_descr,
};

static constexpr EbpfHelperPrototype bpf_trace_vprintk_proto = {
    .name = "trace_vprintk",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM_OR_NULL,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
};

constexpr EbpfHelperPrototype bpf_skc_to_unix_sock_proto = {
    .name = "skc_to_unix_sock",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
        }
    //    .ret_btf_id		= &btf_sock_ids[BTF_SOCK_TYPE_UNIX],
};

constexpr EbpfHelperPrototype bpf_find_vma_proto = {
    .name = "find_vma",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_FUNC,
            EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    // .arg1_btf_id = &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
};

constexpr EbpfHelperPrototype bpf_loop_proto = {
    .name = "loop",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_FUNC,
            EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};
// Map operations
static constexpr EbpfHelperPrototype bpf_map_lookup_percpu_elem_proto = {
    .name = "map_lookup_percpu_elem",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_DONTCARE,
            EBPF_ARGUMENT_TYPE_DONTCARE,
        },
    .allowed_map_types = MT_PERCPU_ARRAY | MT_PERCPU_HASH | MT_LRU_PERCPU_HASH,
};

// Time operations
static constexpr EbpfHelperPrototype bpf_ktime_get_tai_ns_proto = {
    .name = "ktime_get_tai_ns",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

// Dynptr ringbuf operations (UNSUPPORTED - dynptr not implemented)
static constexpr EbpfHelperPrototype bpf_ringbuf_reserve_dynptr_proto = {
    .name = "ringbuf_reserve_dynptr",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_ALLOC_MEM_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .allowed_map_types = MT_RINGBUF,
    .unsupported = true,
};

static constexpr EbpfHelperPrototype bpf_ringbuf_submit_dynptr_proto = {
    .name = "ringbuf_submit_dynptr",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .unsupported = true,
};

// Helper 199 - ringbuf_discard_dynptr
static constexpr EbpfHelperPrototype bpf_ringbuf_discard_dynptr_proto = {
    .name = "ringbuf_discard_dynptr",
    .return_type = EBPF_RETURN_TYPE_INTEGER, // Returns void (always succeeds) = 0
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING, // ptr (dynptr)
            EBPF_ARGUMENT_TYPE_ANYTHING, // flags
        },
    .unsupported = true,
};

// Socket type conversions
static constexpr EbpfHelperPrototype bpf_skc_to_mptcp_sock_proto = {
    .name = "skc_to_mptcp_sock",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
        },
};

// Copy from user task
static constexpr EbpfHelperPrototype bpf_copy_from_user_task_proto = {
    .name = "copy_from_user_task",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .might_sleep = true,
};

// Return value operations
static constexpr EbpfHelperPrototype bpf_set_retval_proto = {
    .name = "set_retval",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_get_retval_proto = {
    .name = "get_retval",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

// User ringbuf (UNSUPPORTED - user ringbuf not implemented)
static constexpr EbpfHelperPrototype bpf_user_ringbuf_drain_proto = {
    .name = "user_ringbuf_drain",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_FUNC,
            EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .allowed_map_types = MT_USER_RINGBUF,
    .unsupported = true,
};

// Cgroup storage
static constexpr EbpfHelperPrototype bpf_cgrp_storage_get_proto = {
    .name = "cgrp_storage_get",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .allowed_map_types = MT_CGRP_STORAGE,
};

static constexpr EbpfHelperPrototype bpf_cgrp_storage_delete_proto = {
    .name = "cgrp_storage_delete",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
        },
    .allowed_map_types = MT_CGRP_STORAGE,
};
// Helper 83 - skb_ancestor_cgroup_id
static constexpr EbpfHelperPrototype bpf_skb_ancestor_cgroup_id_proto = {
    .name = "skb_ancestor_cgroup_id",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING, // ancestor_level
        },
    .ctx_descriptor = &g_sk_buff,
};

// Helper 122 - get_netns_cookie
static constexpr EbpfHelperPrototype bpf_get_netns_cookie_proto = {
    .name = "get_netns_cookie",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX_OR_NULL,
        },
};

// Helper 142 - load_hdr_opt (sock_ops_load_hdr_opt)
static constexpr EbpfHelperPrototype bpf_load_hdr_opt_proto = {
    .name = "load_hdr_opt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READWRITE_MEM, // searchby_res
            EBPF_ARGUMENT_TYPE_CONST_SIZE,           // len
            EBPF_ARGUMENT_TYPE_ANYTHING,             // flags
        },
    .ctx_descriptor = &g_sock_ops_descr,
};

// Helper 143 - store_hdr_opt (sock_ops_store_hdr_opt)
static constexpr EbpfHelperPrototype bpf_store_hdr_opt_proto = {
    .name = "store_hdr_opt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // from
            EBPF_ARGUMENT_TYPE_CONST_SIZE,          // len
            EBPF_ARGUMENT_TYPE_ANYTHING,            // flags
        },
    .reallocate_packet = true,
    .ctx_descriptor = &g_sock_ops_descr,
};

// Helper 144 - reserve_hdr_opt (sock_ops_reserve_hdr_opt)
static constexpr EbpfHelperPrototype bpf_reserve_hdr_opt_proto = {
    .name = "reserve_hdr_opt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING, // len
            EBPF_ARGUMENT_TYPE_ANYTHING, // flags
        },
    .ctx_descriptor = &g_sock_ops_descr,
};

// Helper 188 - xdp_get_buff_len
static constexpr EbpfHelperPrototype bpf_xdp_get_buff_len_proto = {
    .name = "xdp_get_buff_len",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .ctx_descriptor = &g_xdp_md,
};

// Helper 189 - xdp_load_bytes
static constexpr EbpfHelperPrototype bpf_xdp_load_bytes_proto = {
    .name = "xdp_load_bytes",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,            // offset
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM, // buf
            EBPF_ARGUMENT_TYPE_CONST_SIZE,          // len
        },
    .ctx_descriptor = &g_xdp_md,
};

// Helper 190 - xdp_store_bytes
static constexpr EbpfHelperPrototype bpf_xdp_store_bytes_proto = {
    .name = "xdp_store_bytes",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,            // offset
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // buf
            EBPF_ARGUMENT_TYPE_CONST_SIZE,          // len
        },
    .ctx_descriptor = &g_xdp_md,
};

// Helper 192 - skb_set_tstamp
static constexpr EbpfHelperPrototype bpf_skb_set_tstamp_proto = {
    .name = "skb_set_tstamp",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING, // tstamp (u64)
            EBPF_ARGUMENT_TYPE_ANYTHING, // tstamp_type (u32)
        },
    .ctx_descriptor = &g_sk_buff,
};

// Helper 193 - ima_file_hash
static constexpr EbpfHelperPrototype bpf_ima_file_hash_proto = {
    .name = "ima_file_hash",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,       // file
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM, // dst
            EBPF_ARGUMENT_TYPE_CONST_SIZE,          // size
        },
    .might_sleep = true,
};

// Helper 194 - kptr_xchg (UNSUPPORTED - kptr fields and ownership transfer not implemented)
// The dst argument is an 8-byte kptr slot inside a map value, but no map is passed to the
// helper, so its bounds cannot be checked against a map argument; see docs/parity/lifetime.md.
static constexpr EbpfHelperPrototype bpf_kptr_xchg_proto = {
    .name = "kptr_xchg",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE, // dst (kptr location)
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,    // ptr (can be NULL)
        },
    .unsupported = true,
};

// Helper 197 - dynptr_from_mem (UNSUPPORTED - dynptr not implemented)
static constexpr EbpfHelperPrototype bpf_dynptr_from_mem_proto = {
    .name = "dynptr_from_mem",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE,    // data
            EBPF_ARGUMENT_TYPE_ANYTHING,            // size
            EBPF_ARGUMENT_TYPE_ANYTHING,            // flags
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM, // ptr (dynptr out)
        },
    .unsupported = true,
};

// Helper 201 - dynptr_read
static constexpr EbpfHelperPrototype bpf_dynptr_read_proto = {
    .name = "dynptr_read",
    .return_type = EBPF_RETURN_TYPE_INTEGER, // Returns 0 on success, negative error on failure
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM, // dst
            EBPF_ARGUMENT_TYPE_CONST_SIZE,          // len
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // src (dynptr)
            EBPF_ARGUMENT_TYPE_ANYTHING,            // offset
            EBPF_ARGUMENT_TYPE_ANYTHING,            // flags
        },
    .unsupported = true,
};

// Helper 202 - dynptr_write
static constexpr EbpfHelperPrototype bpf_dynptr_write_proto = {
    .name = "dynptr_write",
    .return_type = EBPF_RETURN_TYPE_INTEGER, // Returns 0 on success, negative error on failure
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM, // dst (dynptr)
            EBPF_ARGUMENT_TYPE_ANYTHING,            // offset
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // src
            EBPF_ARGUMENT_TYPE_CONST_SIZE,          // len
            EBPF_ARGUMENT_TYPE_ANYTHING,            // flags
        },
    .unsupported = true,
};

// Helper 203 - dynptr_data
static constexpr EbpfHelperPrototype bpf_dynptr_data_proto = {
    .name = "dynptr_data",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MEM_OR_BTF_ID_OR_NULL, // Pointer or NULL
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // ptr (dynptr)
            EBPF_ARGUMENT_TYPE_ANYTHING,            // offset
            EBPF_ARGUMENT_TYPE_ANYTHING,            // len
        },
    .unsupported = true,
};

// Helper 204 - tcp_raw_gen_syncookie_ipv4
static constexpr EbpfHelperPrototype bpf_tcp_raw_gen_syncookie_ipv4_proto = {
    .name = "tcp_raw_gen_syncookie_ipv4",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // iph
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // th
            EBPF_ARGUMENT_TYPE_ANYTHING,            // th_len
        },
};

// Helper 205 - tcp_raw_gen_syncookie_ipv6
static constexpr EbpfHelperPrototype bpf_tcp_raw_gen_syncookie_ipv6_proto = {
    .name = "tcp_raw_gen_syncookie_ipv6",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // iph
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // th
            EBPF_ARGUMENT_TYPE_ANYTHING,            // th_len
        },
};

// Helper 206 - tcp_raw_check_syncookie_ipv4
static constexpr EbpfHelperPrototype bpf_tcp_raw_check_syncookie_ipv4_proto = {
    .name = "tcp_raw_check_syncookie_ipv4",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // iph
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // th
        },
};

// Helper 207 - tcp_raw_check_syncookie_ipv6
static constexpr EbpfHelperPrototype bpf_tcp_raw_check_syncookie_ipv6_proto = {
    .name = "tcp_raw_check_syncookie_ipv6",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // iph
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // th
        },
};

#define FN(N, x) bpf_##x##_proto
static constexpr EbpfHelperPrototype prototypes[] = {
    FN(0, unspec),
    FN(1, map_lookup_elem),
    FN(2, map_update_elem),
    FN(3, map_delete_elem),
    FN(4, probe_read),
    FN(5, ktime_get_ns),
    FN(6, trace_printk),
    FN(7, get_prandom_u32),
    FN(8, get_smp_processor_id),
    FN(9, skb_store_bytes),
    FN(10, l3_csum_replace),
    FN(11, l4_csum_replace),
    FN(12, tail_call),
    FN(13, clone_redirect),
    FN(14, get_current_pid_tgid),
    FN(15, get_current_uid_gid),
    FN(16, get_current_comm),
    FN(17, get_cgroup_classid),
    FN(18, skb_vlan_push),
    FN(19, skb_vlan_pop),
    FN(20, skb_get_tunnel_key),
    FN(21, skb_set_tunnel_key),
    FN(22, perf_event_read),
    FN(23, redirect),
    FN(24, get_route_realm),
    FN(25, perf_event_output),
    FN(26, skb_load_bytes),
    FN(27, get_stackid),
    FN(28, csum_diff),
    FN(29, skb_get_tunnel_opt),
    FN(30, skb_set_tunnel_opt),
    FN(31, skb_change_proto),
    FN(32, skb_change_type),
    FN(33, skb_under_cgroup),
    FN(34, get_hash_recalc),
    FN(35, get_current_task),
    FN(36, probe_write_user),
    FN(37, current_task_under_cgroup),
    FN(38, skb_change_tail),
    FN(39, skb_pull_data),
    FN(40, csum_update),
    FN(41, set_hash_invalid),
    FN(42, get_numa_node_id),
    FN(43, skb_change_head),
    FN(44, xdp_adjust_head),
    FN(45, probe_read_str),
    FN(46, get_socket_cookie),
    FN(47, get_socket_uid),
    FN(48, set_hash),
    FN(49, setsockopt),
    FN(50, skb_adjust_room),
    FN(51, redirect_map),
    FN(52, sk_redirect_map),
    FN(53, sock_map_update),
    FN(54, xdp_adjust_meta),
    FN(55, perf_event_read_value),
    FN(56, perf_prog_read_value),
    FN(57, getsockopt),
    FN(58, override_return),
    FN(59, sock_ops_cb_flags_set),
    FN(60, msg_redirect_map),
    FN(61, msg_apply_bytes),
    FN(62, msg_cork_bytes),
    FN(63, msg_pull_data),
    FN(64, bind),
    FN(65, xdp_adjust_tail),
    FN(66, skb_get_xfrm_state),
    FN(67, get_stack),
    FN(68, skb_load_bytes_relative),
    FN(69, fib_lookup),
    FN(70, sock_hash_update),
    FN(71, msg_redirect_hash),
    FN(72, sk_redirect_hash),
    FN(73, lwt_push_encap),
    FN(74, lwt_seg6_store_bytes),
    FN(75, lwt_seg6_adjust_srh),
    FN(76, lwt_seg6_action),
    FN(77, rc_repeat),
    FN(78, rc_keydown),
    FN(79, skb_cgroup_id),
    FN(80, get_current_cgroup_id),
    FN(81, get_local_storage),
    FN(82, sk_select_reuseport),
    FN(83, skb_ancestor_cgroup_id),
    FN(84, sk_lookup_tcp),
    FN(85, sk_lookup_udp),
    FN(86, sk_release),
    FN(87, map_push_elem),
    FN(88, map_pop_elem),
    FN(89, map_peek_elem),
    FN(90, msg_push_data),
    FN(91, msg_pop_data),
    FN(92, rc_pointer_rel),
    FN(93, spin_lock),
    FN(94, spin_unlock),
    FN(95, sk_fullsock),
    FN(96, tcp_sock),
    FN(97, skb_ecn_set_ce),
    FN(98, get_listener_sock),
    FN(99, skc_lookup_tcp),
    FN(100, tcp_check_syncookie),
    FN(101, sysctl_get_name),
    FN(102, sysctl_get_current_value),
    FN(103, sysctl_get_new_value),
    FN(104, sysctl_set_new_value),
    FN(105, strtol),
    FN(106, strtoul),
    FN(107, sk_storage_get),
    FN(108, sk_storage_delete),
    FN(109, send_signal),
    FN(110, tcp_gen_syncookie),
    FN(111, skb_output),
    FN(112, probe_read_user),
    FN(113, probe_read_kernel),
    FN(114, probe_read_user_str),
    FN(115, probe_read_kernel_str),
    FN(116, tcp_send_ack),
    FN(117, send_signal_thread),
    FN(118, jiffies64),
    FN(119, read_branch_records),
    FN(120, get_ns_current_pid_tgid),
    FN(121, xdp_output),
    FN(122, get_netns_cookie),
    FN(123, get_current_ancestor_cgroup_id),
    FN(124, sk_assign),
    FN(125, ktime_get_boot_ns),
    FN(126, seq_printf),
    FN(127, seq_write),
    FN(128, sk_cgroup_id),
    FN(129, sk_ancestor_cgroup_id),
    FN(130, ringbuf_output),
    FN(131, ringbuf_reserve),
    FN(132, ringbuf_submit),
    FN(133, ringbuf_discard),
    FN(134, ringbuf_query),
    FN(135, csum_level),
    FN(136, skc_to_tcp6_sock),
    FN(137, skc_to_tcp_sock),
    FN(138, skc_to_tcp_timewait_sock),
    FN(139, skc_to_tcp_request_sock),
    FN(140, skc_to_udp6_sock),
    FN(141, get_task_stack),
    FN(142, load_hdr_opt),
    FN(143, store_hdr_opt),
    FN(144, reserve_hdr_opt),
    FN(145, inode_storage_get),
    FN(146, inode_storage_delete),
    FN(147, d_path),
    FN(148, copy_from_user),
    FN(149, snprintf_btf),
    FN(150, seq_printf_btf),
    FN(151, skb_cgroup_classid),
    FN(152, redirect_neigh),
    FN(153, per_cpu_ptr),
    FN(154, this_cpu_ptr),
    FN(155, redirect_peer),
    FN(156, task_storage_get),
    FN(157, task_storage_delete),
    FN(158, get_current_task_btf),
    FN(159, bprm_opts_set),
    FN(160, ktime_get_coarse_ns),
    FN(161, ima_inode_hash),
    FN(162, sock_from_file),
    FN(163, check_mtu),
    FN(164, for_each_map_elem),
    FN(165, snprintf),
    FN(166, sys_bpf),
    FN(167, btf_find_by_name_kind),
    FN(168, sys_close),
    FN(169, timer_init),
    FN(170, timer_set_callback),
    FN(171, timer_start),
    FN(172, timer_cancel),
    FN(173, get_func_ip),
    FN(174, get_attach_cookie),
    FN(175, task_pt_regs),
    FN(176, get_branch_snapshot),
    FN(177, trace_vprintk),
    FN(178, skc_to_unix_sock),
    FN(179, kallsyms_lookup_name),
    FN(180, find_vma),
    FN(181, loop),
    FN(182, strncmp),
    FN(183, get_func_arg),
    FN(184, get_func_ret),
    FN(185, get_func_arg_cnt),
    FN(186, get_retval),
    FN(187, set_retval),
    FN(188, xdp_get_buff_len),
    FN(189, xdp_load_bytes),
    FN(190, xdp_store_bytes),
    FN(191, copy_from_user_task),
    FN(192, skb_set_tstamp),
    FN(193, ima_file_hash),
    FN(194, kptr_xchg),
    FN(195, map_lookup_percpu_elem),
    FN(196, skc_to_mptcp_sock),
    FN(197, dynptr_from_mem),
    FN(198, ringbuf_reserve_dynptr),
    FN(199, ringbuf_submit_dynptr),
    FN(200, ringbuf_discard_dynptr),
    FN(201, dynptr_read),
    FN(202, dynptr_write),
    FN(203, dynptr_data),
    FN(204, tcp_raw_gen_syncookie_ipv4),
    FN(205, tcp_raw_gen_syncookie_ipv6),
    FN(206, tcp_raw_check_syncookie_ipv4),
    FN(207, tcp_raw_check_syncookie_ipv6),
    FN(208, ktime_get_tai_ns),
    FN(209, user_ringbuf_drain),
    FN(210, cgrp_storage_get),
    FN(211, cgrp_storage_delete),
};

std::optional<int32_t> resolve_helper_id_linux(const std::string& name) {
    std::string_view candidate{name};
    if (candidate.starts_with("bpf_")) {
        candidate.remove_prefix(4);
    } else if (candidate.starts_with("ebpf_")) {
        candidate.remove_prefix(5);
    }

    for (int32_t id = 0; id < static_cast<int32_t>(std::size(prototypes)); ++id) {
        if (candidate == prototypes[id].name) {
            return id;
        }
    }
    return std::nullopt;
}

// ---- Helper availability by program type ----------------------------------------------------------------------
//
// Linux decides per program type whether a program may call a helper: every program type has a
// get_func_proto() callback that maps a helper id to the function the id stands for in that type, or to none.
// A helper that is safe where the hook has prepared for it is not safe elsewhere: bpf_skb_pull_data(), say,
// recomputes two pointers into skb->cb, which belongs to the program in a tc hook and to the receiving protocol
// in a socket filter.
//
// The sets below transcribe those callbacks from Linux 6.18. Each is named after the kernel function it
// transcribes and is built the way that function is: the cases of its own switch, joined with the set of the
// function it falls back to.
//
// An id is in a set only if the prototype row above describes the function the id is bound to there. Linux
// binds some ids to functions of different signatures in different program types. Where the row takes the
// context and the bound function takes something else (a `struct sock *`, an `xdp_buff *`), the id is left
// out, with a comment: the context is the one argument such a function must not be given. Those functions
// are not modeled, so the program type cannot call the helper at all.
//
// Capabilities (CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN), lockdown and kernel configuration are taken as granted:
// the sets are what a fully privileged loader on a full kernel is offered.
//
// EbpfProgramType::name does not tell the attach types of a program type apart, nor the functions a program
// attaches to. A helper that a callback offers to some of them only is offered to the whole program type, and
// its set says so (docs/parity/program-types.md).
namespace {
constexpr size_t helper_count = std::size(prototypes);

/// The lengths of the names of the prototype rows, by helper id. They are measured once, and a name is compared
/// with the rows of its own length only, to keep the compile-time lookups below well within the evaluation
/// limits of the compilers.
struct HelperNameLengths {
    size_t of[helper_count]{};
};
constexpr HelperNameLengths helper_name_length = [] {
    HelperNameLengths lengths;
    for (size_t id = 0; id < helper_count; ++id) {
        lengths.of[id] = std::string_view{prototypes[id].name}.size();
    }
    return lengths;
}();

/// The id of the helper called `name`. Not a constant expression if there is none, so a misspelt name in a
/// set below does not compile.
constexpr size_t helper_id(const std::string_view name) {
    const size_t length = name.size();
    for (size_t id = 0; id < helper_count; ++id) {
        if (helper_name_length.of[id] == length && name == std::string_view{prototypes[id].name, length}) {
            return id;
        }
    }
    throw std::invalid_argument("no helper has this name");
}

/// A set of helper ids.
class HelperSet {
    static constexpr size_t word_bits = 64;
    std::array<uint64_t, (helper_count + word_bits - 1) / word_bits> words{};

  public:
    constexpr HelperSet() = default;

    /// The helpers of these names: the names of the prototype rows, which are those of the kernel's
    /// BPF_FUNC_<name> but for two rows (see tracing_prog_func_proto_any).
    constexpr HelperSet(const std::initializer_list<std::string_view> names) {
        for (const std::string_view name : names) {
            const size_t id = helper_id(name);
            words[id / word_bits] |= uint64_t{1} << (id % word_bits);
        }
    }

    constexpr HelperSet operator|(const HelperSet& other) const {
        HelperSet result = *this;
        for (size_t i = 0; i < words.size(); ++i) {
            result.words[i] |= other.words[i];
        }
        return result;
    }

    constexpr HelperSet without(const HelperSet& other) const {
        HelperSet result = *this;
        for (size_t i = 0; i < words.size(); ++i) {
            result.words[i] &= ~other.words[i];
        }
        return result;
    }

    [[nodiscard]]
    constexpr bool contains(const int32_t id) const {
        if (id < 0 || static_cast<size_t>(id) >= helper_count) {
            return false;
        }
        const auto index = static_cast<size_t>(id);
        return (words[index / word_bits] >> (index % word_bits) & 1) != 0;
    }
};

// kernel/bpf/helpers.c
// get_cgroup_classid is bpf_get_cgroup_classid_curr() here, which takes no argument and reads the current task.
// The row asks for an sk_buff context, which is more than that function needs and harms nothing.
constexpr HelperSet bpf_base_func_proto{
    "map_lookup_elem",
    "map_update_elem",
    "map_delete_elem",
    "map_push_elem",
    "map_pop_elem",
    "map_peek_elem",
    "map_lookup_percpu_elem",
    "get_prandom_u32",
    "get_smp_processor_id",
    "get_numa_node_id",
    "tail_call",
    "ktime_get_ns",
    "ktime_get_boot_ns",
    "ktime_get_tai_ns",
    "ringbuf_output",
    "ringbuf_reserve",
    "ringbuf_submit",
    "ringbuf_discard",
    "ringbuf_query",
    "strncmp",
    "strtol",
    "strtoul",
    "get_current_pid_tgid",
    "get_ns_current_pid_tgid",
    "get_current_uid_gid",
    "spin_lock",
    "spin_unlock",
    "jiffies64",
    "per_cpu_ptr",
    "this_cpu_ptr",
    "timer_init",
    "timer_set_callback",
    "timer_start",
    "timer_cancel",
    "kptr_xchg",
    "for_each_map_elem",
    "loop",
    "user_ringbuf_drain",
    "ringbuf_reserve_dynptr",
    "ringbuf_submit_dynptr",
    "ringbuf_discard_dynptr",
    "dynptr_from_mem",
    "dynptr_read",
    "dynptr_write",
    "dynptr_data",
    "cgrp_storage_get",
    "cgrp_storage_delete",
    "get_current_cgroup_id",
    "get_current_ancestor_cgroup_id",
    "current_task_under_cgroup",
    "get_cgroup_classid",
    "task_storage_get",
    "task_storage_delete",
    "trace_printk",
    "get_current_task",
    "get_current_task_btf",
    "get_current_comm",
    "probe_read_user",
    "probe_read_kernel",
    "probe_read_user_str",
    "probe_read_kernel_str",
    "copy_from_user",
    "copy_from_user_task",
    "snprintf_btf",
    "snprintf",
    "task_pt_regs",
    "trace_vprintk",
    "perf_event_read_value",
    "perf_event_read",
    "send_signal",
    "send_signal_thread",
    "get_task_stack",
    "get_branch_snapshot",
    "find_vma",
};

// kernel/bpf/cgroup.c: cgroup_common_func_proto(), which the cgroup program types consult first. It offers
// get_local_storage to all of them. It offers get_retval and set_retval except on the attach types
// BPF_CGROUP_INET_INGRESS and BPF_CGROUP_INET_EGRESS (all of cgroup_skb), BPF_CGROUP_SOCK_OPS (all of sock_ops)
// and the recvmsg, getpeername and getsockname hooks of cgroup_sock_addr.
constexpr HelperSet cgroup_common_storage{"get_local_storage"};
constexpr HelperSet cgroup_common_func_proto = HelperSet{"get_retval", "set_retval"} | cgroup_common_storage;

// net/core/filter.c
constexpr HelperSet bpf_sk_base_func_proto =
    HelperSet{
        "skc_to_tcp6_sock", "skc_to_tcp_sock",  "skc_to_tcp_timewait_sock", "skc_to_tcp_request_sock",
        "skc_to_udp6_sock", "skc_to_unix_sock", "skc_to_mptcp_sock",        "ktime_get_coarse_ns",
    } |
    bpf_base_func_proto;

// cgroup_sock: the context is the socket, a struct bpf_sock.
constexpr HelperSet sock_filter_func_proto =
    HelperSet{
        "get_socket_cookie", "get_netns_cookie", "perf_event_output", "sk_storage_get", "ktime_get_coarse_ns",
    } |
    bpf_base_func_proto | cgroup_common_func_proto;

// cgroup_sock_addr. Offered to some of its attach types only, and listed because the program type has one
// name here:
// - bind: the connect4 and connect6 hooks, which hold the lock of the socket they would rebind.
// - get_retval, set_retval: all but the recvmsg, getpeername and getsockname hooks (see
//   cgroup_common_func_proto above).
// setsockopt and getsockopt are bpf_sock_addr_setsockopt(ctx) and bpf_sock_addr_getsockopt(ctx), on every attach
// type of the program type.
constexpr HelperSet sock_addr_func_proto =
    HelperSet{
        "bind",       "get_socket_cookie", "get_netns_cookie", "perf_event_output", "sk_lookup_tcp", "sk_lookup_udp",
        "sk_release", "skc_lookup_tcp",    "sk_storage_get",   "sk_storage_delete", "setsockopt",    "getsockopt",
    } |
    bpf_sk_base_func_proto | cgroup_common_func_proto;

// socket_filter
constexpr HelperSet sk_filter_func_proto =
    HelperSet{
        "skb_load_bytes",   "skb_load_bytes_relative", "get_socket_cookie",
        "get_netns_cookie", "get_socket_uid",          "perf_event_output",
    } |
    bpf_sk_base_func_proto;

// cgroup_skb. Not get_retval and set_retval (see cgroup_common_func_proto above).
constexpr HelperSet cg_skb_func_proto =
    HelperSet{
        "sk_fullsock",   "sk_storage_get",         "sk_storage_delete", "perf_event_output",
        "skb_cgroup_id", "skb_ancestor_cgroup_id", "sk_cgroup_id",      "sk_ancestor_cgroup_id",
        "sk_lookup_tcp", "sk_lookup_udp",          "sk_release",        "skc_lookup_tcp",
        "tcp_sock",      "get_listener_sock",      "skb_ecn_set_ce",
    } |
    sk_filter_func_proto | cgroup_common_storage;

// sched_cls and sched_act
constexpr HelperSet tc_cls_act_func_proto =
    HelperSet{
        "skb_store_bytes",
        "skb_load_bytes",
        "skb_load_bytes_relative",
        "skb_pull_data",
        "csum_diff",
        "csum_update",
        "csum_level",
        "l3_csum_replace",
        "l4_csum_replace",
        "clone_redirect",
        "get_cgroup_classid",
        "skb_vlan_push",
        "skb_vlan_pop",
        "skb_change_proto",
        "skb_change_type",
        "skb_adjust_room",
        "skb_change_tail",
        "skb_change_head",
        "skb_get_tunnel_key",
        "skb_set_tunnel_key",
        "skb_get_tunnel_opt",
        "skb_set_tunnel_opt",
        "redirect",
        "redirect_neigh",
        "redirect_peer",
        "get_route_realm",
        "get_hash_recalc",
        "set_hash_invalid",
        "set_hash",
        "perf_event_output",
        "get_smp_processor_id",
        "skb_under_cgroup",
        "get_socket_cookie",
        "get_netns_cookie",
        "get_socket_uid",
        "fib_lookup",
        "check_mtu",
        "sk_fullsock",
        "sk_storage_get",
        "sk_storage_delete",
        "skb_get_xfrm_state",
        "skb_cgroup_classid",
        "skb_cgroup_id",
        "skb_ancestor_cgroup_id",
        "sk_lookup_tcp",
        "sk_lookup_udp",
        "sk_release",
        "tcp_sock",
        "get_listener_sock",
        "skc_lookup_tcp",
        "tcp_check_syncookie",
        "skb_ecn_set_ce",
        "tcp_gen_syncookie",
        "sk_assign",
        "skb_set_tstamp",
        "tcp_raw_gen_syncookie_ipv4",
        "tcp_raw_gen_syncookie_ipv6",
        "tcp_raw_check_syncookie_ipv4",
        "tcp_raw_check_syncookie_ipv6",
    } |
    bpf_sk_base_func_proto;

constexpr HelperSet xdp_func_proto =
    HelperSet{
        "perf_event_output",
        "get_smp_processor_id",
        "csum_diff",
        "xdp_adjust_head",
        "xdp_adjust_meta",
        "redirect",
        "redirect_map",
        "xdp_adjust_tail",
        "xdp_get_buff_len",
        "xdp_load_bytes",
        "xdp_store_bytes",
        "fib_lookup",
        "check_mtu",
        "sk_lookup_udp",
        "sk_lookup_tcp",
        "sk_release",
        "skc_lookup_tcp",
        "tcp_check_syncookie",
        "tcp_gen_syncookie",
        "tcp_raw_gen_syncookie_ipv4",
        "tcp_raw_gen_syncookie_ipv6",
        "tcp_raw_check_syncookie_ipv4",
        "tcp_raw_check_syncookie_ipv6",
    } |
    bpf_sk_base_func_proto;

// setsockopt and getsockopt are bpf_sock_ops_setsockopt(ctx) and bpf_sock_ops_getsockopt(ctx).
// Not get_retval and set_retval (see cgroup_common_func_proto above).
constexpr HelperSet sock_ops_func_proto =
    HelperSet{
        "setsockopt",        "getsockopt",        "sock_ops_cb_flags_set", "sock_map_update",   "sock_hash_update",
        "get_socket_cookie", "perf_event_output", "sk_storage_get",        "sk_storage_delete", "get_netns_cookie",
        "load_hdr_opt",      "store_hdr_opt",     "reserve_hdr_opt",       "tcp_sock",
    } |
    bpf_sk_base_func_proto | cgroup_common_storage;

constexpr HelperSet sk_msg_func_proto =
    HelperSet{
        "msg_redirect_map", "msg_redirect_hash", "msg_apply_bytes",  "msg_cork_bytes",
        "msg_pull_data",    "msg_push_data",     "msg_pop_data",     "perf_event_output",
        "sk_storage_get",   "sk_storage_delete", "get_netns_cookie",
    } |
    bpf_sk_base_func_proto;

// skb_pull_data, skb_change_tail, skb_change_head and skb_adjust_room are sk_skb's own functions here, which
// do not recompute the packet pointers in skb->cb.
constexpr HelperSet sk_skb_func_proto =
    HelperSet{
        "skb_store_bytes",   "skb_load_bytes",    "skb_pull_data",  "skb_change_tail", "skb_change_head",
        "skb_adjust_room",   "get_socket_cookie", "get_socket_uid", "sk_redirect_map", "sk_redirect_hash",
        "perf_event_output", "sk_lookup_tcp",     "sk_lookup_udp",  "sk_release",      "skc_lookup_tcp",
    } |
    bpf_sk_base_func_proto;

constexpr HelperSet flow_dissector_func_proto = HelperSet{"skb_load_bytes"} | bpf_sk_base_func_proto;

constexpr HelperSet lwt_out_func_proto =
    HelperSet{
        "skb_load_bytes",     "skb_pull_data",        "csum_diff",
        "get_cgroup_classid", "get_route_realm",      "get_hash_recalc",
        "perf_event_output",  "get_smp_processor_id", "skb_under_cgroup",
    } |
    bpf_sk_base_func_proto;

constexpr HelperSet lwt_in_func_proto = HelperSet{"lwt_push_encap"} | lwt_out_func_proto;

constexpr HelperSet lwt_xmit_func_proto =
    HelperSet{
        "skb_get_tunnel_key", "skb_set_tunnel_key", "skb_get_tunnel_opt", "skb_set_tunnel_opt", "redirect",
        "clone_redirect",     "skb_change_tail",    "skb_change_head",    "skb_store_bytes",    "csum_update",
        "csum_level",         "l3_csum_replace",    "l4_csum_replace",    "set_hash_invalid",   "lwt_push_encap",
    } |
    lwt_out_func_proto;

// Not skb_pull_data, which Linux 6.18 offers here through lwt_out_func_proto() and later kernels refuse
// (commit e4a62833adff): the hook keeps a pointer to the segment routing header in per-CPU state, and the
// helper may reallocate the packet head that it points into.
constexpr HelperSet lwt_seg6local_func_proto =
    HelperSet{"lwt_seg6_store_bytes", "lwt_seg6_action", "lwt_seg6_adjust_srh"} |
    lwt_out_func_proto.without(HelperSet{"skb_pull_data"});

// Not get_socket_cookie: here the id is bpf_get_socket_ptr_cookie(sk).
constexpr HelperSet sk_reuseport_func_proto =
    HelperSet{"sk_select_reuseport", "skb_load_bytes", "skb_load_bytes_relative", "ktime_get_coarse_ns"} |
    bpf_base_func_proto;

constexpr HelperSet sk_lookup_func_proto =
    HelperSet{"perf_event_output", "sk_assign", "sk_release"} | bpf_sk_base_func_proto;

// kernel/bpf/cgroup.c
constexpr HelperSet cgroup_dev_func_proto =
    HelperSet{"perf_event_output"} | bpf_base_func_proto | cgroup_common_func_proto;

constexpr HelperSet sysctl_func_proto =
    HelperSet{
        "sysctl_get_name",      "sysctl_get_current_value", "sysctl_get_new_value",
        "sysctl_set_new_value", "ktime_get_coarse_ns",      "perf_event_output",
    } |
    bpf_base_func_proto | cgroup_common_func_proto;

// cgroup_sockopt. Not setsockopt and getsockopt: here the ids are bpf_sk_setsockopt(sk) and
// bpf_sk_getsockopt(sk), offered to the setsockopt hook only.
constexpr HelperSet cg_sockopt_func_proto =
    HelperSet{"get_netns_cookie", "sk_storage_get", "sk_storage_delete", "tcp_sock", "perf_event_output"} |
    bpf_base_func_proto | cgroup_common_func_proto;

// kernel/trace/bpf_trace.c
//
// bpf_tracing_func_proto() also has a case for get_func_ip, but the verifier then refuses the call
// (check_get_func_ip()) except in kprobe programs and in tracing programs that run from a trampoline, so the
// helper is listed with those two.
constexpr HelperSet bpf_tracing_func_proto =
    HelperSet{"get_smp_processor_id", "probe_read", "probe_read_str", "probe_write_user"} | bpf_base_func_proto;

constexpr HelperSet kprobe_prog_func_proto =
    HelperSet{
        "perf_event_output", "get_stackid", "get_stack", "override_return", "get_func_ip", "get_attach_cookie",
    } |
    bpf_tracing_func_proto;

// tracepoint
constexpr HelperSet tp_prog_func_proto =
    HelperSet{"perf_event_output", "get_stackid", "get_stack", "get_attach_cookie"} | bpf_tracing_func_proto;

// perf_event
constexpr HelperSet pe_prog_func_proto =
    HelperSet{
        "perf_event_output",    "get_stackid",         "get_stack",
        "perf_prog_read_value", "read_branch_records", "get_attach_cookie",
    } |
    bpf_tracing_func_proto;

// raw_tracepoint and raw_tracepoint_writable
constexpr HelperSet raw_tp_prog_func_proto =
    HelperSet{"perf_event_output", "get_stackid", "get_stack", "get_attach_cookie"} | bpf_tracing_func_proto;

// What tracing_prog_func_proto() offers whatever the program is: what it takes from raw_tp_prog_func_proto(),
// and those of its own cases that depend neither on the attach type nor on an `allowed` callback of the
// function. It serves the tracing, lsm and syscall program types.
// skb_event_output and xdp_event_output are the rows of BPF_FUNC_skb_output and BPF_FUNC_xdp_output.
// Not get_socket_cookie: here the id is bpf_get_socket_ptr_cookie(sk).
// Not xdp_get_buff_len: here the id is a function that takes an `xdp_buff *`, not the context.
// Not get_attach_cookie: tracing_prog_func_proto() has a case of its own, which hides the one of
// raw_tp_prog_func_proto() and offers the helper to tp_btf programs and to programs run from a trampoline.
constexpr HelperSet tracing_prog_func_proto_any =
    HelperSet{
        "perf_event_output",       "get_stackid",      "get_stack",        "skb_event_output",
        "xdp_event_output",        "skc_to_tcp6_sock", "skc_to_tcp_sock",  "skc_to_tcp_timewait_sock",
        "skc_to_tcp_request_sock", "skc_to_udp6_sock", "skc_to_unix_sock", "skc_to_mptcp_sock",
        "sock_from_file",
    } |
    bpf_tracing_func_proto;

// The tracing program type. What follows is offered to some of its attach types only, and is listed because
// the program type has one name here:
// - seq_printf, seq_write, seq_printf_btf: iter programs.
// - get_func_arg, get_func_ret, get_func_arg_cnt, get_func_ip: programs run from a trampoline (fentry,
//   fexit, fmod_ret).
// - get_attach_cookie: those and tp_btf programs.
// - sk_storage_get, sk_storage_delete (bpf_sk_storage_tracing_allowed()): iter and tp_btf programs, and
//   fentry and fexit programs that do not trace the socket storage functions themselves.
// - d_path (bpf_d_path_allowed()): iter programs, and programs attached to one of a list of functions.
// An iter program is also offered what its target adds (bpf_iter_get_func_proto()): the tcp and unix socket
// iterators add setsockopt and getsockopt as bpf_sk_setsockopt(sk) and bpf_sk_getsockopt(sk), which are left
// out like every other socket-taking binding of those ids.
constexpr HelperSet tracing_prog_func_proto =
    HelperSet{
        "seq_printf",  "seq_write",         "seq_printf_btf", "get_func_arg",      "get_func_ret", "get_func_arg_cnt",
        "get_func_ip", "get_attach_cookie", "sk_storage_get", "sk_storage_delete", "d_path",
    } |
    tracing_prog_func_proto_any;

// kernel/bpf/bpf_lsm.c, for the attach type BPF_LSM_MAC, which is what the sections `lsm/` and `lsm.s/` hold.
// Such a program runs from a trampoline, so tracing_prog_func_proto() offers it get_func_arg, get_func_ret and
// get_func_arg_cnt; check_get_func_ip() refuses get_func_ip outside kprobe and tracing programs.
// d_path, ima_inode_hash and ima_file_hash are offered to the hooks that may sleep.
// Not cgroup_common_func_proto(), setsockopt and getsockopt: those are for BPF_LSM_CGROUP, and the last two
// are bpf_sk_setsockopt(sk) and bpf_sk_getsockopt(sk).
constexpr HelperSet bpf_lsm_func_proto =
    HelperSet{
        "inode_storage_get", "inode_storage_delete",
        "sk_storage_get",    "sk_storage_delete",
        "spin_lock",         "spin_unlock",
        "bprm_opts_set",     "ima_inode_hash",
        "ima_file_hash",     "get_attach_cookie",
        "get_func_arg",      "get_func_ret",
        "get_func_arg_cnt",  "d_path",
    } |
    tracing_prog_func_proto_any;

// kernel/bpf/syscall.c. A syscall program has no attach type, so it gets none of what
// tracing_prog_func_proto() offers by attach type or attach target.
constexpr HelperSet syscall_prog_func_proto =
    HelperSet{"sys_bpf", "btf_find_by_name_kind", "sys_close", "kallsyms_lookup_name"} | tracing_prog_func_proto_any;

// struct_ops: each kernel structure that programs can implement has a callback of its own. This is
// bpf_tcp_ca_get_func_proto() of net/ipv4/bpf_tcp_ca.c, for tcp_congestion_ops; sched_ext_ops, Qdisc_ops and
// hid_bpf_ops offer bpf_base_func_proto() alone. Which structure a program implements is not known here, so
// the larger set is offered: what it adds is a clock, and helpers that work on a socket passed to them.
// Not setsockopt and getsockopt: here the ids are bpf_sk_setsockopt(sk) and bpf_sk_getsockopt(sk).
constexpr HelperSet bpf_tcp_ca_get_func_proto =
    HelperSet{"tcp_send_ack", "sk_storage_get", "sk_storage_delete", "ktime_get_coarse_ns"} | bpf_base_func_proto;

// drivers/media/rc/bpf-lirc.c. This callback does not fall back to bpf_base_func_proto().
constexpr HelperSet lirc_mode2_func_proto{
    "rc_repeat",         "rc_keydown",    "rc_pointer_rel",  "map_lookup_elem", "map_update_elem",
    "map_delete_elem",   "map_push_elem", "map_pop_elem",    "map_peek_elem",   "ktime_get_ns",
    "ktime_get_boot_ns", "tail_call",     "get_prandom_u32", "trace_printk",
};

// net/netfilter/nf_bpf_link.c
constexpr HelperSet bpf_nf_func_proto = bpf_base_func_proto;

/// The helpers each program type may call, by EbpfProgramType::name.
struct ProgramTypeHelpers {
    std::string_view program_type;
    HelperSet helpers;
};
constexpr ProgramTypeHelpers helpers_by_program_type[] = {
    {"socket_filter", sk_filter_func_proto},
    {"xdp", xdp_func_proto},
    {"cgroup_device", cgroup_dev_func_proto},
    {"cgroup_skb", cg_skb_func_proto},
    {"cgroup_sock", sock_filter_func_proto},
    {"kprobe", kprobe_prog_func_proto},
    {"lwt_in", lwt_in_func_proto},
    {"lwt_out", lwt_out_func_proto},
    {"lwt_xmit", lwt_xmit_func_proto},
    {"perf_event", pe_prog_func_proto},
    {"sched_act", tc_cls_act_func_proto},
    {"sched_cls", tc_cls_act_func_proto},
    {"sk_skb", sk_skb_func_proto},
    {"sock_ops", sock_ops_func_proto},
    {"tracepoint", tp_prog_func_proto},
    {"cgroup_sockopt", cg_sockopt_func_proto},
    {"sk_msg", sk_msg_func_proto},
    {"raw_tracepoint", raw_tp_prog_func_proto},
    {"raw_tracepoint_writable", raw_tp_prog_func_proto},
    {"cgroup_sock_addr", sock_addr_func_proto},
    {"lwt_seg6local", lwt_seg6local_func_proto},
    {"lirc_mode2", lirc_mode2_func_proto},
    {"sk_reuseport", sk_reuseport_func_proto},
    {"flow_dissector", flow_dissector_func_proto},
    {"cgroup_sysctl", sysctl_func_proto},
    // A freplace program takes the place of a function of another program and is offered what that program's
    // type is. The target is not known here, so only the helpers that every callback but lirc_mode2's falls
    // back to are offered.
    {"ext", bpf_base_func_proto},
    {"tracing", tracing_prog_func_proto},
    {"struct_ops", bpf_tcp_ca_get_func_proto},
    {"lsm", bpf_lsm_func_proto},
    {"sk_lookup", sk_lookup_func_proto},
    {"syscall", syscall_prog_func_proto},
    {"netfilter", bpf_nf_func_proto},
    // cilium's name for a sched_cls program.
    {"lxc", tc_cls_act_func_proto},
};

/// What at least one program type may call.
constexpr HelperSet helpers_of_some_program_type = [] {
    HelperSet result;
    for (const ProgramTypeHelpers& entry : helpers_by_program_type) {
        result = result | entry.helpers;
    }
    return result;
}();

/// The helpers left out of some set above because the id is bound there to a function that does not take the
/// context where the prototype row does.
constexpr HelperSet helpers_of_several_signatures{"get_socket_cookie", "setsockopt", "getsockopt", "xdp_get_buff_len"};

/// Whether Linux offers the helper to programs of the type, bound to the function that the helper's prototype
/// row describes. A program type that the table does not name is offered nothing.
bool is_helper_offered_to(const int32_t id, const EbpfProgramType& program_type) {
    // A section whose name names no program type: what the program will be loaded as is not known, so neither
    // is what it will be offered. It may call what some program type may, except where the id stands for
    // functions of different signatures: there the program type decides what the first argument must be. The
    // helper's context descriptor, if it has one, is then the only other restriction
    // (docs/parity/program-types.md).
    if (program_type.name == linux_unknown_program_type.name) {
        return helpers_of_some_program_type.contains(id) && !helpers_of_several_signatures.contains(id);
    }
    for (const auto& [name, helpers] : helpers_by_program_type) {
        if (name == program_type.name) {
            return helpers.contains(id);
        }
    }
    return false;
}
} // namespace

bool is_helper_usable_linux(const int32_t n, const EbpfProgramType& program_type) {
    if (n >= static_cast<int>(std::size(prototypes)) || n < 0) {
        return false;
    }

    // Check if explicitly marked as unsupported
    if (prototypes[n].unsupported) {
        return false;
    }

    // The program type must be one that Linux offers the helper to.
    if (!is_helper_offered_to(n, program_type)) {
        return false;
    }

    // Sleepable helpers are only usable in sleepable programs.
    if (prototypes[n].might_sleep && !program_type.is_sleepable) {
        return false;
    }

    // If the helper has a ctx_descriptor, it must match the hook's ctx_descriptor.
    // g_sk_buff_no_meta is the same __sk_buff struct as g_sk_buff without the
    // tc-only data_meta pointer, so __sk_buff helpers accept both.
    const ebpf_ctx_descriptor_t* hook_ctx_descriptor =
        program_type.ctx_descriptor == &g_sk_buff_no_meta ? &g_sk_buff : program_type.ctx_descriptor;
    if (prototypes[n].ctx_descriptor && prototypes[n].ctx_descriptor != hook_ctx_descriptor) {
        return false;
    }

    return true;
}

EbpfHelperPrototype get_helper_prototype_linux(const int32_t n, const EbpfProgramType& program_type) {
    if (!is_helper_usable_linux(n, program_type)) {
        return EbpfHelperPrototype{};
    }
    return prototypes[n];
}
} // namespace prevail

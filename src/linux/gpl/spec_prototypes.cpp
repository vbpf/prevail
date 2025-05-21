#include "platform.hpp"
#include "spec_type_descriptors.hpp"

namespace prevail {
#define EBPF_RETURN_TYPE_PTR_TO_SOCK_COMMON_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED
#define EBPF_RETURN_TYPE_PTR_TO_SOCKET_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED
#define EBPF_RETURN_TYPE_PTR_TO_TCP_SOCKET_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED
#define EBPF_RETURN_TYPE_PTR_TO_ALLOC_MEM_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED
#define EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED
#define EBPF_RETURN_TYPE_PTR_TO_MEM_OR_BTF_ID_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED
#define EBPF_RETURN_TYPE_PTR_TO_BTF_ID EBPF_RETURN_TYPE_UNSUPPORTED
#define EBPF_RETURN_TYPE_PTR_TO_MEM_OR_BTF_ID EBPF_RETURN_TYPE_UNSUPPORTED

#define EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_SPIN_LOCK EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_SOCK_COMMON EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_LONG EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_INT EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_CONST_STR EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_FUNC EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_CONST_ALLOC_SIZE_OR_ZERO EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_ALLOC_MEM EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_ALLOC_MEM EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE_OR_NULL EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_TIMER EBPF_ARGUMENT_TYPE_UNSUPPORTED
#define EBPF_ARGUMENT_TYPE_PTR_TO_PERCPU_BTF_ID EBPF_ARGUMENT_TYPE_UNSUPPORTED

const ebpf_context_descriptor_t g_sk_buff = sk_buff;
const ebpf_context_descriptor_t g_xdp_md = xdp_md;
const ebpf_context_descriptor_t g_sk_msg_md = sk_msg_md;
const ebpf_context_descriptor_t g_unspec_descr = unspec_descr;
const ebpf_context_descriptor_t g_cgroup_dev_descr = cgroup_dev_descr;
const ebpf_context_descriptor_t g_kprobe_descr = kprobe_descr;
const ebpf_context_descriptor_t g_tracepoint_descr = tracepoint_descr;
const ebpf_context_descriptor_t g_perf_event_descr = perf_event_descr;
const ebpf_context_descriptor_t g_cgroup_sock_descr = cgroup_sock_descr;
const ebpf_context_descriptor_t g_sock_ops_descr = sock_ops_descr;

// eBPF helpers are documented at the following links:
// https://github.com/iovisor/bpf-docs/blob/master/bpf_helpers.rst
// https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html

static constexpr EbpfHelperPrototype bpf_unspec_proto = {
    .name = "unspec",
    .return_type = EBPF_RETURN_TYPE_UNSUPPORTED,
};

constexpr EbpfHelperPrototype bpf_tail_call_proto = {
    .name = "tail_call",
    .return_type = EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_override_return_proto = {
    .name = "override_return",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
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
};

static constexpr EbpfHelperPrototype bpf_perf_prog_read_value_proto = {.name = "perf_prog_read_value",
                                                                       .return_type = EBPF_RETURN_TYPE_INTEGER,
                                                                       .argument_type =
                                                                           {
                                                                               EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
                                                                               EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
                                                                               EBPF_ARGUMENT_TYPE_CONST_SIZE,
                                                                           },
                                                                       .context_descriptor = &g_perf_event_descr};

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
    .context_descriptor = &g_sock_ops_descr,
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
    .context_descriptor = &g_sock_ops_descr,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_pull_data_proto = {
    .name = "skb_pull_data",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_msg_md,
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
    .context_descriptor = &g_sk_msg_md,
};

static constexpr EbpfHelperPrototype bpf_msg_apply_bytes_proto = {
    .name = "msg_apply_bytes",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .context_descriptor = &g_sk_msg_md,
};

static constexpr EbpfHelperPrototype bpf_msg_cork_bytes_proto = {
    .name = "msg_cork_bytes",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .context_descriptor = &g_sk_msg_md,
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
    .context_descriptor = &g_sk_msg_md,
};
static constexpr EbpfHelperPrototype bpf_get_cgroup_classid_proto = {
    .name = "get_cgroup_classid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_get_route_realm_proto = {
    .name = "get_route_realm",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_get_hash_recalc_proto = {
    .name = "get_hash_recalc",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_set_hash_invalid_proto = {
    .name = "set_hash_invalid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_set_hash_proto = {
    .name = "set_hash",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_vlan_pop_proto = {
    .name = "skb_vlan_pop",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_change_type_proto = {
    .name = "skb_change_type",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_xdp_descr,
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
    .context_descriptor = &g_xdp_descr,
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
    .context_descriptor = &g_xdp_descr,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_skb_cgroup_id_proto = {
    .name = "skb_cgroup_id",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_get_socket_cookie_proto = {
    .name = "get_socket_cookie",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_get_socket_uid_proto = {
    .name = "get_socket_uid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sock_ops_descr,
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
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_fib_lookup_proto = {
    .name = "fib_lookup",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
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
    .context_descriptor = &g_sk_buff,
};

static constexpr EbpfHelperPrototype bpf_rc_repeat_proto = {
    .name = "rc_repeat",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
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
};

static constexpr EbpfHelperPrototype bpf_get_local_storage_proto = {
    .name = "get_local_storage",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL, // BUT never NULL. TODO: add type
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
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
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO: readonly
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
        EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO: readonly
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
};

static constexpr EbpfHelperPrototype bpf_map_pop_elem_proto = {
    .name = "map_pop_elem",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE, // TODO: uninit
    },
};

static constexpr EbpfHelperPrototype bpf_map_peek_elem_proto = {
    .name = "map_peek_elem",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,       // TODO: const
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE, // TODO: uninit
    },
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
    .context_descriptor = &g_sk_msg_md,
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
    .context_descriptor = &g_sk_msg_md,
};

static constexpr EbpfHelperPrototype bpf_rc_pointer_rel_proto = {
    .name = "rc_pointer_rel",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
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
};

static constexpr EbpfHelperPrototype bpf_tcp_check_syncookie_proto = {
    .name = "tcp_check_syncookie",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO: readonly
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO: readonly
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_get_listener_sock_proto = {
    .name = "EbpfHelperPrototype",
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
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO: readonly
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
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
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
};

static constexpr EbpfHelperPrototype bpf_sysctl_set_new_value_proto = {
    .name = "sysctl_set_new_value",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO: readonly
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_strtol_proto = {
    .name = "strtol",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO: readonly
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
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO: readonly
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
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE, // TODO: OR_NULL,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_sk_storage_get_cg_sock_proto = {
    .name = "sk_storage_get",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,       /* context is 'struct sock' */
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE, // TODO: OR_NULL,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_sk_storage_delete_proto = {
    .name = "sk_storage_delete",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON,
        },
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
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO: readonly
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO: readonly
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
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO readonly
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
    //.arg1_btf_id = &bpf_skb_output_btf_ids[0],
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
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_get_ns_current_pid_tgid_proto = {
    .name = "get_ns_current_pid_tgid",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM, // TODO: or null
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
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO : readonly
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
    // .arg1_btf_id = &bpf_xdp_output_btf_ids[0],
};

static constexpr EbpfHelperPrototype bpf_get_netns_cookie_sock_proto = {
    .name = "get_netns_cookie_sock",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX, // TODO: or null
        },
};

static constexpr EbpfHelperPrototype bpf_get_netns_cookie_sock_addr_proto = {
    .name = "get_netns_cookie_sock_addr",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX, // TODO: or null
        },
};

static constexpr EbpfHelperPrototype bpf_sk_assign_proto = {
    .name = "get_netns_cookie_sock",
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
};

constexpr EbpfHelperPrototype bpf_ringbuf_query_proto = {
    .name = "ringbuf_query",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP, // TODO: const
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_csum_level_proto = {
    .name = "csum_level",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
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

static constexpr EbpfHelperPrototype bpf_sock_ops_load_hdr_opt_proto = {
    .name = "sock_ops_load_hdr_opt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_sock_ops_store_hdr_opt_proto = {
    .name = "sock_ops_store_hdr_opt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_sock_ops_reserve_hdr_opt_proto = {
    .name = "sock_ops_reserve_hdr_opt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
};

static constexpr EbpfHelperPrototype bpf_inode_storage_get_proto = {
    .name = "inode_storage_get",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE_OR_NULL, // TODO: as argument too
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    //.arg2_btf_id = &bpf_inode_storage_btf_ids[0],
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
};

static constexpr EbpfHelperPrototype bpf_d_path_proto = {
    .name = "d_path",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
    // .allowed = bpf_d_path_allowed,
    // .arg1_btf_id = &bpf_d_path_btf_ids[0],
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
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM,
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
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE, // TODO: or null
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
    // .arg2_btf_id = &bpf_task_storage_btf_ids[0],
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
};

static constexpr EbpfHelperPrototype bpf_get_current_task_btf_proto = {
    .name = "get_current_task_btf", .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID,
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
};

static constexpr EbpfHelperPrototype bpf_snprintf_proto = {
    .name = "snprintf",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
            EBPF_ARGUMENT_TYPE_PTR_TO_CONST_STR,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL, //  TODO: readonly
            EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        },
};

static constexpr EbpfHelperPrototype bpf_sys_bpf_proto = {
    .name = "sys_bpf",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_ANYTHING,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, //  TODO: readonly
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
};

static constexpr EbpfHelperPrototype bpf_btf_find_by_name_kind_proto = {
    .name = "btf_find_by_name_kind",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, //  TODO: readonly
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
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP, // TODO: const
            EBPF_ARGUMENT_TYPE_ANYTHING,
        },
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
};

static constexpr EbpfHelperPrototype bpf_get_func_ret_proto = {
    .name = "get_func_ret",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_LONG,
        },
};

static constexpr EbpfHelperPrototype bpf_get_func_arg_cnt_proto = {
    .name = "get_func_arg_cnt",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
};

static constexpr EbpfHelperPrototype bpf_trace_vprintk_proto = {
    .name = "trace_vprintk",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM, // TODO: readonly
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
            EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL, // TODO: readonly
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

#define FN(x) bpf_##x##_proto
// keep this on a round line
constexpr EbpfHelperPrototype prototypes[] = {
    FN(unspec),
    FN(map_lookup_elem),
    FN(map_update_elem),
    FN(map_delete_elem),
    FN(probe_read),
    FN(ktime_get_ns),
    FN(trace_printk),
    FN(get_prandom_u32),
    FN(get_smp_processor_id),
    FN(skb_store_bytes),
    FN(l3_csum_replace),
    FN(l4_csum_replace),
    FN(tail_call),
    FN(clone_redirect),
    FN(get_current_pid_tgid),
    FN(get_current_uid_gid),
    FN(get_current_comm),
    FN(get_cgroup_classid),
    FN(skb_vlan_push),
    FN(skb_vlan_pop),
    FN(skb_get_tunnel_key),
    FN(skb_set_tunnel_key),
    FN(perf_event_read),
    FN(redirect),
    FN(get_route_realm),
    FN(perf_event_output),
    FN(skb_load_bytes),
    FN(get_stackid),
    FN(csum_diff),
    FN(skb_get_tunnel_opt),
    FN(skb_set_tunnel_opt),
    FN(skb_change_proto),
    FN(skb_change_type),
    FN(skb_under_cgroup),
    FN(get_hash_recalc),
    FN(get_current_task),
    FN(probe_write_user),
    FN(current_task_under_cgroup),
    FN(skb_change_tail),
    FN(skb_pull_data),
    FN(csum_update),
    FN(set_hash_invalid),
    FN(get_numa_node_id),
    FN(skb_change_head),
    FN(xdp_adjust_head),
    FN(probe_read_str),
    FN(get_socket_cookie),
    FN(get_socket_uid),
    FN(set_hash),
    FN(setsockopt),
    FN(skb_adjust_room),
    FN(redirect_map),
    FN(sk_redirect_map),
    FN(sock_map_update),
    FN(xdp_adjust_meta),
    FN(perf_event_read_value),
    FN(perf_prog_read_value),
    FN(getsockopt),
    FN(override_return),
    FN(sock_ops_cb_flags_set),
    FN(msg_redirect_map),
    FN(msg_apply_bytes),
    FN(msg_cork_bytes),
    FN(msg_pull_data),
    FN(bind),
    FN(xdp_adjust_tail),
    FN(skb_get_xfrm_state),
    FN(get_stack),
    FN(skb_load_bytes_relative),
    FN(fib_lookup),
    FN(sock_hash_update),
    FN(msg_redirect_hash),
    FN(sk_redirect_hash),
    FN(lwt_push_encap),
    FN(lwt_seg6_store_bytes),
    FN(lwt_seg6_adjust_srh),
    FN(lwt_seg6_action),
    FN(rc_repeat),
    FN(rc_keydown),
    FN(skb_cgroup_id),
    FN(get_current_cgroup_id),
    FN(get_local_storage),
    FN(sk_select_reuseport),
    FN(get_current_cgroup_id),
    FN(sk_lookup_tcp),
    FN(sk_lookup_udp),
    FN(sk_release),
    FN(map_push_elem),
    FN(map_pop_elem),
    FN(map_peek_elem),
    FN(msg_push_data),
    FN(msg_pop_data),
    FN(rc_pointer_rel),
    FN(spin_lock),
    FN(spin_unlock),
    FN(sk_fullsock),
    FN(tcp_sock),
    FN(skb_ecn_set_ce),
    FN(get_listener_sock),
    FN(skc_lookup_tcp),
    FN(tcp_check_syncookie),
    FN(sysctl_get_name),
    FN(sysctl_get_current_value),
    FN(sysctl_get_new_value),
    FN(sysctl_set_new_value),
    FN(strtol),
    FN(strtoul),
    FN(sk_storage_get),
    FN(sk_storage_delete),
    FN(send_signal),
    FN(tcp_gen_syncookie),
    FN(skb_output),
    FN(probe_read_user),
    FN(probe_read_kernel),
    FN(probe_read_user_str),
    FN(probe_read_kernel_str),
    FN(tcp_send_ack),
    FN(send_signal_thread),
    FN(jiffies64),
    FN(read_branch_records),
    FN(get_ns_current_pid_tgid),
    FN(xdp_output),
    FN(get_netns_cookie_sock), // XXX: same signature for bpf_get_netns_cookie_sock_addr_proto  or
                               // bpf_get_netns_cookie_sock_addr_proto
    FN(get_current_ancestor_cgroup_id),
    FN(sk_assign),
    FN(ktime_get_boot_ns),
    FN(seq_printf),
    FN(seq_write),
    FN(sk_cgroup_id),
    FN(sk_ancestor_cgroup_id),
    FN(ringbuf_output),
    FN(ringbuf_reserve),
    FN(ringbuf_submit),
    FN(ringbuf_discard),
    FN(ringbuf_query),
    FN(csum_level),
    FN(skc_to_tcp6_sock),
    FN(skc_to_tcp_sock),
    FN(skc_to_tcp_timewait_sock),
    FN(skc_to_tcp_request_sock),
    FN(skc_to_udp6_sock),
    FN(get_task_stack),
    FN(sock_ops_load_hdr_opt),
    FN(sock_ops_store_hdr_opt),
    FN(sock_ops_reserve_hdr_opt),
    FN(inode_storage_get),
    FN(inode_storage_delete),
    FN(d_path),
    FN(copy_from_user),
    FN(snprintf_btf),
    FN(seq_printf_btf),
    FN(skb_cgroup_classid),
    FN(redirect_neigh),
    FN(per_cpu_ptr),
    FN(this_cpu_ptr),
    FN(redirect_peer),
    FN(task_storage_get),
    FN(task_storage_delete),
    FN(get_current_task_btf),
    FN(bprm_opts_set),
    FN(ktime_get_coarse_ns),
    FN(ima_inode_hash),
    FN(sock_from_file),
    FN(check_mtu),
    FN(for_each_map_elem),
    FN(snprintf),
    FN(sys_bpf),
    FN(btf_find_by_name_kind),
    FN(sys_close),
    FN(timer_init),
    FN(timer_set_callback),
    FN(timer_start),
    FN(timer_cancel),
    FN(get_func_ip),
    FN(get_attach_cookie),
    FN(task_pt_regs),
    FN(get_branch_snapshot),
    FN(trace_vprintk),
    FN(skc_to_unix_sock),
    FN(kallsyms_lookup_name),
    FN(find_vma),
    FN(loop),
    FN(strncmp),
    FN(get_func_arg),
    FN(get_func_ret),
    FN(get_func_arg_cnt),
};

bool is_helper_usable_linux(const int32_t n) {
    if (n >= (int)(sizeof(prototypes) / sizeof(prototypes[0])) || n < 0) {
        return false;
    }

    // If the helper has a context_descriptor, it must match the hook's context_descriptor.
    if ((prototypes[n].context_descriptor != nullptr) &&
        (prototypes[n].context_descriptor != thread_local_program_info->type.context_descriptor)) {
        return false;
    }

    return true;
}

EbpfHelperPrototype get_helper_prototype_linux(const int32_t n) {
    if (!is_helper_usable_linux(n)) {
        throw std::exception();
    }
    return prototypes[n];
}
} // namespace prevail
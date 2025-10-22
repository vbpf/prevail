#include "platform.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"

namespace prevail {
// Unsupported or partially supported return types

// Returns pointer to struct sock_common or NULL on lookup failure.
// Used by: bpf_sk_lookup_tcp(), bpf_skc_lookup_tcp()
// Requires: BTF type information for socket structures
#define EBPF_RETURN_TYPE_PTR_TO_SOCK_COMMON_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED

// Returns pointer to struct socket (full socket) or NULL.
// Used by: bpf_sk_lookup_udp(), bpf_sk_fullsock()
// Requires: BTF type information, socket state validation
#define EBPF_RETURN_TYPE_PTR_TO_SOCKET_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED

// Returns pointer to struct tcp_sock (TCP-specific socket) or NULL.
// Used by: bpf_tcp_sock(), bpf_get_listener_sock()
// Requires: BTF type information, TCP socket casting validation
#define EBPF_RETURN_TYPE_PTR_TO_TCP_SOCKET_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED

// Returns pointer to dynamically allocated memory or NULL.
// Used by: bpf_ringbuf_reserve()
// Requires: Memory allocation tracking, release validation
// Note: Returned memory must be submitted or discarded, enforced by verifier
#define EBPF_RETURN_TYPE_PTR_TO_ALLOC_MEM_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED

// Returns pointer to kernel object identified by BTF type ID, or NULL.
// Used by: bpf_skc_to_tcp_sock(), bpf_skc_to_tcp6_sock(), bpf_sock_from_file()
// Requires: BTF type information, dynamic type casting validation
// Note: Type ID determines what kernel structure is pointed to
#define EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED

// Returns pointer to either generic memory or BTF-identified object, or NULL.
// Used by: bpf_dynptr_data(), bpf_per_cpu_ptr()
// Requires: BTF for type identification, memory bounds tracking
// Note: Dual nature allows flexibility in return type
#define EBPF_RETURN_TYPE_PTR_TO_MEM_OR_BTF_ID_OR_NULL EBPF_RETURN_TYPE_UNSUPPORTED

// Returns non-NULL pointer to kernel object identified by BTF type ID.
// Used by: bpf_get_current_task_btf(), bpf_task_pt_regs()
// Requires: BTF type information
// Note: Unlike _OR_NULL variant, verifier can assume non-null
#define EBPF_RETURN_TYPE_PTR_TO_BTF_ID EBPF_RETURN_TYPE_UNSUPPORTED

// Returns non-NULL pointer to either generic memory or BTF-identified object.
// Used by: bpf_this_cpu_ptr()
// Requires: BTF for type identification when returning BTF object
// Note: Always succeeds, never returns NULL
#define EBPF_RETURN_TYPE_PTR_TO_MEM_OR_BTF_ID EBPF_RETURN_TYPE_UNSUPPORTED

// Alias: Treat non-nullable map value return as nullable for compatibility.
// Used by: bpf_get_local_storage()
// Reason: Simplifies implementation - both map value return types use same code path
// Note: Helper actually never returns NULL, but type system treats as nullable
#define EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL

// Unsupported or partially supported argument types

// Pointer to struct sock_common identified by BTF.
// Used by: bpf_sk_release(), bpf_sk_cgroup_id(), bpf_tcp_check_syncookie()
// Requires: BTF type information, socket pointer validation
// Note: Base socket type that other socket types derive from
#define EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Pointer to struct bpf_spin_lock within a map value.
// Used by: bpf_spin_lock(), bpf_spin_unlock()
// Requires: BTF to locate lock field, 4-byte alignment validation
// Note: Lock must be at top level of map value struct, cannot be nested
#define EBPF_ARGUMENT_TYPE_PTR_TO_SPIN_LOCK EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Pointer to struct sock_common (non-BTF variant).
// Used by: bpf_sk_fullsock(), bpf_tcp_sock(), bpf_get_listener_sock()
// Requires: Socket type validation, state checking
// Note: Less type-safe than PTR_TO_BTF_ID_SOCK_COMMON
#define EBPF_ARGUMENT_TYPE_PTR_TO_SOCK_COMMON EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Pointer to kernel object identified by BTF type ID.
// Used by: bpf_task_storage_get(), bpf_inode_storage_get(), bpf_tcp_send_ack()
// Requires: BTF type information, type-specific validation
// Note: Generic BTF pointer - actual type determined by helper's BTF ID specification
#define EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Pointer to long integer for output.
// Used by: bpf_strtol(), bpf_strtoul(), bpf_get_func_arg(), bpf_get_func_ret()
// Requires: Writable memory validation, proper alignment (8 bytes)
// Note: Output parameter for functions that return long values
#define EBPF_ARGUMENT_TYPE_PTR_TO_LONG EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Pointer to int for output.
// Used by: bpf_check_mtu() (for mtu_len parameter)
// Requires: Writable memory validation, proper alignment (4 bytes)
// Note: Output parameter for functions that return int values
#define EBPF_ARGUMENT_TYPE_PTR_TO_INT EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Pointer to constant null-terminated string in read-only memory.
// Used by: bpf_strncmp(), bpf_snprintf() (format string)
// Requires: Read-only memory validation, null termination verification
// Note: String must be compile-time constant or from read-only map
#define EBPF_ARGUMENT_TYPE_PTR_TO_CONST_STR EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Pointer to a static BPF function for callbacks.
// Used by: bpf_for_each_map_elem(), bpf_loop(), bpf_timer_set_callback(), bpf_find_vma()
// Requires: Function signature validation, static function verification
// Note: Function must be in same BPF program, cannot be helper or external function
#define EBPF_ARGUMENT_TYPE_PTR_TO_FUNC EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Constant allocation size, zero allowed (for dynamic memory allocation).
// Used by: bpf_ringbuf_reserve() (size parameter)
// Requires: Compile-time constant or bounded value, zero is valid (allocation fails gracefully)
// Note: Used to reserve variable-sized memory chunks
#define EBPF_ARGUMENT_TYPE_CONST_ALLOC_SIZE_OR_ZERO EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Pointer to previously allocated memory (for release operations).
// Used by: bpf_ringbuf_submit(), bpf_ringbuf_discard()
// Requires: Verification that pointer was from bpf_ringbuf_reserve()
// Note: Verifier tracks allocation/release pairing
#define EBPF_ARGUMENT_TYPE_PTR_TO_ALLOC_MEM EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Alias: Allow NULL map value pointers (for optional map value arguments).
// Used by: bpf_sk_storage_get() (value parameter when creating new entry)
// Reason: Simplifies handling - same validation as non-nullable, plus NULL check
// Note: NULL means "use zero-initialized value" for storage creation
#define EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE_OR_NULL EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE

// Pointer to struct bpf_timer within a map value.
// Used by: bpf_timer_init(), bpf_timer_set_callback(), bpf_timer_start(), bpf_timer_cancel()
// Requires: BTF to locate timer field, proper initialization tracking
// Note: Timer must be in map value, similar constraints to spin locks
#define EBPF_ARGUMENT_TYPE_PTR_TO_TIMER EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Pointer to per-CPU BTF-identified object.
// Used by: bpf_per_cpu_ptr() returns this, bpf_this_cpu_ptr()
// Requires: BTF type information, per-CPU variable handling
// Note: Points to per-CPU copy of kernel variable
#define EBPF_ARGUMENT_TYPE_PTR_TO_PERCPU_BTF_ID EBPF_ARGUMENT_TYPE_UNSUPPORTED

// Alias: Modern name for read-only memory pointer.
// Reason: Naming consistency with kernel terminology (readonly vs readable)
// Note: Functionally identical to PTR_TO_READABLE_MEM
#define EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM

// Alias: Modern name for optional read-only memory pointer.
// Reason: Naming consistency with kernel terminology
// Note: Functionally identical to PTR_TO_READABLE_MEM_OR_NULL
#define EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM_OR_NULL EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL

// Alias: Uninitialized map value (output parameter for map operations).
// Used by: bpf_map_pop_elem(), bpf_map_peek_elem()
// Reason: Semantically identical to PTR_TO_MAP_VALUE - memory will be written
// Note: Indicates helper will initialize the memory (pop/peek operations)
#define EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MAP_VALUE EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE

// Alias: Const-qualified map pointer (helper won't modify map structure).
// Used by: bpf_map_peek_elem(), bpf_ringbuf_query() (read-only map operations)
// Reason: Same validation as PTR_TO_MAP - const is semantic documentation
// Note: Indicates helper only reads map metadata, doesn't modify map
#define EBPF_ARGUMENT_TYPE_CONST_PTR_TO_MAP EBPF_ARGUMENT_TYPE_PTR_TO_MAP

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

static constexpr EbpfHelperPrototype bpf_perf_prog_read_value_proto = {
    .name = "perf_prog_read_value",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
    .context_descriptor = &g_perf_event_descr,
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
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE,
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
};

static constexpr EbpfHelperPrototype bpf_map_pop_elem_proto = {
    .name = "map_pop_elem",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MAP_VALUE,
    },
};

static constexpr EbpfHelperPrototype bpf_map_peek_elem_proto = {
    .name = "map_peek_elem",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type{
        EBPF_ARGUMENT_TYPE_CONST_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MAP_VALUE,
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
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
            EBPF_ARGUMENT_TYPE_CONST_SIZE,
        },
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
            EBPF_ARGUMENT_TYPE_CONST_PTR_TO_MAP,
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
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
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
            EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM,
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
};

static constexpr EbpfHelperPrototype bpf_cgrp_storage_delete_proto = {
    .name = "cgrp_storage_delete",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,
        },
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
    .context_descriptor = &g_sk_buff,
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
            EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM, // searchby_res
            EBPF_ARGUMENT_TYPE_CONST_SIZE,          // len
            EBPF_ARGUMENT_TYPE_ANYTHING,            // flags
        },
    .context_descriptor = &g_sock_ops_descr,
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
    .context_descriptor = &g_sock_ops_descr,
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
    .context_descriptor = &g_sock_ops_descr,
};

// Helper 188 - xdp_get_buff_len
static constexpr EbpfHelperPrototype bpf_xdp_get_buff_len_proto = {
    .name = "xdp_get_buff_len",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        },
    .context_descriptor = &g_xdp_md,
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
    .context_descriptor = &g_xdp_md,
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
    .context_descriptor = &g_xdp_md,
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
    .context_descriptor = &g_sk_buff,
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
};

// Helper 194 - kptr_xchg
static constexpr EbpfHelperPrototype bpf_kptr_xchg_proto = {
    .name = "kptr_xchg",
    .return_type = EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL,
    .argument_type =
        {
            EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE, // dst (kptr location)
            EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID,    // ptr (can be NULL)
        },
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

bool is_helper_usable_linux(const int32_t n) {
    if (n >= static_cast<int>(std::size(prototypes)) || n < 0) {
        return false;
    }

    // Check if explicitly marked as unsupported
    if (prototypes[n].unsupported) {
        return false;
    }

    // If the helper has a context_descriptor, it must match the hook's context_descriptor.
    if (prototypes[n].context_descriptor &&
        prototypes[n].context_descriptor != thread_local_program_info->type.context_descriptor) {
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
#pragma once

#include <array>

#include "spec/type_descriptors.hpp"

namespace prevail {
constexpr int NMAPS = 64;
constexpr int NONMAPS = 5;
constexpr int ALL_TYPES = NMAPS + NONMAPS;

// Context struct sizes — verified against kernel 6.14 uapi headers.
// A size is the upper bound every context access is checked against, so it
// must never exceed the object the program actually receives: rounding up
// accepts out-of-bounds accesses. pt_regs is architecture-specific and an
// ELF object does not name its target, so kprobe and perf_event model the
// x86_64 layout; that is merely conservative for targets with a larger
// pt_regs (e.g. arm64), and a platform targeting a smaller one must supply
// its own descriptors.
constexpr int perf_max_trace_size = 2048;
constexpr int ptregs_size = 21 * 8;         // sizeof(pt_regs) on x86_64: r15 through ss
constexpr int cgroup_dev_regions = 12;      // sizeof(bpf_cgroup_dev_ctx): 3 × u32
constexpr int kprobe_regions = ptregs_size; // sizeof(pt_regs)
constexpr int tracepoint_regions = perf_max_trace_size;
constexpr int perf_event_regions = ptregs_size + 2 * 8; // sizeof(bpf_perf_event_data): regs, sample_period, addr
constexpr int sk_skb_regions = 192;                     // sizeof(__sk_buff): 48 fields through hwtstamp
constexpr int xdp_regions = 24;                         // sizeof(xdp_md): 6 × u32, incl. egress_ifindex
constexpr int cgroup_sock_regions = 80;                 // sizeof(bpf_sock): through rx_queue_mapping
constexpr int sock_ops_regions = 224;                   // sizeof(bpf_sock_ops): through skb_hwtstamp
constexpr int sock_addr_regions = 72;                   // sizeof(bpf_sock_addr)
constexpr int sockopt_regions = 40;                     // sizeof(bpf_sockopt)
constexpr int sk_lookup_regions = 72;                   // sizeof(bpf_sk_lookup)
constexpr int sk_reuseport_regions = 56;                // sizeof(sk_reuseport_md)
constexpr int cgroup_sysctl_regions = 8;                // sizeof(bpf_sysctl): 2 × u32
// Tracing, LSM, struct_ops and raw tracepoint programs receive arguments as context:
// an array of u64 values. The kernel allows up to 12 args
// (MAX_BPF_FUNC_ARGS), but typical functions have at most 5.
constexpr int tracing_regions = 12 * 8;
// LIRC_MODE2: context is a single u32 (pulse/space sample).
constexpr int lirc_mode2_regions = 4;
// Netfilter: context is struct bpf_nf_ctx { nf_hook_state*, sk_buff* }.
constexpr int netfilter_regions = 2 * 8;
// Syscall: context is user-supplied buffer, kernel allows up to U16_MAX.
constexpr int syscall_regions = 65535;

constexpr int bpf_sock_bound_dev_if_offset = 0;
constexpr int bpf_sock_family_offset = 4;
constexpr int bpf_sock_src_ip4_offset = 24;
constexpr int bpf_sock_src_ip6_offset = 28;
constexpr int bpf_sock_src_ip6_end = 44;
constexpr int bpf_sock_src_port_offset = 44;
constexpr int bpf_sock_dst_port_offset = 48;
constexpr int bpf_sock_dst_port_end = 50;
constexpr int bpf_sock_dst_ip4_offset = 52;
constexpr int bpf_sock_dst_ip6_offset = 56;
constexpr int bpf_sock_dst_ip6_end = 72;
constexpr int bpf_sock_state_offset = 72;
constexpr int bpf_sock_rx_queue_mapping_offset = 76;
constexpr int bpf_sock_u32_field_size = 4;

constexpr EbpfStructFieldDescriptor readonly_bpf_sock_u32_field(const int offset) {
    return EbpfStructFieldDescriptor{.offset = offset,
                                     .span = bpf_sock_u32_field_size,
                                     .permission = EbpfStructFieldPermission::read_only,
                                     .max_access_width = bpf_sock_u32_field_size,
                                     .allow_narrow_access = true};
}

// Prevail currently collapses Linux's PTR_TO_SOCK_COMMON and PTR_TO_SOCKET into
// one T_SOCKET, so direct socket access uses this common safe field subset. The
// table intentionally excludes the type..priority range and padding bytes.
inline constexpr std::array bpf_sock_common_fields{
    // Unlike the other u32 fields, bound_dev_if does not opt into narrow
    // sub-field reads: it is accepted only at its exact 32-bit width. Narrow
    // access here is intentionally left out of the verified-safe subset, which
    // is conservative (stricter than the kernel only rejects valid programs; it
    // never accepts invalid ones). Widen this to allow_narrow_access if a real
    // program needs sub-word bound_dev_if reads.
    EbpfStructFieldDescriptor{.offset = bpf_sock_bound_dev_if_offset,
                              .span = bpf_sock_u32_field_size,
                              .permission = EbpfStructFieldPermission::read_only,
                              .max_access_width = bpf_sock_u32_field_size},
    readonly_bpf_sock_u32_field(bpf_sock_family_offset),
    readonly_bpf_sock_u32_field(bpf_sock_src_ip4_offset),
    EbpfStructFieldDescriptor{.offset = bpf_sock_src_ip6_offset,
                              .span = bpf_sock_src_ip6_end - bpf_sock_src_ip6_offset,
                              .permission = EbpfStructFieldPermission::read_only,
                              .max_access_width = bpf_sock_u32_field_size,
                              .allow_narrow_access = true},
    readonly_bpf_sock_u32_field(bpf_sock_src_port_offset),
    EbpfStructFieldDescriptor{.offset = bpf_sock_dst_port_offset,
                              .span = bpf_sock_dst_port_end - bpf_sock_dst_port_offset,
                              .permission = EbpfStructFieldPermission::read_only,
                              .max_access_width = bpf_sock_dst_port_end - bpf_sock_dst_port_offset,
                              .allow_narrow_access = true,
                              // The kernel permits a 32-bit read starting at
                              // dst_port although the logical field is 16 bits.
                              .extra_read_width_at_start = bpf_sock_u32_field_size},
    readonly_bpf_sock_u32_field(bpf_sock_dst_ip4_offset),
    EbpfStructFieldDescriptor{.offset = bpf_sock_dst_ip6_offset,
                              .span = bpf_sock_dst_ip6_end - bpf_sock_dst_ip6_offset,
                              .permission = EbpfStructFieldPermission::read_only,
                              .max_access_width = bpf_sock_u32_field_size,
                              .allow_narrow_access = true},
    readonly_bpf_sock_u32_field(bpf_sock_state_offset),
    readonly_bpf_sock_u32_field(bpf_sock_rx_queue_mapping_offset),
};

inline constexpr EbpfStructDescriptor bpf_sock_common_layout{
    .size = cgroup_sock_regions, .fields = bpf_sock_common_fields.data(), .field_count = bpf_sock_common_fields.size()};

// Context layouts: the accesses that each program type's is_valid_access() admits in Linux, which rewrites a
// context access into an access to the kernel object behind the field at its offset.

// bpf_perf_event_data (pe_prog_is_valid_access, pe_prog_convert_ctx_access): every load outside sample_period
// and addr runs as a load of a whole word of the interrupted pt_regs, so only those are admitted; the two
// u64 fields are loaded whole and then narrowed, so they admit narrow loads.
inline constexpr std::array bpf_perf_event_data_fields{
    array_of(exact_field(0, 8), ptregs_size / 8),
    narrow_field(ptregs_size, 8),     // sample_period
    narrow_field(ptregs_size + 8, 8), // addr
};
inline constexpr EbpfStructDescriptor bpf_perf_event_data_layout{.size = perf_event_regions,
                                                                 .fields = bpf_perf_event_data_fields.data(),
                                                                 .field_count = bpf_perf_event_data_fields.size()};

constexpr ebpf_ctx_descriptor_t sk_buff = {sk_skb_regions, 76, 80, 140}; // data/data_end/data_meta
// __sk_buff outside tc: Linux rejects data_meta for these program types, and the
// cgroup_skb, sk_skb and socket_filter entry points never compute the pointer
// behind it (the slot holds unrelated skb->cb bytes), so it must not be typed
// as a packet pointer.
constexpr ebpf_ctx_descriptor_t sk_buff_no_meta = {sk_skb_regions, 76, 80, -1};
constexpr ebpf_ctx_descriptor_t xdp_md = {xdp_regions, 0, 4, 8}; // data/data_end/data_meta
constexpr ebpf_ctx_descriptor_t sk_msg_md = {80, 0, 8, -1};      // sizeof(sk_msg_md), data/data_end
constexpr ebpf_ctx_descriptor_t unspec_descr = {0, -1, -1, -1};
// Four kinds of context are arrays of u64 of this one size. They differ in what lies around the array, and so in
// the helpers that may be handed the context. A helper names the context it works on by the address of the
// descriptor (is_helper_usable_linux()), so each kind has a descriptor object of its own.
//
// The arguments of a traced function or of an LSM hook, saved by a BPF trampoline (fentry, fexit, fmod_ret, lsm).
// The trampoline stores the number of arguments in the word in front of the array and, where the program runs
// after the function, the function's result in the word behind it. bpf_get_func_arg(), bpf_get_func_arg_cnt()
// and bpf_get_func_ret() read those words.
constexpr ebpf_ctx_descriptor_t tracing_descr = {tracing_regions, -1, -1, -1};
// The arguments of a tracepoint, which bpf_trace_run<N>() collects in a local array of its own for a
// raw_tracepoint, raw_tracepoint_writable or tp_btf program. No count precedes that array and no result follows
// it: the words around it are whatever else the frame holds.
constexpr ebpf_ctx_descriptor_t raw_tracepoint_descr = {tracing_regions, -1, -1, -1};
// struct bpf_iter__<target>: a pointer to the metadata of the iteration, then pointers to the object visited.
constexpr ebpf_ctx_descriptor_t iter_descr = {tracing_regions, -1, -1, -1};
// The arguments of the kernel callback that a struct_ops program implements. The program is the callback: no
// function is traced, and no result of one lies behind the array.
constexpr ebpf_ctx_descriptor_t struct_ops_descr = {tracing_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t lirc_mode2_descr = {lirc_mode2_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t netfilter_descr = {netfilter_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t syscall_descr = {syscall_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t cgroup_dev_descr = {cgroup_dev_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t kprobe_descr = {kprobe_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t tracepoint_descr = {tracepoint_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t perf_event_descr = {perf_event_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t cgroup_sock_descr = {cgroup_sock_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t sock_ops_descr = {sock_ops_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t sock_addr_descr = {sock_addr_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t sockopt_descr = {sockopt_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t sk_lookup_descr = {sk_lookup_regions, -1, -1, -1};
constexpr ebpf_ctx_descriptor_t sk_reuseport_descr = {sk_reuseport_regions, 0, 1 * 8, -1};
constexpr ebpf_ctx_descriptor_t cgroup_sysctl_descr = {cgroup_sysctl_regions, -1, -1, -1};
// flow_dissector uses __sk_buff layout but without data_meta.
constexpr ebpf_ctx_descriptor_t flow_dissector_descr = {sk_skb_regions, 76, 80, -1};

extern const ebpf_ctx_descriptor_t g_sk_buff;
extern const ebpf_ctx_descriptor_t g_sk_buff_no_meta;
extern const ebpf_ctx_descriptor_t g_xdp_md;
extern const ebpf_ctx_descriptor_t g_sk_msg_md;
extern const ebpf_ctx_descriptor_t g_unspec_descr;
extern const ebpf_ctx_descriptor_t g_tracing_descr;
extern const ebpf_ctx_descriptor_t g_raw_tracepoint_descr;
extern const ebpf_ctx_descriptor_t g_iter_descr;
extern const ebpf_ctx_descriptor_t g_struct_ops_descr;
extern const ebpf_ctx_descriptor_t g_lirc_mode2_descr;
extern const ebpf_ctx_descriptor_t g_netfilter_descr;
extern const ebpf_ctx_descriptor_t g_syscall_descr;
extern const ebpf_ctx_descriptor_t g_cgroup_dev_descr;
extern const ebpf_ctx_descriptor_t g_kprobe_descr;
extern const ebpf_ctx_descriptor_t g_tracepoint_descr;
extern const ebpf_ctx_descriptor_t g_perf_event_descr;
extern const ebpf_ctx_descriptor_t g_cgroup_sock_descr;
extern const ebpf_ctx_descriptor_t g_sock_ops_descr;
extern const ebpf_ctx_descriptor_t g_sock_addr_descr;
extern const ebpf_ctx_descriptor_t g_sockopt_descr;
extern const ebpf_ctx_descriptor_t g_sk_lookup_descr;
extern const ebpf_ctx_descriptor_t g_sk_reuseport_descr;
extern const ebpf_ctx_descriptor_t g_cgroup_sysctl_descr;
extern const ebpf_ctx_descriptor_t g_flow_dissector_descr;

// The following all use the __sk_buff context struct; only tc programs get data_meta.
#define g_sched_descr g_sk_buff
#define g_socket_filter_descr g_sk_buff_no_meta
#define g_lwt_xmit_descr g_sk_buff_no_meta
#define g_lwt_inout_descr g_sk_buff_no_meta
#define g_sk_skb_descr g_sk_buff_no_meta

// And these were also interchangeable.
#define g_xdp_descr g_xdp_md

} // namespace prevail

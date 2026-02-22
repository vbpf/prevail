#pragma once
#include "spec/ebpf_base.h"

namespace prevail {
constexpr int NMAPS = 64;
constexpr int NONMAPS = 5;
constexpr int ALL_TYPES = NMAPS + NONMAPS;

// Context struct sizes — verified against kernel 6.14 uapi headers.
// kprobe and perf_event use a cross-arch upper bound for pt_regs.
constexpr int perf_max_trace_size = 2048;
constexpr int ptregs_size = (3 + 63 + 8 + 2) * 8; // cross-arch upper bound
constexpr int cgroup_dev_regions = 12;            // sizeof(bpf_cgroup_dev_ctx): 3 × u32
constexpr int kprobe_regions = ptregs_size;       // cross-arch upper bound (x86_64 actual: 168)
constexpr int tracepoint_regions = perf_max_trace_size;
constexpr int perf_event_regions = 3 * 8 + ptregs_size; // cross-arch upper bound (x86_64 actual: 184)
constexpr int sk_skb_regions = 192;                     // sizeof(__sk_buff): 48 fields through hwtstamp
constexpr int xdp_regions = 24;                         // sizeof(xdp_md): 6 × u32, incl. egress_ifindex
constexpr int cgroup_sock_regions = 80;                 // sizeof(bpf_sock): through rx_queue_mapping
constexpr int sock_ops_regions = 224;                   // sizeof(bpf_sock_ops): through skb_hwtstamp
constexpr int sock_addr_regions = 72;                   // sizeof(bpf_sock_addr)
constexpr int sockopt_regions = 40;                     // sizeof(bpf_sockopt)
constexpr int sk_lookup_regions = 72;                   // sizeof(bpf_sk_lookup)
constexpr int sk_reuseport_regions = 56;                // sizeof(sk_reuseport_md)
constexpr int cgroup_sysctl_regions = 8;                // sizeof(bpf_sysctl): 2 × u32
// Tracing/LSM/struct_ops programs receive function arguments as context:
// an array of u64 values. The kernel allows up to 12 args
// (MAX_BPF_FUNC_ARGS), but typical functions have at most 5.
constexpr int tracing_regions = 12 * 8;
// LIRC_MODE2: context is a single u32 (pulse/space sample).
constexpr int lirc_mode2_regions = 4;
// Netfilter: context is struct bpf_nf_ctx { nf_hook_state*, sk_buff* }.
constexpr int netfilter_regions = 2 * 8;
// Syscall: context is user-supplied buffer, kernel allows up to U16_MAX.
constexpr int syscall_regions = 65535;

constexpr ebpf_context_descriptor_t sk_buff = {sk_skb_regions, 76, 80, 140}; // data/data_end/data_meta
constexpr ebpf_context_descriptor_t xdp_md = {xdp_regions, 0, 4, 8};         // data/data_end/data_meta
constexpr ebpf_context_descriptor_t sk_msg_md = {80, 0, 8, -1};              // sizeof(sk_msg_md), data/data_end
constexpr ebpf_context_descriptor_t unspec_descr = {0, -1, -1, -1};
constexpr ebpf_context_descriptor_t tracing_descr = {tracing_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t lirc_mode2_descr = {lirc_mode2_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t netfilter_descr = {netfilter_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t syscall_descr = {syscall_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t cgroup_dev_descr = {cgroup_dev_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t kprobe_descr = {kprobe_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t tracepoint_descr = {tracepoint_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t perf_event_descr = {perf_event_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t cgroup_sock_descr = {cgroup_sock_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t sock_ops_descr = {sock_ops_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t sock_addr_descr = {sock_addr_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t sockopt_descr = {sockopt_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t sk_lookup_descr = {sk_lookup_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t sk_reuseport_descr = {sk_reuseport_regions, 0, 1 * 8, -1};
constexpr ebpf_context_descriptor_t cgroup_sysctl_descr = {cgroup_sysctl_regions, -1, -1, -1};
// flow_dissector uses __sk_buff layout but without data_meta.
constexpr ebpf_context_descriptor_t flow_dissector_descr = {sk_skb_regions, 76, 80, -1};

extern const ebpf_context_descriptor_t g_sk_buff;
extern const ebpf_context_descriptor_t g_xdp_md;
extern const ebpf_context_descriptor_t g_sk_msg_md;
extern const ebpf_context_descriptor_t g_unspec_descr;
extern const ebpf_context_descriptor_t g_tracing_descr;
extern const ebpf_context_descriptor_t g_lirc_mode2_descr;
extern const ebpf_context_descriptor_t g_netfilter_descr;
extern const ebpf_context_descriptor_t g_syscall_descr;
extern const ebpf_context_descriptor_t g_cgroup_dev_descr;
extern const ebpf_context_descriptor_t g_kprobe_descr;
extern const ebpf_context_descriptor_t g_tracepoint_descr;
extern const ebpf_context_descriptor_t g_perf_event_descr;
extern const ebpf_context_descriptor_t g_cgroup_sock_descr;
extern const ebpf_context_descriptor_t g_sock_ops_descr;
extern const ebpf_context_descriptor_t g_sock_addr_descr;
extern const ebpf_context_descriptor_t g_sockopt_descr;
extern const ebpf_context_descriptor_t g_sk_lookup_descr;
extern const ebpf_context_descriptor_t g_sk_reuseport_descr;
extern const ebpf_context_descriptor_t g_cgroup_sysctl_descr;
extern const ebpf_context_descriptor_t g_flow_dissector_descr;

// The following all use the __sk_buff context struct (with data/data_end/data_meta).
#define g_socket_filter_descr g_sk_buff
#define g_sched_descr g_sk_buff
#define g_lwt_xmit_descr g_sk_buff
#define g_lwt_inout_descr g_sk_buff
#define g_sk_skb_descr g_sk_buff

// And these were also interchangeable.
#define g_xdp_descr g_xdp_md

} // namespace prevail

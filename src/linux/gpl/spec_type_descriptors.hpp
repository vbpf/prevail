#pragma once
#include "spec/ebpf_base.h"

namespace prevail {
constexpr int NMAPS = 64;
constexpr int NONMAPS = 5;
constexpr int ALL_TYPES = NMAPS + NONMAPS;

// rough estimates:
constexpr int perf_max_trace_size = 2048;
constexpr int ptregs_size = (3 + 63 + 8 + 2) * 8;
constexpr int cgroup_dev_regions = 3 * 4;
constexpr int kprobe_regions = ptregs_size;
constexpr int tracepoint_regions = perf_max_trace_size;
constexpr int perf_event_regions = 3 * 8 + ptregs_size;
constexpr int socket_filter_regions = 24 * 4;
constexpr int sched_regions = 24 * 4;
constexpr int xdp_regions = 5 * 4;
constexpr int lwt_regions = 24 * 4;
constexpr int cgroup_sock_regions = 12 * 4;
constexpr int sock_ops_regions = 42 * 4 + 2 * 8;
constexpr int sk_skb_regions = 36 * 4;
constexpr int sock_addr_regions = 72;
constexpr int sockopt_regions = 40;
constexpr int sk_lookup_regions = 72;
constexpr int sk_reuseport_regions = 56;
constexpr int flow_dissector_regions = 56;
constexpr int cgroup_sysctl_regions = 8;

constexpr ebpf_context_descriptor_t sk_buff = {sk_skb_regions, 19 * 4, 20 * 4, 35 * 4};
constexpr ebpf_context_descriptor_t xdp_md = {xdp_regions, 0, 1 * 4, 2 * 4};
constexpr ebpf_context_descriptor_t sk_msg_md = {17 * 4, 0, 1 * 8, -1}; // TODO: verify
constexpr ebpf_context_descriptor_t unspec_descr = {0, -1, -1, -1};
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
constexpr ebpf_context_descriptor_t flow_dissector_descr = {flow_dissector_regions, -1, -1, -1};
constexpr ebpf_context_descriptor_t cgroup_sysctl_descr = {cgroup_sysctl_regions, -1, -1, -1};

extern const ebpf_context_descriptor_t g_sk_buff;
extern const ebpf_context_descriptor_t g_xdp_md;
extern const ebpf_context_descriptor_t g_sk_msg_md;
extern const ebpf_context_descriptor_t g_unspec_descr;
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
extern const ebpf_context_descriptor_t g_flow_dissector_descr;
extern const ebpf_context_descriptor_t g_cgroup_sysctl_descr;

// The following all used the sk_buff descriptor and so the ctx is apparently interchangeable.
#define g_socket_filter_descr g_sk_buff
#define g_sched_descr g_sk_buff
#define g_lwt_xmit_descr g_sk_buff
#define g_lwt_inout_descr g_sk_buff
#define g_sk_skb_descr g_sk_buff

// And these were also interchangeable.
#define g_xdp_descr g_xdp_md

} // namespace prevail

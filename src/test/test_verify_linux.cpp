// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// Auto-generated test file for project: linux
#include "test_verify.hpp"

TEST_CASE("linux/cpustat_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"cpustat_kern.o",
                                   {
                                       {.section = "tracepoint/power/cpu_idle"},
                                       {.section = "tracepoint/power/cpu_frequency"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/lathist_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"lathist_kern.o",
                                   {
                                       {.section = "kprobe/trace_preempt_off"},
                                       {.section = "kprobe/trace_preempt_on"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/lwt_len_hist_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"lwt_len_hist_kern.o",
                                   {
                                       {.section = "len_hist"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/map_perf_test_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"map_perf_test_kern.o",
                                   {
                                       {.section = "kprobe/sys_getuid"},
                                       {.section = "kprobe/sys_geteuid"},
                                       {.section = "kprobe/sys_getgid"},
                                       {.section = "kprobe/sys_getegid"},
                                       {.section = "kprobe/sys_connect"},
                                       {.section = "kprobe/sys_gettid"},
                                       {.section = "kprobe/sys_getpgid"},
                                       {.section = "kprobe/sys_getppid"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/offwaketime_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"offwaketime_kern.o",
                                   {
                                       {.section = "kprobe/try_to_wake_up"},
                                       {.section = "tracepoint/sched/sched_switch"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/sampleip_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"sampleip_kern.o",
                                   {
                                       {.section = "perf_event"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/sock_flags_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"sock_flags_kern.o",
                                   {
                                       {.section = "cgroup/sock1"},
                                       {.section = "cgroup/sock2"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/sockex1_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"sockex1_kern.o",
                                   {
                                       {.section = "socket1"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/sockex2_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"sockex2_kern.o",
                                   {
                                       {.section = "socket2"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/sockex3_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"sockex3_kern.o",
                                   {
                                       {.section = "socket/3"},
                                       {.section = "socket/4"},
                                       {.section = "socket/1"},
                                       {.section = "socket/2"},
                                       {.section = "socket/0"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/spintest_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"spintest_kern.o",
                                   {
                                       {.section = "kprobe/spin_unlock"},
                                       {.section = "kprobe/spin_lock"},
                                       {.section = "kprobe/mutex_spin_on_owner"},
                                       {.section = "kprobe/rwsem_spin_on_owner"},
                                       {.section = "kprobe/spin_unlock_irqrestore"},
                                       {.section = "kprobe/_raw_spin_unlock_irqrestore"},
                                       {.section = "kprobe/_raw_spin_unlock_bh"},
                                       {.section = "kprobe/_raw_spin_unlock"},
                                       {.section = "kprobe/_raw_spin_lock_irqsave"},
                                       {.section = "kprobe/_raw_spin_trylock_bh"},
                                       {.section = "kprobe/_raw_spin_lock_irq"},
                                       {.section = "kprobe/_raw_spin_trylock"},
                                       {.section = "kprobe/_raw_spin_lock"},
                                       {.section = "kprobe/_raw_spin_lock_bh"},
                                       {.section = "kprobe/htab_map_update_elem"},
                                       {.section = "kprobe/__htab_percpu_map_update_elem"},
                                       {.section = "kprobe/htab_map_alloc"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/syscall_tp_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"syscall_tp_kern.o",
                                   {
                                       {.section = "tracepoint/syscalls/sys_enter_open"},
                                       {.section = "tracepoint/syscalls/sys_exit_open"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/task_fd_query_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"task_fd_query_kern.o",
                                   {
                                       {.section = "kprobe/blk_start_request"},
                                       {.section = "kretprobe/blk_account_io_completion"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tc_l2_redirect_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tc_l2_redirect_kern.o",
                                   {
                                       {.section = "l2_to_iptun_ingress_forward"},
                                       {.section = "l2_to_iptun_ingress_redirect"},
                                       {.section = "l2_to_ip6tun_ingress_redirect"},
                                       {.section = "drop_non_tun_vip"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tcbpf1_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tcbpf1_kern.o",
                                   {
                                       {.section = "classifier"},
                                       {.section = "redirect_xmit"},
                                       {.section = "redirect_recv"},
                                       {.section = "clone_redirect_xmit"},
                                       {.section = "clone_redirect_recv"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tcp_basertt_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tcp_basertt_kern.o",
                                   {
                                       {.section = "sockops"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tcp_bufs_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tcp_bufs_kern.o",
                                   {
                                       {.section = "sockops"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tcp_clamp_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tcp_clamp_kern.o",
                                   {
                                       {.section = "sockops"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tcp_cong_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tcp_cong_kern.o",
                                   {
                                       {.section = "sockops"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tcp_iw_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tcp_iw_kern.o",
                                   {
                                       {.section = "sockops"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tcp_rwnd_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tcp_rwnd_kern.o",
                                   {
                                       {.section = "sockops"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tcp_synrto_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tcp_synrto_kern.o",
                                   {
                                       {.section = "sockops"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/test_cgrp2_tc_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"test_cgrp2_tc_kern.o",
                                   {
                                       {.section = "filter"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/test_current_task_under_cgroup_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"test_current_task_under_cgroup_kern.o",
                                   {
                                       {.section = "kprobe/sys_sync"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/test_map_in_map_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"test_map_in_map_kern.o",
                                   {
                                       {.section = "kprobe/sys_connect", .expect = Expect::Xfail},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/test_overhead_kprobe_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"test_overhead_kprobe_kern.o",
                                   {
                                       {.section = "kprobe/__set_task_comm"},
                                       {.section = "kprobe/urandom_read"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/test_overhead_raw_tp_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"test_overhead_raw_tp_kern.o",
                                   {
                                       {.section = "raw_tracepoint/task_rename"},
                                       {.section = "raw_tracepoint/urandom_read"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/test_overhead_tp_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"test_overhead_tp_kern.o",
                                   {
                                       {.section = "tracepoint/task/task_rename"},
                                       {.section = "tracepoint/random/urandom_read"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/test_probe_write_user_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"test_probe_write_user_kern.o",
                                   {
                                       {.section = "kprobe/sys_connect"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/trace_event_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"trace_event_kern.o",
                                   {
                                       {.section = "perf_event"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/trace_output_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"trace_output_kern.o",
                                   {
                                       {.section = "kprobe/sys_write"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tracex1_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tracex1_kern.o",
                                   {
                                       {.section = "kprobe/__netif_receive_skb_core"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tracex2_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tracex2_kern.o",
                                   {
                                       {.section = "kprobe/kfree_skb"},
                                       {.section = "kprobe/sys_write"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tracex3_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tracex3_kern.o",
                                   {
                                       {.section = "kprobe/blk_start_request"},
                                       {.section = "kprobe/blk_account_io_completion"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tracex4_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tracex4_kern.o",
                                   {
                                       {.section = "kprobe/kmem_cache_free"},
                                       {.section = "kretprobe/kmem_cache_alloc_node"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tracex5_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tracex5_kern.o",
                                   {
                                       {.section = "kprobe/__seccomp_filter"},
                                       {.section = "kprobe/1"},
                                       {.section = "kprobe/0"},
                                       {.section = "kprobe/9"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tracex6_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tracex6_kern.o",
                                   {
                                       {.section = "kprobe/htab_map_get_next_key"},
                                       {.section = "kprobe/htab_map_lookup_elem"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/tracex7_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"tracex7_kern.o",
                                   {
                                       {.section = "kprobe/open_ctree"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp1_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp1_kern.o",
                                   {
                                       {.section = "xdp1"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp2_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp2_kern.o",
                                   {
                                       {.section = "xdp1"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp2skb_meta_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp2skb_meta_kern.o",
                                   {
                                       {.section = "xdp_mark"},
                                       {.section = "tc_mark"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp_adjust_tail_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp_adjust_tail_kern.o",
                                   {
                                       {.section = "xdp_icmp"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp_fwd_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp_fwd_kern.o",
                                   {
                                       {.section = "xdp_fwd"},
                                       {.section = "xdp_fwd_direct"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp_monitor_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp_monitor_kern.o",
                                   {
                                       {.section = "tracepoint/xdp/xdp_redirect_err"},
                                       {.section = "tracepoint/xdp/xdp_redirect_map_err"},
                                       {.section = "tracepoint/xdp/xdp_redirect"},
                                       {.section = "tracepoint/xdp/xdp_redirect_map"},
                                       {.section = "tracepoint/xdp/xdp_exception"},
                                       {.section = "tracepoint/xdp/xdp_cpumap_enqueue"},
                                       {.section = "tracepoint/xdp/xdp_cpumap_kthread"},
                                       {.section = "tracepoint/xdp/xdp_devmap_xmit"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp_redirect_cpu_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp_redirect_cpu_kern.o",
                                   {
                                       {.section = "xdp_cpu_map0"},
                                       {.section = "xdp_cpu_map1_touch_data"},
                                       {.section = "xdp_cpu_map2_round_robin"},
                                       {.section = "xdp_cpu_map3_proto_separate"},
                                       {.section = "xdp_cpu_map4_ddos_filter_pktgen"},
                                       {.section = "xdp_cpu_map5_lb_hash_ip_pairs"},
                                       {.section = "tracepoint/xdp/xdp_redirect_err"},
                                       {.section = "tracepoint/xdp/xdp_redirect_map_err"},
                                       {.section = "tracepoint/xdp/xdp_exception"},
                                       {.section = "tracepoint/xdp/xdp_cpumap_enqueue"},
                                       {.section = "tracepoint/xdp/xdp_cpumap_kthread"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp_redirect_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp_redirect_kern.o",
                                   {
                                       {.section = "xdp_redirect"},
                                       {.section = "xdp_redirect_dummy"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp_redirect_map_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp_redirect_map_kern.o",
                                   {
                                       {.section = "xdp_redirect_map"},
                                       {.section = "xdp_redirect_dummy"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp_router_ipv4_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp_router_ipv4_kern.o",
                                   {
                                       {.section = "xdp_router_ipv4"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp_rxq_info_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp_rxq_info_kern.o",
                                   {
                                       {.section = "xdp_prog0"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp_sample_pkts_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp_sample_pkts_kern.o",
                                   {
                                       {.section = "xdp_sample"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdp_tx_iptunnel_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdp_tx_iptunnel_kern.o",
                                   {
                                       {.section = "xdp_tx_iptunnel"},
                                   }};
    verify_file("linux", file);
}

TEST_CASE("linux/xdpsock_kern.o", "[verify][samples][linux]") {
    static const FileEntry file = {"xdpsock_kern.o",
                                   {
                                       {.section = "xdp_sock"},
                                   }};
    verify_file("linux", file);
}

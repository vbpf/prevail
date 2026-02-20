// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// Auto-generated test file for project: prototype-kernel
#include "test_verify.hpp"

TEST_CASE("prototype-kernel/napi_monitor_kern.o", "[verify][samples][prototype-kernel]") {
    static const FileEntry file = {"napi_monitor_kern.o",
                                   {
                                       {.section = "tracepoint/napi/napi_poll"},
                                       {.section = "tracepoint/irq/softirq_entry"},
                                       {.section = "tracepoint/irq/softirq_exit"},
                                       {.section = "tracepoint/irq/softirq_raise"},
                                   }};
    verify_file("prototype-kernel", file);
}

TEST_CASE("prototype-kernel/tc_bench01_redirect_kern.o", "[verify][samples][prototype-kernel]") {
    static const FileEntry file = {"tc_bench01_redirect_kern.o",
                                   {
                                       {.section = "ingress_redirect"},
                                   }};
    verify_file("prototype-kernel", file);
}

TEST_CASE("prototype-kernel/xdp_bench01_mem_access_cost_kern.o", "[verify][samples][prototype-kernel]") {
    static const FileEntry file = {"xdp_bench01_mem_access_cost_kern.o",
                                   {
                                       {.section = "xdp_bench01"},
                                   }};
    verify_file("prototype-kernel", file);
}

TEST_CASE("prototype-kernel/xdp_bench02_drop_pattern_kern.o", "[verify][samples][prototype-kernel]") {
    static const FileEntry file = {"xdp_bench02_drop_pattern_kern.o",
                                   {
                                       {.section = "xdp_bench02"},
                                   }};
    verify_file("prototype-kernel", file);
}

TEST_CASE("prototype-kernel/xdp_ddos01_blacklist_kern.o", "[verify][samples][prototype-kernel]") {
    static const FileEntry file = {"xdp_ddos01_blacklist_kern.o",
                                   {
                                       {.section = ".text", .expect = Expect::Xfail},
                                       {.section = "xdp_prog", .expect = Expect::Xfail},
                                   }};
    verify_file("prototype-kernel", file);
}

TEST_CASE("prototype-kernel/xdp_monitor_kern.o", "[verify][samples][prototype-kernel]") {
    static const FileEntry file = {"xdp_monitor_kern.o",
                                   {
                                       {.section = "tracepoint/xdp/xdp_redirect_err"},
                                       {.section = "tracepoint/xdp/xdp_redirect_map_err"},
                                       {.section = "tracepoint/xdp/xdp_redirect"},
                                       {.section = "tracepoint/xdp/xdp_redirect_map"},
                                   }};
    verify_file("prototype-kernel", file);
}

TEST_CASE("prototype-kernel/xdp_redirect_cpu_kern.o", "[verify][samples][prototype-kernel]") {
    static const FileEntry file = {"xdp_redirect_cpu_kern.o",
                                   {
                                       {.section = "xdp_cpu_map0"},
                                       {.section = "xdp_cpu_map1_touch_data"},
                                       {.section = "xdp_cpu_map2_round_robin"},
                                       {.section = "xdp_cpu_map3_proto_separate"},
                                       {.section = "xdp_cpu_map4_ddos_filter_pktgen"},
                                       {.section = "xdp_cpu_map5_ip_l3_flow_hash"},
                                       {.section = "tracepoint/xdp/xdp_redirect_err"},
                                       {.section = "tracepoint/xdp/xdp_redirect_map_err"},
                                       {.section = "tracepoint/xdp/xdp_exception"},
                                       {.section = "tracepoint/xdp/xdp_cpumap_enqueue"},
                                       {.section = "tracepoint/xdp/xdp_cpumap_kthread"},
                                   }};
    verify_file("prototype-kernel", file);
}

TEST_CASE("prototype-kernel/xdp_redirect_err_kern.o", "[verify][samples][prototype-kernel]") {
    static const FileEntry file = {"xdp_redirect_err_kern.o",
                                   {
                                       {.section = "xdp_redirect_map"},
                                       {.section = "xdp_redirect_dummy"},
                                       {.section = "xdp_redirect_map_rr"},
                                   }};
    verify_file("prototype-kernel", file);
}

TEST_CASE("prototype-kernel/xdp_tcpdump_kern.o", "[verify][samples][prototype-kernel]") {
    static const FileEntry file = {"xdp_tcpdump_kern.o",
                                   {
                                       {.section = "xdp_tcpdump_to_perf_ring"},
                                   }};
    verify_file("prototype-kernel", file);
}

TEST_CASE("prototype-kernel/xdp_ttl_kern.o", "[verify][samples][prototype-kernel]") {
    static const FileEntry file = {"xdp_ttl_kern.o",
                                   {
                                       {.section = "xdp_ttl"},
                                   }};
    verify_file("prototype-kernel", file);
}

TEST_CASE("prototype-kernel/xdp_vlan01_kern.o", "[verify][samples][prototype-kernel]") {
    static const FileEntry file = {"xdp_vlan01_kern.o",
                                   {
                                       {.section = "xdp_drop_vlan_4011"},
                                       {.section = "xdp_vlan_change"},
                                       {.section = "xdp_vlan_remove_outer"},
                                       {.section = "xdp_vlan_remove_outer2"},
                                       {.section = "tc_vlan_push"},
                                   }};
    verify_file("prototype-kernel", file);
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT-core
#include "test_verify.hpp"

TEST_CASE("cilium-core/bpf_alignchecker.o", "[verify][samples][cilium-core]") {
    static const FileEntry file = {"bpf_alignchecker.o",
                                   {
                                       {.section = "tc/tail", .function = "tail_icmp6_send_time_exceeded", .count = 2},
                                       {.section = "tc/tail", .function = "tail_icmp6_handle_ns", .count = 2},
                                   }};
    verify_file("cilium-core", file);
}

TEST_CASE("cilium-core/bpf_host.o", "[verify][samples][cilium-core]") {
    static const FileEntry file = {
        "bpf_host.o",
        {
            {.section = ".text", .function = "__check_eth_header_length", .count = 2, .expect = Expect::Xfail},
            {.section = ".text", .function = "__check_device_mtu", .count = 2, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_drop_notify", .count = 28},
            {.section = "tc/tail", .function = "tail_icmp6_send_time_exceeded", .count = 28},
            {.section = "tc/tail", .function = "tail_icmp6_handle_ns", .count = 28},
            {.section = "tc/tail", .function = "tail_srv6_encap", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_srv6_decap", .count = 28},
            {.section = "tc/tail", .function = "tail_nodeport_ipv6_dsr", .count = 28},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_ingress_ipv6", .count = 28},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_egress_ipv6", .count = 28},
            {.section = "tc/tail", .function = "tail_nodeport_nat_ingress_ipv6", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_nodeport_nat_egress_ipv6", .count = 28},
            {.section = "tc/tail", .function = "tail_nodeport_ipv4_dsr", .count = 28},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_ipv4", .count = 28},
            {.section = "tc/tail", .function = "tail_nodeport_nat_ingress_ipv4", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_nodeport_nat_egress_ipv4", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_snat_fwd_ipv6", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_nat_fwd_ipv6", .count = 28},
            {.section = "tc/tail", .function = "tail_handle_snat_fwd_ipv4", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_nat_fwd_ipv4", .count = 28},
            {.section = "tc/tail", .function = "tail_handle_ipv6_cont_from_host", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/tail",
             .function = "tail_handle_ipv6_cont_from_netdev",
             .count = 28,
             .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_ipv6_from_host", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_ipv6_from_netdev", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_ipv4_cont_from_host", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/tail",
             .function = "tail_handle_ipv4_cont_from_netdev",
             .count = 28,
             .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_ipv4_from_host", .count = 28},
            {.section = "tc/tail", .function = "tail_handle_ipv4_from_netdev", .count = 28},
            {.section = "tc/tail", .function = "tail_ipv6_host_policy_ingress", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_ipv4_host_policy_ingress", .count = 28, .expect = Expect::Xfail},
            {.section = "tc/entry", .function = "cil_from_netdev", .count = 5, .expect = Expect::Xfail},
            {.section = "tc/entry", .function = "cil_from_host", .count = 5, .expect = Expect::Xfail},
            {.section = "tc/entry", .function = "cil_to_netdev", .count = 5, .expect = Expect::Xfail},
            {.section = "tc/entry", .function = "cil_to_host", .count = 5, .expect = Expect::Xfail},
            {.section = "tc/entry", .function = "cil_host_policy", .count = 5, .expect = Expect::Xfail},
        }};
    verify_file("cilium-core", file);
}

TEST_CASE("cilium-core/bpf_lxc.o", "[verify][samples][cilium-core]") {
    static const FileEntry file = {
        "bpf_lxc.o",
        {
            {.section = ".text", .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_drop_notify", .count = 30},
            {.section = "tc/tail", .function = "tail_icmp6_send_time_exceeded", .count = 30},
            {.section = "tc/tail", .function = "tail_icmp6_handle_ns", .count = 30},
            {.section = "tc/tail", .function = "tail_srv6_encap", .count = 30},
            {.section = "tc/tail", .function = "tail_srv6_decap", .count = 30},
            {.section = "tc/tail", .function = "tail_nodeport_ipv6_dsr", .count = 30},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_ingress_ipv6", .count = 30},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_egress_ipv6", .count = 30},
            {.section = "tc/tail", .function = "tail_nodeport_nat_ingress_ipv6", .count = 30, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_nodeport_nat_egress_ipv6", .count = 30},
            {.section = "tc/tail", .function = "tail_nodeport_ipv4_dsr", .count = 30},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_ipv4", .count = 30},
            {.section = "tc/tail", .function = "tail_nodeport_nat_ingress_ipv4", .count = 30, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_nodeport_nat_egress_ipv4", .count = 30, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_ipv6_cont", .count = 30, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_ipv6_ct_egress", .count = 30},
            {.section = "tc/tail", .function = "tail_handle_ipv6", .count = 30, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_ipv4_cont", .count = 30, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_ipv4_ct_egress", .count = 30},
            {.section = "tc/tail", .function = "tail_handle_ipv4", .count = 30},
            {.section = "tc/tail", .function = "tail_handle_arp", .count = 30},
            {.section = "tc/tail", .function = "tail_ipv6_policy", .count = 30, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_ipv6_to_endpoint", .count = 30, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_ipv6_ct_ingress_policy_only", .count = 30},
            {.section = "tc/tail", .function = "tail_ipv6_ct_ingress", .count = 30},
            {.section = "tc/tail", .function = "tail_ipv4_policy", .count = 30, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_ipv4_to_endpoint", .count = 30, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_ipv4_ct_ingress_policy_only", .count = 30},
            {.section = "tc/tail", .function = "tail_ipv4_ct_ingress", .count = 30},
            {.section = "tc/tail", .function = "tail_policy_denied_ipv4", .count = 30},
            {.section = "tc/entry", .function = "cil_from_container", .count = 4},
            {.section = "tc/entry", .function = "cil_lxc_policy", .count = 4},
            {.section = "tc/entry", .function = "cil_lxc_policy_egress", .count = 4},
            {.section = "tc/entry", .function = "cil_to_container", .count = 4},
        }};
    verify_file("cilium-core", file);
}

TEST_CASE("cilium-core/bpf_network.o", "[verify][samples][cilium-core]") {
    static const FileEntry file = {"bpf_network.o",
                                   {
                                       {.section = "tc/tail"},
                                       {.section = "tc/entry"},
                                   }};
    verify_file("cilium-core", file);
}

TEST_CASE("cilium-core/bpf_overlay.o", "[verify][samples][cilium-core]") {
    static const FileEntry file = {
        "bpf_overlay.o",
        {
            {.section = ".text", .function = "__mcast_ep_delivery", .count = 2, .expect = Expect::Xfail},
            {.section = ".text", .function = "__check_device_mtu", .count = 2, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_drop_notify", .count = 19},
            {.section = "tc/tail", .function = "tail_icmp6_send_time_exceeded", .count = 19},
            {.section = "tc/tail", .function = "tail_mcast_ep_delivery", .count = 19, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_nodeport_ipv6_dsr", .count = 19},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_ingress_ipv6", .count = 19},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_egress_ipv6", .count = 19},
            {.section = "tc/tail", .function = "tail_nodeport_nat_ingress_ipv6", .count = 19, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_nodeport_nat_egress_ipv6", .count = 19},
            {.section = "tc/tail", .function = "tail_nodeport_ipv4_dsr", .count = 19},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_ipv4", .count = 19},
            {.section = "tc/tail", .function = "tail_nodeport_nat_ingress_ipv4", .count = 19, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_nodeport_nat_egress_ipv4", .count = 19, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_snat_fwd_ipv6", .count = 19, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_nat_fwd_ipv6", .count = 19},
            {.section = "tc/tail", .function = "tail_handle_snat_fwd_ipv4", .count = 19, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_nat_fwd_ipv4", .count = 19},
            {.section = "tc/tail", .function = "tail_handle_ipv6", .count = 19, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_ipv4", .count = 19, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_arp", .count = 19},
            {.section = "tc/entry", .function = "cil_from_overlay", .count = 2},
            {.section = "tc/entry", .function = "cil_to_overlay", .count = 2, .expect = Expect::Xfail},
        }};
    verify_file("cilium-core", file);
}

TEST_CASE("cilium-core/bpf_sock.o", "[verify][samples][cilium-core]") {
    static const FileEntry file = {"bpf_sock.o",
                                   {
                                       {.section = "cgroup/connect4"},
                                       {.section = "cgroup/post_bind4"},
                                       {.section = "cgroup/sendmsg4"},
                                       {.section = "cgroup/recvmsg4"},
                                       {.section = "cgroup/post_bind6"},
                                       {.section = "cgroup/connect6"},
                                       {.section = "cgroup/sendmsg6"},
                                       {.section = "cgroup/recvmsg6", .expect = Expect::Xfail},
                                       {.section = "cgroup/sock_release", .expect = Expect::Xfail},
                                   }};
    verify_file("cilium-core", file);
}

TEST_CASE("cilium-core/bpf_wireguard.o", "[verify][samples][cilium-core]") {
    static const FileEntry file = {
        "bpf_wireguard.o",
        {
            {.section = ".text", .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_drop_notify", .count = 17},
            {.section = "tc/tail", .function = "tail_icmp6_send_time_exceeded", .count = 17},
            {.section = "tc/tail", .function = "tail_nodeport_ipv6_dsr", .count = 17},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_ingress_ipv6", .count = 17},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_egress_ipv6", .count = 17},
            {.section = "tc/tail", .function = "tail_nodeport_nat_ingress_ipv6", .count = 17, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_nodeport_nat_egress_ipv6", .count = 17},
            {.section = "tc/tail", .function = "tail_nodeport_ipv4_dsr", .count = 17},
            {.section = "tc/tail", .function = "tail_nodeport_rev_dnat_ipv4", .count = 17},
            {.section = "tc/tail", .function = "tail_nodeport_nat_ingress_ipv4", .count = 17, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_nodeport_nat_egress_ipv4", .count = 17, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_snat_fwd_ipv6", .count = 17},
            {.section = "tc/tail", .function = "tail_handle_nat_fwd_ipv6", .count = 17},
            {.section = "tc/tail", .function = "tail_handle_snat_fwd_ipv4", .count = 17},
            {.section = "tc/tail", .function = "tail_handle_nat_fwd_ipv4", .count = 17},
            {.section = "tc/tail", .function = "tail_handle_ipv6", .count = 17, .expect = Expect::Xfail},
            {.section = "tc/tail", .function = "tail_handle_ipv4", .count = 17, .expect = Expect::Xfail},
            {.section = "tc/entry", .function = "cil_from_wireguard", .count = 2},
            {.section = "tc/entry", .function = "cil_to_wireguard", .count = 2},
        }};
    verify_file("cilium-core", file);
}

TEST_CASE("cilium-core/bpf_xdp.o", "[verify][samples][cilium-core]") {
    static const FileEntry file = {
        "bpf_xdp.o",
        {
            {.section = ".text", .expect = Expect::Xfail},
            {.section = "xdp/tail", .function = "tail_drop_notify", .count = 12},
            {.section = "xdp/tail", .function = "tail_nodeport_ipv6_dsr", .count = 12, .expect = Expect::Xfail},
            {.section = "xdp/tail",
             .function = "tail_nodeport_rev_dnat_ingress_ipv6",
             .count = 12,
             .expect = Expect::Xfail},
            {.section = "xdp/tail",
             .function = "tail_nodeport_rev_dnat_egress_ipv6",
             .count = 12,
             .expect = Expect::Xfail},
            {.section = "xdp/tail", .function = "tail_nodeport_nat_ingress_ipv6", .count = 12, .expect = Expect::Xfail},
            {.section = "xdp/tail", .function = "tail_nodeport_nat_egress_ipv6", .count = 12, .expect = Expect::Xfail},
            {.section = "xdp/tail", .function = "tail_nodeport_ipv4_dsr", .count = 12, .expect = Expect::Xfail},
            {.section = "xdp/tail", .function = "tail_nodeport_rev_dnat_ipv4", .count = 12, .expect = Expect::Xfail},
            {.section = "xdp/tail", .function = "tail_nodeport_nat_ingress_ipv4", .count = 12, .expect = Expect::Xfail},
            {.section = "xdp/tail", .function = "tail_nodeport_nat_egress_ipv4", .count = 12, .expect = Expect::Xfail},
            {.section = "xdp/tail", .function = "tail_lb_ipv4", .count = 12, .expect = Expect::Xfail},
            {.section = "xdp/tail", .function = "tail_lb_ipv6", .count = 12, .expect = Expect::Xfail},
            {.section = "xdp/entry", .expect = Expect::Xfail},
        }};
    verify_file("cilium-core", file);
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// Auto-generated test file for project: suricata
#include "test_verify.hpp"

TEST_CASE("suricata/bypass_filter.o", "[verify][samples][suricata]") {
    static const FileEntry file = {"bypass_filter.o",
                                   {
                                       {.section = "filter"},
                                   }};
    verify_file("suricata", file);
}

TEST_CASE("suricata/filter.o", "[verify][samples][suricata]") {
    static const FileEntry file = {"filter.o",
                                   {
                                       {.section = "filter"},
                                   }};
    verify_file("suricata", file);
}

TEST_CASE("suricata/lb.o", "[verify][samples][suricata]") {
    static const FileEntry file = {"lb.o",
                                   {
                                       {.section = "loadbalancer"},
                                   }};
    verify_file("suricata", file);
}

TEST_CASE("suricata/vlan_filter.o", "[verify][samples][suricata]") {
    static const FileEntry file = {"vlan_filter.o",
                                   {
                                       {.section = "filter"},
                                   }};
    verify_file("suricata", file);
}

TEST_CASE("suricata/xdp_filter.o", "[verify][samples][suricata]") {
    static const FileEntry file = {"xdp_filter.o",
                                   {
                                       {.section = "xdp"},
                                   }};
    verify_file("suricata", file);
}

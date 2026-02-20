// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "test_verify.hpp"

TEST_SECTION_LEGACY("suricata", "bypass_filter.o", "filter")
TEST_SECTION_LEGACY("suricata", "lb.o", "loadbalancer")
TEST_SECTION("suricata", "filter.o", "filter")
TEST_SECTION("suricata", "vlan_filter.o", "filter")
TEST_SECTION("suricata", "xdp_filter.o", "xdp")

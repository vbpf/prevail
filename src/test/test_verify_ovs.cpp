// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "test_verify.hpp"

TEST_CASE("ovs/datapath.o", "[verify][samples][ovs]") {
    static const FileEntry file = {
        "datapath.o",
        {
            {.section = "tail-32"}, {.section = "tail-33"}, {.section = "tail-0"},   {.section = "tail-1"},
            {.section = "tail-3"},  {.section = "tail-4"},  {.section = "tail-5"},   {.section = "tail-7"},
            {.section = "tail-8"},  {.section = "tail-11"}, {.section = "tail-13"},  {.section = "tail-12"},
            {.section = "tail-2"},  {.section = "xdp"},     {.section = "af_xdp"},   {.section = "tail-35"},
            {.section = "ingress"}, {.section = "egress"},  {.section = "downcall"},
        }};
    verify_file("ovs", file);
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <array>

#include <catch2/catch_all.hpp>

#include "ir/unmarshal.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"
#include "platform.hpp"
#include "spec/function_prototypes.hpp"

using namespace prevail;

namespace {

struct ProgramTypeExpectation {
    const char* section;
    const char* expected_name;
    const ebpf_context_descriptor_t* expected_context;
};

struct MapTypeExpectation {
    uint32_t id;
    const char* expected_name;
    bool expected_is_array;
    EbpfMapValueType expected_value_type;
};

bool has_unmodeled_return_type(const ebpf_return_type_t type) {
    switch (type) {
    case EBPF_RETURN_TYPE_INTEGER:
    case EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL:
    case EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED: return false;
    default: return true;
    }
}

bool has_unmodeled_argument_type(const ebpf_argument_type_t type) {
    switch (type) {
    case EBPF_ARGUMENT_TYPE_DONTCARE:
    case EBPF_ARGUMENT_TYPE_ANYTHING:
    case EBPF_ARGUMENT_TYPE_CONST_SIZE:
    case EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO:
    case EBPF_ARGUMENT_TYPE_PTR_TO_CTX:
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP:
    case EBPF_ARGUMENT_TYPE_CONST_PTR_TO_MAP:
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS:
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY:
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE:
    case EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MAP_VALUE:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM:
    case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_STACK:
    case EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_CTX_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_FUNC: return false;
    default: return true;
    }
}

bool has_unmodeled_abi_type(const EbpfHelperPrototype& proto) {
    if (has_unmodeled_return_type(proto.return_type)) {
        return true;
    }
    for (const auto arg_type : proto.argument_type) {
        if (has_unmodeled_argument_type(arg_type)) {
            return true;
        }
    }
    return false;
}

} // namespace

TEST_CASE("linux program-type table maps modern section prefixes", "[platform][tables]") {
    const std::array<ProgramTypeExpectation, 15> expectations{{
        {"cgroup/bind4", "cgroup_sock_addr", &g_sock_addr_descr},
        {"cgroup/post_bind6", "cgroup_sock_addr", &g_sock_addr_descr},
        {"cgroup/connect6", "cgroup_sock_addr", &g_sock_addr_descr},
        {"cgroup/recvmsg4", "cgroup_sock_addr", &g_sock_addr_descr},
        {"cgroup/getpeername6", "cgroup_sock_addr", &g_sock_addr_descr},
        {"cgroup/getsockname4", "cgroup_sock_addr", &g_sock_addr_descr},
        {"cgroup/getsockopt", "cgroup_sockopt", &g_sockopt_descr},
        {"cgroup/setsockopt", "cgroup_sockopt", &g_sockopt_descr},
        {"raw_tp/probe", "raw_tracepoint", &g_tracepoint_descr},
        {"raw_tp.w/probe", "raw_tracepoint_writable", &g_tracepoint_descr},
        {"sk_reuseport/test", "sk_reuseport", &g_sk_reuseport_descr},
        {"flow_dissector", "flow_dissector", &g_flow_dissector_descr},
        {"cgroup/sysctl", "cgroup_sysctl", &g_cgroup_sysctl_descr},
        {"sk_lookup/test", "sk_lookup", &g_sk_lookup_descr},
        {"freplace/test", "ext", &g_unspec_descr},
    }};

    for (const auto& [section, expected_name, expected_context] : expectations) {
        const EbpfProgramType type = g_ebpf_platform_linux.get_program_type(section, "");
        CAPTURE(section);
        REQUIRE(type.name == expected_name);
        REQUIRE(type.context_descriptor == expected_context);
    }
}

TEST_CASE("linux map-type table covers post-cpumap map ids", "[platform][tables]") {
    const std::array<MapTypeExpectation, 17> expectations{{
        {17, "XSKMAP", false, EbpfMapValueType::ANY},
        {18, "SOCKHASH", false, EbpfMapValueType::ANY},
        {19, "CGROUP_STORAGE", false, EbpfMapValueType::ANY},
        {20, "REUSEPORT_SOCKARRAY", false, EbpfMapValueType::ANY},
        {21, "PERCPU_CGROUP_STORAGE", false, EbpfMapValueType::ANY},
        {22, "QUEUE", false, EbpfMapValueType::ANY},
        {23, "STACK", false, EbpfMapValueType::ANY},
        {24, "SK_STORAGE", false, EbpfMapValueType::ANY},
        {25, "DEVMAP_HASH", false, EbpfMapValueType::ANY},
        {26, "STRUCT_OPS", false, EbpfMapValueType::ANY},
        {27, "RINGBUF", false, EbpfMapValueType::ANY},
        {28, "INODE_STORAGE", false, EbpfMapValueType::ANY},
        {29, "TASK_STORAGE", false, EbpfMapValueType::ANY},
        {30, "BLOOM_FILTER", false, EbpfMapValueType::ANY},
        {31, "USER_RINGBUF", false, EbpfMapValueType::ANY},
        {32, "CGRP_STORAGE", false, EbpfMapValueType::ANY},
        {33, "ARENA", false, EbpfMapValueType::ANY},
    }};

    for (const auto& [id, expected_name, expected_is_array, expected_value_type] : expectations) {
        const EbpfMapType type = g_ebpf_platform_linux.get_map_type(id);
        CAPTURE(id);
        REQUIRE(type.platform_specific_type == id);
        REQUIRE(type.name == expected_name);
        REQUIRE(type.is_array == expected_is_array);
        REQUIRE(type.value_type == expected_value_type);
    }
}

TEST_CASE("helper prototypes with unmodeled ABI classes are conservatively rejected", "[platform][tables]") {
    // Related: #959
    ProgramInfo info{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("socket", ""),
    };
    thread_local_program_info = info;

    size_t usable_helpers = 0;
    size_t unmodeled_helpers = 0;
    for (int32_t id = 0; id <= 211; ++id) {
        if (!g_ebpf_platform_linux.is_helper_usable(id)) {
            continue;
        }
        ++usable_helpers;
        const EbpfHelperPrototype proto = g_ebpf_platform_linux.get_helper_prototype(id);
        if (!has_unmodeled_abi_type(proto)) {
            continue;
        }

        ++unmodeled_helpers;
        const Call call = make_call(id, g_ebpf_platform_linux);
        CAPTURE(id, proto.name);
        REQUIRE_FALSE(call.is_supported);
        REQUIRE_FALSE(call.unsupported_reason.empty());
    }

    REQUIRE(usable_helpers > 0);
    REQUIRE(unmodeled_helpers > 0);
}

TEST_CASE("socket cookie helper availability is not treated as fully context-agnostic", "[platform][tables]") {
    // Related: #959
    thread_local_program_info = ProgramInfo{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("cgroup/connect4", ""),
    };
    REQUIRE(g_ebpf_platform_linux.is_helper_usable(46)); // get_socket_cookie

    thread_local_program_info = ProgramInfo{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("xdp", ""),
    };
    REQUIRE_FALSE(g_ebpf_platform_linux.is_helper_usable(46));

    thread_local_program_info = ProgramInfo{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("cgroup/connect4", ""),
    };
    REQUIRE_FALSE(g_ebpf_platform_linux.is_helper_usable(47)); // get_socket_uid remains skb-only
}

TEST_CASE("new Linux context descriptors keep expected layout constants", "[platform][tables]") {
    REQUIRE(g_sock_addr_descr.size == 72);
    REQUIRE(g_sock_addr_descr.data == -1);
    REQUIRE(g_sock_addr_descr.end == -1);
    REQUIRE(g_sock_addr_descr.meta == -1);

    REQUIRE(g_sockopt_descr.size == 40);
    REQUIRE(g_sockopt_descr.data == -1);
    REQUIRE(g_sockopt_descr.end == -1);
    REQUIRE(g_sockopt_descr.meta == -1);

    REQUIRE(g_sk_lookup_descr.size == 72);
    REQUIRE(g_sk_lookup_descr.data == -1);
    REQUIRE(g_sk_lookup_descr.end == -1);
    REQUIRE(g_sk_lookup_descr.meta == -1);

    REQUIRE(g_sk_reuseport_descr.size == 56);
    REQUIRE(g_sk_reuseport_descr.data == 0);
    REQUIRE(g_sk_reuseport_descr.end == 8);
    REQUIRE(g_sk_reuseport_descr.meta == -1);

    REQUIRE(g_flow_dissector_descr.size == 56);
    REQUIRE(g_flow_dissector_descr.data == -1);
    REQUIRE(g_flow_dissector_descr.end == -1);
    REQUIRE(g_flow_dissector_descr.meta == -1);

    REQUIRE(g_cgroup_sysctl_descr.size == 8);
    REQUIRE(g_cgroup_sysctl_descr.data == -1);
    REQUIRE(g_cgroup_sysctl_descr.end == -1);
    REQUIRE(g_cgroup_sysctl_descr.meta == -1);
}

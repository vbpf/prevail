// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <array>
#include <algorithm>

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
    case EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED:
    case EBPF_RETURN_TYPE_PTR_TO_SOCK_COMMON_OR_NULL:
    case EBPF_RETURN_TYPE_PTR_TO_SOCKET_OR_NULL:
    case EBPF_RETURN_TYPE_PTR_TO_TCP_SOCKET_OR_NULL:
    case EBPF_RETURN_TYPE_PTR_TO_ALLOC_MEM_OR_NULL:
    case EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL:
    case EBPF_RETURN_TYPE_PTR_TO_MEM_OR_BTF_ID_OR_NULL:
    case EBPF_RETURN_TYPE_PTR_TO_BTF_ID:
    case EBPF_RETURN_TYPE_PTR_TO_MEM_OR_BTF_ID: return false;
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
    case EBPF_ARGUMENT_TYPE_PTR_TO_FUNC:
    case EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON:
    case EBPF_ARGUMENT_TYPE_PTR_TO_SOCK_COMMON:
    case EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID:
    case EBPF_ARGUMENT_TYPE_PTR_TO_PERCPU_BTF_ID:
    case EBPF_ARGUMENT_TYPE_PTR_TO_ALLOC_MEM:
    case EBPF_ARGUMENT_TYPE_PTR_TO_SPIN_LOCK:
    case EBPF_ARGUMENT_TYPE_PTR_TO_TIMER:
    case EBPF_ARGUMENT_TYPE_CONST_ALLOC_SIZE_OR_ZERO:
    case EBPF_ARGUMENT_TYPE_PTR_TO_LONG:
    case EBPF_ARGUMENT_TYPE_PTR_TO_INT: return false;
    // PTR_TO_CONST_STR remains unmodeled until const-string provenance is supported.
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

bool has_single_arg(const Call& call, const ArgSingle::Kind kind, const Reg reg, const bool or_null = false) {
    return std::any_of(call.singles.begin(), call.singles.end(), [&](const ArgSingle& arg) {
        return arg.kind == kind && arg.reg == reg && arg.or_null == or_null;
    });
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

TEST_CASE("new helper ABI classes map to modeled call contracts", "[platform][tables]") {
    ProgramInfo info{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("socket", ""),
    };
    thread_local_program_info = info;

    const auto require_supported = [](const int32_t id) -> Call {
        const Call call = make_call(id, g_ebpf_platform_linux);
        CAPTURE(id, call.name, call.unsupported_reason);
        REQUIRE(call.is_supported);
        return call;
    };

    const Call strtoul = require_supported(106);
    REQUIRE(has_single_arg(strtoul, ArgSingle::Kind::PTR_TO_WRITABLE_LONG, Reg{4}));

    const Call ringbuf_reserve = require_supported(131);
    REQUIRE(ringbuf_reserve.return_ptr_type.has_value());
    REQUIRE(*ringbuf_reserve.return_ptr_type == T_ALLOC_MEM);
    REQUIRE(ringbuf_reserve.return_nullable);
    REQUIRE(has_single_arg(ringbuf_reserve, ArgSingle::Kind::CONST_SIZE_OR_ZERO, Reg{2}));

    const Call ringbuf_submit = require_supported(132);
    REQUIRE(has_single_arg(ringbuf_submit, ArgSingle::Kind::PTR_TO_ALLOC_MEM, Reg{1}));

    const Call per_cpu_ptr = require_supported(153);
    REQUIRE(per_cpu_ptr.return_ptr_type.has_value());
    REQUIRE(*per_cpu_ptr.return_ptr_type == T_BTF_ID);
    REQUIRE(per_cpu_ptr.return_nullable);
    REQUIRE(has_single_arg(per_cpu_ptr, ArgSingle::Kind::PTR_TO_BTF_ID, Reg{1}));

    const Call this_cpu_ptr = require_supported(154);
    REQUIRE(this_cpu_ptr.return_ptr_type.has_value());
    REQUIRE(*this_cpu_ptr.return_ptr_type == T_BTF_ID);
    REQUIRE_FALSE(this_cpu_ptr.return_nullable);
    REQUIRE(has_single_arg(this_cpu_ptr, ArgSingle::Kind::PTR_TO_BTF_ID, Reg{1}));

    const Call check_mtu = require_supported(163);
    REQUIRE(has_single_arg(check_mtu, ArgSingle::Kind::PTR_TO_WRITABLE_INT, Reg{3}));

    const Call timer_init = require_supported(169);
    REQUIRE(has_single_arg(timer_init, ArgSingle::Kind::PTR_TO_TIMER, Reg{1}));

    const Call sk_fullsock = require_supported(95);
    REQUIRE(sk_fullsock.return_ptr_type.has_value());
    REQUIRE(*sk_fullsock.return_ptr_type == T_SOCKET);
    REQUIRE(sk_fullsock.return_nullable);
    REQUIRE(has_single_arg(sk_fullsock, ArgSingle::Kind::PTR_TO_SOCKET, Reg{1}));
}

TEST_CASE("PTR_TO_CONST_STR helpers remain explicitly unsupported", "[platform][tables]") {
    ProgramInfo info{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("socket", ""),
    };
    thread_local_program_info = info;

    const Call strncmp = make_call(182, g_ebpf_platform_linux);
    CAPTURE(strncmp.name, strncmp.unsupported_reason);
    REQUIRE_FALSE(strncmp.is_supported);
    REQUIRE_FALSE(strncmp.unsupported_reason.empty());
}

TEST_CASE("socket cookie helper availability is not treated as fully context-agnostic", "[platform][tables]") {
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

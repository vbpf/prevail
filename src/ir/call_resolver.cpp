// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <array>
#include <string>

#include <gsl/narrow>

#include "ir/call_resolver.hpp"
#include "spec/function_prototypes.hpp"

namespace prevail {

namespace {

ArgSingle::Kind to_arg_single_kind(const ebpf_argument_type_t t) {
    switch (t) {
    case EBPF_ARGUMENT_TYPE_ANYTHING: return ArgSingle::Kind::ANYTHING;
    case EBPF_ARGUMENT_TYPE_PTR_TO_STACK: return ArgSingle::Kind::PTR_TO_STACK;
    case EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL: return ArgSingle::Kind::PTR_TO_STACK;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP: return ArgSingle::Kind::MAP_FD;
    case EBPF_ARGUMENT_TYPE_CONST_PTR_TO_MAP: return ArgSingle::Kind::MAP_FD;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS: return ArgSingle::Kind::MAP_FD_PROGRAMS;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY: return ArgSingle::Kind::PTR_TO_MAP_KEY;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE: return ArgSingle::Kind::PTR_TO_MAP_VALUE;
    case EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MAP_VALUE: return ArgSingle::Kind::PTR_TO_MAP_VALUE;
    case EBPF_ARGUMENT_TYPE_PTR_TO_CTX: return ArgSingle::Kind::PTR_TO_CTX;
    case EBPF_ARGUMENT_TYPE_PTR_TO_CTX_OR_NULL: return ArgSingle::Kind::PTR_TO_CTX;
    case EBPF_ARGUMENT_TYPE_PTR_TO_FUNC: return ArgSingle::Kind::PTR_TO_FUNC;
    default: break;
    }
    return {};
}

ArgPair::Kind to_arg_pair_kind(const ebpf_argument_type_t t) {
    switch (t) {
    case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM: return ArgPair::Kind::PTR_TO_READABLE_MEM;
    case EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM: return ArgPair::Kind::PTR_TO_READABLE_MEM;
    case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM: return ArgPair::Kind::PTR_TO_WRITABLE_MEM;
    default: break;
    }
    return {};
}

ResolvedCall make_unsupported(const Call& call, std::string name, std::string reason) {
    return ResolvedCall{.call = call,
                        .name = std::move(name),
                        .is_supported = false,
                        .unsupported_reason = std::move(reason),
                        .contract = {}};
}

ResolvedCall resolve_helper(const Call& call, const ProgramInfo& info) {
    // Matches the unmarshal-time branching: a helper whose id is known to the
    // platform but unusable for *this* program type must surface as "helper
    // function is unavailable on this platform", not the generic "prototype"
    // diagnostic. Critical for program-type-specific gates (e.g.,
    // bpf_get_socket_cookie is allowed from cgroup/connect4 but not xdp).
    if (!info.platform->is_helper_usable(call.func, info.type)) {
        std::string name = std::to_string(call.func);
        if (const auto name_from_proto = info.platform->get_helper_prototype(call.func, info.type).name) {
            name = name_from_proto;
        }
        return make_unsupported(call, std::move(name), "helper function is unavailable on this platform");
    }

    const EbpfHelperPrototype proto = info.platform->get_helper_prototype(call.func, info.type);
    const std::string helper_prototype_name = proto.name ? proto.name : std::to_string(call.func);
    const auto return_info = classify_call_return_type(proto.return_type);
    if (!return_info.has_value()) {
        return make_unsupported(call, helper_prototype_name,
                                "helper prototype is unavailable on this platform: " + helper_prototype_name);
    }

    ResolvedCall res{.call = call, .name = helper_prototype_name};
    res.contract.return_ptr_type = return_info->pointer_type;
    res.contract.return_nullable = return_info->pointer_nullable;
    res.contract.reallocate_packet = proto.reallocate_packet;
    res.contract.is_map_lookup = proto.return_type == EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL;

    const std::array<ebpf_argument_type_t, 7> args = {
        {EBPF_ARGUMENT_TYPE_DONTCARE, proto.argument_type[0], proto.argument_type[1], proto.argument_type[2],
         proto.argument_type[3], proto.argument_type[4], EBPF_ARGUMENT_TYPE_DONTCARE}};
    for (size_t i = 1; i < args.size() - 1; i++) {
        switch (args[i]) {
        case EBPF_ARGUMENT_TYPE_UNSUPPORTED:
            return make_unsupported(call, helper_prototype_name,
                                    "helper argument type is unavailable on this platform: " + helper_prototype_name);
        case EBPF_ARGUMENT_TYPE_DONTCARE: return res;
        case EBPF_ARGUMENT_TYPE_ANYTHING:
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP:
        case EBPF_ARGUMENT_TYPE_CONST_PTR_TO_MAP:
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS:
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY:
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE:
        case EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MAP_VALUE:
        case EBPF_ARGUMENT_TYPE_PTR_TO_STACK:
        case EBPF_ARGUMENT_TYPE_PTR_TO_CTX:
        case EBPF_ARGUMENT_TYPE_PTR_TO_FUNC:
            res.contract.singles.push_back({to_arg_single_kind(args[i]), false, Reg{gsl::narrow<uint8_t>(i)}});
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL:
        case EBPF_ARGUMENT_TYPE_PTR_TO_CTX_OR_NULL:
            res.contract.singles.push_back({to_arg_single_kind(args[i]), true, Reg{gsl::narrow<uint8_t>(i)}});
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON:
        case EBPF_ARGUMENT_TYPE_PTR_TO_SOCK_COMMON:
            res.contract.singles.push_back({ArgSingle::Kind::PTR_TO_SOCKET, false, Reg{gsl::narrow<uint8_t>(i)}});
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID:
        case EBPF_ARGUMENT_TYPE_PTR_TO_PERCPU_BTF_ID:
            res.contract.singles.push_back({ArgSingle::Kind::PTR_TO_BTF_ID, false, Reg{gsl::narrow<uint8_t>(i)}});
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_ALLOC_MEM:
            res.contract.singles.push_back({ArgSingle::Kind::PTR_TO_ALLOC_MEM, false, Reg{gsl::narrow<uint8_t>(i)}});
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_SPIN_LOCK:
            res.contract.singles.push_back({ArgSingle::Kind::PTR_TO_SPIN_LOCK, false, Reg{gsl::narrow<uint8_t>(i)}});
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_TIMER:
            res.contract.singles.push_back({ArgSingle::Kind::PTR_TO_TIMER, false, Reg{gsl::narrow<uint8_t>(i)}});
            break;
        case EBPF_ARGUMENT_TYPE_CONST_ALLOC_SIZE_OR_ZERO:
            res.contract.singles.push_back({ArgSingle::Kind::CONST_SIZE_OR_ZERO, false, Reg{gsl::narrow<uint8_t>(i)}});
            res.contract.alloc_size_reg = Reg{gsl::narrow<uint8_t>(i)};
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_LONG:
            res.contract.singles.push_back(
                {ArgSingle::Kind::PTR_TO_WRITABLE_LONG, false, Reg{gsl::narrow<uint8_t>(i)}});
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_INT:
            res.contract.singles.push_back({ArgSingle::Kind::PTR_TO_WRITABLE_INT, false, Reg{gsl::narrow<uint8_t>(i)}});
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_CONST_STR:
            return make_unsupported(call, helper_prototype_name,
                                    "helper argument type is unavailable on this platform: " + helper_prototype_name);
        case EBPF_ARGUMENT_TYPE_CONST_SIZE:
            return make_unsupported(call, helper_prototype_name,
                                    "mismatched EBPF_ARGUMENT_TYPE_PTR_TO* and EBPF_ARGUMENT_TYPE_CONST_SIZE: " +
                                        helper_prototype_name);
        case EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO:
            return make_unsupported(
                call, helper_prototype_name,
                "mismatched EBPF_ARGUMENT_TYPE_PTR_TO* and EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: " +
                    helper_prototype_name);
        case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
        case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM:
        case EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM_OR_NULL:
        case EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM:
        case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL:
        case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM: {
            if (args.size() - i < 2) {
                return make_unsupported(
                    call, helper_prototype_name,
                    "missing EBPF_ARGUMENT_TYPE_CONST_SIZE or EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: " +
                        helper_prototype_name);
            }
            if (args[i + 1] != EBPF_ARGUMENT_TYPE_CONST_SIZE && args[i + 1] != EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO) {
                return make_unsupported(call, helper_prototype_name,
                                        "Pointer argument not followed by EBPF_ARGUMENT_TYPE_CONST_SIZE or "
                                        "EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: " +
                                            helper_prototype_name);
            }
            const bool can_be_zero = (args[i + 1] == EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO);
            const bool or_null = args[i] == EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL ||
                                 args[i] == EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM_OR_NULL ||
                                 args[i] == EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL;
            res.contract.pairs.push_back({to_arg_pair_kind(args[i]), or_null, Reg{gsl::narrow<uint8_t>(i)},
                                          Reg{gsl::narrow<uint8_t>(i + 1)}, can_be_zero});
            i++;
            break;
        }
        }
    }
    return res;
}

ResolvedCall resolve_kfunc(const Call& call, const ProgramInfo& info) {
    if (!info.platform || !info.platform->resolve_kfunc_call) {
        return make_unsupported(call, std::to_string(call.func), "kfunc resolution is unavailable on this platform");
    }
    std::string why_not;
    if (const auto c = info.platform->resolve_kfunc_call(call.func, info.type, &why_not)) {
        return *c;
    }
    return make_unsupported(call, std::to_string(call.func), std::move(why_not));
}

ResolvedCall resolve_builtin(const Call& call, const ProgramInfo& info) {
    if (info.platform && info.platform->get_builtin_call) {
        if (const auto c = info.platform->get_builtin_call(call.func)) {
            return *c;
        }
    }
    return make_unsupported(call, std::to_string(call.func), "helper function is unavailable on this platform");
}

} // namespace

ResolvedCall resolve(const Call& call, const ProgramInfo& info) {
    switch (call.kind) {
    case CallKind::helper: return resolve_helper(call, info);
    case CallKind::kfunc: return resolve_kfunc(call, info);
    case CallKind::builtin: return resolve_builtin(call, info);
    }
    return make_unsupported(call, std::to_string(call.func), "unknown CallKind");
}

} // namespace prevail

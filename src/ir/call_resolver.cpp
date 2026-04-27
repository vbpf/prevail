// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <array>
#include <string>

#include "ir/arg_kind.hpp"
#include "ir/call_resolver.hpp"
#include "spec/function_prototypes.hpp"

namespace prevail {

namespace {

ResolvedCall make_unsupported(const Call& call, std::string name, std::string reason) {
    return ResolvedCall{.call = call,
                        .name = std::move(name),
                        .is_supported = false,
                        .unsupported_reason = std::move(reason),
                        .contract = {}};
}

ResolvedCall resolve_helper(const Call& call, const ProgramInfo& info) {
    if (!info.platform) {
        return make_unsupported(call, std::to_string(call.func), "platform is unavailable");
    }
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
    for (size_t i = 1; i < args.size() - 1;) {
        switch (process_arg(res.contract, args, i)) {
        case ArgOutcome::Single: i += 1; break;
        case ArgOutcome::Pair: i += 2; break;
        case ArgOutcome::Stop: return res;
        case ArgOutcome::Unavailable:
            return make_unsupported(call, helper_prototype_name,
                                    "helper argument type is unavailable on this platform: " + helper_prototype_name);
        case ArgOutcome::MismatchedSize:
            return make_unsupported(call, helper_prototype_name,
                                    "Pointer argument not followed by EBPF_ARGUMENT_TYPE_CONST_SIZE or "
                                    "EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: " +
                                        helper_prototype_name);
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
        // Stamp the key from our argument so the invariant is enforced here
        // rather than relying on every platform implementation to set it.
        ResolvedCall r = *c;
        r.call = call;
        return r;
    }
    return make_unsupported(call, std::to_string(call.func), std::move(why_not));
}

ResolvedCall resolve_builtin(const Call& call, const ProgramInfo& info) {
    if (info.platform && info.platform->get_builtin_call) {
        if (const auto c = info.platform->get_builtin_call(call.func)) {
            ResolvedCall r = *c;
            r.call = call;
            return r;
        }
    }
    return make_unsupported(call, std::to_string(call.func), "builtin function is unavailable on this platform");
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

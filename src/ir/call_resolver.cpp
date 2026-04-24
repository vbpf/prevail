// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <string>

#include "ir/call_resolver.hpp"
#include "ir/unmarshal.hpp"

namespace prevail {

namespace {
ResolvedCall resolve_helper(const Call& call, const ProgramInfo& info) {
    // Match the branching that Unmarshaller::makeJmp used to do: a helper that
    // exists in the platform table but isn't available for *this* program type
    // must report "helper function is unavailable on this platform", not the
    // make_call-internal "prototype is unavailable" diagnostic.
    if (!info.platform->is_helper_usable(call.target.func, info.type)) {
        std::string name = std::to_string(call.target.func);
        if (const auto name_from_proto = info.platform->get_helper_prototype(call.target.func, info.type).name) {
            name = name_from_proto;
        }
        return ResolvedCall{.call = call,
                            .name = std::move(name),
                            .is_supported = false,
                            .unsupported_reason = "helper function is unavailable on this platform",
                            .contract = {}};
    }
    const Call resolved = make_call(call.target.func, *info.platform, info.type);
    return ResolvedCall{.call = call,
                        .name = resolved.target.name,
                        .is_supported = resolved.target.is_supported,
                        .unsupported_reason = resolved.target.unsupported_reason,
                        .contract = resolved.contract};
}

ResolvedCall resolve_kfunc(const Call& call, const ProgramInfo& info) {
    if (!info.platform || !info.platform->resolve_kfunc_call) {
        return ResolvedCall{.call = call,
                            .name = std::to_string(call.target.func),
                            .is_supported = false,
                            .unsupported_reason = "kfunc resolution is unavailable on this platform",
                            .contract = {}};
    }
    std::string why_not;
    if (const auto c = info.platform->resolve_kfunc_call(call.target.func, info.type, &why_not)) {
        return ResolvedCall{.call = call,
                            .name = c->target.name,
                            .is_supported = c->target.is_supported,
                            .unsupported_reason = c->target.unsupported_reason,
                            .contract = c->contract};
    }
    return ResolvedCall{.call = call,
                        .name = std::to_string(call.target.func),
                        .is_supported = false,
                        .unsupported_reason = std::move(why_not),
                        .contract = {}};
}

ResolvedCall resolve_builtin(const Call& call, const ProgramInfo& info) {
    if (info.platform && info.platform->get_builtin_call) {
        if (const auto c = info.platform->get_builtin_call(call.target.func)) {
            return ResolvedCall{.call = call,
                                .name = c->target.name,
                                .is_supported = c->target.is_supported,
                                .unsupported_reason = c->target.unsupported_reason,
                                .contract = c->contract};
        }
    }
    return ResolvedCall{.call = call,
                        .name = std::to_string(call.target.func),
                        .is_supported = false,
                        .unsupported_reason = "helper function is unavailable on this platform",
                        .contract = {}};
}
} // namespace

ResolvedCall resolve(const Call& call, const ProgramInfo& info) {
    switch (call.target.kind) {
    case CallKind::helper: return resolve_helper(call, info);
    case CallKind::kfunc: return resolve_kfunc(call, info);
    case CallKind::builtin: return resolve_builtin(call, info);
    }
    return ResolvedCall{.call = call, .is_supported = false, .unsupported_reason = "unknown CallKind"};
}

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <string>

#include "ir/call_resolver.hpp"
#include "ir/unmarshal.hpp"

namespace prevail {

namespace {
ResolvedCall resolve_helper(const Call& call, const ProgramInfo& info) {
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

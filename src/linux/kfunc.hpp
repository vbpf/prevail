// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <string>

#include "ir/syntax.hpp"

namespace prevail {

enum class KfuncFlags : uint32_t {
    none = 0,
    acquire = 1u << 0,
    release = 1u << 1,
    trusted_args = 1u << 2,
    sleepable = 1u << 3,
    destructive = 1u << 4,
};

constexpr KfuncFlags operator|(const KfuncFlags a, const KfuncFlags b) {
    return static_cast<KfuncFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

constexpr KfuncFlags operator&(const KfuncFlags a, const KfuncFlags b) {
    return static_cast<KfuncFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

constexpr KfuncFlags operator^(const KfuncFlags a, const KfuncFlags b) {
    return static_cast<KfuncFlags>(static_cast<uint32_t>(a) ^ static_cast<uint32_t>(b));
}

constexpr KfuncFlags operator~(const KfuncFlags a) { return static_cast<KfuncFlags>(~static_cast<uint32_t>(a)); }

constexpr KfuncFlags& operator|=(KfuncFlags& a, const KfuncFlags b) {
    a = a | b;
    return a;
}

constexpr KfuncFlags& operator&=(KfuncFlags& a, const KfuncFlags b) {
    a = a & b;
    return a;
}

constexpr KfuncFlags& operator^=(KfuncFlags& a, const KfuncFlags b) {
    a = a ^ b;
    return a;
}

// Resolve a Linux kfunc identified by (`btf_id`, `module`) to a ResolvedCall
// used by the verifier. `module` is the kernel module identifier (0 == vmlinux),
// matching `CallBtf::module`. BTF ids are not unique across modules, so callers
// must pass both. Returns nullopt and populates `why_not` if the (btf_id, module)
// pair is unknown or currently unsupported.
std::optional<ResolvedCall> make_kfunc_call(int32_t btf_id, int16_t module, const EbpfProgramType& program_type,
                                            std::string* why_not = nullptr);

} // namespace prevail

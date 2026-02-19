// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
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

// Resolve a kfunc BTF ID to a Call contract used by the verifier.
// Returns nullopt and populates `why_not` if the ID is unknown or currently unsupported.
std::optional<Call> make_kfunc_call(int32_t btf_id, const ProgramInfo* info = nullptr, std::string* why_not = nullptr);

} // namespace prevail

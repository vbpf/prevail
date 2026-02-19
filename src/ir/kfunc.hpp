// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <string>

#include "ir/syntax.hpp"

namespace prevail {

// Resolve a kfunc BTF ID to a Call contract used by the verifier.
// Returns nullopt and populates `why_not` if the ID is unknown or currently unsupported.
std::optional<Call> make_kfunc_call(int32_t btf_id, std::string* why_not = nullptr);

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <string>

#include "spec/function_prototypes.hpp"

namespace prevail {
EbpfHelperPrototype get_helper_prototype_linux(int32_t n);
bool is_helper_usable_linux(int32_t n);
std::optional<int32_t> resolve_helper_id_linux(const std::string& name);
std::optional<int32_t> resolve_builtin_call_linux(const std::string& name);
} // namespace prevail

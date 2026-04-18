// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <string>

#include "platform.hpp"

namespace prevail {
EbpfHelperPrototype get_helper_prototype_linux(int32_t n, const EbpfProgramType& program_type);
bool is_helper_usable_linux(int32_t n, const EbpfProgramType& program_type);
std::optional<int32_t> resolve_helper_id_linux(const std::string& name);
std::optional<int32_t> resolve_builtin_call_linux(const std::string& name);
std::optional<KsymBtfId> resolve_ksym_btf_id_linux(const std::string& name);
} // namespace prevail

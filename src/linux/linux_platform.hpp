// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "spec/function_prototypes.hpp"

namespace prevail {
EbpfHelperPrototype get_helper_prototype_linux(int32_t n);
EbpfHelperPrototype get_helper_prototype_by_name_linux(const std::string& name, int32_t& out_id);
bool is_helper_usable_linux(int32_t n);
bool is_helper_usable_by_name_linux(const std::string& name);
} // namespace prevail

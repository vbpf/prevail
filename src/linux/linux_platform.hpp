// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "helpers.hpp"

namespace prevail {
EbpfHelperPrototype get_helper_prototype_linux(int32_t n);
bool is_helper_usable_linux(int32_t n);
} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <unordered_set>

#include "arith/num_big.hpp"

namespace splitdbm {

// DBM weights use Number (backed by checked i128 arithmetic).
using Weight = prevail::Number;

using VertId = uint16_t;
using VertSet = std::unordered_set<VertId>;

} // namespace splitdbm
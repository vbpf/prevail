// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <unordered_set>

#include "arith/num_big.hpp"

namespace splitdbm {

/** DBM weights (Weight) can be represented using one of the following
 * types:
 *
 * 1) basic integer type: e.g., long
 * 2) safei64
 * 3) Number
 *
 * 1) is the fastest but things can go wrong if some DBM
 * operation overflows. 2) is slower than 1) but it checks for
 * overflow before any DBM operation. 3) is the slowest, and it
 * represents weights using unbounded mathematical integers so
 * overflow is not a concern, but it might not be what you need
 * when reasoning about programs with wraparound semantics.
 **/
using Weight = prevail::Number;

using VertId = uint16_t;
using VertSet = std::unordered_set<VertId>;

} // namespace splitdbm
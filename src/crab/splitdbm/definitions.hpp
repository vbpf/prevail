// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>
#include <unordered_set>

#include "arith/num_big.hpp"

namespace splitdbm {

// DBM weights use Number (backed by checked i128 arithmetic).
using Weight = prevail::Number;

// Closure and join derive edges by adding up the weights of other edges, and the analyzed program can feed each
// sum into the next one (a join turns a bound into a relation of the same width, and closing the next comparison
// adds that relation to the same bound), so without a limit the weights double until the checked arithmetic
// overflows. The variables stand for 64-bit values, and two 64-bit values, signed or unsigned, are less than
// 2^65 apart.
inline constexpr Weight derived_weight_limit{static_cast<prevail::Int128>(1) << 65};

// The weight to store for an edge derived as a sum of other weights, or nothing if the edge is not worth storing.
// A weight of 2^65 or more holds for all 64-bit values. A weight below -2^65 holds for none, and neither does -2^65.
// Dropping an edge and raising its weight only weaken the constraints (and keep the potentials a valid model),
// so this is sound for any values.
inline std::optional<Weight> derived_weight(const Weight& sum) {
    if (sum >= derived_weight_limit) {
        return std::nullopt;
    }
    return std::max(sum, -derived_weight_limit);
}

using VertId = uint16_t;
using VertSet = std::unordered_set<VertId>;

} // namespace splitdbm
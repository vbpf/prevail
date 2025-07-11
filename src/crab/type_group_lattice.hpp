// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "crab/type_encoding.hpp" // For TypeGroup enum

namespace prevail {

namespace TypeGroupLattice {
// Define the partial order: a <= b in the lattice
static bool operator<=(TypeGroup a, TypeGroup b);

// Define the join (Least Upper Bound - LUB)
static TypeGroup join(TypeGroup a, TypeGroup b);

// Define the meet (Greatest Lower Bound - GLB)
static TypeGroup meet(TypeGroup a, TypeGroup b);

// Maps a concrete TypeEncoding to its most specific TypeGroup lattice element.
static TypeGroup from_type_encoding(TypeEncoding enc);

}; // namespace TypeGroupLattice

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <iosfwd>

namespace prevail {

// Wrapper for typed variables used by the abstract domains and linear_constraints.
// Being a class (instead of a type alias) enables overloading in dsl_syntax
class Variable final {
    uint64_t _id;

    explicit Variable(const uint64_t id) : _id(id) {}

  public:
    [[nodiscard]]
    std::size_t hash() const {
        return _id;
    }

    bool operator==(const Variable o) const { return _id == o._id; }

    bool operator!=(const Variable o) const { return (!(operator==(o))); }

    // for flat_map
    bool operator<(const Variable o) const { return _id < o._id; }

    friend std::ostream& operator<<(std::ostream& o, const Variable& v);
}; // class Variable

} // namespace prevail

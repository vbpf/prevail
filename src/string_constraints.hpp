// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <set>
#include <string>
#include <vector>

#include "arith/linear_constraint.hpp"
#include "arith/variable.hpp"
#include "crab/interval.hpp"
#include "crab/type_encoding.hpp"
#include "crab_utils/debug.hpp"

namespace prevail {
struct StringInvariant {
    std::optional<std::set<std::string>> maybe_inv{};

    StringInvariant() = default;

    explicit StringInvariant(std::set<std::string> inv) : maybe_inv(std::move(inv)) {}

    StringInvariant(const StringInvariant& inv) = default;
    StringInvariant& operator=(const StringInvariant& inv) = default;
    StringInvariant(StringInvariant&& inv) = default;
    StringInvariant& operator=(StringInvariant&& inv) = default;

    [[nodiscard]]
    bool is_bottom() const {
        return !maybe_inv;
    }
    [[nodiscard]]
    bool empty() const {
        return maybe_inv && maybe_inv->empty();
    }

    static StringInvariant top() { return StringInvariant{{}}; }
    static StringInvariant bottom() { return StringInvariant{}; }

    [[nodiscard]]
    const std::set<std::string>& value() const {
        if (is_bottom()) {
            CRAB_ERROR("cannot iterate bottom");
        }
        return *maybe_inv;
    }

    StringInvariant operator+(const StringInvariant& b) const;

    // Render as the set of text lines used for display/diffing. Bottom is the
    // single line "_|_", exactly the form the YAML harness parses back into a
    // bottom invariant; a non-bottom invariant is its set of constraint lines.
    [[nodiscard]]
    std::set<std::string> to_lines() const;

    bool operator==(const StringInvariant& other) const { return maybe_inv == other.maybe_inv; }

    [[nodiscard]]
    bool contains(const std::string& item) const {
        return value().contains(item);
    }

    friend std::ostream& operator<<(std::ostream&, const StringInvariant& inv);
};

struct TypeSetRestriction {
    Variable var;
    TypeSet types;
};

/// Parsed type equality: v1.type == v2.type.
struct TypeEquality {
    Variable v1;
    Variable v2;
};

/// All constraint kinds produced by parsing a `StringInvariant`. Consumed as a
/// single bundle by `EbpfDomain::from_constraints`. `numeric_ranges` carries
/// stack byte ranges that should be marked numeric in `ArrayDomain::num_bytes`
/// — distinct sub-domain from the other three, but always parsed and applied
/// alongside them.
struct ParsedConstraints {
    std::vector<TypeEquality> type_equalities;
    std::vector<TypeSetRestriction> type_restrictions;
    std::vector<LinearConstraint> value_csts;
    std::vector<Interval> numeric_ranges;
};
} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <set>
#include <string>
#include <vector>

#include "arith/linear_constraint.hpp"
#include "crab/interval.hpp"

namespace prevail {
struct StringInvariant {
    std::optional<std::set<std::string>> maybe_inv{};

    StringInvariant() = default;

    explicit StringInvariant(std::set<std::string> inv) : maybe_inv(std::move(inv)) {}

    StringInvariant(const StringInvariant& inv) = default;
    StringInvariant& operator=(const StringInvariant& inv) = default;

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
            throw std::runtime_error("cannot iterate bottom");
        }
        return *maybe_inv;
    }

    StringInvariant operator-(const StringInvariant& b) const;
    StringInvariant operator+(const StringInvariant& b) const;

    bool operator==(const StringInvariant& other) const { return maybe_inv == other.maybe_inv; }

    [[nodiscard]]
    bool contains(const std::string& item) const {
        return maybe_inv.value().contains(item);
    }

    friend std::ostream& operator<<(std::ostream&, const StringInvariant& inv);
};

std::vector<LinearConstraint> parse_linear_constraints(const std::set<std::string>& constraints,
                                                       std::vector<Interval>& numeric_ranges);
} // namespace prevail

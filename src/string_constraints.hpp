// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <regex>
#include <set>
#include <string>
#include <vector>

#include "crab/interval.hpp"
#include "crab/linear_constraint.hpp"

struct string_invariant {
    std::optional<std::set<std::string>> maybe_inv{};

    string_invariant() = default;

    explicit string_invariant(std::set<std::string> inv) : maybe_inv(std::move(inv)) {};

    string_invariant(const string_invariant& inv) = default;
    string_invariant& operator=(const string_invariant& inv) = default;

    [[nodiscard]]
    bool is_bottom() const {
        return !maybe_inv;
    }
    [[nodiscard]]
    bool empty() const {
        return maybe_inv && maybe_inv->empty();
    }

    static string_invariant top() { return string_invariant{{}}; }
    static string_invariant bottom() { return string_invariant{}; }

    [[nodiscard]]
    const std::set<std::string>& value() const {
        if (is_bottom()) {
            throw std::runtime_error("cannot iterate bottom");
        }
        return *maybe_inv;
    }

    string_invariant operator-(const string_invariant& b) const;
    string_invariant operator+(const string_invariant& b) const;

    bool operator==(const string_invariant& other) const { return maybe_inv == other.maybe_inv; }

    [[nodiscard]]
    bool contains(const std::string& item) const {
        return maybe_inv.value().contains(item);
    }

    friend std::ostream& operator<<(std::ostream&, const string_invariant& inv);
};

std::vector<prevail::linear_constraint_t> parse_linear_constraints(const std::set<std::string>& constraints,
                                                                   std::vector<prevail::interval_t>& numeric_ranges);

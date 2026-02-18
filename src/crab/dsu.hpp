// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cassert>
#include <vector>

namespace prevail {

/// A disjoint-set (union-find) over integer elements 0..n.
/// Supports path compression on find and union by rank.
class DisjointSetUnion {
    std::vector<size_t> parent_;
    std::vector<size_t> rank_;

  public:
    DisjointSetUnion() = default;

    explicit DisjointSetUnion(const size_t n) : parent_(n), rank_(n, 0) {
        for (size_t i = 0; i < n; i++) {
            parent_[i] = i;
        }
    }

    /// Find representative with path compression.
    size_t find(const size_t x) {
        assert(x < parent_.size());
        if (parent_[x] != x) {
            parent_[x] = find(parent_[x]);
        }
        return parent_[x];
    }

    /// Find representative without mutation (path walking, no compression).
    [[nodiscard]]
    size_t find_const(size_t x) const {
        assert(x < parent_.size());
        while (parent_[x] != x) {
            x = parent_[x];
        }
        return x;
    }

    /// Merge the sets containing x and y. Returns the new representative.
    size_t unite(const size_t x_in, const size_t y_in) {
        const size_t rx = find(x_in);
        const size_t ry = find(y_in);
        if (rx == ry) {
            return rx;
        }
        if (rank_[rx] < rank_[ry]) {
            parent_[rx] = ry;
            return ry;
        }
        if (rank_[rx] > rank_[ry]) {
            parent_[ry] = rx;
            return rx;
        }
        parent_[ry] = rx;
        rank_[rx]++;
        return rx;
    }

    /// Whether x and y are in the same set.
    [[nodiscard]]
    bool same(const size_t x, const size_t y) const {
        return find_const(x) == find_const(y);
    }

    /// Add a new singleton element and return its index.
    size_t push() {
        const size_t id = parent_.size();
        parent_.push_back(id);
        rank_.push_back(0);
        return id;
    }

    /// Number of elements.
    [[nodiscard]]
    size_t size() const {
        return parent_.size();
    }
};

} // namespace prevail

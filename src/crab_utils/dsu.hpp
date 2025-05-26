// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <numeric>   // For std::iota
#include <stdexcept> // For std::out_of_range, std::invalid_argument
#include <vector>

namespace prevail {

class DisjointSetUnion {
    std::vector<int> parent;
    std::vector<int> rank;
    int num_elements{};
    int _num_disjoint_sets{};

    void link(const int root_x, const int root_y) {
        if (rank[root_x] > rank[root_y]) {
            parent[root_y] = root_x;
        } else {
            parent[root_x] = root_y;
            if (rank[root_x] == rank[root_y]) {
                rank[root_y]++;
            }
        }
        _num_disjoint_sets--;
    }

    void check_bounds(const int v) const {
        if (v < 0 || v >= num_elements) {
            throw std::out_of_range("DSU: index out of bounds");
        }
    }

    static void check_nonnegative(const int count) {
        if (count < 0) {
            throw std::invalid_argument("DSU count must be positive");
        }
    }

    bool is_representative(const int v) const {
        // An element is a representative if it's its own parent
        return parent[v] == v;
    }

  public:
    explicit DisjointSetUnion(const int count) : num_elements{count}, _num_disjoint_sets{count} {
        check_nonnegative(count);
        parent.resize(count);
        // Each element is its own parent
        std::iota(parent.begin(), parent.end(), 0);
        // The initial rank is 0 for all
        rank.assign(count, 0);
    }

    DisjointSetUnion() {}

    // Resets the DSU to 'count' disjoint sets.
    void reset(const int count) {
        check_nonnegative(count);
        num_elements = count;
        _num_disjoint_sets = count;
        parent.resize(count);
        std::iota(parent.begin(), parent.end(), 0);
        rank.assign(count, 0);
    }

    // Finds the representative of the set containing 'v' (with path compression).
    // This method is non-const as path compression modifies the 'parent' array.
    int find_set(const int v) {
        check_bounds(v);

        const int root = const_cast<const DisjointSetUnion*>(this)->find_set(v);

        // Iterative path compression
        int current = v;
        while (current != root) {
            const int next = parent[current];
            parent[current] = root;
            current = next;
        }
        return root;
    }

    // Const version of find_set without path compression.
    // Useful if the DSU instance is const and modifications are not allowed.
    int find_set(int v) const {
        check_bounds(v);
        while (v != parent[v]) {
            v = parent[v];
        }
        return v;
    }

    // Unites the sets containing 'v1' and 'v2'.
    // Returns the representative of the new merged set.
    // Behavior is well-defined even if v1 and v2 are already in the same set.
    int union_sets(const int v1, const int v2) {
        check_bounds(v1);
        check_bounds(v2);

        const int root_v1 = find_set(v1); // Path compression happens here
        const int root_v2 = find_set(v2); // And here

        if (root_v1 != root_v2) {
            link(root_v1, root_v2);
            // The new root is the one that didn't become a child.
            // Find_set will correctly identify it after link().
            return find_set(root_v1); // Or find_set(root_v2), they are now connected.
        }
        return root_v1; // Already in the same set, return their common root.
    }

    // Returns a list of all unique set representatives.
    std::vector<int> get_representatives() const {
        std::vector<int> representatives;
        representatives.reserve(_num_disjoint_sets); // Optimization: reserve space
        for (int i = 0; i < num_elements; ++i) {
            if (is_representative(i)) {
                representatives.push_back(i);
            }
        }
        return representatives;
    }

    // Returns the total number of elements the DSU was initialized with.
    int get_num_elements() const { return num_elements; }

    // Returns the current number of disjoint sets.
    int num_disjoint_sets() const { return _num_disjoint_sets; }

    // Checks if two elements are in the same set.
    bool is_same_set(const int v1, const int v2) { // non-const due to find_set path compression
        check_bounds(v1);
        check_bounds(v2);
        return find_set(v1) == find_set(v2);
    }

    // Const version of is_same_set
    bool is_same_set(const int v1, const int v2) const {
        check_bounds(v1);
        check_bounds(v2);
        return find_set(v1) == find_set(v2);
    }

    // Clears the DSU, making it empty (0 elements, 0 sets).
    void clear() {
        parent.clear();
        rank.clear();
        num_elements = 0;
        _num_disjoint_sets = 0;
    }
};
} // namespace prevail

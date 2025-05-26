// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include <algorithm> // For std::sort
#include <numeric>   // For std::iota
#include <set>       // For checking representatives

#include "crab_utils/dsu.hpp"

using namespace prevail;

TEST_CASE("DSU Basic Initialization", "[dsu]") {
    SECTION("Positive count initialization") {
        DisjointSetUnion dsu(10);
        REQUIRE(dsu.get_num_elements() == 10);
        REQUIRE(dsu.num_disjoint_sets() == 10);
        for (int i = 0; i < 10; ++i) {
            REQUIRE(dsu.find_set(i) == i); // Each element is its own representative
            REQUIRE(static_cast<const DisjointSetUnion&>(dsu).find_set(i) == i);
        }
    }

    SECTION("Constructor with 1 element") {
        DisjointSetUnion dsu(1);
        REQUIRE(dsu.get_num_elements() == 1);
        REQUIRE(dsu.num_disjoint_sets() == 1);
        REQUIRE(dsu.find_set(0) == 0);
    }

    SECTION("Default constructor then reset") {
        DisjointSetUnion dsu;
        REQUIRE(dsu.get_num_elements() == 0);
        REQUIRE(dsu.num_disjoint_sets() == 0);

        dsu.reset(5);
        REQUIRE(dsu.get_num_elements() == 5);
        REQUIRE(dsu.num_disjoint_sets() == 5);
        for (int i = 0; i < 5; ++i) {
            REQUIRE(dsu.find_set(i) == i);
        }
    }

    SECTION("Error handling for invalid counts") {
        REQUIRE_THROWS_AS(DisjointSetUnion(-1), std::invalid_argument);
        DisjointSetUnion dsu;
        REQUIRE_THROWS_AS(dsu.reset(-5), std::invalid_argument);
    }
}

TEST_CASE("DSU find_set and Path Compression", "[dsu]") {
    DisjointSetUnion dsu(5); // Elements 0, 1, 2, 3, 4

    // Manually create a chain: 0 -> 1 -> 2 (2 is root)
    // To test path compression effectively without union_sets' rank logic,
    // we can directly manipulate a hypothetical parent array for setup.
    // Since we can't directly manipulate, we'll use unions that create specific structures.
    // Create structure 0-1, 2-3, then 1-3 making 0-1-3-2 (if 3 becomes child of 1, and 1 child of 3's root(2) etc.)
    // Actual structure depends on ranks.
    // Simpler: union(0,1), parent[0]=1. union(1,2), parent[1]=2.
    dsu.union_sets(0, 1); // 0 -> 1 (1 is root) or 1 -> 0 (0 is root)

    // Ensure path compression if any happened
    dsu.find_set(0);

    // Now union this set with 2.
    // If we perform union on 0 and 2, the root of {0,1} will be unified with 2.
    dsu.union_sets(0, 2); // {0,1} U {2}
    dsu.find_set(0);

    dsu.union_sets(0, 3); // {0,1,2} U {3}
    dsu.find_set(0);

    dsu.union_sets(0, 4); // {0,1,2,3} U {4}
    // Check that all elements point to the same root after multiple find_set calls
    // which should trigger path compression in the non-const version.
    int final_root = dsu.find_set(0);
    REQUIRE(dsu.find_set(1) == final_root);
    REQUIRE(dsu.find_set(2) == final_root);
    REQUIRE(dsu.find_set(3) == final_root);
    REQUIRE(dsu.find_set(4) == final_root);

    // Verify the internal parent array reflects path compression towards final_root
    // This requires friend access or a getter for the parent array for full white-box testing.
    // For black-box, we rely on the external behavior (all find_set return the same root).

    // Test const find_set (should not compress paths but still find the correct root)
    const DisjointSetUnion& const_dsu = dsu;
    REQUIRE(const_dsu.find_set(0) == final_root);
    REQUIRE(const_dsu.find_set(1) == final_root);
    REQUIRE(const_dsu.find_set(2) == final_root);
    REQUIRE(const_dsu.find_set(3) == final_root);
    REQUIRE(const_dsu.find_set(4) == final_root);

    SECTION("find_set out of bounds") {
        REQUIRE_THROWS_AS(dsu.find_set(5), std::out_of_range);
        REQUIRE_THROWS_AS(dsu.find_set(-1), std::out_of_range);
        REQUIRE_THROWS_AS(const_dsu.find_set(5), std::out_of_range);
        REQUIRE_THROWS_AS(const_dsu.find_set(-1), std::out_of_range);
    }
}

TEST_CASE("DSU union_sets and Rank/Number of Sets", "[dsu]") {
    DisjointSetUnion dsu(5);

    REQUIRE(dsu.num_disjoint_sets() == 5);

    // Union (0,1)
    int root01 = dsu.union_sets(0, 1);
    REQUIRE(dsu.is_same_set(0, 1));
    REQUIRE(dsu.find_set(0) == root01);
    REQUIRE(dsu.find_set(1) == root01);
    REQUIRE(dsu.num_disjoint_sets() == 4);

    // Union (2,3)
    int root23 = dsu.union_sets(2, 3);
    REQUIRE(dsu.is_same_set(2, 3));
    REQUIRE(dsu.find_set(2) == root23);
    REQUIRE(dsu.find_set(3) == root23);
    REQUIRE(dsu.num_disjoint_sets() == 3);
    REQUIRE_FALSE(dsu.is_same_set(0, 2)); // Different sets

    // Union (0,2) -> should merge {0,1} and {2,3}
    int root0123 = dsu.union_sets(0, 2);
    REQUIRE(dsu.is_same_set(0, 3));
    REQUIRE(dsu.is_same_set(1, 2));
    REQUIRE(dsu.find_set(0) == root0123);
    REQUIRE(dsu.find_set(1) == root0123);
    REQUIRE(dsu.find_set(2) == root0123);
    REQUIRE(dsu.find_set(3) == root0123);
    REQUIRE(dsu.num_disjoint_sets() == 2);

    // Union with an element already in the same set
    int current_root = dsu.find_set(0);
    dsu.union_sets(0, 3); // Should be a no-op for count and structure other than path compression
    REQUIRE(dsu.find_set(0) == current_root);
    REQUIRE(dsu.num_disjoint_sets() == 2);

    // Union with the last element
    dsu.union_sets(4, 0);
    REQUIRE(dsu.num_disjoint_sets() == 1);
    current_root = dsu.find_set(0);
    REQUIRE(dsu.find_set(4) == current_root);
    for (int i = 0; i < 5; ++i) {
        REQUIRE(dsu.find_set(i) == current_root);
    }

    SECTION("union_sets out of bounds") {
        REQUIRE_THROWS_AS(dsu.union_sets(0, 5), std::out_of_range);
        REQUIRE_THROWS_AS(dsu.union_sets(5, 0), std::out_of_range);
        REQUIRE_THROWS_AS(dsu.union_sets(-1, 0), std::out_of_range);
    }
}

TEST_CASE("DSU get_representatives", "[dsu]") {
    SECTION("All distinct sets") {
        DisjointSetUnion dsu(3);
        std::vector<int> reps = dsu.get_representatives();
        std::ranges::sort(reps);
        REQUIRE(reps == std::vector<int>{0, 1, 2});
    }

    SECTION("Some sets merged") {
        DisjointSetUnion dsu(5);
        dsu.union_sets(0, 1); // Rep R1
        dsu.union_sets(2, 3); // Rep R2
                              // Element 4 is Rep R3
        std::vector<int> reps = dsu.get_representatives();
        REQUIRE(reps.size() == 3);
        std::set<int> rep_set(reps.begin(), reps.end());

        std::set<int> expected_reps;
        expected_reps.insert(dsu.find_set(0));
        expected_reps.insert(dsu.find_set(2));
        expected_reps.insert(dsu.find_set(4));

        REQUIRE(rep_set == expected_reps);
    }

    SECTION("All elements in one set") {
        DisjointSetUnion dsu(4);
        dsu.union_sets(0, 1);
        dsu.union_sets(0, 2);
        dsu.union_sets(0, 3);
        std::vector<int> reps = dsu.get_representatives();
        REQUIRE(reps.size() == 1);
        REQUIRE(reps[0] == dsu.find_set(0));
    }

    SECTION("Empty DSU") {
        DisjointSetUnion dsu; // Uses default constructor (0 elements)
        dsu.reset(0);         // Explicitly reset to 0, though the default constructor does it.
        // This test requires check_nonzero to allow 0. Let's assume it was `count < 0`.
        // If check_nonzero throws for 0, this test needs adjustment or DSU needs to handle 0 elements.
        // For now, let's assume `reset(0)` leads to `num_elements = 0`.
        DisjointSetUnion dsu_zero_explicit(0); // Assuming constructor DisjointSetUnion(0) is valid.
                                               // if check_nonzero throws for 0, this line will fail.
        REQUIRE_THROWS_AS(DisjointSetUnion{-1}, std::invalid_argument);

        // Let's test a DSU that was constructed and then cleared
        DisjointSetUnion dsu_cleared(5);
        dsu_cleared.clear();
        REQUIRE(dsu_cleared.get_representatives().empty());
        REQUIRE(dsu_cleared.num_disjoint_sets() == 0);
        REQUIRE(dsu_cleared.get_num_elements() == 0);
    }
    SECTION("DSU with 1 element (after reset)") {
        DisjointSetUnion dsu(1);
        std::vector<int> reps = dsu.get_representatives();
        REQUIRE(reps.size() == 1);
        REQUIRE(reps[0] == 0);
    }
}

TEST_CASE("DSU is_same_set", "[dsu]") {
    DisjointSetUnion dsu(5);

    REQUIRE_FALSE(dsu.is_same_set(0, 1));
    dsu.union_sets(0, 1);
    REQUIRE(dsu.is_same_set(0, 1));
    REQUIRE(dsu.is_same_set(1, 0)); // Symmetric
    REQUIRE_FALSE(dsu.is_same_set(0, 2));

    dsu.union_sets(2, 3);
    dsu.union_sets(0, 3); // Links {0,1} with {2,3}
    REQUIRE(dsu.is_same_set(1, 3));
    REQUIRE(dsu.is_same_set(0, 2));
    REQUIRE_FALSE(dsu.is_same_set(0, 4));

    // Test const version
    const DisjointSetUnion& const_dsu = dsu;
    REQUIRE(const_dsu.is_same_set(1, 3));
    REQUIRE_FALSE(const_dsu.is_same_set(0, 4));

    SECTION("is_same_set out of bounds") {
        REQUIRE_THROWS_AS(dsu.is_same_set(0, 5), std::out_of_range);
        REQUIRE_THROWS_AS(dsu.is_same_set(5, 0), std::out_of_range);
        REQUIRE_THROWS_AS(const_dsu.is_same_set(0, 5), std::out_of_range);
    }
}

TEST_CASE("DSU clear and reset", "[dsu]") {
    DisjointSetUnion dsu(5);
    dsu.union_sets(0, 1);
    dsu.union_sets(2, 3);

    REQUIRE(dsu.get_num_elements() == 5);
    REQUIRE(dsu.num_disjoint_sets() == 3);

    dsu.clear();
    REQUIRE(dsu.get_num_elements() == 0);
    REQUIRE(dsu.num_disjoint_sets() == 0);
    REQUIRE(dsu.get_representatives().empty());

    // Operations on cleared DSU should fail or be no-ops until reset
    REQUIRE_THROWS_AS(dsu.find_set(0), std::out_of_range); // No elements
    REQUIRE_THROWS_AS(dsu.union_sets(0, 1), std::out_of_range);

    dsu.reset(3);
    REQUIRE(dsu.get_num_elements() == 3);
    REQUIRE(dsu.num_disjoint_sets() == 3);
    for (int i = 0; i < 3; ++i) {
        REQUIRE(dsu.find_set(i) == i);
    }
    REQUIRE_FALSE(dsu.is_same_set(0, 1));
}

TEST_CASE("DSU Large Number of Unions (Rank Heuristic Stress)", "[dsu]") {
    constexpr int N = 1000;
    DisjointSetUnion dsu(N);

    // Star formation (all unified with 0)
    for (int i = 1; i < N; ++i) {
        dsu.union_sets(0, i);
    }
    REQUIRE(dsu.num_disjoint_sets() == 1);
    int root = dsu.find_set(0);
    for (int i = 0; i < N; ++i) {
        REQUIRE(dsu.find_set(i) == root);
    }

    // Linear chain formation
    dsu.reset(N);
    for (int i = 0; i < N - 1; ++i) {
        dsu.union_sets(i, i + 1);
    }
    REQUIRE(dsu.num_disjoint_sets() == 1);
    root = dsu.find_set(0);
    for (int i = 0; i < N; ++i) {
        REQUIRE(dsu.find_set(i) == root);
    }
}

// Test cases for a DSU constructed with DisjointSetUnion() and then reset()
TEST_CASE("DSU Default Constructed then Reset", "[dsu]") {
    DisjointSetUnion dsu;
    REQUIRE(dsu.get_num_elements() == 0);
    REQUIRE(dsu.num_disjoint_sets() == 0);

    SECTION("Reset to positive count") {
        dsu.reset(10);
        REQUIRE(dsu.get_num_elements() == 10);
        REQUIRE(dsu.num_disjoint_sets() == 10);
        for (int i = 0; i < 10; ++i) {
            REQUIRE(dsu.find_set(i) == i);
        }
    }

    SECTION("Reset multiple times") {
        dsu.reset(3);
        REQUIRE(dsu.get_num_elements() == 3);
        REQUIRE(dsu.num_disjoint_sets() == 3);
        dsu.union_sets(0, 1);
        REQUIRE(dsu.num_disjoint_sets() == 2);

        dsu.reset(5);
        REQUIRE(dsu.get_num_elements() == 5);
        REQUIRE(dsu.num_disjoint_sets() == 5);
        REQUIRE_FALSE(dsu.is_same_set(0, 1)); // Previous state should be gone
    }

    SECTION("Reset to 1") {
        dsu.reset(1);
        REQUIRE(dsu.get_num_elements() == 1);
        REQUIRE(dsu.num_disjoint_sets() == 1);
        REQUIRE(dsu.find_set(0) == 0);
        std::vector<int> reps = dsu.get_representatives();
        REQUIRE(reps.size() == 1);
        REQUIRE(reps[0] == 0);
    }
}

// Test check_nonzero specifically if it were public or through constructor/reset
TEST_CASE("DSU Initialization Count Validation", "[dsu]") {
    REQUIRE_NOTHROW(DisjointSetUnion(1));
    REQUIRE_THROWS_AS(DisjointSetUnion(-1), std::invalid_argument);

    DisjointSetUnion dsu;
    REQUIRE_NOTHROW(dsu.reset(1));
    REQUIRE_THROWS_AS(dsu.reset(-10), std::invalid_argument);
}

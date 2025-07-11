// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <algorithm> // For std::set_intersection, std::set_union
#include <map>
#include <set>
#include <stdexcept>
#include <vector>

#include "type_group_lattice.hpp"

namespace prevail {

// Hasse Diagram encoding through direct parent relationships.
// For a TypeGroup `g`, `get_direct_supergroups(g)` returns its immediate parents.
// An empty vector implies its only parent is any (for initialized types) or it's a top-like element.

static const std::map<TypeGroup, std::vector<TypeGroup>>& get_direct_supergroups_map() {
    static const std::map<TypeGroup, std::vector<TypeGroup>> dg = {
        // Atomic/Base types
        {TypeGroup::number, {TypeGroup::mem_or_num, TypeGroup::ptr_or_num}},
        {TypeGroup::map_fd, {/* Directly under any or a more specific FD group */}},
        {TypeGroup::map_fd_programs, {/* Directly under any or a more specific FD group */}},
        {TypeGroup::ctx, {TypeGroup::singleton_ptr}},
        {TypeGroup::packet, {TypeGroup::stack_or_packet}},
        {TypeGroup::stack, {TypeGroup::stack_or_packet}},
        {TypeGroup::shared, {TypeGroup::mem}}, // shared is mem but not necessarily stack_or_packet or singleton_ptr

        // First level composed types
        {TypeGroup::stack_or_packet, {TypeGroup::mem, TypeGroup::singleton_ptr}},
        {TypeGroup::singleton_ptr, {TypeGroup::pointer}},
        {TypeGroup::mem, {TypeGroup::pointer, TypeGroup::mem_or_num}},

        // Higher level composed types
        {TypeGroup::pointer, {TypeGroup::ptr_or_num}},
        {TypeGroup::mem_or_num,
         {TypeGroup::ptr_or_num}}, // Assuming ptr_or_num is the most general before any for these

        // These are quite general already
        {TypeGroup::ptr_or_num, {/* TypeGroup::any */}},
        {TypeGroup::uninit, {TypeGroup::any}}, // Explicitly making uninit <= any
    };
    return dg;
}

// Recursive helper to get all ancestors (including self)
static void get_all_ancestors_recursive(const TypeGroup g, std::set<TypeGroup>& ancestors) {
    if (ancestors.contains(g)) {
        return;
    }
    ancestors.insert(g);
    const auto& supergroups_map = get_direct_supergroups_map();
    const auto it = supergroups_map.find(g);
    if (it != supergroups_map.end()) {
        for (const TypeGroup parent : it->second) {
            get_all_ancestors_recursive(parent, ancestors);
        }
    }
}

bool TypeGroupLattice::operator<=(const TypeGroup a, const TypeGroup b) {
    if (a == TypeGroup::empty) {
        return true; // Bottom <= X
    }
    if (b == TypeGroup::any) {
        return true; // X <= Top
    }
    if (a == TypeGroup::any) {
        return false; // Top only <= Top
    }
    if (b == TypeGroup::empty) {
        return false; // X only <= Bottom if X is Bottom
    }

    if (a == TypeGroup::uninit) {
        return (b == TypeGroup::uninit);
    }
    if (b == TypeGroup::uninit) { // a is concrete or any
        return false;             // No initialized type or any is <= uninit
    }

    // Both a and b are concrete/composed TypeGroups (not Empty, Any, Uninit)
    if (a == b) {
        return true;
    }

    std::set<TypeGroup> ancestors_of_a;
    get_all_ancestors_recursive(a, ancestors_of_a);
    return ancestors_of_a.contains(b); // Is b an ancestor of a?
}

// Iterative helper to get all unique ancestors (including self) for a given TypeGroup.
static std::set<TypeGroup> get_all_ancestors(const TypeGroup g) {
    if (g == TypeGroup::any) {
        return {TypeGroup::any};
    }
    if (g == TypeGroup::empty) {
        return {TypeGroup::empty};
    }
    // `uninit` is handled correctly by the loop if its parent is `any` in the map.
    // Or handle explicitly:
    // if (g == TypeGroup::uninit) return {TypeGroup::uninit, TypeGroup::any};

    std::set<TypeGroup> ancestors;
    std::vector<TypeGroup> worklist;

    ancestors.insert(g);
    worklist.push_back(g);

    size_t head = 0;
    while (head < worklist.size()) {
        TypeGroup current = worklist[head++];
        const auto& supergroups_map = get_direct_supergroups_map();
        if (supergroups_map.contains(current)) {
            for (TypeGroup parent_group : supergroups_map.at(current)) {
                if (!ancestors.contains(parent_group)) { // if not visited
                    ancestors.insert(parent_group);
                    worklist.push_back(parent_group);
                }
            }
        }
    }
    // Ensure any is an ancestor of all valid types.
    ancestors.insert(TypeGroup::any);
    return ancestors;
}

TypeGroup TypeGroupLattice::join(const TypeGroup a, TypeGroup b) {
    if (a <= b) {
        return b;
    }
    if (b <= a) {
        return a;
    }

    // At this point, a and b are not Empty, and neither is <= the other.
    // If either is any, the result is any (already covered by operator<= if one was any).
    // If one is uninit and the other is a concrete type, their join is any.
    if (a == TypeGroup::uninit || b == TypeGroup::uninit) {
        return TypeGroup::any;
    }

    // Both a and b are "normal" (initialized, non-Any, non-Empty) TypeGroups and incomparable.
    // Find the Lowest Common Ancestor (LCA).
    std::set<TypeGroup> ancestors_a;
    get_all_ancestors_recursive(a, ancestors_a);

    // Optimized LCA search: Start from b and go up. The first ancestor of b
    // also in ancestors_a is an LCA candidate. We need the "lowest" such.
    // For this specific Hasse diagram, we can hardcode some common joins for "obviousness".

    // Specific joins based on the diagram:
    if ((ancestors_a.contains(TypeGroup::mem) || a == TypeGroup::mem) &&
        (get_all_ancestors(b).contains(TypeGroup::mem) || b == TypeGroup::mem) &&
        TypeGroup::mem <= join(a, b)) { // Check if MEM is a valid LCA
        if (a <= TypeGroup::mem && b <= TypeGroup::mem) {
            return TypeGroup::mem;
        }
    }

    if ((ancestors_a.contains(TypeGroup::pointer) || a == TypeGroup::pointer) &&
        (get_all_ancestors(b).contains(TypeGroup::pointer) || b == TypeGroup::pointer) &&
        TypeGroup::pointer <= join(a, b)) {
        if (a <= TypeGroup::pointer && b <= TypeGroup::pointer) {
            return TypeGroup::pointer;
        }
    }

    if ((ancestors_a.contains(TypeGroup::ptr_or_num) || a == TypeGroup::ptr_or_num) &&
        (get_all_ancestors(b).contains(TypeGroup::ptr_or_num) || b == TypeGroup::ptr_or_num) &&
        TypeGroup::ptr_or_num <= join(a, b)) {
        if (a <= TypeGroup::ptr_or_num && b <= TypeGroup::ptr_or_num) {
            return TypeGroup::ptr_or_num;
        }
    }

    // Default LCA is any if no more specific common ancestor is found by the above.
    return TypeGroup::any;
}

TypeGroup TypeGroupLattice::meet(const TypeGroup a, const TypeGroup b) {
    if (a <= b) {
        return a;
    }
    if (b <= a) {
        return b;
    }

    // At this point, a and b are not Empty, and neither is <= the other.
    // If either is any, the result is the other type (meet with Top).
    // If one is uninit and the other is a concrete type, their meet is empty.
    if (a == TypeGroup::uninit || b == TypeGroup::uninit) {
        return TypeGroup::empty;
    }

    // Both a and b are "normal" (initialized, non-Any, non-Empty, non-Uninit) TypeGroups and incomparable.
    // Find the Greatest Common Descendant (GCD).
    // For many pairs this will be empty (e.g., number and stack).
    // If `a` is 'pointer' and `b` is 'mem', their meet is 'mem'.
    // This requires iterating descendants or checking direct relationships.
    // Given the current TypeGroup structure, if they are incomparable and concrete, meet is Empty.
    return TypeGroup::empty;
}

TypeGroup TypeGroupLattice::from_type_encoding(const TypeEncoding enc) {
    switch (enc) {
    case T_UNINIT: return TypeGroup::uninit;
    case T_NUM: return TypeGroup::number;
    case T_CTX: return TypeGroup::ctx;
    case T_PACKET: return TypeGroup::packet;
    case T_STACK: return TypeGroup::stack;
    case T_SHARED: return TypeGroup::shared;
    case T_MAP: return TypeGroup::map_fd;
    case T_MAP_PROGRAMS: return TypeGroup::map_fd_programs;
    default: CRAB_ERROR("Unknown TypeEncoding in from_type_encoding");
    }
}

} // namespace prevail
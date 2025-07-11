// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include "array_domain.hpp"

#include <algorithm> // For std::max, std::find_if
#include <map>
#include <optional> // For std::optional
#include <sstream>  // For std::ostringstream in to_string
#include <string>
#include <vector>

#include "arith/variable.hpp"
#include "crab/type_encoding.hpp" // For TypeGroup enum, TypeEncoding enum
#include "crab/var_registry.hpp"  // For variable_registry for printing
#include "crab_utils/dsu.hpp"

namespace prevail {

class EqualityTypeDomain {
  private:
    // DSU manages equivalence sets of integer IDs.
    DisjointSetUnion dsu;

    // Annotates the representative of each DSU set with its TypeGroup lattice value.
    // Key is the DSU representative ID.
    std::map<int, TypeGroup> representative_type_annotation;

    // Manages mapping between program Variables and integer IDs used by DSU.
    // These are mutable to allow get_or_create_dsu_id in const query methods,
    // as querying a new variable doesn't change the abstract semantic value.
    mutable std::map<Variable, int, decltype(&VariableRegistry::printing_order)> variable_to_dsu_id;
    mutable std::vector<std::optional<Variable>> dsu_id_to_variable; // For debugging/printing
    mutable int next_dsu_id = 0;                                     // Tracks the next available DSU integer ID

    // Flag to indicate if the domain represents an unreachable/contradictory state.
    bool _is_bottom_flag = false;

    // Max number of distinct variables this domain instance can track (and thus DSU size).
    const int max_trackable_variables;

    // Internal helper to get or create a DSU ID for a Variable.
    // Potentially resizes DSU if it were dynamic (not in current DSU design).
    int get_or_create_dsu_id(const Variable& var) const {
        auto it = variable_to_dsu_id.find(var);
        if (it != variable_to_dsu_id.end()) {
            return it->second;
        }
        if (next_dsu_id >= max_trackable_variables) {
            CRAB_ERROR("EqualityTypeDomain: Exceeded max trackable variables. DSU needs to be larger.");
        }
        int new_id = next_dsu_id++;
        variable_to_dsu_id.emplace(var, new_id);
        if (static_cast<size_t>(new_id) >= dsu_id_to_variable.size()) {
            dsu_id_to_variable.resize(new_id + 1);
        }
        dsu_id_to_variable[new_id] = var;
        // New DSU elements are initially in their own set.
        // Their representative annotation should default to a sensible value, e.g., AnyType.
        // The DSU class constructor already makes each element its own representative.
        // We must ensure representative_type_annotation has an entry for this new rep.
        // Note: get_annotation_for_rep handles non-existent entries by returning AnyType,
        // so explicit insertion here is mainly for consistency if other parts assume presence.
        // However, it's better to initialize explicitly.
        // The constructor of EqualityTypeDomain should initialize all possible rep annotations to AnyType.
        // Here, we ensure if a new variable creates a new DSU id that might become a rep, it's covered.
        // Actually, the default annotation is handled by constructor and get_annotation_for_rep.
        return new_id;
    }

    // Helper to get annotation for a representative, defaults to AnyType if not found.
    TypeGroup get_annotation_for_rep(int rep) const {
        if (_is_bottom_flag) {
            return TypeGroup::empty;
        }
        auto it = representative_type_annotation.find(rep);
        return (it == representative_type_annotation.end()) ? TypeGroup::any : it->second;
    }

    // Helper to set annotation for a representative.
    void set_annotation_for_rep(int rep, TypeGroup annotation) {
        if (_is_bottom_flag) {
            return;
        }
        if (annotation == TypeGroup::empty) {
            set_to_bottom();
            return;
        }
        representative_type_annotation[rep] = annotation;
    }

    // Helper to reconstruct variable mappings for a joined/met domain
    void reconstruct_var_mappings_from(const EqualityTypeDomain& d1, const EqualityTypeDomain& d2) {
        // This method assumes 'this->dsu' is already the result of a DSU merge.
        // It rebuilds 'this->variable_to_dsu_id' and 'this->next_dsu_id'.
        // This is tricky if DSU IDs are not preserved.
        // A simpler way: copy all mappings, then let get_or_create_dsu_id handle new ones.
        // For join/meet, we iterate over the union of keys.
        std::set<Variable, decltype(&VariableRegistry::printing_order)> all_vars(VariableRegistry::printing_order);
        for (const auto& pair : d1.variable_to_dsu_id) {
            all_vars.insert(pair.first);
        }
        for (const auto& pair : d2.variable_to_dsu_id) {
            all_vars.insert(pair.first);
        }

        reset_variable_mappings(); // Clear current mappings
        for (const auto& var : all_vars) {
            // This will assign new DSU IDs in 'this' domain as needed.
            // The DSU structure itself must have been formed correctly before this.
            (void)get_or_create_dsu_id(var);
        }
    }

    void reset_variable_mappings() const { // Mutable due to map access
        variable_to_dsu_id.clear();
        dsu_id_to_variable.clear();
        next_dsu_id = 0;
    }

  public:
    explicit EqualityTypeDomain(int max_vars = 256); // Default max variables

    // Default copy/move constructors and assignment operators should be okay
    // if DSU and std::map handle them correctly.
    EqualityTypeDomain(const EqualityTypeDomain& other);
    EqualityTypeDomain& operator=(const EqualityTypeDomain& other);
    EqualityTypeDomain(EqualityTypeDomain&& other) noexcept;
    EqualityTypeDomain& operator=(EqualityTypeDomain&& other) noexcept;

    // --- Core API ---
    bool assign_concrete_type(const Variable& var, TypeEncoding concrete_type_encoding);
    bool assign_group_type(const Variable& var, TypeGroup group_type);
    bool unify_types(const Variable& var_lhs, const Variable& var_rhs);
    TypeGroup get_var_type(const Variable& var) const;
    bool are_types_equal(const Variable& v1, const Variable& v2);       // non-const due to DSU path compression
    bool are_types_equal(const Variable& v1, const Variable& v2) const; // const version
    bool is_in_group(const Variable& var, TypeGroup query_group) const;
    bool has_type(const Variable& var, const TypeEncoding type) const {
        const auto t = get_var_type(var);
        return prevail::has_type(t, type);
    }

    // --- Abstract Domain API ---
    static EqualityTypeDomain top(int max_variables = 256);
    static EqualityTypeDomain bottom(int max_variables = 256);
    void set_to_top();
    void set_to_bottom();
    bool is_bottom() const;
    bool is_top() const;

    bool operator<=(const EqualityTypeDomain& other) const;
    bool operator==(const EqualityTypeDomain& other) const;

    EqualityTypeDomain join(const EqualityTypeDomain& other) const;
    EqualityTypeDomain meet(const EqualityTypeDomain& other) const;
    EqualityTypeDomain widen(const EqualityTypeDomain& other) const;
    EqualityTypeDomain narrow(const EqualityTypeDomain& other) const;

    std::string to_string() const;
    friend std::ostream& operator<<(std::ostream& o, const EqualityTypeDomain& dom);
};

} // namespace prevail
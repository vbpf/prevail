// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <set> // For processing common variables in join/meet
#include <sstream>

#include "crab/type_equality_domain.hpp"
#include "crab/type_group_lattice.hpp"

namespace prevail {

using namespace TypeGroupLattice;

EqualityTypeDomain::EqualityTypeDomain(int max_vars)
    : dsu(max_vars > 0 ? max_vars : 1), // DSU must have at least 1 element if not 0 for check_nonzero
      variable_to_dsu_id(VariableRegistry::printing_order), max_trackable_variables(max_vars) {
    if (max_vars <= 0) {
        // Handle the case where an "empty" domain is created. It's effectively bottom or needs reset.
        // Or ensure max_vars is always positive. DSU(0) might be problematic for check_nonzero.
        // For now, if max_vars is 0, dsu(1) might be a placeholder, but this state is weird.
        // Let's assume max_vars will be reasonably positive (e.g., for registers).
        // If max_vars is 0, it implies a domain that can't track anything.
        _is_bottom_flag = (max_vars < 0); // Consider negative max_vars as an error state -> bottom.
                                          // DSU(0) is invalid due to check_nonzero.
        return;
    }
    for (int i = 0; i < max_vars; ++i) {
        // All DSU elements are initially their own representatives.
        // Annotate them as any (Top of TypeGroupLattice).
        representative_type_annotation[i] = TypeGroup::any;
    }
}

// Copy constructor
EqualityTypeDomain::EqualityTypeDomain(const EqualityTypeDomain& other)
    : dsu(other.dsu), // Relies on DSU's copy constructor
      representative_type_annotation(other.representative_type_annotation),
      variable_to_dsu_id(other.variable_to_dsu_id), dsu_id_to_variable(other.dsu_id_to_variable),
      next_dsu_id(other.next_dsu_id), _is_bottom_flag(other._is_bottom_flag),
      max_trackable_variables(other.max_trackable_variables) {}

// Copy assignment
EqualityTypeDomain& EqualityTypeDomain::operator=(const EqualityTypeDomain& other) {
    if (this == &other) {
        return *this;
    }
    dsu = other.dsu; // Relies on DSU's copy assignment
    representative_type_annotation = other.representative_type_annotation;
    _is_bottom_flag = other._is_bottom_flag;
    variable_to_dsu_id = other.variable_to_dsu_id; // std::map assignment
    dsu_id_to_variable = other.dsu_id_to_variable; // std::vector assignment
    next_dsu_id = other.next_dsu_id;
    // max_trackable_variables is const, no need to assign. Should be same if assignable.
    // If they could differ, this operator would be problematic.
    // assert(max_trackable_variables == other.max_trackable_variables);
    return *this;
}

// Move constructor
EqualityTypeDomain::EqualityTypeDomain(EqualityTypeDomain&& other) noexcept
    : dsu(std::move(other.dsu)), // DSU needs move constructor
      representative_type_annotation(std::move(other.representative_type_annotation)),
      variable_to_dsu_id(std::move(other.variable_to_dsu_id)), dsu_id_to_variable(std::move(other.dsu_id_to_variable)),
      next_dsu_id(other.next_dsu_id), _is_bottom_flag(other._is_bottom_flag),
      max_trackable_variables(other.max_trackable_variables) {
    other.next_dsu_id = 0;
    other._is_bottom_flag = false; // Or some other sensible default for a moved-from state
}

// Move assignment
EqualityTypeDomain& EqualityTypeDomain::operator=(EqualityTypeDomain&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    dsu = std::move(other.dsu); // DSU needs move assignment
    representative_type_annotation = std::move(other.representative_type_annotation);
    _is_bottom_flag = other._is_bottom_flag;
    variable_to_dsu_id = std::move(other.variable_to_dsu_id);
    dsu_id_to_variable = std::move(other.dsu_id_to_variable);
    next_dsu_id = other.next_dsu_id;
    // max_trackable_variables is const
    // assert(max_trackable_variables == other.max_trackable_variables);

    other.next_dsu_id = 0;
    other._is_bottom_flag = false;
    return *this;
}

bool EqualityTypeDomain::assign_concrete_type(const Variable& var, const TypeEncoding concrete_type_encoding) {
    return assign_group_type(var, TypeGroupLattice::from_type_encoding(concrete_type_encoding));
}

bool EqualityTypeDomain::assign_group_type(const Variable& var, const TypeGroup group_type) {
    if (is_bottom()) {
        return false;
    }
    const int var_dsu_id = get_or_create_dsu_id(var);
    const int rep = dsu.find_set(var_dsu_id);
    const TypeGroup current_annotation = get_annotation_for_rep(rep);
    const TypeGroup new_annotation = TypeGroupLattice::meet(current_annotation, group_type);

    if (new_annotation == TypeGroup::empty) {
        set_to_bottom();
        return false;
    }
    set_annotation_for_rep(rep, new_annotation);
    return true;
}

bool EqualityTypeDomain::unify_types(const Variable& var_lhs, const Variable& var_rhs) {
    if (is_bottom()) {
        return false;
    }
    const int lhs_dsu_id = get_or_create_dsu_id(var_lhs);
    const int rhs_dsu_id = get_or_create_dsu_id(var_rhs);

    const int root_lhs = dsu.find_set(lhs_dsu_id);
    const int root_rhs = dsu.find_set(rhs_dsu_id);

    if (root_lhs != root_rhs) {
        const TypeGroup type_lhs_ann = get_annotation_for_rep(root_lhs);
        const TypeGroup type_rhs_ann = get_annotation_for_rep(root_rhs);

        // When unifying two sets, their types must be compatible. The new type is the meet.
        const TypeGroup merged_annotation = TypeGroupLattice::meet(type_lhs_ann, type_rhs_ann);

        if (merged_annotation == TypeGroup::empty) {
            set_to_bottom();
            return false;
        }

        const int new_root = dsu.union_sets(root_lhs, root_rhs);

        // Consolidate annotations
        if (new_root == root_lhs && root_lhs != root_rhs) { // root_rhs merged into root_lhs
            representative_type_annotation.erase(root_rhs);
        } else if (new_root == root_rhs && root_lhs != root_rhs) { // root_lhs merged into root_rhs
            representative_type_annotation.erase(root_lhs);
        }
        set_annotation_for_rep(new_root, merged_annotation);
    }
    return true;
}

TypeGroup EqualityTypeDomain::get_var_type(const Variable& var) const {
    if (is_bottom()) {
        return TypeGroup::empty;
    }
    const auto it = variable_to_dsu_id.find(var);
    if (it == variable_to_dsu_id.end()) {
        // Variable not explicitly tracked, conceptually it's any.
        return TypeGroup::any;
    }
    return get_annotation_for_rep(dsu.find_set(it->second));
}

bool EqualityTypeDomain::are_types_equal(const Variable& v1,
                                         const Variable& v2) { // Non-const due to DSU path compression
    if (is_bottom()) {
        return true; // Or false, depending on desired semantics for bottom
    }

    const auto it1 = variable_to_dsu_id.find(v1);
    const auto it2 = variable_to_dsu_id.find(v2);

    if (it1 != variable_to_dsu_id.end() && it2 != variable_to_dsu_id.end()) {
        return dsu.find_set(it1->second) == dsu.find_set(it2->second);
    }
    // If one or both variables are not tracked, their type is implicitly any.
    // They are considered "equal" if both are untracked, or if one is untracked and the other's tracked type is
    // any.
    return get_var_type(v1) == get_var_type(v2);
}
bool EqualityTypeDomain::are_types_equal(const Variable& v1, const Variable& v2) const { // Const version
    if (is_bottom()) {
        return true;
    }
    const auto it1 = variable_to_dsu_id.find(v1);
    const auto it2 = variable_to_dsu_id.find(v2);
    if (it1 != variable_to_dsu_id.end() && it2 != variable_to_dsu_id.end()) {
        return dsu.find_set(it1->second) == dsu.find_set(it2->second);
    }
    return get_var_type(v1) == get_var_type(v2);
}

bool EqualityTypeDomain::is_in_group(const Variable& var, TypeGroup query_group) const {
    if (is_bottom()) {
        return false; // Or based on query_group == empty
    }
    return get_var_type(var) <= query_group;
}

// --- Abstract Domain Operations ---
EqualityTypeDomain EqualityTypeDomain::top(int max_variables) { return EqualityTypeDomain(max_variables); }
EqualityTypeDomain EqualityTypeDomain::bottom(int max_variables) {
    EqualityTypeDomain dom(max_variables);
    dom.set_to_bottom();
    return dom;
}

void EqualityTypeDomain::set_to_top() {
    _is_bottom_flag = false;
    dsu.reset(max_trackable_variables > 0 ? max_trackable_variables : 1);
    representative_type_annotation.clear();
    for (int i = 0; i < max_trackable_variables; ++i) {
        representative_type_annotation[i] = TypeGroup::any;
    }
    // Variable mappings should be cleared as the DSU structure is new
    reset_variable_mappings();
}

void EqualityTypeDomain::set_to_bottom() {
    _is_bottom_flag = true;
    // Optionally clear another state for canonical bottom, though a flag is enough.
    // representative_type_annotation.clear();
    // variable_to_dsu_id.clear();
    // dsu_id_to_variable.clear();
    // next_dsu_id = 0;
}

bool EqualityTypeDomain::is_bottom() const { return _is_bottom_flag; }

bool EqualityTypeDomain::is_top() const {
    if (_is_bottom_flag) {
        return false;
    }
    // All tracked variables must have type any, and no non-trivial equalities.
    for (const auto& pair : variable_to_dsu_id) {
        const Variable& var = pair.first;
        const int dsu_id = pair.second;
        if (dsu.find_set(dsu_id) != dsu_id) { // Check if this var's ID is part of a larger set
            bool part_of_larger_set = false;
            for (const auto& other_pair : variable_to_dsu_id) {
                if (var == other_pair.first) {
                    continue;
                }
                if (dsu.find_set(dsu_id) == dsu.find_set(other_pair.second)) {
                    part_of_larger_set = true;
                    break;
                }
            }
            if (part_of_larger_set) {
                return false;
            }
        }
        if (get_annotation_for_rep(dsu.find_set(dsu_id)) != TypeGroup::any) {
            return false;
        }
    }
    // If variable_to_dsu_id is empty, it's TOP (or if dsu has 0 elements).
    return true;
}

bool EqualityTypeDomain::operator<=(const EqualityTypeDomain& other) const {
    if (this->is_bottom()) {
        return true;
    }
    if (other.is_bottom()) {
        return false;
    }
    if (other.is_top()) {
        return true;
    }
    if (this->is_top()) {
        return false;
    }

    // Get union of all variables tracked in either domain.
    std::set<Variable, decltype(&VariableRegistry::printing_order)> all_vars(VariableRegistry::printing_order);
    for (const auto& pair : this->variable_to_dsu_id) {
        all_vars.insert(pair.first);
    }
    for (const auto& pair : other.variable_to_dsu_id) {
        all_vars.insert(pair.first);
    }

    for (const auto& v1 : all_vars) {
        // Check type annotation: type_this(v1) <= type_other(v1)
        if (!(this->get_var_type(v1) <= other.get_var_type(v1))) {
            return false;
        }

        // Check equalities: if type(v1)==type(v2) in other, must also hold in this.
        for (const auto& v2 : all_vars) {
            if (v1 == v2) {
                continue; // Using Variable::operator==
            }
            if (other.are_types_equal(v1, v2)) {
                if (!this->are_types_equal(v1, v2)) {
                    return false;
                }
            }
        }
    }
    return true;
}

bool EqualityTypeDomain::operator==(const EqualityTypeDomain& other) const {
    if (this->_is_bottom_flag != other._is_bottom_flag) {
        return false;
    }
    if (this->_is_bottom_flag) {
        return true; // Both bottom
    }

    // For non-bottom domains to be equal:
    // 1. They must track the same set of Variables.
    if (this->variable_to_dsu_id.size() != other.variable_to_dsu_id.size()) {
        return false;
    }

    std::vector<Variable> this_vars;
    for (const auto& pair_this : this->variable_to_dsu_id) {
        this_vars.push_back(pair_this.first);
        if (!other.variable_to_dsu_id.contains(pair_this.first)) {
            return false; // Other doesn't track a var this one does
        }
    }
    // (And vice versa is implied by the same size)

    // 2. For every pair of tracked Variables (v1, v2),
    //    v1 and v2 must be in the same DSU set in *this* IFF they are in the same set in *other*.
    for (size_t i = 0; i < this_vars.size(); ++i) {
        for (size_t j = i + 1; j < this_vars.size(); ++j) {
            const Variable& v1 = this_vars[i];
            const Variable& v2 = this_vars[j];
            // Use the const version of are_types_equal to avoid path compression side effects during comparison
            if (const_cast<EqualityTypeDomain*>(this)->are_types_equal(v1, v2) !=
                const_cast<EqualityTypeDomain&>(other).are_types_equal(v1, v2)) {
                return false;
            }
        }
    }

    // 3. For every tracked Variable v, its concrete type annotation must be the same in both.
    for (const auto& var : this_vars) {
        if (this->get_var_type(var) != other.get_var_type(var)) {
            return false;
        }
    }
    return true;
}

EqualityTypeDomain EqualityTypeDomain::join(const EqualityTypeDomain& other) const {
    if (is_bottom()) {
        return other;
    }
    if (other.is_bottom()) {
        return *this;
    }
    if (is_top() && other.is_top()) {
        return top(max_trackable_variables);
    }
    if (is_top() || other.is_top()) {
        return top(max_trackable_variables);
    }

    EqualityTypeDomain result(max_trackable_variables);

    std::set<Variable, decltype(&VariableRegistry::printing_order)> all_vars_tracked(VariableRegistry::printing_order);
    for (const auto& pair : this->variable_to_dsu_id) {
        all_vars_tracked.insert(pair.first);
    }
    for (const auto& pair : other.variable_to_dsu_id) {
        all_vars_tracked.insert(pair.first);
    }

    for (const auto& var : all_vars_tracked) {
        (void)result.get_or_create_dsu_id(var);
    }

    // 1. Resulting DSU: type(v1)==type(v2) IFF (type(v1)==type(v2) in THIS) AND (type(v1)==type(v2) in OTHER)
    for (const auto& v1_pair : result.variable_to_dsu_id) {
        const Variable& v1 = v1_pair.first;
        const int v1_res_id = v1_pair.second;
        for (const auto& v2_pair : result.variable_to_dsu_id) {
            const Variable& v2 = v2_pair.first;
            if (v1 == v2) {
                continue;
            }
            const int v2_res_id = v2_pair.second;

            if (this->are_types_equal(v1, v2) && other.are_types_equal(v1, v2)) {
                result.dsu.union_sets(v1_res_id, v2_res_id);
            }
        }
    }

    // 2. Resulting annotations: For each representative `res_rep` in `result.dsu`,
    //    its annotation is `type_this(var).join(type_other(var))` (lattice join)
    //    for any var in its class.
    std::map<int, TypeGroup> new_annotations;
    for (const auto& pair : result.variable_to_dsu_id) {
        const Variable& var = pair.first;
        const int var_res_dsu_id = pair.second;
        int res_rep = result.dsu.find_set(var_res_dsu_id);

        if (!new_annotations.contains(res_rep)) {
            const TypeGroup type_this = this->get_var_type(var);
            const TypeGroup type_other = other.get_var_type(var);
            const TypeGroup joined_annotation = TypeGroupLattice::join(type_this, type_other);

            if (joined_annotation == TypeGroup::empty) {
                result.set_to_bottom();
                return result;
            }
            new_annotations[res_rep] = joined_annotation;
        }
    }
    result.representative_type_annotation = new_annotations;
    return result;
}

EqualityTypeDomain EqualityTypeDomain::meet(const EqualityTypeDomain& other) const {
    if (is_bottom() || other.is_bottom()) {
        return bottom(max_trackable_variables);
    }
    if (is_top()) {
        return other;
    }
    if (other.is_top()) {
        return *this;
    }

    EqualityTypeDomain result(max_trackable_variables);

    std::set<Variable, decltype(&VariableRegistry::printing_order)> all_vars_tracked(VariableRegistry::printing_order);
    for (const auto& pair : this->variable_to_dsu_id) {
        all_vars_tracked.insert(pair.first);
    }
    for (const auto& pair : other.variable_to_dsu_id) {
        all_vars_tracked.insert(pair.first);
    }

    for (const auto& var : all_vars_tracked) {
        (void)result.get_or_create_dsu_id(var);
    }

    // 1. Resulting DSU: Equalities from BOTH this AND other are unified.
    // This part is complex: result.dsu starts as discrete.
    // We need to find a DSU that is the join (supremum) of the partitions.
    // Effectively, take all pairs (v1,v2) such that v1 eq v2 in THIS, union them in the result.
    // Then take all pairs (v1,v2) such that v1 eq v2 in OTHER, union them in the result.
    for (const auto& v1_pair : result.variable_to_dsu_id) {
        const Variable& v1 = v1_pair.first;
        const int v1_res_id = v1_pair.second;
        for (const auto& v2_pair : result.variable_to_dsu_id) {
            const Variable& v2 = v2_pair.first;
            if (v1 == v2) {
                continue;
            }
            const int v2_res_id = v2_pair.second;

            if (this->are_types_equal(v1, v2)) {
                result.dsu.union_sets(v1_res_id, v2_res_id);
            }
            if (other.are_types_equal(v1, v2)) {
                result.dsu.union_sets(v1_res_id, v2_res_id);
            }
        }
    }

    // 2. Resulting annotations: For each representative `res_rep` in `result.dsu`,
    //    its annotation is `type_this(var).meet(type_other(var))` (lattice meet).
    std::map<int, TypeGroup> new_annotations;
    for (const auto& pair : result.variable_to_dsu_id) {
        const int var_res_dsu_id = pair.second;
        int res_rep = result.dsu.find_set(var_res_dsu_id);

        // Calculate the new annotation if this representative hasn't been processed yet.
        if (!new_annotations.contains(res_rep)) {
            // The annotation for the *new* representative `res_rep` is the meet of
            // the annotations of all original classes (from `this` and `other`)
            // that got merged into this `res_rep`.
            // A simpler way: for each variable `v` in the class of `res_rep`:
            //   `target_ann = target_ann.meet(this->get_var_type(v))`
            //   `target_ann = target_ann.meet(other->get_var_type(v))`
            // This is effectively: `meet of (meets of original annotations for all elements in new class)`
            // which simplifies to: `meet over all v in class(res_rep) of (this.type(v) meet other.type(v))`

            TypeGroup accumulated_meet_val = TypeGroup::any; // Start with Top for meet accumulation
            for (const auto& inner_pair : result.variable_to_dsu_id) {
                const Variable& current_var_in_class = inner_pair.first;
                if (result.dsu.find_set(inner_pair.second) == res_rep) {
                    const TypeGroup type_this = this->get_var_type(current_var_in_class);
                    const TypeGroup type_other = other.get_var_type(current_var_in_class);
                    accumulated_meet_val =
                        TypeGroupLattice::meet(accumulated_meet_val, TypeGroupLattice::meet(type_this, type_other));
                }
            }

            if (accumulated_meet_val == TypeGroup::empty) {
                result.set_to_bottom();
                return result;
            }
            new_annotations[res_rep] = accumulated_meet_val;
        }
    }
    result.representative_type_annotation = new_annotations;
    return result;
}

EqualityTypeDomain EqualityTypeDomain::widen(const EqualityTypeDomain& other) const {
    // Standard widening for equality domains: if an equivalence is in 'this' but not in 'other', it's dropped.
    // This is equivalent to join for the DSU structure.
    // For annotations: T1 widen T2 = if T1 <= T2 (lattice order) then T2 else Top (any).
    if (is_bottom()) {
        return other;
    }
    if (other.is_bottom()) {
        return *this;
    }

    EqualityTypeDomain result = this->join(other); // Handles DSU structure (intersection of equivalences)
                                                   // and initial annotation join.
    if (result.is_bottom()) {
        return result;
    }

    // Apply widening to annotations based on *original* this and other.
    std::map<int, TypeGroup> widened_annotations;
    for (const auto& pair : result.variable_to_dsu_id) {
        const Variable& var = pair.first;
        int res_rep = result.dsu.find_set(pair.second);

        if (!widened_annotations.contains(res_rep)) {
            const TypeGroup type_this = this->get_var_type(var);
            const TypeGroup type_other = other.get_var_type(var);

            TypeGroup widened_val;
            if (type_this <= type_other) {
                widened_val = type_other;
            } else {
                widened_val = TypeGroup::any; // Widen to Top
            }

            if (widened_val == TypeGroup::empty) {
                result.set_to_bottom();
                return result;
            }
            widened_annotations[res_rep] = widened_val;
        }
    }
    result.representative_type_annotation = widened_annotations;
    return result;
}

EqualityTypeDomain EqualityTypeDomain::narrow(const EqualityTypeDomain& other) const {
    // Narrowing is typically a meet for equality domains.
    return this->meet(other);
}

std::string EqualityTypeDomain::to_string() const {
    std::stringstream ss;
    ss << *this;
    return ss.str();
}

std::ostream& operator<<(std::ostream& o, const EqualityTypeDomain& dom) {
    if (dom.is_bottom()) {
        return o << "_|_";
    }
    o << "{TrackedVars: " << dom.variable_to_dsu_id.size() << "/" << dom.next_dsu_id
      << "; DSU_Sets:" << dom.dsu.num_disjoint_sets() << "; Details: ";
    if (dom.dsu.get_num_elements() == 0 && dom.representative_type_annotation.empty()) {
        o << "(empty/uninitialized DSU)";
    } else {
        bool first_class = true;
        const std::vector<int> reps = dom.dsu.get_representatives();
        for (int rep : reps) {
            // Only print info for representatives that are actually "live" via variable_to_dsu_id
            bool rep_is_live = false;
            std::vector<std::string> var_names_in_class;
            for (const auto& pair : dom.variable_to_dsu_id) {
                if (dom.dsu.find_set(pair.second) == rep) {
                    rep_is_live = true;
                    var_names_in_class.push_back(variable_registry->name(pair.first));
                }
            }
            if (!rep_is_live && !dom.representative_type_annotation.contains(rep)) {
                // This representative isn't associated with any tracked variables AND has no specific annotation
                // (might happen if DSU has more elements than tracked variables, and this rep is for an unused DSU ID)
                continue;
            }

            if (!first_class) {
                o << "; ";
            }
            first_class = false;
            const TypeGroup rep_ann = dom.get_annotation_for_rep(rep);
            o << "RepID" << rep << "(" << rep_ann << "): {";
            bool first_in_class = true;
            for (const auto& name : var_names_in_class) {
                if (!first_in_class) {
                    o << ", ";
                }
                o << name;
                first_in_class = false;
            }
            if (var_names_in_class.empty() && dom.representative_type_annotation.contains(rep)) {
                // Rep has an annotation, but no vars map to it yet (e.g., fresh DSU)
                o << "(empty class with explicit annotation)";
            } else if (var_names_in_class.empty()) {
                // o << "(unused DSU slot)"; // Too noisy for normal output
            }
            o << "}";
        }
    }
    o << "}";
    return o;
}

} // namespace prevail
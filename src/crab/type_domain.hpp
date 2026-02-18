// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.
#include <map>
#include <optional>
#include <vector>

#include "arith/linear_constraint.hpp"
#include "arith/variable.hpp"
#include "crab/dsu.hpp"
#include "crab/type_encoding.hpp"
#include "ir/syntax.hpp"
#include "string_constraints.hpp"

namespace prevail {

Variable reg_type(const Reg& lhs);

/// Bidirectional map between Variables and DSU element IDs.
///
/// Maintains a partial bijection: every live Variable maps to exactly one ID
/// and vice versa. Orphaned IDs (from detach) have no Variable but still
/// occupy a slot in id_to_var.
class VarIdMap {
    std::map<Variable, size_t> var_to_id_;
    std::vector<std::optional<Variable>> id_to_var_;

  public:
    VarIdMap() = default;

    /// Look up the DSU element ID for a variable, or nullopt if absent.
    [[nodiscard]]
    std::optional<size_t> find_id(Variable v) const {
        if (const auto it = var_to_id_.find(v); it != var_to_id_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /// Look up the variable for a DSU element ID, or nullopt if orphaned.
    [[nodiscard]]
    std::optional<Variable> find_var(size_t id) const {
        if (id < id_to_var_.size()) {
            return id_to_var_[id];
        }
        return std::nullopt;
    }

    /// Whether a variable is present.
    [[nodiscard]]
    bool contains(Variable v) const {
        return var_to_id_.contains(v);
    }

    /// Insert or overwrite a bidirectional mapping. Grows id_to_var if needed.
    void insert(Variable v, size_t id) {
        var_to_id_[v] = id;
        while (id_to_var_.size() <= id) {
            id_to_var_.push_back(std::nullopt);
        }
        id_to_var_[id] = v;
    }

    /// Orphan an ID: remove its variable mapping (if any), but keep the slot.
    void orphan(size_t id) {
        if (id < id_to_var_.size()) {
            if (const auto& var = id_to_var_[id]) {
                var_to_id_.erase(*var);
            }
            id_to_var_[id] = std::nullopt;
        }
    }

    /// Orphan the old ID for a variable (if any) without removing the variable
    /// from var_to_id. Used by detach, which immediately re-inserts.
    void orphan_var(Variable v) {
        if (const auto it = var_to_id_.find(v); it != var_to_id_.end()) {
            id_to_var_[it->second] = std::nullopt;
        }
    }

    /// Number of ID slots (including orphaned).
    [[nodiscard]]
    size_t id_capacity() const {
        return id_to_var_.size();
    }

    /// Iterate over all live (Variable, ID) pairs.
    [[nodiscard]]
    const std::map<Variable, size_t>& vars() const {
        return var_to_id_;
    }
};

/// Type abstract domain based on disjoint-set with TypeSet annotations.
///
/// Tracks must-equality between type variables (partition into equivalence
/// classes) and exact finite sets of possible types per class.
///
/// ## Representation
///
/// - Bottom = nullopt (state_ has no value). Unique representation.
/// - Top = default State (sentinels only, no variables). Unique representation.
/// - Non-trivial = State with variables registered in the DSU.
///   The representation is NOT unique: DSU element IDs depend on insertion
///   order, orphaned elements accumulate from detach(), and DSU tree shape
///   depends on union/find history. Two TypeDomains can represent the same
///   abstract value with different internal states. This means equality
///   comparison must be semantic (compare partitions + TypeSets), not
///   structural (compare raw state).
///
/// Note on TypeSet vs TypeDomain defaults: TypeSet{} is bottom (empty bitset,
/// "no types possible"), while TypeDomain{} is top ("all types possible for
/// every variable"). This asymmetry is intentional and follows from how each
/// lattice works: for TypeSet, the empty set is the strongest constraint;
/// for TypeDomain, having no registered variables means no constraints.
///
/// ## Invariants (when state_ has value, i.e., not bottom)
///
/// 1. Sentinels: IDs 0..7 exist. class_types[type_to_bit(te)] = {te}.
/// 2. Singleton-merging: any class with singleton TypeSet {te} has the same
///    DSU representative as sentinel type_to_bit(te). This ensures same_type()
///    is a single DSU rep comparison and join uses raw reps as partition keys.
/// 3. class_types[dsu.find(id)] is the TypeSet for id's equivalence class.
///    class_types at non-representative indices may be stale.
/// 4. var_ids maintains a partial bijection between live Variables and DSU IDs.
/// 5. class_types.size() == var_ids.id_capacity() == dsu.size().
/// 6. No representative has an empty TypeSet (empty -> bottom).
class TypeDomain {
  public:
    TypeDomain();

    TypeDomain(const TypeDomain& other) = default;
    TypeDomain(TypeDomain&& other) noexcept = default;
    TypeDomain& operator=(const TypeDomain& other) = default;
    TypeDomain& operator=(TypeDomain&& other) noexcept = default;

    // Lattice operations
    void operator|=(const TypeDomain& other);

    TypeDomain operator|(const TypeDomain& other) const;

    [[nodiscard]]
    std::optional<TypeDomain> meet(const TypeDomain& other) const;
    bool operator<=(const TypeDomain& other) const;
    void set_to_top();
    static TypeDomain top() { return TypeDomain{}; }
    [[nodiscard]]
    bool is_bottom() const {
        return !state_.has_value();
    }
    [[nodiscard]]
    TypeDomain widen(const TypeDomain& other) const {
        return *this | other;
    }
    [[nodiscard]]
    TypeDomain narrow(const TypeDomain& other) const;

    // Assignment
    void assign_type(const Reg& lhs, const Reg& rhs);
    void assign_type(const Reg& lhs, const std::optional<LinearExpression>& rhs);
    void assign_type(std::optional<Variable> lhs, const LinearExpression& t);
    void assign_type(const Reg& lhs, TypeEncoding type);

    // Constraint handling (== and != only; order comparisons are not meaningful)
    void add_constraint(const LinearConstraint& cst);

    // Type set restriction (direct, non-convex)
    void restrict_to(Variable v, TypeSet mask);

    /// Remove a single type from a variable's set.
    void remove_type(Variable v, TypeEncoding te);

    // Havoc
    void havoc_type(const Reg& r);
    void havoc_type(const Variable& v);

    // Query methods
    [[nodiscard]]
    bool type_is_pointer(const Reg& r) const;
    [[nodiscard]]
    bool type_is_number(const Reg& r) const;
    [[nodiscard]]
    bool type_is_not_stack(const Reg& r) const;
    [[nodiscard]]
    bool type_is_not_number(const Reg& r) const;

    [[nodiscard]]
    std::vector<TypeEncoding> iterate_types(const Reg& reg) const;

    [[nodiscard]]
    std::optional<TypeEncoding> get_type(const Reg& r) const;

    /// Check: "if premise_reg belongs to premise_group, then conclusion_reg's
    /// types must be a subset of conclusion_set."
    [[nodiscard]]
    bool implies_group(const Reg& premise_reg, TypeGroup premise_group, const Reg& conclusion_reg,
                       TypeSet conclusion_set) const;

    /// Check: "if premise_reg's type is not excluded_type, then conclusion_reg's
    /// types must be a subset of conclusion_set."
    [[nodiscard]]
    bool implies_not_type(const Reg& premise_reg, TypeEncoding excluded_type, const Reg& conclusion_reg,
                          TypeSet conclusion_set) const;

    /// Check whether a variable's type is certainly `te` (singleton TypeSet).
    [[nodiscard]]
    bool entail_type(Variable v, TypeEncoding te) const;

    [[nodiscard]]
    bool may_have_type(const LinearExpression& v, TypeEncoding type) const;
    [[nodiscard]]
    bool may_have_type(const Reg& r, TypeEncoding type) const;
    [[nodiscard]]
    bool may_have_type(Variable v, TypeEncoding type) const;

    [[nodiscard]]
    bool is_initialized(const Reg& r) const;
    [[nodiscard]]
    bool is_initialized(const LinearExpression& v) const;

    [[nodiscard]]
    bool same_type(const Reg& a, const Reg& b) const;
    [[nodiscard]]
    bool is_in_group(const Reg& r, TypeGroup group) const;

    /// Check whether a LinearConstraint (== or !=) is entailed.
    /// Used by the test infrastructure; prefer entail_type for new code.
    [[nodiscard]]
    bool entail(const LinearConstraint& cst) const;

    [[nodiscard]]
    StringInvariant to_set() const;
    friend std::ostream& operator<<(std::ostream& o, const TypeDomain& dom);

  private:
    /// Internal state. Present = live domain, absent = bottom.
    struct State {
        DisjointSetUnion dsu;
        VarIdMap var_ids;
        std::vector<TypeSet> class_types;

        State();
    };
    std::optional<State> state_{State{}};

    void set_to_bottom() { state_.reset(); }

    // Internal helpers (all require state_ to have value)
    void merge_if_singleton(size_t id);
    size_t ensure_var(Variable v);
    void detach(Variable v);
    [[nodiscard]]
    TypeSet get_typeset(Variable v) const;
    void restrict_var(Variable v, TypeSet mask);
    void unify(Variable v1, Variable v2);
    void assign_from_expr(Variable lhs, const LinearExpression& expr);
    [[nodiscard]]
    TypeDomain join(const TypeDomain& other) const;
};

} // namespace prevail

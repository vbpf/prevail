// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <memory>
#include <optional>
#include <vector>

#include "arith/linear_constraint.hpp"
#include "arith/variable.hpp"
#include "crab/type_encoding.hpp"
#include "ir/syntax.hpp"
#include "string_constraints.hpp"

namespace prevail {

Variable reg_type(const Reg& lhs);

/// Type abstract domain based on disjoint-set with TypeSet annotations.
///
/// Tracks must-equality between type variables (partition into equivalence
/// classes) and exact finite sets of possible types per class.
///
/// ## Representation
///
/// - Bottom = nullptr (state_ is empty). Unique representation.
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
/// ## Invariants (when state_ is non-null, i.e., not bottom)
///
/// 1. Sentinels: IDs 0..7 exist. class_types[type_to_bit(te)] = {te}.
/// 2. Singleton-merging: any class with singleton TypeSet {te} has the same
///    DSU representative as sentinel type_to_bit(te). This ensures same_type()
///    is a single DSU rep comparison and join uses raw reps as partition keys.
/// 3. class_types[dsu.find(id)] is the TypeSet for id's equivalence class.
///    class_types at non-representative indices may be stale.
/// 4. var_ids maintains a partial bijection between live Variables and DSU IDs.
///    Same pattern as ZoneDomain's VertMap/RevMap (Variable <-> VertId).
/// 5. class_types.size() == var_ids.id_capacity() == dsu.size().
/// 6. No representative has an empty TypeSet (empty -> bottom).
class TypeDomain {
  public:
    TypeDomain();
    ~TypeDomain();

    TypeDomain(const TypeDomain& other);
    TypeDomain(TypeDomain&& other) noexcept;
    TypeDomain& operator=(const TypeDomain& other);
    TypeDomain& operator=(TypeDomain&& other) noexcept;

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
        return !state_;
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
    bool is_initialized(const LinearExpression& expr) const;

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
    struct State;
    std::unique_ptr<State> state_;

    void set_to_bottom();

    [[nodiscard]]
    TypeSet get_typeset(Variable v) const;
    [[nodiscard]]
    TypeDomain join(const TypeDomain& other) const;
};

} // namespace prevail

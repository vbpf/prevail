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

/// Number of sentinel DSU elements (one per TypeEncoding value).
constexpr size_t NUM_TYPE_SENTINELS = 8;

/// Type abstract domain based on disjoint-set with TypeSet annotations.
///
/// Tracks must-equality between type variables (partition into equivalence
/// classes) and exact finite sets of possible types per class.
///
/// ## Singleton-merging invariant
///
/// The domain pre-allocates 8 *sentinel* DSU elements (IDs 0..7), one per
/// TypeEncoding value. Sentinel `i` has `class_types[i] = {te}` where
/// `type_to_bit(te) == i`. After every mutation that may narrow a class's
/// TypeSet to a singleton, the class is merged with the corresponding sentinel
/// via `merge_if_singleton`. This guarantees:
///
///   All DSU elements whose TypeSet is the singleton {te} belong to the
///   same equivalence class as sentinel type_to_bit(te).
///
/// Consequences:
/// - `same_type(a, b)` reduces to a single DSU rep comparison.
/// - `join` can use raw DSU reps as partition keys (no singleton_key hack).
/// - `operator<=` equality check is pure DSU (no singleton special-case).
class TypeDomain {
  public:
    TypeDomain();

    TypeDomain(const TypeDomain& other) = default;
    TypeDomain(TypeDomain&& other) noexcept = default;
    TypeDomain& operator=(const TypeDomain& other) = default;
    TypeDomain& operator=(TypeDomain&& other) noexcept = default;

    // Lattice operations
    void operator|=(const TypeDomain& other);
    void operator|=(TypeDomain&& other) { *this |= other; }

    TypeDomain operator|(const TypeDomain& other) const;
    TypeDomain operator|(TypeDomain&& other) const { return *this | other; }

    std::optional<TypeDomain> meet(const TypeDomain& other) const;
    bool operator<=(const TypeDomain& other) const;
    void set_to_top();
    static TypeDomain top() { return TypeDomain{}; }
    [[nodiscard]] bool is_bottom() const { return is_bottom_; }
    TypeDomain widen(const TypeDomain& other) const { return *this | other; }
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
    [[nodiscard]] bool type_is_pointer(const Reg& r) const;
    [[nodiscard]] bool type_is_number(const Reg& r) const;
    [[nodiscard]] bool type_is_not_stack(const Reg& r) const;
    [[nodiscard]] bool type_is_not_number(const Reg& r) const;

    [[nodiscard]] std::vector<TypeEncoding> iterate_types(const Reg& reg) const;

    [[nodiscard]] std::optional<TypeEncoding> get_type(const Reg& r) const;

    /// Check: "if premise_reg belongs to premise_group, then conclusion_reg's
    /// types must be a subset of conclusion_set."
    [[nodiscard]] bool implies_group(const Reg& premise_reg, TypeGroup premise_group,
                                     const Reg& conclusion_reg, TypeSet conclusion_set) const;

    /// Check: "if premise_reg's type is not excluded_type, then conclusion_reg's
    /// types must be a subset of conclusion_set."
    [[nodiscard]] bool implies_not_type(const Reg& premise_reg, TypeEncoding excluded_type,
                                        const Reg& conclusion_reg, TypeSet conclusion_set) const;

    /// Check whether a variable's type is certainly `te` (singleton TypeSet).
    [[nodiscard]] bool entail_type(Variable v, TypeEncoding te) const;

    [[nodiscard]] bool may_have_type(const LinearExpression& v, TypeEncoding type) const;
    [[nodiscard]] bool may_have_type(const Reg& r, TypeEncoding type) const;
    [[nodiscard]] bool may_have_type(Variable v, TypeEncoding type) const;

    [[nodiscard]] bool is_initialized(const Reg& r) const;
    [[nodiscard]] bool is_initialized(const LinearExpression& v) const;

    [[nodiscard]] bool same_type(const Reg& a, const Reg& b) const;
    [[nodiscard]] bool is_in_group(const Reg& r, TypeGroup group) const;

    /// Check whether a LinearConstraint (== or !=) is entailed.
    /// Used by the test infrastructure; prefer entail_type for new code.
    [[nodiscard]] bool entail(const LinearConstraint& cst) const;

    [[nodiscard]] StringInvariant to_set() const;
    friend std::ostream& operator<<(std::ostream& o, const TypeDomain& dom);

  private:
    DisjointSetUnion dsu;
    std::map<Variable, size_t> var_to_id;
    std::vector<std::optional<Variable>> id_to_var;
    std::vector<TypeSet> class_types; // indexed by DSU element, valid at representative
    bool is_bottom_ = false;

    // Internal helpers
    void init_sentinels();
    void merge_if_singleton(size_t id);
    size_t ensure_var(Variable v);
    void detach(Variable v);
    [[nodiscard]] TypeSet get_typeset(Variable v) const;
    void restrict_var(Variable v, TypeSet mask);
    void unify(Variable v1, Variable v2);
    void assign_from_expr(Variable lhs, const LinearExpression& expr);
    [[nodiscard]] TypeDomain join(const TypeDomain& other) const;
};

} // namespace prevail

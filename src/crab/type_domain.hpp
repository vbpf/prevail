// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <optional>

#include "arith/variable.hpp"
#include "arith/dsl_syntax.hpp"
#include "asm_syntax.hpp" // for Reg
#include "crab/split_dbm.hpp"
#include "crab/type_encoding.hpp"

namespace prevail {

Variable reg_type(const Reg& lhs);

inline LinearConstraint type_is_pointer(const Reg& r) {
    using namespace dsl_syntax;
    return reg_type(r) >= T_CTX;
}

inline LinearConstraint type_is_number(const Reg& r) {
    using namespace dsl_syntax;
    return reg_type(r) == T_NUM;
}

inline LinearConstraint type_is_not_stack(const Reg& r) {
    using namespace dsl_syntax;
    return reg_type(r) != T_STACK;
}

inline LinearConstraint type_is_not_number(const Reg& r) {
    using namespace dsl_syntax;
    return reg_type(r) != T_NUM;
}

struct TypeDomain {
    // Underlying numerical domain should be different, but for interop with ArrayDomain we reuse NumAbsDomain.
    using T = NumAbsDomain;
    T inv;

    TypeDomain() : inv(T::top()) {}
    explicit TypeDomain(const T& other) : inv(other) {};

    TypeDomain(const TypeDomain& other) = default;
    TypeDomain(TypeDomain&& other) noexcept : inv(std::move(other.inv)) {}
    TypeDomain& operator=(const TypeDomain& other) {
        if (this != &other) {
            inv = other.inv;
        }
        return *this;
    }

    TypeDomain operator|(const TypeDomain& other) const { return TypeDomain{inv | other.inv}; }

    std::optional<TypeDomain> meet(const TypeDomain& other) const {
        if (auto res = this->inv & other.inv) {
            return TypeDomain{std::move(res)};
        }
        return {};
    }
    bool operator<=(const TypeDomain& other) const { return inv <= other.inv; }
    void set_to_top() { inv.set_to_top(); }
    static TypeDomain top() { return TypeDomain{}; }
    TypeDomain widen(const TypeDomain& other) const { return TypeDomain{inv.widen(other.inv)}; }
    TypeDomain narrow(const TypeDomain& other) const { return TypeDomain{inv.narrow(other.inv)}; }

    void assign_type(const Reg& lhs, const Reg& rhs);
    void assign_type(const Reg& lhs, const std::optional<LinearExpression>& rhs);
    void assign_type(std::optional<Variable> lhs, const LinearExpression& t);
    void add_constraint(const LinearConstraint& cst) { inv.add_constraint(cst); }
    void havoc_type(const Reg& r);
    void havoc_type(const Variable& v);

    bool type_is_pointer(const Reg& r) const {
        using namespace dsl_syntax;
        return inv.entail(reg_type(r) >= T_CTX);
    }

    bool type_is_number(const Reg& r) const {
        using namespace dsl_syntax;
        return inv.entail(reg_type(r) == T_NUM);
    }

    bool type_is_not_stack(const Reg& r) const {
        using namespace dsl_syntax;
        return inv.entail(reg_type(r) != T_STACK);
    }

    bool type_is_not_number(const Reg& r) const {
        using namespace dsl_syntax;
        return inv.entail(reg_type(r) != T_NUM);
    }

    std::vector<TypeEncoding> iterate_types(const Reg& reg) const;

    [[nodiscard]]
    TypeEncoding get_type(const LinearExpression& v) const;
    [[nodiscard]]
    TypeEncoding get_type(const Reg& r) const;

    [[nodiscard]]
    bool implies(const LinearConstraint& premise, const LinearConstraint& conclusion) const {
        return inv.when(premise).entail(conclusion);
    }

    [[nodiscard]]
    bool may_have_type(const LinearExpression& v, TypeEncoding type) const;
    [[nodiscard]]
    bool may_have_type(const Reg& r, TypeEncoding type) const;

    [[nodiscard]]
    bool is_initialized(const Reg& r) const;

    [[nodiscard]]
    bool is_initialized(const LinearExpression& v) const;

    [[nodiscard]]
    bool same_type(const Reg& a, const Reg& b) const;

    [[nodiscard]]
    bool is_in_group(const Reg& r, TypeGroup group) const;

    StringInvariant to_set() const { return inv.to_set(); }
    friend std::ostream& operator<<(std::ostream& o, const TypeDomain& dom);
};

} // namespace prevail

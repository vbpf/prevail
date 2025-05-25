// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <gsl/narrow>

#include "linear_expression.hpp"

// A linear constraint is of the form:
//    <linear expression> <operator> 0
namespace prevail {

enum class ConstraintKind { EQUALS_ZERO, LESS_THAN_OR_EQUALS_ZERO, LESS_THAN_ZERO, NOT_ZERO };

class LinearConstraint final {
  private:
    LinearExpression _expression = LinearExpression(0);
    ConstraintKind _constraint_kind;

  public:
    LinearConstraint(LinearExpression expression, ConstraintKind constraint_kind)
        : _expression(std::move(expression)), _constraint_kind(constraint_kind) {}

    [[nodiscard]]
    const LinearExpression& expression() const {
        return _expression;
    }
    [[nodiscard]]
    ConstraintKind kind() const {
        return _constraint_kind;
    }

    // Test whether the constraint is guaranteed to be true.
    [[nodiscard]]
    bool is_tautology() const {
        if (!_expression.is_constant()) {
            return false;
        }
        const Number constant = _expression.constant_term();
        switch (_constraint_kind) {
        case ConstraintKind::EQUALS_ZERO: return constant == 0;
        case ConstraintKind::LESS_THAN_OR_EQUALS_ZERO: return constant <= 0;
        case ConstraintKind::LESS_THAN_ZERO: return constant < 0;
        case ConstraintKind::NOT_ZERO: return constant != 0;
        default: throw std::exception();
        }
    }

    // Test whether the constraint is guaranteed to be false.
    [[nodiscard]]
    bool is_contradiction() const {
        if (!_expression.is_constant()) {
            return false;
        }
        return !is_tautology();
    }

    // Construct the logical NOT of this constraint.
    [[nodiscard]]
    LinearConstraint negate() const {
        switch (_constraint_kind) {
        case ConstraintKind::NOT_ZERO: return LinearConstraint(_expression, ConstraintKind::EQUALS_ZERO);
        case ConstraintKind::EQUALS_ZERO: return LinearConstraint(_expression, ConstraintKind::NOT_ZERO);
        case ConstraintKind::LESS_THAN_ZERO:
            return LinearConstraint(_expression.negate(), ConstraintKind::LESS_THAN_OR_EQUALS_ZERO);
        case ConstraintKind::LESS_THAN_OR_EQUALS_ZERO:
            return LinearConstraint(_expression.negate(), ConstraintKind::LESS_THAN_ZERO);
        default: throw std::exception();
        }
    }

    static LinearConstraint false_const() { return LinearConstraint{LinearExpression(0), ConstraintKind::NOT_ZERO}; }

    static LinearConstraint true_const() { return LinearConstraint{LinearExpression(0), ConstraintKind::EQUALS_ZERO}; }
};

// Output a linear constraint to a stream.
inline std::ostream& operator<<(std::ostream& o, const LinearConstraint& constraint) {
    if (constraint.is_contradiction()) {
        o << "false";
    } else if (constraint.is_tautology()) {
        o << "true";
    } else {
        // Display constraint as the simpler form of (e.g.):
        //     Ax + By < -C
        // instead of the internal representation of:
        //     Ax + By + C < 0
        const auto& expression = constraint.expression();
        expression.output_variable_terms(o);

        constexpr std::array constraint_kind_label{" == ", " <= ", " < ", " != "};
        const size_t kind = gsl::narrow<size_t>(constraint.kind());
        if (kind >= std::size(constraint_kind_label)) {
            throw std::exception();
        }
        o << constraint_kind_label[kind] << -expression.constant_term();
    }
    return o;
}

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <map>

#include "crab/variable.hpp"
#include "crab_utils/num_big.hpp"

namespace prevail {

// A linear expression is of the form: Ax + By + Cz + ... + N.
// That is, a sum of terms where each term is either a
// coefficient * variable or simply a coefficient
// (of which there is only one such term).
class LinearExpression final {

    // Use a map for the variable terms to simplify adding two expressions
    // with the same variable.
    using VariableTerms = std::map<Variable, Number>;

  private:
    Number _constant_term{};
    VariableTerms _variable_terms{};

    // Get the coefficient for a given variable, which is 0 if it has no term in the expression.
    [[nodiscard]]
    Number coefficient_of(const Variable& variable) const {
        const auto it = _variable_terms.find(variable);
        if (it == _variable_terms.end()) {
            return 0;
        }
        return it->second;
    }

  public:
    LinearExpression(Number coefficient) : _constant_term(std::move(coefficient)) {}

    LinearExpression(std::integral auto coefficient) : _constant_term(coefficient) {}
    LinearExpression(is_enum auto coefficient) : _constant_term(coefficient) {}
    LinearExpression(Variable variable) { _variable_terms[variable] = 1; }

    LinearExpression(const Number& coefficient, const Variable& variable) {
        if (coefficient != 0) {
            _variable_terms[variable] = coefficient;
        }
    }

    LinearExpression(VariableTerms variable_terms, Number constant_term) : _constant_term(std::move(constant_term)) {
        for (const auto& [variable, coefficient] : variable_terms) {
            if (coefficient != 0) {
                _variable_terms.emplace(variable, coefficient);
            }
        }
    }

    // Allow a caller to access individual terms.
    [[nodiscard]]
    const VariableTerms& variable_terms() const {
        return _variable_terms;
    }
    [[nodiscard]]
    const Number& constant_term() const {
        return _constant_term;
    }

    // Test whether the expression is a constant.
    [[nodiscard]]
    bool is_constant() const {
        return _variable_terms.empty();
    }

    // Multiply a linear expression by a constant.
    [[nodiscard]]
    LinearExpression multiply(const finite_integral auto& constant) const {
        VariableTerms variable_terms;
        for (const auto& [variable, coefficient] : _variable_terms) {
            variable_terms.emplace(variable, coefficient * constant);
        }
        return LinearExpression(variable_terms, _constant_term * constant);
    }

    // Add a constant to a linear expression.
    [[nodiscard]]
    LinearExpression plus(const finite_integral auto& constant) const {
        return LinearExpression(VariableTerms(_variable_terms), _constant_term + constant);
    }

    // Add a variable (with coefficient of 1) to a linear expression.
    [[nodiscard]]
    LinearExpression plus(const Variable& variable) const {
        VariableTerms variable_terms = _variable_terms;
        variable_terms[variable] = coefficient_of(variable) + 1;
        return LinearExpression(variable_terms, _constant_term);
    }

    // Add two expressions.
    [[nodiscard]]
    LinearExpression plus(const LinearExpression& expression) const {
        VariableTerms variable_terms = _variable_terms;
        for (const auto& [variable, coefficient] : expression.variable_terms()) {
            variable_terms[variable] = coefficient_of(variable) + coefficient;
        }
        return LinearExpression(variable_terms, _constant_term + expression.constant_term());
    }

    // Apply unary minus to an expression.
    [[nodiscard]]
    LinearExpression negate() const {
        return multiply(-1);
    }

    // Subtract a constant from a linear expression.
    [[nodiscard]]
    LinearExpression subtract(const finite_integral auto& constant) const {
        return LinearExpression(VariableTerms(_variable_terms), _constant_term - constant);
    }

    // Subtract a variable (with coefficient of 1) from a linear expression.
    [[nodiscard]]
    LinearExpression subtract(const Variable& variable) const {
        VariableTerms variable_terms = _variable_terms;
        variable_terms[variable] = coefficient_of(variable) - 1;
        return LinearExpression(variable_terms, _constant_term);
    }

    // Subtract one expression from another.
    [[nodiscard]]
    LinearExpression subtract(const LinearExpression& expression) const {
        VariableTerms variable_terms = _variable_terms;
        for (const auto& [variable, coefficient] : expression.variable_terms()) {
            variable_terms[variable] = coefficient_of(variable) - coefficient;
        }
        return LinearExpression(variable_terms, _constant_term - expression.constant_term());
    }

    // Output all variable terms to a stream.
    void output_variable_terms(std::ostream& o) const {
        for (const auto& [variable, coefficient] : variable_terms()) {
            if (variable_terms().begin()->first != variable) {
                o << " + ";
            }
            if (coefficient == -1) {
                o << "-";
            } else if (coefficient != 1) {
                o << coefficient << " * ";
            }
            o << variable;
        }
    }
};

// Output a linear expression to a stream.
inline std::ostream& operator<<(std::ostream& o, const LinearExpression& expression) {
    expression.output_variable_terms(o);

    // Output the constant term.
    const Number constant = expression.constant_term();
    if (constant < 0) {
        o << constant;
    } else if (constant > 0) {
        o << " + " << constant;
    }
    return o;
}

} // namespace prevail

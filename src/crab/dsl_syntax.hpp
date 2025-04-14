// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "crab/cfg.hpp"
#include "crab/linear_constraint.hpp"

namespace prevail::dsl_syntax {

inline linear_expression_t operator-(const linear_expression_t& e) { return e.negate(); }

inline linear_expression_t operator*(variable_t x, const number_t& n) { return linear_expression_t(n, x); }

inline linear_expression_t operator*(const number_t& n, const linear_expression_t& e) { return e.multiply(n); }

inline linear_expression_t operator+(const linear_expression_t& e1, const linear_expression_t& e2) {
    return e1.plus(e2);
}

inline linear_expression_t operator-(const linear_expression_t& e1, const linear_expression_t& e2) {
    return e1.subtract(e2);
}

inline linear_constraint_t operator<=(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>=(const linear_expression_t& e1, const linear_expression_t& e2) { return e2 <= e1; }

inline linear_constraint_t operator>(const linear_expression_t& e1, const linear_expression_t& e2) { return e2 < e1; }

inline linear_constraint_t eq(const variable_t a, const variable_t b) {
    using namespace prevail::dsl_syntax;
    return {a - b, constraint_kind_t::EQUALS_ZERO};
}

inline linear_constraint_t neq(const variable_t a, const variable_t b) {
    using namespace prevail::dsl_syntax;
    return {a - b, constraint_kind_t::NOT_ZERO};
}

inline linear_constraint_t operator==(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator!=(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, constraint_kind_t::NOT_ZERO);
}

} // end namespace prevail::dsl_syntax

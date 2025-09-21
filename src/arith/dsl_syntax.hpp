// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "linear_constraint.hpp"

namespace prevail::dsl_syntax {

inline LinearExpression operator-(const LinearExpression& e) { return e.negate(); }

inline LinearExpression operator*(const ProgVar& x, const Number& n) { return LinearExpression(n, x); }

inline LinearExpression operator*(const Number& n, const LinearExpression& e) { return e.multiply(n); }

inline LinearExpression operator+(const LinearExpression& e1, const LinearExpression& e2) { return e1.plus(e2); }

inline LinearExpression operator-(const LinearExpression& e1, const LinearExpression& e2) { return e1.subtract(e2); }

inline LinearConstraint operator<=(const LinearExpression& e1, const LinearExpression& e2) {
    return LinearConstraint(e1 - e2, ConstraintKind::LESS_THAN_OR_EQUALS_ZERO);
}

inline LinearConstraint operator<(const LinearExpression& e1, const LinearExpression& e2) {
    return LinearConstraint(e1 - e2, ConstraintKind::LESS_THAN_ZERO);
}

inline LinearConstraint operator>=(const LinearExpression& e1, const LinearExpression& e2) { return e2 <= e1; }

inline LinearConstraint operator>(const LinearExpression& e1, const LinearExpression& e2) { return e2 < e1; }

inline LinearConstraint eq(const ProgVar& a, const ProgVar& b) {
    using namespace dsl_syntax;
    return {a - b, ConstraintKind::EQUALS_ZERO};
}

inline LinearConstraint neq(const ProgVar& a, const ProgVar& b) {
    using namespace dsl_syntax;
    return {a - b, ConstraintKind::NOT_ZERO};
}

inline LinearConstraint operator==(const LinearExpression& e1, const LinearExpression& e2) {
    return LinearConstraint(e1 - e2, ConstraintKind::EQUALS_ZERO);
}

inline LinearConstraint operator!=(const LinearExpression& e1, const LinearExpression& e2) {
    return LinearConstraint(e1 - e2, ConstraintKind::NOT_ZERO);
}

} // end namespace prevail::dsl_syntax

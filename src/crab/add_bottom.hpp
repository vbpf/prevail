// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>

#include "crab/finite_domain.hpp"

namespace prevail {

class AddBottom final {
    using T = FiniteDomain;
    std::optional<T> dom{};
    AddBottom() {}

  public:
    explicit AddBottom(auto&& _dom) : dom{std::forward<decltype(_dom)>(_dom)} {}
    AddBottom(const AddBottom& other) = default;
    AddBottom(AddBottom& other) = default;
    AddBottom(AddBottom&& other) = default;

    AddBottom& operator=(const AddBottom& o) = default;
    AddBottom& operator=(AddBottom&& o) = default;

    explicit operator bool() const { return static_cast<bool>(dom); }

    T* operator->() { return &dom.value(); }

    const T* operator->() const { return &dom.value(); }

    void set_to_top() {
        if (dom) {
            dom->set_to_top();
        } else {
            dom = T::top();
        }
    }

    void set_to_bottom() { dom = {}; }

    [[nodiscard]]
    bool is_bottom() const {
        return !dom;
    }

    static AddBottom top() { return AddBottom(T::top()); }

    static AddBottom bottom() { return AddBottom(); }

    [[nodiscard]]
    bool is_top() const {
        return dom && dom->is_top();
    }

    bool operator<=(const AddBottom& o) const {
        if (!dom) {
            return true;
        }
        if (!o.dom) {
            return false;
        }
        return *dom <= *o.dom;
    }

    void operator|=(const AddBottom& o) {
        if (!o.dom) {
            return;
        }
        if (!dom) {
            dom = *o.dom;
            return;
        }
        (*dom) |= *o.dom;
    }

    void operator|=(AddBottom&& o) {
        if (!o.dom) {
            return;
        }
        if (!dom) {
            dom = std::move(o.dom);
            return;
        }
        *dom |= std::move(*o.dom);
    }

    template <typename Left, typename Right>
    friend AddBottom operator|(Left&& left, Right&& right) {
        using LDOM = decltype(*std::forward<Left>(left).dom);
        using RDOM = decltype(*std::forward<Right>(right).dom);
        if (!left.dom) {
            return std::forward<Right>(right);
        }
        if (!right.dom) {
            return std::forward<Left>(left);
        }
        return AddBottom(std::forward<LDOM>(*left.dom) | std::forward<RDOM>(*right.dom));
    }

    [[nodiscard]]
    AddBottom widen(const AddBottom& o) const {
        if (!dom) {
            return o;
        }
        if (!o.dom) {
            return *this;
        }
        return AddBottom(dom->widen(*o.dom));
    }

    AddBottom operator&(const AddBottom& o) const {
        if (!dom || !o.dom) {
            return bottom();
        }
        if (auto res = dom->meet(*o.dom)) {
            return AddBottom(*res);
        }
        return bottom();
    }

    AddBottom operator&(AddBottom&& o) const {
        if (!dom || !o.dom) {
            return bottom();
        }
        if (auto res = dom->meet(std::move(*o.dom))) {
            return AddBottom(*res);
        }
        return bottom();
    }

    [[nodiscard]]
    AddBottom narrow(const AddBottom& o) const {
        if (!dom || !o.dom) {
            return bottom();
        }
        return AddBottom(dom->narrow(*o.dom));
    }

    [[nodiscard]]
    AddBottom narrow(AddBottom&& o) const {
        if (!dom || !o.dom) {
            return bottom();
        }
        return AddBottom(dom->narrow(std::move(*o.dom)));
    }

    [[nodiscard]]
    AddBottom when(const LinearConstraint& cst) const {
        if (dom) {
            AddBottom result(*dom);
            if (!result.dom->add_constraint(cst)) {
                result.dom = {};
            }
            return result;
        }
        return bottom();
    }

    void havoc(const Variable v) {
        if (dom) {
            dom->havoc(v);
        }
    }

    void set_min_only(const Variable v) {
        if (dom) {
            dom->set_min_only(v);
        }
    }

    void add_constraint(const LinearConstraint& cst) {
        if (dom) {
            if (!dom->add_constraint(cst)) {
                dom = {};
            }
        }
    }

    [[nodiscard]]
    Interval eval_interval(const LinearExpression& e) const {
        if (dom) {
            return dom->eval_interval(e);
        }
        return Interval::bottom();
    }

    void set(Variable x, const Interval& intv) {
        if (intv.is_bottom()) {
            dom = {};
        } else if (dom) {
            dom->set(x, intv);
        }
    }

    void assign(const std::optional<Variable> x, const LinearExpression& e) {
        if (x) {
            assign(*x, e);
        }
    }

    template <typename V>
    void assign(Variable x, const V& value) {
        if (dom) {
            // XXX: maybe needs to return false when becomes bottom
            // is this possible?
            dom->assign(x, value);
        }
    }

    template <typename Op, typename Left, typename Right>
    void apply(Op op, Variable x, const Left& left, const Right& right, int finite_width) {
        if (dom) {
            dom->apply(op, x, left, right, finite_width);
        }
    }

    // Return true if inv intersects with cst.
    [[nodiscard]]
    bool intersect(const LinearConstraint& cst) const {
        if (dom) {
            return dom->intersect(cst);
        }
        return false;
    }

    // Return true if entails rhs.
    [[nodiscard]]
    bool entail(const LinearConstraint& cst) const {
        if (dom) {
            return dom->entail(cst);
        }
        return true;
    }

    friend std::ostream& operator<<(std::ostream& o, const AddBottom& dom) {
        if (dom.dom) {
            return o << *dom.dom;
        }
        return o << "_|_";
    }

    [[nodiscard]]
    StringInvariant to_set() const {
        if (dom) {
            return dom->to_set();
        }
        return StringInvariant::bottom();
    }
}; // class AddBottom

// Numerical abstract domain.
using NumAbsDomain = AddBottom;

} // namespace prevail

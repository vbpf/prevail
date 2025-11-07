// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// wto.hpp and wto.cpp implement Weak Topological Ordering as defined in
// Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993
// http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.38.3574
//
// Using the example from section 3.1 in the paper, the graph:
//
//         4 --> 5 <-> 6
//         ^ \________ |
//         |          vv
//         3 <-------- 7
//         ^           |
//         |           v
//   1 --> 2 --------> 8
//
// results in the WTO: 1 2 (3 4 (5 6) 7) 8
// where a single vertex is represented via Label, and a
// cycle such as (5 6) is represented via a wto_cycle_t.
// Each arrow points to a CycleOrLabel, which can be either a
// single vertex such as 8, or a cycle such as (5 6).

#include <memory>
#include <optional>
#include <stack>
#include <utility>
#include <variant>
#include <vector>

#include "cfg/cfg.hpp"
#include "cfg/label.hpp"

namespace prevail {

// Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993
// uses the notation w(c) to refer to the set of heads of the nested components
// containing a vertex c.  This class holds such a set of heads.  The table
// mapping c to w(c) is stored outside the class, in wto_collector_t._nesting.
class WtoNesting final {
    // To optimize insertion performance, the list of heads is stored in reverse
    // order, i.e., from innermost to outermost cycle.
    std::vector<Label> _heads;

    friend class PrintVisitor;

  public:
    explicit WtoNesting(std::vector<Label>&& heads) : _heads(std::move(heads)) {}

    // Test whether this nesting is a longer subset of another nesting.
    bool operator>(const WtoNesting& nesting) const;
};

// Define types used by both this header file and wto_cycle.hpp
using CycleOrLabel = std::variant<std::shared_ptr<class WtoCycle>, Label>;
using WtoPartition = std::vector<CycleOrLabel>;

// Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993
// section 3 uses the term "nested component" to refer to what WtoCycle implements.
class WtoCycle final {
    // List of subcomponents (i.e., vertices or other cycles) contained in this cycle.
    WtoPartition _components;

    // The cycle containing this cycle, or null if there is no parent cycle.
    std::weak_ptr<WtoCycle> _containing_cycle;

    friend class Wto;
    friend class WtoBuilder;

  public:
    explicit WtoCycle(const std::weak_ptr<WtoCycle>& containing_cycle) : _containing_cycle(containing_cycle) {}

    // Get a vertex of an entry point of the cycle.
    [[nodiscard]]
    const Label& head() const {
        // Any cycle must start with a vertex, not another cycle,
        // per Definition 1 in the paper.  Since the vector is in reverse
        // order, the head is the last element.
        if (_components.empty()) {
            CRAB_ERROR("Empty cycle");
        }
        if (const auto label = std::get_if<Label>(&_components.back())) {
            return *label;
        }
        CRAB_ERROR("Expected Label at the back of _components");
    }

    [[nodiscard]]
    WtoPartition::const_reverse_iterator begin() const {
        return _components.crbegin();
    }

    [[nodiscard]]
    WtoPartition::const_reverse_iterator end() const {
        return _components.crend();
    }

    void for_each_loop_head(auto&& f) const {
        for (const auto& component : *this) {
            if (const auto pc = std::get_if<std::shared_ptr<WtoCycle>>(&component)) {
                f((*pc)->head());
                (*pc)->for_each_loop_head(f);
            }
        }
    }
};

// Check if node is a member of the wto component.
bool is_component_member(const Label& label, const CycleOrLabel& component);

class Wto final {
    // Top level components, in reverse order.
    WtoPartition _components;

    // Table mapping label to the cycle containing the label.
    std::map<Label, std::weak_ptr<WtoCycle>> _containing_cycle;

    // Table mapping label to the list of heads of cycles containing the label.
    // This is an on-demand cache, since for most vertices the nesting is never
    // looked at so we only create a WtoNesting for cases we actually need it.
    mutable std::map<Label, WtoNesting> _nesting;

    std::vector<Label> collect_heads(const Label& label) const;
    std::optional<Label> head(const Label& label) const;

    Wto() = default;
    friend class WtoBuilder;

  public:
    explicit Wto(const Cfg& cfg);

    [[nodiscard]]
    WtoPartition::const_reverse_iterator begin() const {
        return _components.crbegin();
    }

    [[nodiscard]]
    WtoPartition::const_reverse_iterator end() const {
        return _components.crend();
    }

    friend std::ostream& operator<<(std::ostream& o, const Wto& wto);
    const WtoNesting& nesting(const Label& label) const;

    /**
     * Visit the heads of all loops in the WTO.
     *
     * @param f The callable to be invoked for each loop head.
     *
     * The order in which the heads are visited is not specified.
     */
    void for_each_loop_head(auto&& f) const {
        for (const auto& component : *this) {
            if (const auto pc = std::get_if<std::shared_ptr<WtoCycle>>(&component)) {
                f((*pc)->head());
                (*pc)->for_each_loop_head(f);
            }
        }
    }
};
} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

/*
 * a CFG to interface with the fixpoint iterators.
 */
#include <map>
#include <ranges>
#include <set>
#include <vector>

#include "cfg/label.hpp"
#include "crab_utils/debug.hpp"

namespace prevail {

/// Control-Flow Graph
class Cfg final {
    friend struct CfgBuilder;

    // the choice to use set means that unmarshaling a conditional jump to the same target may be different
    using LabelVec = std::set<Label>;

    struct Adjacent final {
        LabelVec parents;
        LabelVec children;

        [[nodiscard]]
        size_t in_degree() const {
            return parents.size();
        }

        [[nodiscard]]
        size_t out_degree() const {
            return children.size();
        }
    };

    std::map<Label, Adjacent> neighbours{{Label::entry, Adjacent{}}, {Label::exit, Adjacent{}}};

    // Helpers
    [[nodiscard]]
    bool has_one_child(const Label& label) const {
        return out_degree(label) == 1;
    }

    [[nodiscard]]
    bool has_one_parent(const Label& label) const {
        return in_degree(label) == 1;
    }

    [[nodiscard]]
    Adjacent& get_node(const Label& _label) {
        const auto it = neighbours.find(_label);
        if (it == neighbours.end()) {
            CRAB_ERROR("Label ", to_string(_label), " not found in the CFG: ");
        }
        return it->second;
    }

    [[nodiscard]]
    const Adjacent& get_node(const Label& _label) const {
        const auto it = neighbours.find(_label);
        if (it == neighbours.end()) {
            CRAB_ERROR("Label ", to_string(_label), " not found in the CFG: ");
        }
        return it->second;
    }

  public:
    [[nodiscard]]
    Label exit_label() const {
        return Label::exit;
    }

    [[nodiscard]]
    Label entry_label() const {
        return Label::entry;
    }

    [[nodiscard]]
    const LabelVec& children_of(const Label& _label) const {
        return get_node(_label).children;
    }

    [[nodiscard]]
    const LabelVec& parents_of(const Label& _label) const {
        return get_node(_label).parents;
    }

    //! return a view of the labels, including entry and exit
    [[nodiscard]]
    auto labels() const {
        return std::views::keys(neighbours);
    }

    [[nodiscard]]
    size_t size() const {
        return neighbours.size();
    }

    [[nodiscard]]
    Label get_child(const Label& label) const {
        if (!has_one_child(label)) {
            CRAB_ERROR("Label ", to_string(label), " does not have a single child");
        }
        return *get_node(label).children.begin();
    }

    [[nodiscard]]
    Label get_parent(const Label& label) const {
        if (!has_one_parent(label)) {
            CRAB_ERROR("Label ", to_string(label), " does not have a single parent");
        }
        return *get_node(label).parents.begin();
    }

    [[nodiscard]]
    bool contains(const Label& label) const {
        return neighbours.contains(label);
    }

    [[nodiscard]]
    int num_siblings(const Label& label) const {
        return get_node(get_parent(label)).out_degree();
    }

    [[nodiscard]]
    int in_degree(const Label& label) const {
        return get_node(label).in_degree();
    }

    [[nodiscard]]
    int out_degree(const Label& label) const {
        return get_node(label).out_degree();
    }
};

class BasicBlock final {
    using StmtList = std::vector<Label>;
    using const_iterator = StmtList::const_iterator;

    StmtList m_ts;

  public:
    std::strong_ordering operator<=>(const BasicBlock& other) const { return first_label() <=> other.first_label(); }

    static std::set<BasicBlock> collect_basic_blocks(const Cfg& cfg, bool simplify);

    explicit BasicBlock(const Label& first_label) : m_ts{first_label} {}
    BasicBlock(BasicBlock&&) noexcept = default;
    BasicBlock(const BasicBlock&) = default;

    [[nodiscard]]
    Label first_label() const {
        return m_ts.front();
    }

    [[nodiscard]]
    Label last_label() const {
        return m_ts.back();
    }

    [[nodiscard]]
    const_iterator begin() const {
        return m_ts.begin();
    }
    [[nodiscard]]
    const_iterator end() const {
        return m_ts.end();
    }

    [[nodiscard]]
    size_t size() const {
        return m_ts.size();
    }
};

Cfg cfg_from_adjacency_list(const std::map<Label, std::vector<Label>>& AdjList);

} // end namespace prevail

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
class cfg_t final {
    friend struct cfg_builder_t;

    // the choice to use set means that unmarshaling a conditional jump to the same target may be different
    using label_vec_t = std::set<label_t>;

    struct adjacent_t final {
        label_vec_t parents;
        label_vec_t children;

        [[nodiscard]]
        size_t in_degree() const {
            return parents.size();
        }

        [[nodiscard]]
        size_t out_degree() const {
            return children.size();
        }
    };

    std::map<label_t, adjacent_t> neighbours{{label_t::entry, adjacent_t{}}, {label_t::exit, adjacent_t{}}};

    // Helpers
    [[nodiscard]]
    bool has_one_child(const label_t& label) const {
        return out_degree(label) == 1;
    }

    [[nodiscard]]
    bool has_one_parent(const label_t& label) const {
        return in_degree(label) == 1;
    }

    [[nodiscard]]
    adjacent_t& get_node(const label_t& _label) {
        const auto it = neighbours.find(_label);
        if (it == neighbours.end()) {
            CRAB_ERROR("Label ", to_string(_label), " not found in the CFG: ");
        }
        return it->second;
    }

    [[nodiscard]]
    const adjacent_t& get_node(const label_t& _label) const {
        const auto it = neighbours.find(_label);
        if (it == neighbours.end()) {
            CRAB_ERROR("Label ", to_string(_label), " not found in the CFG: ");
        }
        return it->second;
    }

  public:
    [[nodiscard]]
    label_t exit_label() const {
        return label_t::exit;
    }

    [[nodiscard]]
    label_t entry_label() const {
        return label_t::entry;
    }

    [[nodiscard]]
    const label_vec_t& children_of(const label_t& _label) const {
        return get_node(_label).children;
    }

    [[nodiscard]]
    const label_vec_t& parents_of(const label_t& _label) const {
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
    label_t get_child(const label_t& label) const {
        if (!has_one_child(label)) {
            CRAB_ERROR("Label ", to_string(label), " does not have a single child");
        }
        return *get_node(label).children.begin();
    }

    [[nodiscard]]
    label_t get_parent(const label_t& label) const {
        if (!has_one_parent(label)) {
            CRAB_ERROR("Label ", to_string(label), " does not have a single parent");
        }
        return *get_node(label).parents.begin();
    }

    [[nodiscard]]
    bool contains(const label_t& label) const {
        return neighbours.contains(label);
    }

    [[nodiscard]]
    int num_siblings(const label_t& label) const {
        return get_node(get_parent(label)).out_degree();
    }

    [[nodiscard]]
    int in_degree(const label_t& label) const {
        return get_node(label).in_degree();
    }

    [[nodiscard]]
    int out_degree(const label_t& label) const {
        return get_node(label).out_degree();
    }
};

class basic_block_t final {
    using stmt_list_t = std::vector<label_t>;
    using const_iterator = stmt_list_t::const_iterator;

    stmt_list_t m_ts;

  public:
    std::strong_ordering operator<=>(const basic_block_t& other) const { return first_label() <=> other.first_label(); }

    static std::set<basic_block_t> collect_basic_blocks(const cfg_t& cfg, bool simplify);

    explicit basic_block_t(const label_t& first_label) : m_ts{first_label} {}
    basic_block_t(basic_block_t&&) noexcept = default;
    basic_block_t(const basic_block_t&) = default;

    [[nodiscard]]
    label_t first_label() const {
        return m_ts.front();
    }

    [[nodiscard]]
    label_t last_label() const {
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

cfg_t cfg_from_adjacency_list(const std::map<label_t, std::vector<label_t>>& adj_list);

} // end namespace prevail

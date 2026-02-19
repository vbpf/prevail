// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <ranges>
#include <vector>

#include <boost/container/flat_map.hpp>

#include "crab/splitdbm/definitions.hpp"

namespace splitdbm {

class TreeSMap final {
  public:
    using Key = uint16_t;
    using Val = size_t;

  private:
    using col = boost::container::flat_map<Key, Val>;
    col map;

  public:
    using ValueIterator = col::const_iterator;
    [[nodiscard]]
    size_t size() const {
        return map.size();
    }

    struct KeyIterator {
        using difference_type = std::ptrdiff_t;
        using value_type = Key;

        KeyIterator() = default;
        explicit KeyIterator(const col::const_iterator& _e) : e(_e) {}

        Key operator*() const { return e->first; }
        bool operator==(const KeyIterator& o) const = default;
        KeyIterator& operator++() {
            ++e;
            return *this;
        }
        KeyIterator operator++(int) {
            auto tmp = *this;
            ++*this;
            return tmp;
        }

        col::const_iterator e;
    };

    struct KeyConstRange : std::ranges::view_interface<KeyConstRange> {
        using iterator = KeyIterator;

        KeyConstRange() : c{&empty_col()} {}
        explicit KeyConstRange(const col& c) : c{&c} {}

        static const col& empty_col() {
            static const col instance;
            return instance;
        }

        [[nodiscard]]
        size_t size() const {
            return c->size();
        }
        [[nodiscard]]
        KeyIterator begin() const {
            return KeyIterator(c->cbegin());
        }
        [[nodiscard]]
        KeyIterator end() const {
            return KeyIterator(c->cend());
        }

        const col* c{};
    };

    [[nodiscard]]
    auto begin() const {
        return map.begin();
    }
    [[nodiscard]]
    auto end() const {
        return map.end();
    }

    [[nodiscard]]
    KeyConstRange keys() const {
        return KeyConstRange(map);
    }

    [[nodiscard]]
    bool contains(const Key k) const {
        return map.count(k);
    }

    [[nodiscard]]
    std::optional<Val> lookup(const Key k) const {
        if (const auto v = map.find(k); v != map.end()) {
            return {v->second};
        }
        return std::nullopt;
    }

    // precondition: k \in S
    void remove(const Key k) { map.erase(k); }

    // precondition: k \notin S
    void add(const Key k, const Val& v) { map.insert_or_assign(k, v); }
    void clear() { map.clear(); }
};

// Adaptive sparse-set based weighted graph implementation
class AdaptGraph final {
  public:
    AdaptGraph() = default;

    AdaptGraph(AdaptGraph&& o) noexcept = default;

    AdaptGraph(const AdaptGraph& o) = default;

    AdaptGraph& operator=(const AdaptGraph& o) = default;

    AdaptGraph& operator=(AdaptGraph&& o) noexcept = default;

    [[nodiscard]]
    auto verts() const {
        return std::views::iota(VertId{0}, static_cast<VertId>(is_free.size())) |
               std::views::filter([this](const VertId v) { return !is_free[v]; });
    }

    struct EdgeConstIterator {
        using difference_type = std::ptrdiff_t;

        struct EdgeRef {
            VertId vert{};
            Weight val;
        };
        using value_type = EdgeRef;

        TreeSMap::ValueIterator it{};
        const std::vector<Weight>* ws{};

        EdgeConstIterator(const TreeSMap::ValueIterator& _it, const std::vector<Weight>& _ws) : it(_it), ws(&_ws) {}
        EdgeConstIterator(const EdgeConstIterator& o) = default;
        EdgeConstIterator& operator=(const EdgeConstIterator& o) = default;
        EdgeConstIterator() = default;

        EdgeRef operator*() const { return EdgeRef{it->first, (*ws)[it->second]}; }
        EdgeConstIterator& operator++() {
            ++it;
            return *this;
        }
        EdgeConstIterator operator++(int) {
            auto tmp = *this;
            ++*this;
            return tmp;
        }
        bool operator==(const EdgeConstIterator& o) const { return it == o.it; }
    };

    struct EdgeConstRange : std::ranges::view_interface<EdgeConstRange> {
        using iterator = EdgeConstIterator;

        const TreeSMap* entries{&empty_entries()};
        const std::vector<Weight>* ws{&empty_ws()};

      private:
        static const TreeSMap& empty_entries() {
            static const TreeSMap instance;
            return instance;
        }
        static const std::vector<Weight>& empty_ws() {
            static std::vector<Weight> instance;
            return instance;
        }

      public:
        EdgeConstRange() = default;
        EdgeConstRange(const TreeSMap& entries, const std::vector<Weight>& ws) : entries{&entries}, ws{&ws} {}

        [[nodiscard]]
        EdgeConstIterator begin() const {
            return {entries->begin(), *ws};
        }
        [[nodiscard]]
        EdgeConstIterator end() const {
            return {entries->end(), *ws};
        }
    };

    [[nodiscard]]
    TreeSMap::KeyConstRange succs(const VertId v) const {
        return _succs[v].keys();
    }
    [[nodiscard]]
    TreeSMap::KeyConstRange preds(const VertId v) const {
        return _preds[v].keys();
    }

    [[nodiscard]]
    EdgeConstRange e_succs(const VertId v) const {
        return {_succs[v], _ws};
    }
    [[nodiscard]]
    EdgeConstRange e_preds(const VertId v) const {
        return {_preds[v], _ws};
    }

    // Management
    [[nodiscard]]
    bool is_empty() const {
        return edge_count == 0;
    }
    [[nodiscard]]
    size_t size() const {
        return _succs.size();
    }
    [[nodiscard]]
    size_t num_edges() const {
        return edge_count;
    }
    VertId new_vertex() {
        VertId v;
        if (!free_id.empty()) {
            v = free_id.back();
            assert(v < _succs.size());
            free_id.pop_back();
            is_free[v] = false;
        } else {
            v = static_cast<VertId>(_succs.size());
            is_free.push_back(false);
            _succs.emplace_back();
            _preds.emplace_back();
        }

        return v;
    }

    void growTo(const size_t v) {
        _succs.reserve(v);
        _preds.reserve(v);
        while (size() < v) {
            new_vertex();
        }
    }

    void forget(const VertId v) {
        if (is_free[v]) {
            return;
        }

        for (const auto& [key, val] : _succs[v]) {
            free_widx.push_back(val);
            _preds[key].remove(v);
        }
        edge_count -= _succs[v].size();
        _succs[v].clear();

        for (const TreeSMap::Key k : _preds[v].keys()) {
            _succs[k].remove(v);
        }
        edge_count -= _preds[v].size();
        _preds[v].clear();

        is_free[v] = true;
        free_id.push_back(v);
    }

    void clear_edges() {
        _ws.clear();
        for (const VertId v : verts()) {
            _succs[v].clear();
            _preds[v].clear();
        }
        edge_count = 0;
    }
    void clear() {
        _ws.clear();
        _succs.clear();
        _preds.clear();
        is_free.clear();
        free_id.clear();
        free_widx.clear();

        edge_count = 0;
    }

    [[nodiscard]]
    bool elem(const VertId s, const VertId d) const {
        return _succs[s].contains(d);
    }

    [[nodiscard]]
    const Weight& edge_val(const VertId s, const VertId d) const {
        return _ws[*_succs[s].lookup(d)];
    }

    Weight* lookup(const VertId s, const VertId d) {
        if (const auto idx = _succs[s].lookup(d)) {
            return &_ws[*idx];
        }
        return {};
    }

    [[nodiscard]]
    const Weight* lookup(const VertId s, const VertId d) const {
        if (const auto idx = _succs[s].lookup(d)) {
            return &_ws[*idx];
        }
        return {};
    }

    void add_edge(const VertId s, const Weight& w, const VertId d) {
        size_t idx;
        if (!free_widx.empty()) {
            idx = free_widx.back();
            free_widx.pop_back();
            _ws[idx] = w;
        } else {
            idx = _ws.size();
            _ws.push_back(w);
        }

        _succs[s].add(d, idx);
        _preds[d].add(s, idx);
        edge_count++;
    }

    void update_edge(const VertId s, const Weight& w, const VertId d) {
        if (const auto idx = _succs[s].lookup(d)) {
            _ws[*idx] = std::min(_ws[*idx], w);
        } else {
            add_edge(s, w, d);
        }
    }

    void set_edge(const VertId s, const Weight& w, const VertId d) {
        if (const auto idx = _succs[s].lookup(d)) {
            _ws[*idx] = w;
        } else {
            add_edge(s, w, d);
        }
    }

    friend std::ostream& operator<<(std::ostream& o, const AdaptGraph& g) {
        o << "[|";
        bool first_vert = true;
        for (const VertId v : g.verts()) {
            bool first_edge = true;
            for (const auto e : g.e_succs(v)) {
                if (first_edge) {
                    o << (first_vert ? "" : ", ") << "[v" << v << " -> ";
                    first_vert = false;
                    first_edge = false;
                } else {
                    o << ", ";
                }
                o << "(" << e.val << ":" << e.vert << ")";
            }
            if (!first_edge) {
                o << "]";
            }
        }
        o << "|]";
        return o;
    }

  private:
    std::vector<TreeSMap> _preds{};
    std::vector<TreeSMap> _succs{};
    std::vector<Weight> _ws{};

    size_t edge_count{};

    std::vector<int> is_free{};
    std::vector<VertId> free_id{};
    std::vector<size_t> free_widx{};
};

// Short alias used throughout the module; AdaptGraph is the only graph implementation.
using Graph = AdaptGraph;

} // namespace splitdbm

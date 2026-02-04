// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

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

    class KeyIterator {
      public:
        KeyIterator() = default;
        explicit KeyIterator(const col::const_iterator& _e) : e(_e) {}

        /// return canonical empty iterator
        static KeyIterator empty_iterator() {
            static KeyIterator empty_iter;
            return empty_iter;
        }

        Key operator*() const { return e->first; }
        bool operator!=(const KeyIterator& o) const { return e != o.e; }
        KeyIterator& operator++() {
            ++e;
            return *this;
        }

        col::const_iterator e;
    };

    class KeyConstRange {
      public:
        using iterator = KeyIterator;

        explicit KeyConstRange(const col& c) : c{c} {}
        [[nodiscard]]
        size_t size() const {
            return c.size();
        }

        [[nodiscard]]
        KeyIterator begin() const {
            return KeyIterator(c.cbegin());
        }
        [[nodiscard]]
        KeyIterator end() const {
            return KeyIterator(c.cend());
        }

        const col& c;
    };

    class ValueRange {
      public:
        explicit ValueRange(const col& c) : c{c} {}
        [[nodiscard]]
        size_t size() const {
            return c.size();
        }

        [[nodiscard]]
        auto begin() const {
            return c.begin();
        }
        [[nodiscard]]
        auto end() const {
            return c.end();
        }

        const col& c;
    };

    class ValueConstRange {
      public:
        explicit ValueConstRange(const col& c) : c{c} {}
        [[nodiscard]]
        size_t size() const {
            return c.size();
        }

        [[nodiscard]]
        auto begin() const {
            return c.cbegin();
        }
        [[nodiscard]]
        auto end() const {
            return c.cend();
        }

        const col& c;
    };

    [[nodiscard]]
    ValueRange values() const {
        return ValueRange(map);
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
        const auto v = map.find(k);
        if (v != map.end()) {
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

    template <class G>
    static AdaptGraph copy(G& o) {
        AdaptGraph g;
        g.growTo(o.size());

        for (VertId s : o.verts()) {
            for (const auto& e : o.e_succs(s)) {
                g.add_edge(s, e.val, e.vert);
            }
        }
        return g;
    }

    struct VertConstIterator {
        VertId v{};
        const std::vector<int>& is_free;

        VertId operator*() const { return v; }

        bool operator!=(const VertConstIterator& o) {
            while (v < o.v && is_free[v]) {
                ++v;
            }
            return v < o.v;
        }

        VertConstIterator& operator++() {
            ++v;
            return *this;
        }
    };
    struct VertConstRange {
        const std::vector<int>& is_free;

        explicit VertConstRange(const std::vector<int>& _is_free) : is_free(_is_free) {}

        [[nodiscard]]
        VertConstIterator begin() const {
            return VertConstIterator{0, is_free};
        }
        [[nodiscard]]
        VertConstIterator end() const {
            return VertConstIterator{static_cast<VertId>(is_free.size()), is_free};
        }

        [[nodiscard]]
        size_t size() const {
            return is_free.size();
        }
    };
    [[nodiscard]]
    VertConstRange verts() const {
        return VertConstRange{is_free};
    }

    struct EdgeConstIterator {
        struct EdgeRef {
            VertId vert{};
            Weight val;
        };

        TreeSMap::ValueIterator it{};
        const std::vector<Weight>* ws{};

        EdgeConstIterator(const TreeSMap::ValueIterator& _it, const std::vector<Weight>& _ws) : it(_it), ws(&_ws) {}
        EdgeConstIterator(const EdgeConstIterator& o) = default;
        EdgeConstIterator& operator=(const EdgeConstIterator& o) = default;
        EdgeConstIterator() = default;

        /// return canonical empty iterator
        static EdgeConstIterator empty_iterator() {
            static EdgeConstIterator empty_iter;
            return empty_iter;
        }

        EdgeRef operator*() const { return EdgeRef{it->first, (*ws)[it->second]}; }
        EdgeConstIterator operator++() {
            ++it;
            return *this;
        }
        bool operator!=(const EdgeConstIterator& o) const { return it != o.it; }
    };

    struct EdgeConstRange {
        using ValueRange = TreeSMap::ValueRange;
        using iterator = EdgeConstIterator;

        ValueRange r;
        const std::vector<Weight>& ws;

        [[nodiscard]]
        EdgeConstIterator begin() const {
            return EdgeConstIterator(r.begin(), ws);
        }
        [[nodiscard]]
        EdgeConstIterator end() const {
            return EdgeConstIterator(r.end(), ws);
        }
        [[nodiscard]]
        size_t size() const {
            return r.size();
        }
    };

    using AdjRange = TreeSMap::KeyConstRange;
    using AdjConstRange = TreeSMap::KeyConstRange;
    using NeighbourConstRange = AdjConstRange;

    [[nodiscard]]
    AdjConstRange succs(const VertId v) const {
        return _succs[v].keys();
    }
    [[nodiscard]]
    AdjConstRange preds(const VertId v) const {
        return _preds[v].keys();
    }

    [[nodiscard]]
    EdgeConstRange e_succs(const VertId v) const {
        return {_succs[v].values(), _ws};
    }
    [[nodiscard]]
    EdgeConstRange e_preds(const VertId v) const {
        return {_preds[v].values(), _ws};
    }

    using ENeighbourConstRange = EdgeConstRange;

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

        for (const auto& [key, val] : _succs[v].values()) {
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

    const Weight& edge_val(const VertId s, const VertId d) const { return _ws[*_succs[s].lookup(d)]; }

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

    // XXX: g cannot be marked const for complicated reasons
    friend std::ostream& operator<<(std::ostream& o, const AdaptGraph& g) {
        o << "[|";
        bool first = true;
        for (const VertId v : g.verts()) {
            auto it = g.e_succs(v).begin();
            auto end = g.e_succs(v).end();

            if (it != end) {
                if (first) {
                    first = false;
                } else {
                    o << ", ";
                }

                o << "[v" << v << " -> ";
                o << "(" << (*it).val << ":" << (*it).vert << ")";
                for (++it; it != end; ++it) {
                    o << ", (" << (*it).val << ":" << (*it).vert << ")";
                }
                o << "]";
            }
        }
        o << "|]";
        return o;
    }

    // Ick. This'll have another indirection on every operation.
    // We'll see what the performance costs are like.
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

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <memory>

#include <boost/container/flat_map.hpp>

#include "crab_utils/num_safeint.hpp"

namespace prevail {

class TreeSMap final {
  public:
    using key_t = uint16_t;
    using val_t = size_t;

  private:
    using col = boost::container::flat_map<key_t, val_t>;
    col map;

  public:
    using elt_iter_t = col::const_iterator;
    [[nodiscard]]
    size_t size() const {
        return map.size();
    }

    class key_iter_t {
      public:
        key_iter_t() = default;
        explicit key_iter_t(const col::const_iterator& _e) : e(_e) {}

        // XXX: to make sure that we always return the same address
        // for the "empty" iterator, otherwise we can trigger
        // undefined behavior.
        inline static std::unique_ptr<key_iter_t> _empty_iter = std::make_unique<key_iter_t>();
        static key_iter_t empty_iterator() { return *_empty_iter; }

        key_t operator*() const { return e->first; }
        bool operator!=(const key_iter_t& o) const { return e != o.e; }
        key_iter_t& operator++() {
            ++e;
            return *this;
        }

        col::const_iterator e;
    };

    class key_const_range_t {
      public:
        using iterator = key_iter_t;

        explicit key_const_range_t(const col& c) : c{c} {}
        [[nodiscard]]
        size_t size() const {
            return c.size();
        }

        [[nodiscard]]
        key_iter_t begin() const {
            return key_iter_t(c.cbegin());
        }
        [[nodiscard]]
        key_iter_t end() const {
            return key_iter_t(c.cend());
        }

        const col& c;
    };

    class elt_range_t {
      public:
        elt_range_t(const col& c) : c{c} {}
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

    class elt_const_range_t {
      public:
        elt_const_range_t(const col& c) : c{c} {}
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
    elt_range_t elts() const {
        return elt_range_t(map);
    }
    [[nodiscard]]
    key_const_range_t keys() const {
        return key_const_range_t(map);
    }

    [[nodiscard]]
    bool contains(key_t k) const {
        return map.count(k);
    }

    [[nodiscard]]
    std::optional<val_t> lookup(key_t k) const {
        auto v = map.find(k);
        if (v != map.end()) {
            return {v->second};
        }
        return std::nullopt;
    }

    // precondition: k \in S
    void remove(key_t k) { map.erase(k); }

    // precondition: k \notin S
    void add(key_t k, const val_t& v) { map.insert_or_assign(k, v); }
    void clear() { map.clear(); }
};

// Adaptive sparse-set based weighted graph implementation
class AdaptGraph final {
    using smap_t = TreeSMap;

  public:
    /** DBM weights (Weight) can be represented using one of the following
     * types:
     *
     * 1) basic integer type: e.g., long
     * 2) safei64
     * 3) number_t
     *
     * 1) is the fastest but things can go wrong if some DBM
     * operation overflows. 2) is slower than 1) but it checks for
     * overflow before any DBM operation. 3) is the slowest, and it
     * represents weights using unbounded mathematical integers so
     * overflow is not a concern, but it might not be what you need
     * when reasoning about programs with wraparound semantics.
     **/
    using Weight = number_t; // previously template
    using vert_id = unsigned int;

    AdaptGraph() : edge_count(0) {}

    AdaptGraph(AdaptGraph&& o) noexcept = default;

    AdaptGraph(const AdaptGraph& o) = default;

    AdaptGraph& operator=(const AdaptGraph& o) = default;

    AdaptGraph& operator=(AdaptGraph&& o) noexcept = default;

    template <class G>
    static AdaptGraph copy(G& o) {
        AdaptGraph g;
        g.growTo(o.size());

        for (vert_id s : o.verts()) {
            for (const auto& e : o.e_succs(s)) {
                g.add_edge(s, e.val, e.vert);
            }
        }
        return g;
    }

    struct vert_const_iterator {
        vert_id v{};
        const std::vector<int>& is_free;

        vert_id operator*() const { return v; }

        bool operator!=(const vert_const_iterator& o) {
            while (v < o.v && is_free[v]) {
                ++v;
            }
            return v < o.v;
        }

        vert_const_iterator& operator++() {
            ++v;
            return *this;
        }
    };
    struct vert_const_range {
        const std::vector<int>& is_free;

        explicit vert_const_range(const std::vector<int>& _is_free) : is_free(_is_free) {}

        [[nodiscard]]
        vert_const_iterator begin() const {
            return vert_const_iterator{0, is_free};
        }
        [[nodiscard]]
        vert_const_iterator end() const {
            return vert_const_iterator{static_cast<vert_id>(is_free.size()), is_free};
        }

        [[nodiscard]]
        size_t size() const {
            return is_free.size();
        }
    };
    [[nodiscard]]
    vert_const_range verts() const {
        return vert_const_range{is_free};
    }

    struct edge_const_iter {
        struct edge_ref {
            vert_id vert{};
            Weight val;
        };

        smap_t::elt_iter_t it{};
        const std::vector<Weight>* ws{};

        edge_const_iter(const smap_t::elt_iter_t& _it, const std::vector<Weight>& _ws) : it(_it), ws(&_ws) {}
        edge_const_iter(const edge_const_iter& o) = default;
        edge_const_iter& operator=(const edge_const_iter& o) = default;
        edge_const_iter() = default;

        // XXX: to make sure that we always return the same address
        // for the "empty" iterator, otherwise we can trigger
        // undefined behavior.
        inline static std::unique_ptr<edge_const_iter> _empty_iter = std::make_unique<edge_const_iter>();
        static edge_const_iter empty_iterator() { return *_empty_iter; }

        edge_ref operator*() const { return edge_ref{it->first, (*ws)[it->second]}; }
        edge_const_iter operator++() {
            ++it;
            return *this;
        }
        bool operator!=(const edge_const_iter& o) const { return it != o.it; }
    };

    struct edge_const_range_t {
        using elt_range_t = smap_t::elt_range_t;
        using iterator = edge_const_iter;

        elt_range_t r;
        const std::vector<Weight>& ws;

        [[nodiscard]]
        edge_const_iter begin() const {
            return edge_const_iter(r.begin(), ws);
        }
        [[nodiscard]]
        edge_const_iter end() const {
            return edge_const_iter(r.end(), ws);
        }
        [[nodiscard]]
        size_t size() const {
            return r.size();
        }
    };

    using fwd_edge_const_iter = edge_const_iter;
    using rev_edge_const_iter = edge_const_iter;

    using adj_range_t = smap_t::key_const_range_t;
    using adj_const_range_t = smap_t::key_const_range_t;
    using neighbour_range = adj_range_t;
    using neighbour_const_range = adj_const_range_t;

    [[nodiscard]]
    adj_const_range_t succs(vert_id v) const {
        return _succs[v].keys();
    }
    [[nodiscard]]
    adj_const_range_t preds(vert_id v) const {
        return _preds[v].keys();
    }

    using fwd_edge_range = edge_const_range_t;
    using rev_edge_range = edge_const_range_t;

    [[nodiscard]]
    edge_const_range_t e_succs(vert_id v) const {
        return {_succs[v].elts(), _ws};
    }
    [[nodiscard]]
    edge_const_range_t e_preds(vert_id v) const {
        return {_preds[v].elts(), _ws};
    }

    using e_neighbour_const_range = edge_const_range_t;

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
    vert_id new_vertex() {
        vert_id v;
        if (!free_id.empty()) {
            v = free_id.back();
            assert(v < _succs.size());
            free_id.pop_back();
            is_free[v] = false;
        } else {
            v = static_cast<vert_id>(_succs.size());
            is_free.push_back(false);
            _succs.emplace_back();
            _preds.emplace_back();
        }

        return v;
    }

    void growTo(size_t v) {
        _succs.reserve(v);
        _preds.reserve(v);
        while (size() < v) {
            new_vertex();
        }
    }

    void forget(vert_id v) {
        if (is_free[v]) {
            return;
        }

        for (const auto& [key, val] : _succs[v].elts()) {
            free_widx.push_back(val);
            _preds[key].remove(v);
        }
        edge_count -= _succs[v].size();
        _succs[v].clear();

        for (smap_t::key_t k : _preds[v].keys()) {
            _succs[k].remove(v);
        }
        edge_count -= _preds[v].size();
        _preds[v].clear();

        is_free[v] = true;
        free_id.push_back(v);
    }

    void clear_edges() {
        _ws.clear();
        for (vert_id v : verts()) {
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
    bool elem(vert_id s, vert_id d) const {
        return _succs[s].contains(d);
    }

    const Weight& edge_val(vert_id s, vert_id d) const { return _ws[*_succs[s].lookup(d)]; }

    class mut_val_ref_t {
      public:
        mut_val_ref_t() : w(nullptr) {}
        operator Weight() const {
            assert(w);
            return *w;
        }
        [[nodiscard]]
        Weight get() const {
            assert(w);
            return *w;
        }
        void operator=(Weight* _w) { w = _w; }
        void operator=(Weight _w) {
            assert(w);
            *w = _w;
        }

      private:
        Weight* w;
    };

    bool lookup(vert_id s, vert_id d, mut_val_ref_t* w) {
        if (auto idx = _succs[s].lookup(d)) {
            *w = &_ws[*idx];
            return true;
        }
        return false;
    }

    [[nodiscard]]
    std::optional<Weight> lookup(vert_id s, vert_id d) const {
        if (auto idx = _succs[s].lookup(d)) {
            return _ws[*idx];
        }
        return {};
    }

    void add_edge(vert_id s, Weight w, vert_id d) {
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

    void update_edge(vert_id s, Weight w, vert_id d) {
        if (auto idx = _succs[s].lookup(d)) {
            _ws[*idx] = std::min(_ws[*idx], w);
        } else {
            add_edge(s, w, d);
        }
    }

    void set_edge(vert_id s, Weight w, vert_id d) {
        if (auto idx = _succs[s].lookup(d)) {
            _ws[*idx] = w;
        } else {
            add_edge(s, w, d);
        }
    }

    // XXX: g cannot be marked const for complicated reasons
    friend std::ostream& operator<<(std::ostream& o, AdaptGraph& g) {
        o << "[|";
        bool first = true;
        for (vert_id v : g.verts()) {
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
    std::vector<smap_t> _preds{};
    std::vector<smap_t> _succs{};
    std::vector<Weight> _ws{};

    size_t edge_count{};

    std::vector<int> is_free{};
    std::vector<vert_id> free_id{};
    std::vector<size_t> free_widx{};
};
} // namespace prevail

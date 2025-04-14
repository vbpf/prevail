// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "crab/thresholds.hpp"
#include "crab/cfg.hpp"
#include "crab/label.hpp"

namespace prevail {

inline namespace iterators {

void thresholds_t::add(const extended_number& v) {
    if (m_thresholds.size() < m_size) {
        if (std::ranges::find(m_thresholds, v) == m_thresholds.end()) {
            const auto ub = std::ranges::upper_bound(m_thresholds, v);

            // don't add consecutive thresholds
            if (v > number_t{0}) {
                auto prev = ub;
                --prev;
                if (prev != m_thresholds.begin()) {
                    if (*prev + number_t{1} == v) {
                        *prev = v;
                        return;
                    }
                }
            } else if (v < number_t{0}) {
                if (*ub - number_t{1} == v) {
                    *ub = v;
                    return;
                }
            }

            m_thresholds.insert(ub, v);
        }
    }
}

std::ostream& operator<<(std::ostream& o, const thresholds_t& t) {
    o << "{";
    for (auto it = t.m_thresholds.begin(), et = t.m_thresholds.end(); it != et;) {
        extended_number b(*it);
        o << b;
        ++it;
        if (it != t.m_thresholds.end()) {
            o << ",";
        }
    }
    o << "}";
    return o;
}

void wto_thresholds_t::get_thresholds(const label_t& label, thresholds_t& thresholds) const {}

void wto_thresholds_t::operator()(const label_t& vertex) {
    if (m_stack.empty()) {
        return;
    }

    const label_t head = m_stack.back();
    const auto it = m_head_to_thresholds.find(head);
    if (it != m_head_to_thresholds.end()) {
        thresholds_t& thresholds = it->second;
        get_thresholds(vertex, thresholds);
    } else {
        CRAB_ERROR("No head found while gathering thresholds");
    }
}

void wto_thresholds_t::operator()(const std::shared_ptr<wto_cycle_t>& cycle) {
    thresholds_t thresholds(m_max_size);
    const auto& head = cycle->head();
    get_thresholds(head, thresholds);

    // XXX: if we want to consider constants from loop
    // initializations
    for (const auto& pre : m_cfg.parents_of(head)) {
        if (pre != head) {
            get_thresholds(pre, thresholds);
        }
    }

    m_head_to_thresholds.insert(std::make_pair(cycle->head(), thresholds));
    m_stack.push_back(cycle->head());
    for (const auto& component : *cycle) {
        std::visit(*this, component);
    }
    m_stack.pop_back();
}

std::ostream& operator<<(std::ostream& o, const wto_thresholds_t& t) {
    for (const auto& [label, th] : t.m_head_to_thresholds) {
        o << to_string(label) << "=" << th << "\n";
    }
    return o;
}
} // namespace iterators

} // namespace prevail

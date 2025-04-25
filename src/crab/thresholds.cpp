// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "crab/thresholds.hpp"
#include "cfg/cfg.hpp"
#include "cfg/label.hpp"

namespace prevail {

void Thresholds::add(const ExtendedNumber& v) {
    if (m_thresholds.size() < m_size) {
        if (std::ranges::find(m_thresholds, v) == m_thresholds.end()) {
            const auto ub = std::ranges::upper_bound(m_thresholds, v);

            // don't add consecutive thresholds
            if (v > Number{0}) {
                auto prev = ub;
                --prev;
                if (prev != m_thresholds.begin()) {
                    if (*prev + Number{1} == v) {
                        *prev = v;
                        return;
                    }
                }
            } else if (v < Number{0}) {
                if (*ub - Number{1} == v) {
                    *ub = v;
                    return;
                }
            }

            m_thresholds.insert(ub, v);
        }
    }
}

std::ostream& operator<<(std::ostream& o, const Thresholds& t) {
    o << "{";
    for (auto it = t.m_thresholds.begin(), et = t.m_thresholds.end(); it != et;) {
        ExtendedNumber b(*it);
        o << b;
        ++it;
        if (it != t.m_thresholds.end()) {
            o << ",";
        }
    }
    o << "}";
    return o;
}

void WtoThresholds::get_thresholds(const Label& label, Thresholds& thresholds) const {}

void WtoThresholds::operator()(const Label& vertex) {
    if (m_stack.empty()) {
        return;
    }

    const Label head = m_stack.back();
    const auto it = m_head_to_thresholds.find(head);
    if (it != m_head_to_thresholds.end()) {
        Thresholds& thresholds = it->second;
        get_thresholds(vertex, thresholds);
    } else {
        CRAB_ERROR("No head found while gathering thresholds");
    }
}

void WtoThresholds::operator()(const std::shared_ptr<WtoCycle>& cycle) {
    Thresholds thresholds(m_max_size);
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

std::ostream& operator<<(std::ostream& o, const WtoThresholds& t) {
    for (const auto& [label, th] : t.m_head_to_thresholds) {
        o << to_string(label) << "=" << th << "\n";
    }
    return o;
}

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <climits>
#include <map>

#include "cfg/cfg.hpp"
#include "cfg/wto.hpp"
#include "crab/interval.hpp"
#include "crab_utils/debug.hpp"

namespace prevail {

/**
    Class that represents a set of thresholds used by the widening operator
**/

class Thresholds final {

  private:
    std::vector<ExtendedNumber> m_thresholds;
    size_t m_size;

  public:
    explicit Thresholds(const size_t size = UINT_MAX) : m_size(size) {
        m_thresholds.push_back(ExtendedNumber::minus_infinity());
        m_thresholds.emplace_back(Number{0});
        m_thresholds.push_back(ExtendedNumber::plus_infinity());
    }

    [[nodiscard]]
    size_t size() const {
        return m_thresholds.size();
    }

    void add(const ExtendedNumber& v);

    friend std::ostream& operator<<(std::ostream& o, const Thresholds& t);
};

/**
   Collect thresholds per wto cycle (i.e. loop)
**/
class WtoThresholds final {
  private:
    // the cfg
    Cfg& m_cfg;
    // maximum number of thresholds
    size_t m_max_size;
    // keep a set of thresholds per wto head
    std::map<Label, Thresholds> m_head_to_thresholds;
    // the top of the stack is the current wto head
    std::vector<Label> m_stack;

    void get_thresholds(const Label& label, Thresholds& thresholds) const;

  public:
    WtoThresholds(Cfg& cfg, const size_t max_size) : m_cfg(cfg), m_max_size(max_size) {}

    void operator()(const Label& vertex);

    void operator()(const std::shared_ptr<WtoCycle>& cycle);

    friend std::ostream& operator<<(std::ostream& o, const WtoThresholds& t);

}; // class WtoThresholds

} // end namespace prevail

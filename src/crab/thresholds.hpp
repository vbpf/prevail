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

class thresholds_t final {

  private:
    std::vector<extended_number> m_thresholds;
    size_t m_size;

  public:
    explicit thresholds_t(const size_t size = UINT_MAX) : m_size(size) {
        m_thresholds.push_back(extended_number::minus_infinity());
        m_thresholds.emplace_back(number_t{0});
        m_thresholds.push_back(extended_number::plus_infinity());
    }

    [[nodiscard]]
    size_t size() const {
        return m_thresholds.size();
    }

    void add(const extended_number& v1);

    friend std::ostream& operator<<(std::ostream& o, const thresholds_t& t);
};

/**
   Collect thresholds per wto cycle (i.e. loop)
**/
class wto_thresholds_t final {
  private:
    // the cfg
    cfg_t& m_cfg;
    // maximum number of thresholds
    size_t m_max_size;
    // keep a set of thresholds per wto head
    std::map<label_t, thresholds_t> m_head_to_thresholds;
    // the top of the stack is the current wto head
    std::vector<label_t> m_stack;

    void get_thresholds(const label_t& label, thresholds_t& thresholds) const;

  public:
    wto_thresholds_t(cfg_t& cfg, const size_t max_size) : m_cfg(cfg), m_max_size(max_size) {}

    void operator()(const label_t& vertex);

    void operator()(const std::shared_ptr<wto_cycle_t>& cycle);

    friend std::ostream& operator<<(std::ostream& o, const wto_thresholds_t& t);

}; // class wto_thresholds_t

} // end namespace prevail

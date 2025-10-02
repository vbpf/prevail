// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
/*******************************************************************************
 * Array expansion domain
 *
 * For a given array, map sequences of consecutive bytes to cells
 * consisting of a triple <offset, size, var> where:
 *
 * - offset is an unsigned number
 * - size is an unsigned number
 * - var is a scalar variable that represents the content of
 *   a[offset, ..., offset + size - 1]
 *
 * The domain is general enough to represent any possible sequence of
 * consecutive bytes including sequences of bytes starting at the same
 * offsets but different sizes, overlapping sequences starting at
 * different offsets, etc. However, there are some cases that have
 * been implemented in an imprecise manner:
 *
 * (1) array store/load with a non-constant index are conservatively ignored.
 * (2) array load from a cell that overlaps with other cells return top.
 ******************************************************************************/

#pragma once

#include <optional>

#include "arith/variable.hpp"
#include "crab/add_bottom.hpp"
#include "crab/bitset_domain.hpp"
#include "crab/type_domain.hpp"

namespace prevail {

void clear_thread_local_state();

class ArrayDomain final {
    BitsetDomain num_bytes;

  public:
    ArrayDomain() = default;

    explicit ArrayDomain(const BitsetDomain& num_bytes) : num_bytes(num_bytes) {}

    void set_to_top();
    void set_to_bottom();
    [[nodiscard]]
    bool is_bottom() const;
    [[nodiscard]]
    bool is_top() const;

    bool operator<=(const ArrayDomain& other) const;
    bool operator==(const ArrayDomain& other) const;

    void operator|=(const ArrayDomain& other);

    ArrayDomain operator|(const ArrayDomain& other) const;
    ArrayDomain operator&(const ArrayDomain& other) const;
    ArrayDomain widen(const ArrayDomain& other) const;
    ArrayDomain narrow(const ArrayDomain& other) const;

    friend std::ostream& operator<<(std::ostream& o, const ArrayDomain& dom);
    [[nodiscard]]
    StringInvariant to_set() const;

    [[nodiscard]]
    bool all_num(const Interval& lb, const Interval& ub) const;
    [[nodiscard]]
    int min_all_num_size(const NumAbsDomain& inv, Variable offset) const;

    [[nodiscard]]
    std::optional<LinearExpression> load(const NumAbsDomain& inv, DataKind kind, const Interval& i, int width) const;
    std::optional<Variable> store(NumAbsDomain& inv, DataKind kind, const Interval& idx, const Interval& elem_size,
                                  const LinearExpression& val);
    std::optional<Variable> store_type(TypeDomain& inv, const Interval& idx, const Interval& width, bool is_num);
    void havoc(NumAbsDomain& inv, DataKind kind, const Interval& idx, const Interval& elem_size);

    // Perform array stores over an array segment
    void store_numbers(const Interval& _idx, const Interval& _width);

    void split_number_var(NumAbsDomain& inv, DataKind kind, const Interval& ii, const Interval& elem_size) const;
    void split_cell(NumAbsDomain& inv, DataKind kind, int cell_start_index, unsigned int len) const;

    void initialize_numbers(int lb, int width);
};

} // namespace prevail

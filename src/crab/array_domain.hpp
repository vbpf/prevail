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

#include <memory>
#include <optional>

#include "arith/variable.hpp"
#include "crab/add_bottom.hpp"
#include "crab/bitset_domain.hpp"
#include "crab/type_domain.hpp"

namespace prevail {

/// Per-analysis registry of the stack cells the analysis is currently tracking, keyed
/// by DataKind. Owned by AnalysisContext; shared by reference across all ArrayDomain
/// instances belonging to one analysis run. Each entry corresponds to a cell variable
/// at a (offset, size); the registry exists so ArrayDomain can deduplicate `mk_cell`
/// calls and answer overlap queries.
class StackCellRegistry;
struct StackCellRegistryDeleter {
    void operator()(StackCellRegistry*) const noexcept;
};
using StackCellRegistryPtr = std::unique_ptr<StackCellRegistry, StackCellRegistryDeleter>;
StackCellRegistryPtr make_stack_cell_registry();
/// Drop all tracked cells. Call this when starting a fresh analysis run against
/// a reused context so stale entries from a prior run don't leak into the new one.
void clear_stack_cell_registry(StackCellRegistry& registry);

class ArrayDomain final {
    BitsetDomain num_bytes;

  public:
    // Top at the requested size.
    explicit ArrayDomain(const size_t stack_size) : num_bytes(BitsetDomain{stack_size}) {}

    [[nodiscard]]
    int total_stack_size() const {
        return gsl::narrow<int>(num_bytes.size());
    }

    // no move constructor to BitsetDomain, and therefore no copy-then-move for ArrayDomain
    explicit ArrayDomain(const BitsetDomain& num_bytes) : num_bytes(num_bytes) {}
    ArrayDomain(const ArrayDomain& arr) = default;

    // ArrayDomain has no bottom of its own; bottom is represented externally
    // (EbpfDomain wraps the stack in std::optional).
    void set_to_top();
    [[nodiscard]]
    bool is_top() const;

    bool operator<=(const ArrayDomain& other) const;
    bool operator==(const ArrayDomain& other) const;

    void operator|=(const ArrayDomain& other);
    void operator|=(ArrayDomain&& other);

    ArrayDomain operator|(const ArrayDomain& other) const;
    ArrayDomain operator&(const ArrayDomain& other) const;
    ArrayDomain widen(const ArrayDomain& other) const;
    ArrayDomain narrow(const ArrayDomain& other) const;

    friend std::ostream& operator<<(std::ostream& o, const ArrayDomain& dom);
    [[nodiscard]]
    StringInvariant to_set() const;

    [[nodiscard]]
    bool all_num_width(const Interval& index, const Interval& width) const;
    [[nodiscard]]
    bool all_num_lb_ub(const Interval& lb, const Interval& ub) const;
    [[nodiscard]]
    int min_all_num_size(const NumAbsDomain& inv, Variable offset) const;

    [[nodiscard]]
    static std::optional<LinearExpression> load(StackCellRegistry& cells, const NumAbsDomain& inv, DataKind kind,
                                                const Interval& i, int width, bool big_endian);
    std::optional<LinearExpression> load_type(StackCellRegistry& cells, const Interval& i, int width) const;
    std::optional<Variable> store(StackCellRegistry& cells, NumAbsDomain& inv, DataKind kind, const Interval& idx,
                                  const Interval& elem_size, bool big_endian) const;
    std::optional<Variable> store_type(StackCellRegistry& cells, TypeDomain& inv, const Interval& idx,
                                       const Interval& width, bool is_num);
    void havoc(StackCellRegistry& cells, NumAbsDomain& inv, DataKind kind, const Interval& idx,
               const Interval& elem_size, bool big_endian) const;
    void havoc_type(StackCellRegistry& cells, TypeDomain& inv, const Interval& idx, const Interval& elem_size);

    // Perform array stores over an array segment
    void store_numbers(const Interval& _idx, const Interval& _width);

    void split_number_var(StackCellRegistry& cells, NumAbsDomain& inv, DataKind kind, const Interval& ii,
                          const Interval& elem_size, bool big_endian) const;
    static void split_cell(StackCellRegistry& cells, NumAbsDomain& inv, DataKind kind, int cell_start_index,
                           unsigned int len, bool big_endian);

    void initialize_numbers(StackCellRegistry& cells, int lb, int width);
};

} // namespace prevail

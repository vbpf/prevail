// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include "boost/endian/conversion.hpp"
#include <gsl/narrow>
#include <map>

#include "arith/dsl_syntax.hpp"
#include "config.hpp"
#include "crab/array_domain.hpp"
#include "crab/var_registry.hpp"
#include "crab_utils/num_safety.hpp"

#include <ranges>

namespace prevail {

using Index = uint64_t;

using offset_t = Index;

// Conceptually, a cell is tuple of an array, offset, size, and
// scalar variable such that:
//   scalar = array[offset, offset + 1, ..., offset + size - 1]
// For simplicity, we don't carry the array inside the cell.
struct Cell final {
    offset_t offset{};
    unsigned size{};

    bool operator==(const Cell&) const = default;
    auto operator<=>(const Cell&) const = default;

    // Return true if [o, o + sz) definitely overlaps with the cell.
    // Offsets are bounded by EBPF_TOTAL_STACK_SIZE (4096), so wraparound cannot occur.
    [[nodiscard]]
    bool overlap(const offset_t o, const unsigned sz) const {
        assert(sz > 0 && "overlap query with zero width");
        return offset < o + sz && o < offset + size;
    }
};

static Interval cell_to_interval(const offset_t o, const unsigned size) {
    assert(o <= EBPF_TOTAL_STACK_SIZE && "offset out of bounds");
    const Number lb{gsl::narrow<int>(o)};
    return {lb, lb + size - 1};
}

// Return true if [symb_lb, symb_ub] may overlap with the cell,
// where symb_lb and symb_ub are not constant expressions.
static bool symbolic_overlap(const Cell& c, const Interval& range) {
    return !(cell_to_interval(c.offset, c.size) & range).is_bottom();
}

std::ostream& operator<<(std::ostream& o, const Cell& c) { return o << "cell(" << c.offset << "," << c.size << ")"; }

static Variable cell_var(const DataKind kind, const Cell& c) {
    return variable_registry->cell_var(kind, c.offset, c.size);
}

// Map offsets to cells.
// std::map/std::set are used deliberately: empirically, the median collection holds ~3 cells,
// overlap queries hit <5% of the time, and the entire offset map is <1% of verifier runtime.
// At these sizes, specialized data structures (patricia tries, flat sorted vectors) show no
// macro-level improvement while adding complexity or external dependencies.
class offset_map_t final {
  private:
    friend class ArrayDomain;

    using cell_set_t = std::set<Cell>;

    using map_t = std::map<offset_t, cell_set_t>;

    map_t _map;

    void remove_cell(const Cell& c);

    void insert_cell(const Cell& c);

    [[nodiscard]]
    std::optional<Cell> get_cell(offset_t o, unsigned size);

    Cell mk_cell(offset_t o, unsigned size);

  public:
    offset_map_t() = default;

    [[nodiscard]]
    bool empty() const {
        return _map.empty();
    }

    [[nodiscard]]
    std::size_t size() const {
        return _map.size();
    }

    void operator-=(const Cell& c) { remove_cell(c); }

    void operator-=(const std::vector<Cell>& cells) {
        for (const auto& c : cells) {
            this->operator-=(c);
        }
    }

    // Return in out all cells that might overlap with (o, size).
    std::vector<Cell> get_overlap_cells(offset_t o, unsigned size);

    [[nodiscard]]
    std::vector<Cell> get_overlap_cells_symbolic_offset(const Interval& range);

    friend std::ostream& operator<<(std::ostream& o, offset_map_t& m);

    /* Operations needed if used as value in a separate_domain */
    [[nodiscard]]
    bool is_top() const {
        return empty();
    }

    [[nodiscard]]
    // ReSharper disable once CppMemberFunctionMayBeStatic
    bool is_bottom() const {
        return false;
    }
    /*
       We don't distinguish between bottom and top.
       This is fine because separate_domain only calls bottom if operator[] is called over a bottom state.
       Thus, we will make sure that we don't call operator[] in that case.
    */
    static offset_map_t bottom() { return offset_map_t(); }
    static offset_map_t top() { return offset_map_t(); }
};

void offset_map_t::remove_cell(const Cell& c) {
    const offset_t key = c.offset;
    if (auto it = _map.find(key); it != _map.end()) {
        it->second.erase(c);
        if (it->second.empty()) {
            _map.erase(it);
        }
    }
}

[[nodiscard]]
std::vector<Cell> offset_map_t::get_overlap_cells_symbolic_offset(const Interval& range) {
    std::vector<Cell> out;
    for (const auto& o_cells : _map | std::views::values) {
        // All cells in o_cells have the same offset. They only differ in the size.
        // If the largest cell overlaps with [offset, offset + size)
        // then the rest of cells are considered to overlap.
        // This is an over-approximation because [offset, offset+size) can overlap
        // with the largest cell, but it doesn't necessarily overlap with smaller cells.
        // For efficiency, we assume it overlaps with all.
        if (!o_cells.empty()) {
            // Cells are sorted by (offset, size); last element has the largest size.
            const Cell& largest_cell = *o_cells.rbegin();
            if (symbolic_overlap(largest_cell, range)) {
                for (const auto& c : o_cells) {
                    out.push_back(c);
                }
            }
        }
    }
    return out;
}

void offset_map_t::insert_cell(const Cell& c) { _map[c.offset].insert(c); }

std::optional<Cell> offset_map_t::get_cell(const offset_t o, const unsigned size) {
    if (const auto it = _map.find(o); it != _map.end()) {
        if (const auto cit = it->second.find(Cell(o, size)); cit != it->second.end()) {
            return *cit;
        }
    }
    return {};
}

Cell offset_map_t::mk_cell(const offset_t o, const unsigned size) {
    // TODO: check array is the array associated to this offset map

    if (const auto maybe_c = get_cell(o, size)) {
        return *maybe_c;
    }
    // create a new scalar variable for representing the contents
    // of bytes array[o,o+1,..., o+size-1]
    const Cell c(o, size);
    insert_cell(c);
    return c;
}

// Return all cells that might overlap with (o, size).
std::vector<Cell> offset_map_t::get_overlap_cells(const offset_t o, const unsigned size) {
    std::vector<Cell> out;
    const Cell query_cell(o, size);

    // Search backwards: cells at offsets <= o that might extend into [o, o+size).
    // We cannot break early: a bucket with small cells may not overlap while an
    // earlier bucket with larger cells does (e.g., Cell(48,8) overlaps [54,56)
    // but Cell(50,2) does not). The map is tiny (~3 entries) so this is fine.
    for (auto it = _map.upper_bound(o); it != _map.begin();) {
        --it;
        for (const Cell& x : it->second) {
            if (x.overlap(o, size) && x != query_cell) {
                out.push_back(x);
            }
        }
    }

    // Search forwards: cells at offsets > o that start within [o, o+size).
    // Early break is safe here: if no cell at offset k overlaps, then k >= o + size,
    // and all subsequent offsets are even larger, so they cannot overlap either.
    // No duplicates: backward and forward scans visit disjoint key ranges.
    for (auto it = _map.upper_bound(o); it != _map.end(); ++it) {
        bool any_overlap = false;
        for (const Cell& x : it->second) {
            if (x.overlap(o, size)) {
                out.push_back(x);
                any_overlap = true;
            }
        }
        if (!any_overlap) {
            break;
        }
    }

    return out;
}

// We use a global array map
using array_map_t = std::unordered_map<DataKind, offset_map_t>;

static thread_local LazyAllocator<array_map_t> thread_local_array_map;

void clear_thread_local_state() { thread_local_array_map.clear(); }

static offset_map_t& lookup_array_map(const DataKind kind) { return (*thread_local_array_map)[kind]; }

void ArrayDomain::initialize_numbers(const int lb, const int width) {
    num_bytes.reset(lb, width);
    lookup_array_map(DataKind::svalues).mk_cell(offset_t{gsl::narrow_cast<Index>(lb)}, width);
}

std::ostream& operator<<(std::ostream& o, offset_map_t& m) {
    if (m._map.empty()) {
        o << "empty";
    } else {
        for (const auto& cells : m._map | std::views::values) {
            o << "{";
            for (auto cit = cells.begin(), cet = cells.end(); cit != cet;) {
                o << *cit;
                ++cit;
                if (cit != cet) {
                    o << ",";
                }
            }
            o << "}\n";
        }
    }
    return o;
}

// Create a new cell that is a subset of an existing cell.
void ArrayDomain::split_cell(NumAbsDomain& inv, const DataKind kind, const int cell_start_index,
                             const unsigned int len) const {
    assert(kind == DataKind::svalues || kind == DataKind::uvalues);

    // Get the values from the indicated stack range.
    const std::optional<LinearExpression> svalue = load(inv, DataKind::svalues, Interval{cell_start_index}, len);
    const std::optional<LinearExpression> uvalue = load(inv, DataKind::uvalues, Interval{cell_start_index}, len);

    // Create a new cell for that range.
    offset_map_t& offset_map = lookup_array_map(kind);
    const Cell new_cell = offset_map.mk_cell(offset_t{gsl::narrow_cast<Index>(cell_start_index)}, len);
    inv.assign(cell_var(DataKind::svalues, new_cell), svalue);
    inv.assign(cell_var(DataKind::uvalues, new_cell), uvalue);
}

// Prepare to havoc bytes in the middle of a cell by potentially splitting the cell if it is numeric,
// into the part to the left of the havoced portion, and the part to the right of the havoced portion.
void ArrayDomain::split_number_var(NumAbsDomain& inv, DataKind kind, const Interval& ii,
                                   const Interval& elem_size) const {
    assert(kind == DataKind::svalues || kind == DataKind::uvalues);
    offset_map_t& offset_map = lookup_array_map(kind);
    const std::optional<Number> n = ii.singleton();
    if (!n) {
        // We can only split a singleton offset.
        return;
    }
    const std::optional<Number> n_bytes = elem_size.singleton();
    if (!n_bytes) {
        // We can only split a singleton size.
        return;
    }
    const auto size = n_bytes->narrow<unsigned int>();
    const offset_t o(n->narrow<Index>());

    const std::vector<Cell> cells = offset_map.get_overlap_cells(o, size);
    for (const Cell& c : cells) {
        const auto [cell_start_index, cell_end_index] = cell_to_interval(c.offset, c.size).pair<int>();
        if (!this->num_bytes.all_num(cell_start_index, cell_end_index + 1) ||
            cell_end_index + 1UL < cell_start_index + sizeof(int64_t)) {
            // We can only split numeric cells of size 8 or less.
            continue;
        }

        if (!inv.eval_interval(cell_var(kind, c)).is_singleton()) {
            // We can only split cells with a singleton value.
            continue;
        }
        if (gsl::narrow_cast<Index>(cell_start_index) < o) {
            // Use the bytes to the left of the specified range.
            split_cell(inv, kind, cell_start_index, gsl::narrow<unsigned int>(o - cell_start_index));
        }
        if (o + size < cell_end_index + 1UL) {
            // Use the bytes to the right of the specified range.
            split_cell(inv, kind, gsl::narrow<int>(o + size),
                       gsl::narrow<unsigned int>(cell_end_index - (o + size - 1)));
        }
    }
}

// we can only treat this as non-member because we use global state
// Find overlapping cells for the given index range and kill (havoc + remove) them.
// Returns the exact offset and size if the index and element size are both constant.
template <typename HavocFn>
static std::optional<std::pair<offset_t, unsigned>> kill_and_find_var(const HavocFn& havoc_var, DataKind kind,
                                                                      const Interval& ii, const Interval& elem_size) {
    std::optional<std::pair<offset_t, unsigned>> res;

    offset_map_t& offset_map = lookup_array_map(kind);
    std::vector<Cell> cells;
    if (const std::optional<Number> n = ii.singleton()) {
        if (const auto n_bytes = elem_size.singleton()) {
            auto size = n_bytes->narrow<unsigned int>();
            // -- Constant index: kill overlapping cells
            offset_t o(n->narrow<Index>());
            cells = offset_map.get_overlap_cells(o, size);
            res = std::make_pair(o, size);
        }
    }
    if (!res) {
        // -- Non-constant index: kill overlapping cells
        cells = offset_map.get_overlap_cells_symbolic_offset(ii | (ii + elem_size));
    }
    if (!cells.empty()) {
        // Forget the scalars from the relevant domain
        for (const auto& c : cells) {
            havoc_var(cell_var(kind, c));

            // Forget signed and unsigned values together.
            if (kind == DataKind::svalues) {
                havoc_var(cell_var(DataKind::uvalues, c));
            } else if (kind == DataKind::uvalues) {
                havoc_var(cell_var(DataKind::svalues, c));
            }
        }
        // Remove the cells. If needed again they will be re-created.
        offset_map -= cells;
    }
    return res;
}
static std::tuple<int, int> as_numbytes_range(const Interval& index, const Interval& width) {
    return (index | (index + width)).bound(0, EBPF_TOTAL_STACK_SIZE);
}

bool ArrayDomain::all_num_lb_ub(const Interval& lb, const Interval& ub) const {
    const auto [min_lb, max_ub] = (lb | ub).bound(0, EBPF_TOTAL_STACK_SIZE);
    if (min_lb > max_ub) {
        return false;
    }
    return this->num_bytes.all_num(min_lb, max_ub);
}

bool ArrayDomain::all_num_width(const Interval& index, const Interval& width) const {
    const auto [min_lb, max_ub] = as_numbytes_range(index, width);
    assert(min_lb <= max_ub);
    return this->num_bytes.all_num(min_lb, max_ub);
}

// Get the number of bytes, starting at offset, that are known to be numbers.
int ArrayDomain::min_all_num_size(const NumAbsDomain& inv, const Variable offset) const {
    const auto min_lb = inv.eval_interval(offset).lb().number();
    const auto max_ub = inv.eval_interval(offset).ub().number();
    if (!min_lb || !max_ub || !min_lb->fits<int32_t>() || !max_ub->fits<int32_t>()) {
        return 0;
    }
    const auto lb = min_lb->narrow<int>();
    const auto ub = max_ub->narrow<int>();
    return std::max(0, this->num_bytes.all_num_width(lb) - (ub - lb));
}

// Get one byte of a value.
std::optional<uint8_t> get_value_byte(const NumAbsDomain& inv, const offset_t o, const int width) {
    const Variable v = variable_registry->cell_var(DataKind::svalues, (o / width) * width, width);
    const std::optional<Number> t = inv.eval_interval(v).singleton();
    if (!t) {
        return {};
    }
    Index n = t->cast_to<Index>();

    // Convert value to bytes of the appropriate endian-ness.
    switch (width) {
    case sizeof(uint8_t): break;
    case sizeof(uint16_t):
        if (thread_local_options.big_endian) {
            n = boost::endian::native_to_big<uint16_t>(n);
        } else {
            n = boost::endian::native_to_little<uint16_t>(n);
        }
        break;
    case sizeof(uint32_t):
        if (thread_local_options.big_endian) {
            n = boost::endian::native_to_big<uint32_t>(n);
        } else {
            n = boost::endian::native_to_little<uint32_t>(n);
        }
        break;
    case sizeof(Index):
        if (thread_local_options.big_endian) {
            n = boost::endian::native_to_big<Index>(n);
        } else {
            n = boost::endian::native_to_little<Index>(n);
        }
        break;
    default: CRAB_ERROR("Unexpected width ", width);
    }
    const auto bytes = reinterpret_cast<uint8_t*>(&n);
    return bytes[o % width];
}

std::optional<LinearExpression> ArrayDomain::load(const NumAbsDomain& inv, const DataKind kind, const Interval& i,
                                                  const int width) const {
    if (const std::optional<Number> n = i.singleton()) {
        offset_map_t& offset_map = lookup_array_map(kind);
        const int64_t k = n->narrow<int64_t>();
        const offset_t o(k);
        const unsigned size = to_unsigned(width);
        if (const auto cell = lookup_array_map(kind).get_cell(o, size)) {
            return cell_var(kind, *cell);
        }
        if (kind == DataKind::svalues || kind == DataKind::uvalues) {
            // Copy bytes into result_buffer, taking into account that the
            // bytes might be in different stack variables and might be unaligned.
            uint8_t result_buffer[8];
            bool found = true;
            for (unsigned int index = 0; index < size; index++) {
                const offset_t byte_offset{o + index};
                std::optional<uint8_t> b = get_value_byte(inv, byte_offset, 8);
                if (!b) {
                    b = get_value_byte(inv, byte_offset, 4);
                    if (!b) {
                        b = get_value_byte(inv, byte_offset, 2);
                        if (!b) {
                            b = get_value_byte(inv, byte_offset, 1);
                        }
                    }
                }
                if (b) {
                    result_buffer[index] = *b;
                } else {
                    found = false;
                    break;
                }
            }
            if (found) {
                // We have an aligned result in result_buffer so we can now
                // convert to an integer.
                if (size == 1) {
                    return *result_buffer;
                }
                if (size == 2) {
                    uint16_t b = *reinterpret_cast<uint16_t*>(result_buffer);
                    if (thread_local_options.big_endian) {
                        b = boost::endian::native_to_big<uint16_t>(b);
                    } else {
                        b = boost::endian::native_to_little<uint16_t>(b);
                    }
                    return b;
                }
                if (size == 4) {
                    uint32_t b = *reinterpret_cast<uint32_t*>(result_buffer);
                    if (thread_local_options.big_endian) {
                        b = boost::endian::native_to_big<uint32_t>(b);
                    } else {
                        b = boost::endian::native_to_little<uint32_t>(b);
                    }
                    return b;
                }
                if (size == 8) {
                    Index b = *reinterpret_cast<Index*>(result_buffer);
                    if (thread_local_options.big_endian) {
                        b = boost::endian::native_to_big<Index>(b);
                    } else {
                        b = boost::endian::native_to_little<Index>(b);
                    }
                    return kind == DataKind::uvalues ? Number(b) : Number(to_signed(b));
                }
            }
        }

        const std::vector<Cell> cells = offset_map.get_overlap_cells(o, size);
        if (cells.empty()) {
            const Cell c = offset_map.mk_cell(o, size);
            // Here it's ok to do assignment (instead of expand) because c is not a summarized variable.
            // Otherwise, it would be unsound.
            return cell_var(kind, c);
        }
        CRAB_WARN("Ignored read from cell ", kind, "[", o, "...", o + size - 1, "]", " because it overlaps with ",
                  cells.size(), " cells");
        /*
            TODO: we can apply here "Value Recomposition" a la Mine'06 (https://arxiv.org/pdf/cs/0703074.pdf)
                to construct values of some type from a sequence of bytes.
                It can be endian-independent but it would more precise if we choose between little- and big-endian.
        */
    } else {
        // TODO: we can be more precise here
        CRAB_WARN("array expansion: ignored array load because of non-constant array index ", i);
    }
    return {};
}

std::optional<LinearExpression> ArrayDomain::load_type(const Interval& i, int width) const {
    if (std::optional<Number> n = i.singleton()) {
        offset_map_t& offset_map = lookup_array_map(DataKind::types);
        int64_t k = n->narrow<int64_t>();
        auto [only_num, only_non_num] = num_bytes.uniformity(k, width);
        if (only_num) {
            return T_NUM;
        }
        if (!only_non_num || width != 8) {
            return {};
        }
        offset_t o(k);
        unsigned size = to_unsigned(width);
        if (auto cell = lookup_array_map(DataKind::types).get_cell(o, size)) {
            return cell_var(DataKind::types, *cell);
        }
        std::vector<Cell> cells = offset_map.get_overlap_cells(o, size);
        if (cells.empty()) {
            Cell c = offset_map.mk_cell(o, size);
            // Here it's ok to do assignment (instead of expand) because c is not a summarized variable.
            // Otherwise, it would be unsound.
            return cell_var(DataKind::types, c);
        }
        CRAB_WARN("Ignored read from cell ", DataKind::types, "[", o, "...", o + size - 1, "]",
                  " because it overlaps with ", cells.size(), " cells");
        /*
            TODO: we can apply here "Value Recomposition" a la Mine'06 (https://arxiv.org/pdf/cs/0703074.pdf)
                to construct values of some type from a sequence of bytes.
                It can be endian-independent but it would more precise if we choose between little- and big-endian.
        */
    } else {
        // Check whether the kind is uniform across the entire interval.
        auto lb = i.lb().number();
        auto ub = i.ub().number();
        if (lb.has_value() && ub.has_value()) {
            Number fullwidth = ub.value() - lb.value() + width;
            if (lb->fits<uint32_t>() && fullwidth.fits<uint32_t>()) {
                auto [only_num, only_non_num] =
                    num_bytes.uniformity(lb->narrow<uint32_t>(), fullwidth.narrow<uint32_t>());
                if (only_num) {
                    return T_NUM;
                }
            }
        }
    }
    return {};
}

// We are about to write to a given range of bytes on the stack.
// Any cells covering that range need to be removed, and any cells that only
// partially cover that range can be split such that any non-covered portions become new cells.
static std::optional<std::pair<offset_t, unsigned>> split_and_find_var(const ArrayDomain& array_domain,
                                                                       NumAbsDomain& inv, const DataKind kind,
                                                                       const Interval& idx, const Interval& elem_size) {
    if (kind == DataKind::svalues || kind == DataKind::uvalues) {
        array_domain.split_number_var(inv, kind, idx, elem_size);
    }
    return kill_and_find_var([&inv](Variable v) { inv.havoc(v); }, kind, idx, elem_size);
}

std::optional<Variable> ArrayDomain::store(NumAbsDomain& inv, const DataKind kind, const Interval& idx,
                                           const Interval& elem_size) {
    if (auto maybe_cell = split_and_find_var(*this, inv, kind, idx, elem_size)) {
        // perform strong update
        auto [offset, size] = *maybe_cell;
        const Cell c = lookup_array_map(kind).mk_cell(offset, size);
        Variable v = cell_var(kind, c);
        return v;
    }
    return {};
}

std::optional<Variable> ArrayDomain::store_type(TypeDomain& inv, const Interval& idx, const Interval& width,
                                                const bool is_num) {
    constexpr auto kind = DataKind::types;
    if (auto maybe_cell = kill_and_find_var([&inv](Variable v) { inv.havoc_type(v); }, kind, idx, width)) {
        // perform strong update
        auto [offset, size] = *maybe_cell;
        if (is_num) {
            num_bytes.reset(offset, size);
        } else {
            num_bytes.havoc(offset, size);
        }
        const Cell c = lookup_array_map(kind).mk_cell(offset, size);
        Variable v = cell_var(kind, c);
        return v;
    } else {
        using namespace dsl_syntax;
        // havoc the entire range
        const auto [lb, ub] = as_numbytes_range(idx, width);
        num_bytes.havoc(lb, ub);
    }
    return {};
}

void ArrayDomain::havoc(NumAbsDomain& inv, const DataKind kind, const Interval& idx, const Interval& elem_size) {
    split_and_find_var(*this, inv, kind, idx, elem_size);
}

void ArrayDomain::havoc_type(TypeDomain& inv, const Interval& idx, const Interval& elem_size) {
    constexpr auto kind = DataKind::types;
    if (auto maybe_cell = kill_and_find_var([&inv](Variable v) { inv.havoc_type(v); }, kind, idx, elem_size)) {
        auto [offset, size] = *maybe_cell;
        num_bytes.havoc(offset, size);
    }
}

void ArrayDomain::store_numbers(const Interval& _idx, const Interval& _width) {
    const std::optional<Number> idx_n = _idx.singleton();
    if (!idx_n) {
        CRAB_WARN("array expansion store range ignored because ", "lower bound is not constant");
        return;
    }

    const std::optional<Number> width = _width.singleton();
    if (!width) {
        CRAB_WARN("array expansion store range ignored because ", "upper bound is not constant");
        return;
    }

    if (*idx_n + *width > EBPF_TOTAL_STACK_SIZE) {
        CRAB_WARN("array expansion store range ignored because ",
                  "the number of elements is larger than default limit of ", EBPF_TOTAL_STACK_SIZE);
        return;
    }
    num_bytes.reset(idx_n->narrow<int>(), width->narrow<int>());
}

void ArrayDomain::set_to_top() { num_bytes.set_to_top(); }

void ArrayDomain::set_to_bottom() { num_bytes.set_to_bottom(); }

bool ArrayDomain::is_bottom() const { return num_bytes.is_bottom(); }

bool ArrayDomain::is_top() const { return num_bytes.is_top(); }

StringInvariant ArrayDomain::to_set() const { return num_bytes.to_set(); }

bool ArrayDomain::operator<=(const ArrayDomain& other) const { return num_bytes <= other.num_bytes; }

bool ArrayDomain::operator==(const ArrayDomain& other) const { return num_bytes == other.num_bytes; }

void ArrayDomain::operator|=(const ArrayDomain& other) { num_bytes |= other.num_bytes; }

void ArrayDomain::operator|=(ArrayDomain&& other) { num_bytes |= std::move(other.num_bytes); }

ArrayDomain ArrayDomain::operator|(const ArrayDomain& other) const { return ArrayDomain(num_bytes | other.num_bytes); }

ArrayDomain ArrayDomain::operator&(const ArrayDomain& other) const { return ArrayDomain(num_bytes & other.num_bytes); }

ArrayDomain ArrayDomain::widen(const ArrayDomain& other) const { return ArrayDomain(num_bytes | other.num_bytes); }

ArrayDomain ArrayDomain::narrow(const ArrayDomain& other) const { return ArrayDomain(num_bytes & other.num_bytes); }

std::ostream& operator<<(std::ostream& o, const ArrayDomain& dom) { return o << dom.num_bytes; }
} // namespace prevail

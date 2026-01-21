// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <optional>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

#include "boost/endian/conversion.hpp"
#include "radix_tree/radix_tree.hpp"
#include <gsl/narrow>

#include "arith/dsl_syntax.hpp"
#include "config.hpp"
#include "crab/array_domain.hpp"
#include "crab/var_registry.hpp"
#include "crab_utils/num_safety.hpp"

namespace prevail {

using Index = uint64_t;

class offset_t final {
    Index _index{};
    int _prefix_length;

  public:
    static constexpr int bitsize = 8 * sizeof(Index);
    offset_t() : _prefix_length(bitsize) {}
    explicit offset_t(const Index index) : _index(index), _prefix_length(bitsize) {}
    offset_t(const Index index, const int prefix_length) : _index(index), _prefix_length(prefix_length) {}
    explicit operator int() const { return gsl::narrow<int>(_index); }
    operator Index() const { return _index; }
    [[nodiscard]]
    int prefix_length() const {
        return _prefix_length;
    }

    Index operator[](const int n) const { return (_index >> (bitsize - 1 - n)) & 1; }
};

// NOTE: required by radix_tree
// Get the length of a key, which is the size usable with the [] operator.
[[maybe_unused]]
int radix_length(const offset_t& offset) {
    return offset.prefix_length();
}

// NOTE: required by radix_tree
// Get a range of bits out of the middle of a key, starting at [begin] for a given length.
[[maybe_unused]]
offset_t radix_substr(const offset_t& key, const int begin, const int length) {
    // radix_tree should only call this with valid bit-slice arguments.
    // If this is violated, treat it as a verifier bug and fail fast.
    if (begin < 0 || length < 0) {
        throw std::runtime_error("radix_substr: negative begin/length");
    }
    if (begin > offset_t::bitsize || length > offset_t::bitsize || begin + length > offset_t::bitsize) {
        throw std::runtime_error("radix_substr: invalid begin/length");
    }

    if (length == 0) {
        return offset_t{0, 0};
    }

    // begin + length <= bitsize implies begin == 0 when length == bitsize.
    if (length == offset_t::bitsize) {
        return offset_t{gsl::narrow_cast<Index>(key), length};
    }

    // 1 <= length <= 63 here, so shifts are well-defined.
    Index mask = (Index{1} << length) - 1;
    mask <<= (offset_t::bitsize - length - begin);

    const Index value = (gsl::narrow_cast<Index>(key) & mask) << begin;
    return offset_t{value, length};
}

// NOTE: required by radix_tree
// Concatenate two bit patterns.
[[maybe_unused]]
offset_t radix_join(const offset_t& entry1, const offset_t& entry2) {
    const Index value = entry1 | (entry2 >> entry1.prefix_length());
    const int prefix_length = entry1.prefix_length() + entry2.prefix_length();
    return offset_t{value, prefix_length};
}

/***
   Conceptually, a cell is tuple of an array, offset, size, and
   scalar variable such that:

_scalar = array[_offset, _offset + 1, ..., _offset + _size - 1]

    For simplicity, we don't carry the array inside the cell class.
    Only, offset_map objects can create cells. They will consider the
            array when generating the scalar variable.
*/
class Cell final {
  private:
    friend class offset_map_t;

    offset_t _offset{};
    unsigned _size{};

    // Only offset_map_t can create cells
    Cell() = default;

    Cell(const offset_t offset, const unsigned size) : _offset(offset), _size(size) {}

    static Interval to_interval(const offset_t o, const unsigned size) {
        const Number lb{gsl::narrow<int>(o)};
        return {lb, lb + size - 1};
    }

  public:
    [[nodiscard]]
    Interval to_interval() const {
        return to_interval(_offset, _size);
    }

    [[nodiscard]]
    bool is_null() const {
        return _offset == 0 && _size == 0;
    }

    [[nodiscard]]
    offset_t get_offset() const {
        return _offset;
    }

    [[nodiscard]]
    Variable get_scalar(const DataKind kind) const {
        return variable_registry->cell_var(kind, gsl::narrow<Index>(_offset), _size);
    }

    // ignore the scalar variable
    bool operator==(const Cell& o) const { return to_interval() == o.to_interval(); }

    // ignore the scalar variable
    bool operator<(const Cell& o) const {
        if (_offset == o._offset) {
            return _size < o._size;
        }
        return _offset < o._offset;
    }

    // Return true if [o, o + size) definitely overlaps with the cell,
    // where o is a constant expression.
    [[nodiscard]]
    bool overlap(const offset_t& o, const unsigned size) const {
        const Interval x = to_interval();
        const Interval y = to_interval(o, size);
        const bool res = (!(x & y).is_bottom());
        CRAB_LOG("array-expansion-overlap",
                 std::cout << "**Checking if " << x << " overlaps with " << y << "=" << res << "\n";);
        return res;
    }

    // Return true if [symb_lb, symb_ub] may overlap with the cell,
    // where symb_lb and symb_ub are not constant expressions.
    [[nodiscard]]
    bool symbolic_overlap(const Interval& range) const;

    friend std::ostream& operator<<(std::ostream& o, const Cell& c) { return o << "cell(" << c.to_interval() << ")"; }
};

// Return true if [symb_lb, symb_ub] may overlap with the cell,
// where symb_lb and symb_ub are not constant expressions.
bool Cell::symbolic_overlap(const Interval& range) const { return !(to_interval() & range).is_bottom(); }

// Map offsets to cells
class offset_map_t final {
  private:
    friend class ArrayDomain;

    using cell_set_t = std::set<Cell>;

    /*
      The keys in the patricia tree are processing in big-endian order. This means that the keys are sorted.
      Sortedness is very important to efficiently perform operations such as checking for overlap cells.
      Since keys are treated as bit patterns, negative offsets can be used, but they are treated as large unsigned
      numbers.
    */
    using PatriciaTree = radix_tree<offset_t, cell_set_t>;

    PatriciaTree _map;

    // for algorithm::lower_bound and algorithm::upper_bound
    struct CompareBinding {
        bool operator()(const PatriciaTree::value_type& kv, const offset_t& o) const { return kv.first < o; }
        bool operator()(const offset_t& o, const PatriciaTree::value_type& kv) const { return o < kv.first; }
        bool operator()(const PatriciaTree::value_type& kv1, const PatriciaTree::value_type& kv2) const {
            return kv1.first < kv2.first;
        }
    };

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
    const offset_t key = c.get_offset();
    _map[key].erase(c);
}

[[nodiscard]]
std::vector<Cell> offset_map_t::get_overlap_cells_symbolic_offset(const Interval& range) {
    std::vector<Cell> out;
    for (const auto& [_offset, o_cells] : _map) {
        // All cells in o_cells have the same offset. They only differ in the size.
        // If the largest cell overlaps with [offset, offset + size)
        // then the rest of cells are considered to overlap.
        // This is an over-approximation because [offset, offset+size) can overlap
        // with the largest cell, but it doesn't necessarily overlap with smaller cells.
        // For efficiency, we assume it overlaps with all.
        Cell largest_cell;
        for (const Cell& c : o_cells) {
            if (largest_cell.is_null()) {
                largest_cell = c;
            } else {
                assert(c.get_offset() == largest_cell.get_offset());
                if (largest_cell < c) {
                    largest_cell = c;
                }
            }
        }
        if (!largest_cell.is_null()) {
            if (largest_cell.symbolic_overlap(range)) {
                for (const auto& c : o_cells) {
                    out.push_back(c);
                }
            }
        }
    }
    return out;
}

void offset_map_t::insert_cell(const Cell& c) { _map[c.get_offset()].insert(c); }

std::optional<Cell> offset_map_t::get_cell(const offset_t o, const unsigned size) {
    cell_set_t& cells = _map[o];
    const auto it = cells.find(Cell(o, size));
    if (it != cells.end()) {
        return *it;
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
    constexpr CompareBinding comp;

    bool added = false;
    auto maybe_c = get_cell(o, size);
    if (!maybe_c) {
        maybe_c = Cell(o, size);
        insert_cell(*maybe_c);
        added = true;
    }

    auto lb_it = std::lower_bound(_map.begin(), _map.end(), o, comp);
    if (lb_it != _map.end()) {
        // Store _map[begin,...,lb_it] into a vector so that we can
        // go backwards from lb_it.
        //
        // TODO: give support for reverse iterator in patricia_tree.
        std::vector<cell_set_t> upto_lb;
        upto_lb.reserve(std::distance(_map.begin(), lb_it));
        for (auto it = _map.begin(), et = lb_it; it != et; ++it) {
            upto_lb.push_back(it->second);
        }
        upto_lb.push_back(lb_it->second);

        for (int i = gsl::narrow<int>(upto_lb.size() - 1); i >= 0; --i) {
            ///////
            // All the cells in upto_lb[i] have the same offset. They
            // just differ in the size.
            //
            // If none of the cells in upto_lb[i] overlap with (o, size)
            // we can stop.
            ////////
            bool continue_outer_loop = false;
            for (const Cell& x : upto_lb[i]) {
                if (x.overlap(o, size)) {
                    if (x != *maybe_c) {
                        // FIXME: we might have some duplicates. this is a very drastic solution.
                        if (std::ranges::find(out, x) == out.end()) {
                            out.push_back(x);
                        }
                    }
                    continue_outer_loop = true;
                }
            }
            if (!continue_outer_loop) {
                break;
            }
        }
    }

    // search for overlapping cells > o
    auto ub_it = std::upper_bound(_map.begin(), _map.end(), o, comp);
    for (; ub_it != _map.end(); ++ub_it) {
        bool continue_outer_loop = false;
        for (const Cell& x : ub_it->second) {
            if (x.overlap(o, size)) {
                // FIXME: we might have some duplicates. this is a very drastic solution.
                if (std::ranges::find(out, x) == out.end()) {
                    out.push_back(x);
                }
                continue_outer_loop = true;
            }
        }
        if (!continue_outer_loop) {
            break;
        }
    }

    // do not forget the rest of overlapping cells == o
    for (auto it = ++lb_it, et = ub_it; it != et; ++it) {
        bool continue_outer_loop = false;
        for (const Cell& x : it->second) {
            if (x == *maybe_c) { // we don't put it in out
                continue;
            }
            if (x.overlap(o, size)) {
                if (std::ranges::find(out, x) == out.end()) {
                    out.push_back(x);
                }
                continue_outer_loop = true;
            }
        }
        if (!continue_outer_loop) {
            break;
        }
    }

    if (added) {
        remove_cell(*maybe_c);
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
        for (const auto& [_offset, cells] : m._map) {
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
    inv.assign(new_cell.get_scalar(DataKind::svalues), svalue);
    inv.assign(new_cell.get_scalar(DataKind::uvalues), uvalue);
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
        const auto [cell_start_index, cell_end_index] = c.to_interval().pair<int>();
        if (!this->num_bytes.all_num(cell_start_index, cell_end_index + 1) ||
            cell_end_index + 1UL < cell_start_index + sizeof(int64_t)) {
            // We can only split numeric cells of size 8 or less.
            continue;
        }

        if (!inv.eval_interval(c.get_scalar(kind)).is_singleton()) {
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
static std::optional<std::pair<offset_t, unsigned>> kill_and_find_var(NumAbsDomain& inv, DataKind kind,
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
        // Forget the scalars from the numerical domain
        for (const auto& c : cells) {
            inv.havoc(c.get_scalar(kind));

            // Forget signed and unsigned values together.
            if (kind == DataKind::svalues) {
                inv.havoc(c.get_scalar(DataKind::uvalues));
            } else if (kind == DataKind::uvalues) {
                inv.havoc(c.get_scalar(DataKind::svalues));
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
            return cell->get_scalar(kind);
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
            return c.get_scalar(kind);
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
            return cell->get_scalar(DataKind::types);
        }
        std::vector<Cell> cells = offset_map.get_overlap_cells(o, size);
        if (cells.empty()) {
            Cell c = offset_map.mk_cell(o, size);
            // Here it's ok to do assignment (instead of expand) because c is not a summarized variable.
            // Otherwise, it would be unsound.
            return c.get_scalar(DataKind::types);
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
    return kill_and_find_var(inv, kind, idx, elem_size);
}

std::optional<Variable> ArrayDomain::store(NumAbsDomain& inv, const DataKind kind, const Interval& idx,
                                           const Interval& elem_size) {
    if (auto maybe_cell = split_and_find_var(*this, inv, kind, idx, elem_size)) {
        // perform strong update
        auto [offset, size] = *maybe_cell;
        Variable v = lookup_array_map(kind).mk_cell(offset, size).get_scalar(kind);
        return v;
    }
    return {};
}

std::optional<Variable> ArrayDomain::store_type(TypeDomain& inv, const Interval& idx, const Interval& width,
                                                const bool is_num) {
    constexpr auto kind = DataKind::types;
    if (auto maybe_cell = split_and_find_var(*this, inv.inv, kind, idx, width)) {
        // perform strong update
        auto [offset, size] = *maybe_cell;
        if (is_num) {
            num_bytes.reset(offset, size);
        } else {
            num_bytes.havoc(offset, size);
        }
        Variable v = lookup_array_map(kind).mk_cell(offset, size).get_scalar(kind);
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
    auto maybe_cell = split_and_find_var(*this, inv.inv, kind, idx, elem_size);
    if (maybe_cell) {
        auto [offset, size] = *maybe_cell;
        num_bytes.havoc(offset, size);
    }
}

void ArrayDomain::store_numbers(const Interval& _idx, const Interval& _width) {

    if (is_bottom()) {
        return;
    }

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

void ArrayDomain::operator|=(const ArrayDomain& other) {
    if (is_bottom()) {
        *this = other;
        return;
    }
    num_bytes |= other.num_bytes;
}

void ArrayDomain::operator|=(ArrayDomain&& other) {
    if (is_bottom()) {
        *this = std::move(other);
        return;
    }
    num_bytes |= std::move(other.num_bytes);
}

ArrayDomain ArrayDomain::operator|(const ArrayDomain& other) const { return ArrayDomain(num_bytes | other.num_bytes); }

ArrayDomain ArrayDomain::operator&(const ArrayDomain& other) const { return ArrayDomain(num_bytes & other.num_bytes); }

ArrayDomain ArrayDomain::widen(const ArrayDomain& other) const { return ArrayDomain(num_bytes | other.num_bytes); }

ArrayDomain ArrayDomain::narrow(const ArrayDomain& other) const { return ArrayDomain(num_bytes & other.num_bytes); }

std::ostream& operator<<(std::ostream& o, const ArrayDomain& dom) { return o << dom.num_bytes; }
} // namespace prevail

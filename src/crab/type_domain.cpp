// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.
#include <algorithm>
#include <cassert>
#include <map>
#include <optional>
#include <set>
#include <sstream>

#include "arith/variable.hpp"
#include "crab/dsu.hpp"
#include "crab/type_domain.hpp"
#include "crab/type_encoding.hpp"
#include "crab/var_id_map.hpp"
#include "crab/var_registry.hpp"
#include "crab_utils/debug.hpp"

#include <ranges>

namespace prevail {

// ============================================================================
// DataKind utilities
// ============================================================================

static void operator++(DataKind& t) { t = static_cast<DataKind>(1 + static_cast<std::underlying_type_t<DataKind>>(t)); }

std::vector<DataKind> iterate_kinds(const DataKind lb, const DataKind ub) {
    if (lb > ub) {
        CRAB_ERROR("lower bound ", lb, " is greater than upper bound ", ub);
    }
    if (lb < KIND_MIN || ub > KIND_MAX) {
        CRAB_ERROR("bounds ", lb, " and ", ub, " are out of range");
    }
    std::vector<DataKind> res;
    for (DataKind i = lb; i <= ub; ++i) {
        res.push_back(i);
    }
    return res;
}

// ============================================================================
// TypeSet constants
// ============================================================================

const TypeSet TS_NUM{T_NUM};
const TypeSet TS_MAP{T_MAP};
const TypeSet TS_POINTER{T_CTX, T_PACKET, T_STACK, T_SHARED};
const TypeSet TS_SINGLETON_PTR{T_CTX, T_PACKET, T_STACK};
const TypeSet TS_MEM{T_PACKET, T_STACK, T_SHARED};
const TypeSet TS_SOCKET{T_SOCKET};
const TypeSet TS_BTF_ID{T_BTF_ID};
const TypeSet TS_ALLOC_MEM{T_ALLOC_MEM};

// ============================================================================
// TypeEncoding utilities
// ============================================================================

static constexpr auto S_UNINIT = "uninit";
static constexpr auto S_STACK = "stack";
static constexpr auto S_PACKET = "packet";
static constexpr auto S_CTX = "ctx";
static constexpr auto S_MAP_PROGRAMS = "map_fd_programs";
static constexpr auto S_MAP = "map_fd";
static constexpr auto S_NUM = "number";
static constexpr auto S_SHARED = "shared";
static constexpr auto S_SOCKET = "socket";
static constexpr auto S_BTF_ID = "btf_id";
static constexpr auto S_ALLOC_MEM = "alloc_mem";
static constexpr auto S_FUNC = "func";

std::string name_of(const DataKind kind) {
    switch (kind) {
    case DataKind::ctx_offsets: return "ctx_offset";
    case DataKind::map_fds: return "map_fd";
    case DataKind::map_fd_programs: return "map_fd_programs";
    case DataKind::packet_offsets: return "packet_offset";
    case DataKind::shared_offsets: return "shared_offset";
    case DataKind::shared_region_sizes: return "shared_region_size";
    case DataKind::stack_numeric_sizes: return "stack_numeric_size";
    case DataKind::stack_offsets: return "stack_offset";
    case DataKind::socket_offsets: return "socket_offset";
    case DataKind::btf_id_offsets: return "btf_id_offset";
    case DataKind::alloc_mem_offsets: return "alloc_mem_offset";
    case DataKind::alloc_mem_sizes: return "alloc_mem_size";
    case DataKind::svalues: return "svalue";
    case DataKind::types: return "type";
    case DataKind::uvalues: return "uvalue";
    }
    return {};
}

DataKind regkind(const std::string& s) {
    static const std::map<std::string, DataKind> string_to_kind{
        {"type", DataKind::types},
        {"ctx_offset", DataKind::ctx_offsets},
        {"map_fd", DataKind::map_fds},
        {"map_fd_programs", DataKind::map_fd_programs},
        {"packet_offset", DataKind::packet_offsets},
        {"shared_offset", DataKind::shared_offsets},
        {"stack_offset", DataKind::stack_offsets},
        {"shared_region_size", DataKind::shared_region_sizes},
        {"stack_numeric_size", DataKind::stack_numeric_sizes},
        {"socket_offset", DataKind::socket_offsets},
        {"btf_id_offset", DataKind::btf_id_offsets},
        {"alloc_mem_offset", DataKind::alloc_mem_offsets},
        {"alloc_mem_size", DataKind::alloc_mem_sizes},
        {"svalue", DataKind::svalues},
        {"uvalue", DataKind::uvalues},
    };
    if (string_to_kind.contains(s)) {
        return string_to_kind.at(s);
    }
    throw std::runtime_error(std::string() + "Bad kind: " + s);
}

std::ostream& operator<<(std::ostream& os, const TypeEncoding s) {
    switch (s) {
    case T_SHARED: return os << S_SHARED;
    case T_STACK: return os << S_STACK;
    case T_PACKET: return os << S_PACKET;
    case T_CTX: return os << S_CTX;
    case T_NUM: return os << S_NUM;
    case T_MAP: return os << S_MAP;
    case T_MAP_PROGRAMS: return os << S_MAP_PROGRAMS;
    case T_UNINIT: return os << S_UNINIT;
    case T_SOCKET: return os << S_SOCKET;
    case T_BTF_ID: return os << S_BTF_ID;
    case T_ALLOC_MEM: return os << S_ALLOC_MEM;
    case T_FUNC: return os << S_FUNC;
    }
    CRAB_ERROR("Unsupported type encoding");
}

TypeEncoding string_to_type_encoding(const std::string& s) {
    static std::map<std::string, TypeEncoding> string_to_type{
        {S_UNINIT, T_UNINIT},
        {S_MAP_PROGRAMS, T_MAP_PROGRAMS},
        {S_MAP, T_MAP},
        {S_NUM, T_NUM},
        {S_CTX, T_CTX},
        {S_STACK, T_STACK},
        {S_PACKET, T_PACKET},
        {S_SHARED, T_SHARED},
        {S_SOCKET, T_SOCKET},
        {S_BTF_ID, T_BTF_ID},
        {S_ALLOC_MEM, T_ALLOC_MEM},
        {S_FUNC, T_FUNC},
    };
    if (string_to_type.contains(s)) {
        return string_to_type[s];
    }
    throw std::runtime_error(std::string("Unsupported type name: ") + s);
}

std::optional<TypeEncoding> int_to_type_encoding(const int v) {
    if (v >= 0 && v < static_cast<int>(NUM_TYPE_ENCODINGS)) {
        return static_cast<TypeEncoding>(v);
    }
    return std::nullopt;
}

std::string typeset_to_string(const std::vector<TypeEncoding>& items) {
    std::stringstream ss;
    ss << "{";
    for (auto it = items.begin(); it != items.end(); ++it) {
        ss << *it;
        if (std::next(it) != items.end()) {
            ss << ", ";
        }
    }
    ss << "}";
    return ss.str();
}

// ============================================================================
// TypeSet methods
// ============================================================================

std::optional<TypeEncoding> TypeSet::as_singleton() const {
    if (!is_singleton()) {
        return std::nullopt;
    }
    for (unsigned i = 0; i < NUM_TYPE_ENCODINGS; i++) {
        if (contains(static_cast<TypeEncoding>(i))) {
            return static_cast<TypeEncoding>(i);
        }
    }
    return std::nullopt; // unreachable
}

std::vector<TypeEncoding> TypeSet::to_vector() const {
    std::vector<TypeEncoding> result;
    for (unsigned i = 0; i < NUM_TYPE_ENCODINGS; i++) {
        if (contains(static_cast<TypeEncoding>(i))) {
            result.push_back(static_cast<TypeEncoding>(i));
        }
    }
    return result;
}

std::string TypeSet::to_string() const {
    const auto items = to_vector();
    if (items.size() == 1) {
        std::stringstream ss;
        ss << items[0];
        return ss.str();
    }
    return typeset_to_string(items);
}

// ============================================================================
// TypeGroup utilities
// ============================================================================

TypeSet to_typeset(const TypeGroup group) {
    switch (group) {
    case TypeGroup::number: return TypeSet{T_NUM};
    case TypeGroup::map_fd: return TypeSet{T_MAP};
    case TypeGroup::ctx: return TypeSet{T_CTX};
    case TypeGroup::packet: return TypeSet{T_PACKET};
    case TypeGroup::stack: return TypeSet{T_STACK};
    case TypeGroup::shared: return TypeSet{T_SHARED};
    case TypeGroup::map_fd_programs: return TypeSet{T_MAP_PROGRAMS};
    case TypeGroup::socket: return TypeSet{T_SOCKET};
    case TypeGroup::btf_id: return TypeSet{T_BTF_ID};
    case TypeGroup::alloc_mem: return TypeSet{T_ALLOC_MEM};
    case TypeGroup::func: return TypeSet{T_FUNC};
    case TypeGroup::ctx_or_num: return TypeSet{T_NUM, T_CTX};
    case TypeGroup::stack_or_num: return TypeSet{T_NUM, T_STACK};
    case TypeGroup::mem: return TS_MEM;
    case TypeGroup::mem_or_num: return TS_MEM | TS_NUM;
    case TypeGroup::pointer: return TS_POINTER;
    case TypeGroup::ptr_or_num: return TS_POINTER | TS_NUM;
    case TypeGroup::stack_or_packet: return TypeSet{T_STACK, T_PACKET};
    case TypeGroup::singleton_ptr: return TS_SINGLETON_PTR;
    }
    CRAB_ERROR("Unsupported type group");
}

/// Whether a TypeGroup maps to a single TypeEncoding value (singleton TypeSet),
/// NOT whether there is a single memory region of that type.
/// For example, shared is singleton here ({T_SHARED}) even though multiple
/// shared regions can exist. In contrast, TypeGroup::mem is not singleton
/// because it maps to {T_PACKET, T_STACK, T_SHARED}.
bool is_singleton_type(const TypeGroup t) {
    switch (t) {
    case TypeGroup::number:
    case TypeGroup::map_fd:
    case TypeGroup::map_fd_programs:
    case TypeGroup::ctx:
    case TypeGroup::packet:
    case TypeGroup::stack:
    case TypeGroup::shared:
    case TypeGroup::socket:
    case TypeGroup::btf_id:
    case TypeGroup::alloc_mem:
    case TypeGroup::func: return true;
    default: return false;
    }
}

std::ostream& operator<<(std::ostream& os, const TypeGroup ts) {
    using namespace prevail;
    static const std::map<TypeGroup, std::string> string_to_type{
        {TypeGroup::number, S_NUM},
        {TypeGroup::map_fd, S_MAP},
        {TypeGroup::map_fd_programs, S_MAP_PROGRAMS},
        {TypeGroup::ctx, S_CTX},
        {TypeGroup::ctx_or_num, typeset_to_string({T_NUM, T_CTX})},
        {TypeGroup::packet, S_PACKET},
        {TypeGroup::stack, S_STACK},
        {TypeGroup::stack_or_num, typeset_to_string({T_NUM, T_STACK})},
        {TypeGroup::shared, S_SHARED},
        {TypeGroup::socket, S_SOCKET},
        {TypeGroup::btf_id, S_BTF_ID},
        {TypeGroup::alloc_mem, S_ALLOC_MEM},
        {TypeGroup::func, S_FUNC},
        {TypeGroup::mem, typeset_to_string({T_STACK, T_PACKET, T_SHARED})},
        {TypeGroup::pointer, typeset_to_string({T_CTX, T_STACK, T_PACKET, T_SHARED})},
        {TypeGroup::ptr_or_num, typeset_to_string({T_NUM, T_CTX, T_STACK, T_PACKET, T_SHARED})},
        {TypeGroup::stack_or_packet, typeset_to_string({T_STACK, T_PACKET})},
        {TypeGroup::singleton_ptr, typeset_to_string({T_CTX, T_STACK, T_PACKET})},
        {TypeGroup::mem_or_num, typeset_to_string({T_NUM, T_STACK, T_PACKET, T_SHARED})},
    };
    if (string_to_type.contains(ts)) {
        return os << string_to_type.at(ts);
    }
    CRAB_ERROR("Unsupported type group");
}

// ============================================================================
// TypeDomain -- DSU-based implementation
// ============================================================================

Variable reg_type(const Reg& lhs) { return variable_registry->type_reg(lhs.v); }

// -- State definition --------------------------------------------------------

struct TypeDomain::State {
    DisjointSetUnion dsu;
    VarIdMap var_ids;
    std::vector<TypeSet> class_types;

    State();

    // Internal helpers
    void merge_if_singleton(size_t id);
    size_t ensure_var(Variable v);
    void detach(Variable v);

    // Queries
    [[nodiscard]]
    TypeSet get_typeset(Variable v) const;
    [[nodiscard]]
    bool same_type(Variable a, Variable b) const;
    [[nodiscard]]
    StringInvariant to_set() const;

    // Mutations returning false on empty TypeSet (caller sets bottom)
    bool restrict_var(Variable v, TypeSet mask);
    bool assume_eq(Variable v1, Variable v2);
    bool remove_type(Variable v, TypeEncoding te);
    bool assign_from_expr(Variable lhs, const LinearExpression& expr);

    // Mutations that never produce bottom
    void assign_copy(Variable lhs, Variable rhs);
    void assign_encoding(Variable v, TypeEncoding te);

    // Lattice
    [[nodiscard]]
    static State join(const State& a, const State& b);
    [[nodiscard]]
    std::optional<State> meet(const State& other) const;
    [[nodiscard]]
    bool is_subsumed_by(const State& other) const;
};

TypeDomain::State::State() {
    dsu = DisjointSetUnion{NUM_TYPE_ENCODINGS};
    var_ids = VarIdMap{};
    class_types.resize(NUM_TYPE_ENCODINGS);
    for (const TypeEncoding te : TypeSet::all().to_vector()) {
        class_types[type_to_bit(te)] = TypeSet{te};
    }
}

// -- Special member functions ------------------------------------------------

TypeDomain::TypeDomain() : state_(std::make_unique<State>()) {}

TypeDomain::~TypeDomain() = default;

TypeDomain::TypeDomain(const TypeDomain& other)
    : state_(other.state_ ? std::make_unique<State>(*other.state_) : nullptr) {}

TypeDomain::TypeDomain(TypeDomain&& other) noexcept = default;

TypeDomain& TypeDomain::operator=(const TypeDomain& other) {
    if (this != &other) {
        state_ = other.state_ ? std::make_unique<State>(*other.state_) : nullptr;
    }
    return *this;
}

TypeDomain& TypeDomain::operator=(TypeDomain&& other) noexcept = default;

// -- State: internal helpers -------------------------------------------------

void TypeDomain::State::merge_if_singleton(const size_t id) {
    const size_t rep = dsu.find(id);
    const TypeSet ts = class_types[rep];
    if (const auto te = ts.as_singleton()) {
        const size_t sentinel = type_to_bit(*te);
        const size_t sentinel_rep = dsu.find(sentinel);
        if (rep != sentinel_rep) {
            const size_t new_rep = dsu.unite(rep, sentinel);
            class_types[new_rep] = ts;
        }
    }
}

size_t TypeDomain::State::ensure_var(const Variable v) {
    if (const auto existing = var_ids.find_id(v)) {
        return *existing;
    }
    const size_t id = dsu.push();
    var_ids.insert(v, id);
    class_types.push_back(TypeSet::all());
    assert(class_types.size() == dsu.size());
    assert(var_ids.id_capacity() == dsu.size());
    return id;
}

void TypeDomain::State::detach(const Variable v) {
    var_ids.orphan_var(v);
    const size_t new_id = dsu.push();
    var_ids.insert(v, new_id);
    class_types.push_back(TypeSet::all());
    assert(class_types.size() == dsu.size());
    assert(var_ids.id_capacity() == dsu.size());
}

// -- State: queries ----------------------------------------------------------

TypeSet TypeDomain::State::get_typeset(const Variable v) const {
    if (const auto id = var_ids.find_id(v)) {
        const size_t rep = dsu.find_const(*id);
        return class_types[rep];
    }
    return TypeSet::all(); // unknown variable = top
}

bool TypeDomain::State::same_type(const Variable a, const Variable b) const {
    const auto id_a = var_ids.find_id(a);
    const auto id_b = var_ids.find_id(b);
    if (id_a && id_b) {
        return dsu.find_const(*id_a) == dsu.find_const(*id_b);
    }
    return false;
}

StringInvariant TypeDomain::State::to_set() const {
    // Group variables by DSU representative.
    std::map<size_t, std::vector<Variable>> classes;
    for (const auto& [v, id] : var_ids.vars()) {
        const size_t rep = dsu.find_const(id);
        classes[rep].push_back(v);
    }

    std::set<std::string> result;

    for (const auto& members : classes | std::views::values) {
        const TypeSet ts = get_typeset(members[0]);
        if (ts == TypeSet::all()) {
            continue; // top = no constraint
        }

        // Sort members for deterministic output
        std::vector<Variable> sorted = members;
        std::ranges::sort(sorted, VariableRegistry::printing_order);

        if (const auto te = ts.as_singleton()) {
            for (const Variable& m : sorted) {
                // Stack type variables with type=number are implicit (not printed)
                if (*te == T_NUM && variable_registry->is_in_stack(m)) {
                    continue;
                }
                result.insert(variable_registry->name(m) + "=" + ts.to_string());
            }
        } else {
            const std::string first_name = variable_registry->name(sorted[0]);
            result.insert(first_name + " in " + ts.to_string());

            for (size_t i = 1; i < sorted.size(); i++) {
                result.insert(variable_registry->name(sorted[i]) + "=" + first_name);
            }
        }
    }

    return StringInvariant{std::move(result)};
}

// -- State: mutations (return false → bottom) --------------------------------

bool TypeDomain::State::restrict_var(const Variable v, const TypeSet mask) {
    const size_t id = ensure_var(v);
    const size_t rep = dsu.find(id);
    const TypeSet result = class_types[rep] & mask;
    class_types[rep] = result;
    if (result.is_empty()) {
        return false;
    }
    merge_if_singleton(id);
    return true;
}

bool TypeDomain::State::assume_eq(const Variable v1, const Variable v2) {
    const size_t id1 = ensure_var(v1);
    const size_t id2 = ensure_var(v2);
    const size_t rep1 = dsu.find(id1);
    const size_t rep2 = dsu.find(id2);
    const TypeSet ts = class_types[rep1] & class_types[rep2];
    const size_t new_rep = dsu.unite(id1, id2);
    class_types[new_rep] = ts;
    if (ts.is_empty()) {
        return false;
    }
    merge_if_singleton(id1);
    return true;
}

bool TypeDomain::State::remove_type(const Variable v, const TypeEncoding te) {
    const size_t id = ensure_var(v);
    const size_t rep = dsu.find(id);
    const TypeSet result = class_types[rep].remove(te);
    class_types[rep] = result;
    if (result.is_empty()) {
        return false;
    }
    merge_if_singleton(id);
    return true;
}

bool TypeDomain::State::assign_from_expr(const Variable lhs, const LinearExpression& expr) {
    if (const auto& terms = expr.variable_terms(); terms.empty()) {
        const int val = expr.constant_term().narrow<int>();
        detach(lhs);
        const size_t id = *var_ids.find_id(lhs);
        if (const auto te = int_to_type_encoding(val)) {
            class_types[id] = TypeSet{*te};
            merge_if_singleton(id);
            return true;
        }
        return false;
    } else if (terms.size() == 1) {
        const auto& [var, coeff] = *terms.begin();
        if (coeff == 1 && expr.constant_term() == 0) {
            assign_copy(lhs, var);
        } else {
            detach(lhs);
        }
    } else {
        detach(lhs);
    }
    return true;
}

// -- State: mutations (never produce bottom) ---------------------------------

void TypeDomain::State::assign_copy(const Variable lhs, const Variable rhs) {
    detach(lhs);
    const size_t rhs_id = ensure_var(rhs);
    const size_t lhs_id = *var_ids.find_id(lhs);
    const TypeSet rhs_ts = class_types[dsu.find(rhs_id)];
    const size_t new_rep = dsu.unite(lhs_id, rhs_id);
    class_types[new_rep] = rhs_ts;
    merge_if_singleton(lhs_id);
}

void TypeDomain::State::assign_encoding(const Variable v, const TypeEncoding te) {
    detach(v);
    const size_t id = *var_ids.find_id(v);
    class_types[id] = TypeSet{te};
    merge_if_singleton(id);
}

// -- State: lattice ----------------------------------------------------------

TypeDomain::State TypeDomain::State::join(const State& a, const State& b) {
    // With the singleton-merging invariant, all variables with singleton {te}
    // share the same DSU rep (the sentinel) in each operand. So raw DSU reps
    // partition correctly without a special singleton key.

    // Collect all variables from both operands.
    std::set<Variable> all_vars_seen;
    for (const auto& v : a.var_ids.vars() | std::views::keys) {
        all_vars_seen.insert(v);
    }
    for (const auto& v : b.var_ids.vars() | std::views::keys) {
        all_vars_seen.insert(v);
    }

    // Compute (rep_left, rep_right) for each variable, group by key pair.
    // Variables absent from one side get unique keys (not nullopt) to avoid
    // falsely unifying unrelated variables that happen to share a rep on the
    // other side.
    size_t next_unique_a = a.dsu.size();
    size_t next_unique_b = b.dsu.size();
    std::map<std::pair<size_t, size_t>, std::vector<Variable>> key_groups;
    for (const auto& v : all_vars_seen) {
        size_t key_a;
        if (const auto id = a.var_ids.find_id(v)) {
            key_a = a.dsu.find_const(*id);
        } else {
            key_a = next_unique_a++;
        }
        size_t key_b;
        if (const auto id = b.var_ids.find_id(v)) {
            key_b = b.dsu.find_const(*id);
        } else {
            key_b = next_unique_b++;
        }
        key_groups[{key_a, key_b}].push_back(v);
    }

    // Build result
    State result;
    for (const auto& members : key_groups | std::views::values) {
        // TypeSet = union of per-variable TypeSets from both operands
        TypeSet ts{};
        for (const Variable& v : members) {
            ts |= a.get_typeset(v);
            ts |= b.get_typeset(v);
        }

        // Register all members in the result, unified
        std::optional<size_t> first_id;
        for (const Variable& v : members) {
            const size_t id = result.ensure_var(v);
            if (first_id) {
                result.dsu.unite(*first_id, id);
            } else {
                first_id = id;
            }
        }
        // Set the TypeSet on the representative (after all unifications).
        if (first_id) {
            result.class_types[result.dsu.find(*first_id)] = ts;
            result.merge_if_singleton(*first_id);
        }
    }

    return result;
}

std::optional<TypeDomain::State> TypeDomain::State::meet(const State& other) const {
    State result = *this;

    // Ensure all other variables exist in result
    for (const auto& v : other.var_ids.vars() | std::views::keys) {
        result.ensure_var(v);
    }

    // Merge equalities from other
    std::map<size_t, std::vector<Variable>> other_classes;
    for (const auto& [v, id] : other.var_ids.vars()) {
        const size_t rep = other.dsu.find_const(id);
        other_classes[rep].push_back(v);
    }
    for (const auto& members : other_classes | std::views::values) {
        for (size_t i = 1; i < members.size(); i++) {
            if (!result.assume_eq(members[0], members[i])) {
                return std::nullopt;
            }
        }
    }

    // Intersect TypeSets from other
    for (const auto& v : other.var_ids.vars() | std::views::keys) {
        if (!result.restrict_var(v, other.get_typeset(v))) {
            return std::nullopt;
        }
    }

    return result;
}

bool TypeDomain::State::is_subsumed_by(const State& other) const {
    // Check TypeSet refinement: S[v] in self must be subset of S[v] in other.
    for (const auto& [v, id] : var_ids.vars()) {
        const size_t rep = dsu.find_const(id);
        const TypeSet ts_self = class_types[rep];
        const TypeSet ts_other = other.get_typeset(v);
        if (!ts_self.is_subset_of(ts_other)) {
            return false;
        }
    }
    for (const auto& [v, id] : other.var_ids.vars()) {
        if (!var_ids.contains(v)) {
            const size_t rep = other.dsu.find_const(id);
            if (other.class_types[rep] != TypeSet::all()) {
                return false;
            }
        }
    }

    // Check equality preservation: other's equalities must hold in self.
    std::map<size_t, std::vector<Variable>> other_classes;
    for (const auto& [v, id] : other.var_ids.vars()) {
        const size_t rep = other.dsu.find_const(id);
        other_classes[rep].push_back(v);
    }
    for (const auto& members : other_classes | std::views::values) {
        if (members.size() <= 1) {
            continue;
        }
        const auto id0 = var_ids.find_id(members[0]);
        if (!id0) {
            for (size_t i = 1; i < members.size(); i++) {
                if (var_ids.contains(members[i])) {
                    return false;
                }
            }
            continue;
        }
        const size_t rep0 = dsu.find_const(*id0);
        for (size_t i = 1; i < members.size(); i++) {
            const auto id_i = var_ids.find_id(members[i]);
            if (!id_i) {
                return false;
            }
            if (dsu.find_const(*id_i) != rep0) {
                return false;
            }
        }
    }

    return true;
}

// ============================================================================
// TypeDomain — thin WithBottom wrappers
// ============================================================================

void TypeDomain::set_to_top() { state_ = std::make_unique<State>(); }
void TypeDomain::set_to_bottom() { state_.reset(); }

// -- Lattice -----------------------------------------------------------------

TypeDomain TypeDomain::join(const TypeDomain& other) const {
    if (!state_) {
        return other;
    }
    if (!other.state_) {
        return *this;
    }
    TypeDomain result;
    result.state_ = std::make_unique<State>(State::join(*state_, *other.state_));
    return result;
}

void TypeDomain::operator|=(const TypeDomain& other) {
    if (!other.state_) {
        return;
    }
    if (!state_) {
        *this = other;
        return;
    }
    *this = join(other);
}

TypeDomain TypeDomain::operator|(const TypeDomain& other) const { return join(other); }

std::optional<TypeDomain> TypeDomain::meet(const TypeDomain& other) const {
    if (!state_ || !other.state_) {
        return std::nullopt;
    }
    if (auto result = state_->meet(*other.state_)) {
        TypeDomain td;
        td.state_ = std::make_unique<State>(std::move(*result));
        return td;
    }
    return std::nullopt;
}

bool TypeDomain::operator<=(const TypeDomain& other) const {
    if (!state_) {
        return true;
    }
    if (!other.state_) {
        return false;
    }
    return state_->is_subsumed_by(*other.state_);
}

TypeDomain TypeDomain::narrow(const TypeDomain& other) const {
    if (auto res = meet(other)) {
        return std::move(*res);
    }
    TypeDomain res;
    res.set_to_bottom();
    return res;
}

// -- Assignment --------------------------------------------------------------

void TypeDomain::assign_type(const Reg& lhs, const Reg& rhs) {
    if (auto* s = state_.get()) {
        s->assign_copy(reg_type(lhs), reg_type(rhs));
    }
}

void TypeDomain::assign_type(const Reg& lhs, const std::optional<LinearExpression>& rhs) {
    if (!state_) {
        return;
    }
    if (!rhs) {
        havoc_type(reg_type(lhs));
        return;
    }
    if (!state_->assign_from_expr(reg_type(lhs), *rhs)) {
        set_to_bottom();
    }
}

void TypeDomain::assign_type(const std::optional<Variable> lhs, const LinearExpression& t) {
    if (!state_ || !lhs) {
        return;
    }
    if (!state_->assign_from_expr(*lhs, t)) {
        set_to_bottom();
    }
}

void TypeDomain::assign_type(const Reg& lhs, const TypeEncoding type) {
    if (auto* s = state_.get()) {
        s->assign_encoding(reg_type(lhs), type);
    }
}

// -- Constraint handling -----------------------------------------------------

void TypeDomain::restrict_to(const Variable v, const TypeSet mask) {
    if (auto* s = state_.get()) {
        if (!s->restrict_var(v, mask)) {
            set_to_bottom();
        }
    }
}

void TypeDomain::assume_eq(const Variable v1, const Variable v2) {
    if (auto* s = state_.get()) {
        if (!s->assume_eq(v1, v2)) {
            set_to_bottom();
        }
    }
}

void TypeDomain::remove_type(const Variable v, const TypeEncoding te) {
    if (auto* s = state_.get()) {
        if (!s->remove_type(v, te)) {
            set_to_bottom();
        }
    }
}

// -- Havoc -------------------------------------------------------------------

void TypeDomain::havoc_type(const Reg& r) {
    if (auto* s = state_.get()) {
        s->detach(reg_type(r));
    }
}

void TypeDomain::havoc_type(const Variable& v) {
    if (auto* s = state_.get()) {
        s->detach(v);
    }
}

// -- Query methods -----------------------------------------------------------

TypeSet TypeDomain::get_typeset(const Variable v) const {
    if (const auto* s = state_.get()) {
        return s->get_typeset(v);
    }
    return TypeSet{}; // bottom
}

std::vector<TypeEncoding> TypeDomain::iterate_types(const Reg& reg) const {
    if (!state_) {
        return {};
    }
    const TypeSet ts = get_typeset(reg_type(reg));
    if (ts.contains(T_UNINIT)) {
        return {T_UNINIT};
    }
    return ts.remove(T_UNINIT).to_vector();
}

std::optional<TypeEncoding> TypeDomain::get_type(const Reg& r) const { return get_typeset(reg_type(r)).as_singleton(); }

bool TypeDomain::implies_superset(const Reg& premise_reg, const TypeSet premise_set, const Reg& conclusion_reg,
                                  const TypeSet conclusion_set) const {
    if (!state_) {
        return true;
    }
    State restricted = *state_;
    if (!restricted.restrict_var(reg_type(premise_reg), premise_set)) {
        return true;
    }
    return restricted.get_typeset(reg_type(conclusion_reg)).is_subset_of(conclusion_set);
}

bool TypeDomain::implies_not_type(const Reg& premise_reg, const TypeEncoding excluded_type, const Reg& conclusion_reg,
                                  const TypeSet conclusion_set) const {
    if (!state_) {
        return true;
    }
    State restricted = *state_;
    if (!restricted.remove_type(reg_type(premise_reg), excluded_type)) {
        return true;
    }
    return restricted.get_typeset(reg_type(conclusion_reg)).is_subset_of(conclusion_set);
}

bool TypeDomain::entail_type(const Variable v, const TypeEncoding te) const {
    if (!state_) {
        return true; // bottom entails everything
    }
    return get_typeset(v) == TypeSet{te};
}

bool TypeDomain::may_have_type(const Reg& r, const TypeEncoding type) const {
    return get_typeset(reg_type(r)).contains(type);
}

bool TypeDomain::may_have_type(const Variable v, const TypeEncoding type) const {
    return get_typeset(v).contains(type);
}

bool TypeDomain::is_initialized(const Reg& r) const { return !get_typeset(reg_type(r)).contains(T_UNINIT); }

bool TypeDomain::is_initialized(const Variable v) const { return !get_typeset(v).contains(T_UNINIT); }

bool TypeDomain::same_type(const Reg& a, const Reg& b) const {
    if (const auto* s = state_.get()) {
        return s->same_type(reg_type(a), reg_type(b));
    }
    return true; // bottom entails everything
}

bool TypeDomain::is_in_group(const Reg& r, const TypeSet types) const {
    return get_typeset(reg_type(r)).is_subset_of(types);
}

// -- Serialization -----------------------------------------------------------

StringInvariant TypeDomain::to_set() const {
    if (!state_) {
        return StringInvariant::bottom();
    }
    return state_->to_set();
}

std::ostream& operator<<(std::ostream& o, const TypeDomain& dom) { return o << dom.to_set(); }

} // namespace prevail

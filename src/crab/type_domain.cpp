// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.
#include <algorithm>
#include <bit>
#include <cassert>
#include <map>
#include <optional>
#include <sstream>

#include "arith/variable.hpp"
#include "crab/type_domain.hpp"
#include "crab/type_encoding.hpp"
#include "crab/var_registry.hpp"
#include "crab_utils/debug.hpp"

namespace prevail {

template <is_enum T>
static void operator++(T& t) {
    t = static_cast<T>(1 + static_cast<std::underlying_type_t<T>>(t));
}

// ============================================================================
// DataKind utilities
// ============================================================================

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
// TypeEncoding utilities
// ============================================================================

std::vector<TypeEncoding> iterate_types(const TypeEncoding lb, const TypeEncoding ub) {
    if (lb > ub) {
        CRAB_ERROR("lower bound ", lb, " is greater than upper bound ", ub);
    }
    if (lb < T_MIN || ub > T_MAX) {
        CRAB_ERROR("bounds ", lb, " and ", ub, " are out of range");
    }
    std::vector<TypeEncoding> res;
    for (TypeEncoding i = lb; i <= ub; ++i) {
        res.push_back(i);
    }
    return res;
}

static constexpr auto S_UNINIT = "uninit";
static constexpr auto S_STACK = "stack";
static constexpr auto S_PACKET = "packet";
static constexpr auto S_CTX = "ctx";
static constexpr auto S_MAP_PROGRAMS = "map_fd_programs";
static constexpr auto S_MAP = "map_fd";
static constexpr auto S_NUM = "number";
static constexpr auto S_SHARED = "shared";

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
    default: CRAB_ERROR("Unsupported type encoding", s);
    }
}

TypeEncoding string_to_type_encoding(const std::string& s) {
    static std::map<std::string, TypeEncoding> string_to_type{
        {S_UNINIT, T_UNINIT}, {S_MAP_PROGRAMS, T_MAP_PROGRAMS},
        {S_MAP, T_MAP},       {S_NUM, T_NUM},
        {S_CTX, T_CTX},       {S_STACK, T_STACK},
        {S_PACKET, T_PACKET}, {S_SHARED, T_SHARED},
    };
    if (string_to_type.contains(s)) {
        return string_to_type[s];
    }
    throw std::runtime_error(std::string("Unsupported type name: ") + s);
}

std::optional<TypeEncoding> int_to_type_encoding(const int v) {
    if (v >= T_MIN && v <= T_MAX) {
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
    const int bit = std::countr_zero(raw());
    return int_to_type_encoding(bit - 7);
}

std::vector<TypeEncoding> TypeSet::to_vector() const {
    std::vector<TypeEncoding> result;
    uint8_t tmp = raw();
    while (tmp != 0) {
        const int bit = std::countr_zero(tmp);
        if (auto te = int_to_type_encoding(bit - 7)) {
            result.push_back(*te);
        }
        tmp &= tmp - 1; // clear lowest set bit
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
    case TypeGroup::number: return TypeSet::singleton(T_NUM);
    case TypeGroup::map_fd: return TypeSet::singleton(T_MAP);
    case TypeGroup::ctx: return TypeSet::singleton(T_CTX);
    case TypeGroup::packet: return TypeSet::singleton(T_PACKET);
    case TypeGroup::stack: return TypeSet::singleton(T_STACK);
    case TypeGroup::shared: return TypeSet::singleton(T_SHARED);
    case TypeGroup::map_fd_programs: return TypeSet::singleton(T_MAP_PROGRAMS);
    case TypeGroup::ctx_or_num: return TypeSet::singleton(T_NUM) | TypeSet::singleton(T_CTX);
    case TypeGroup::stack_or_num: return TypeSet::singleton(T_NUM) | TypeSet::singleton(T_STACK);
    case TypeGroup::mem:
        return TypeSet::singleton(T_PACKET) | TypeSet::singleton(T_STACK) | TypeSet::singleton(T_SHARED);
    case TypeGroup::mem_or_num:
        return TypeSet::singleton(T_NUM) | TypeSet::singleton(T_PACKET) | TypeSet::singleton(T_STACK) |
               TypeSet::singleton(T_SHARED);
    case TypeGroup::pointer:
        return TypeSet::singleton(T_CTX) | TypeSet::singleton(T_PACKET) | TypeSet::singleton(T_STACK) |
               TypeSet::singleton(T_SHARED);
    case TypeGroup::ptr_or_num:
        return TypeSet::singleton(T_NUM) | TypeSet::singleton(T_CTX) | TypeSet::singleton(T_PACKET) |
               TypeSet::singleton(T_STACK) | TypeSet::singleton(T_SHARED);
    case TypeGroup::stack_or_packet: return TypeSet::singleton(T_STACK) | TypeSet::singleton(T_PACKET);
    case TypeGroup::singleton_ptr:
        return TypeSet::singleton(T_CTX) | TypeSet::singleton(T_PACKET) | TypeSet::singleton(T_STACK);
    default: CRAB_ERROR("Unsupported type group", group);
    }
}

bool is_singleton_type(const TypeGroup t) {
    switch (t) {
    case TypeGroup::number:
    case TypeGroup::map_fd:
    case TypeGroup::map_fd_programs:
    case TypeGroup::ctx:
    case TypeGroup::packet:
    case TypeGroup::stack:
    case TypeGroup::shared: return true;
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
    CRAB_ERROR("Unsupported type group", ts);
}

// ============================================================================
// TypeDomain — DSU-based implementation
// ============================================================================

Variable reg_type(const Reg& lhs) { return variable_registry->type_reg(lhs.v); }

// -- Sentinel initialization -------------------------------------------------

void TypeDomain::init_sentinels() {
    dsu = DisjointSetUnion{NUM_TYPE_SENTINELS};
    id_to_var.assign(NUM_TYPE_SENTINELS, std::nullopt);
    class_types.resize(NUM_TYPE_SENTINELS);
    for (const TypeEncoding te : TypeSet::all().to_vector()) {
        class_types[type_to_bit(te)] = TypeSet::singleton(te);
    }
}

TypeDomain::TypeDomain() { init_sentinels(); }

/// If the class containing `id` has a singleton TypeSet, merge it with the
/// corresponding sentinel element to maintain the singleton-merging invariant.
void TypeDomain::merge_if_singleton(const size_t id) {
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

// -- Internal helpers --------------------------------------------------------

size_t TypeDomain::ensure_var(const Variable v) {
    if (const auto it = var_to_id.find(v); it != var_to_id.end()) {
        return it->second;
    }
    const size_t id = dsu.push();
    var_to_id[v] = id;
    while (id_to_var.size() <= id) {
        id_to_var.push_back(std::nullopt);
    }
    id_to_var[id] = v;
    class_types.push_back(TypeSet::all());
    assert(class_types.size() == dsu.size());
    assert(id_to_var.size() == dsu.size());
    return id;
}

void TypeDomain::detach(const Variable v) {
    if (const auto it = var_to_id.find(v); it != var_to_id.end()) {
        id_to_var[it->second] = std::nullopt; // orphan old element
    }
    const size_t new_id = dsu.push();
    var_to_id[v] = new_id;
    while (id_to_var.size() <= new_id) {
        id_to_var.push_back(std::nullopt);
    }
    id_to_var[new_id] = v;
    class_types.push_back(TypeSet::all());
    assert(class_types.size() == dsu.size());
    assert(id_to_var.size() == dsu.size());
}

TypeSet TypeDomain::get_typeset(const Variable v) const {
    if (is_bottom_) {
        return TypeSet::empty();
    }
    const auto it = var_to_id.find(v);
    if (it == var_to_id.end()) {
        return TypeSet::all(); // unknown variable = top
    }
    const size_t rep = dsu.find_const(it->second);
    return class_types[rep];
}

void TypeDomain::restrict_var(const Variable v, const TypeSet mask) {
    if (is_bottom_) {
        return;
    }
    const size_t id = ensure_var(v);
    const size_t rep = dsu.find(id);
    const TypeSet result = class_types[rep] & mask;
    class_types[rep] = result;
    if (result.is_empty()) {
        is_bottom_ = true;
    } else {
        merge_if_singleton(id);
    }
}

void TypeDomain::unify(const Variable v1, const Variable v2) {
    if (is_bottom_) {
        return;
    }
    const size_t id1 = ensure_var(v1);
    const size_t id2 = ensure_var(v2);
    const size_t rep1 = dsu.find(id1);
    const size_t rep2 = dsu.find(id2);
    const TypeSet ts = class_types[rep1] & class_types[rep2];
    const size_t new_rep = dsu.unite(id1, id2);
    class_types[new_rep] = ts;
    if (ts.is_empty()) {
        is_bottom_ = true;
    } else {
        merge_if_singleton(id1);
    }
}

// -- Lattice operations ------------------------------------------------------

void TypeDomain::set_to_top() {
    var_to_id.clear();
    id_to_var.clear();
    class_types.clear();
    is_bottom_ = false;
    init_sentinels();
}

TypeDomain TypeDomain::join(const TypeDomain& other) const {
    if (is_bottom_) {
        return other;
    }
    if (other.is_bottom_) {
        return *this;
    }

    // With the singleton-merging invariant, all variables with singleton {te}
    // share the same DSU rep (the sentinel) in each operand. So raw DSU reps
    // partition correctly without a special singleton key.

    // Collect all variables from both operands.
    std::map<Variable, bool> all_vars_seen;
    for (const auto& [v, _] : var_to_id) {
        all_vars_seen[v] = true;
    }
    for (const auto& [v, _] : other.var_to_id) {
        all_vars_seen[v] = true;
    }

    // Compute (rep_left, rep_right) for each variable, group by key pair.
    // Variables absent from one side get unique keys (not nullopt) to avoid
    // falsely unifying unrelated variables that happen to share a rep on the
    // other side.
    size_t next_unique_a = dsu.size();
    size_t next_unique_b = other.dsu.size();
    std::map<std::pair<size_t, size_t>, std::vector<Variable>> key_groups;
    for (const auto& [v, _] : all_vars_seen) {
        size_t key_a;
        if (const auto it = var_to_id.find(v); it != var_to_id.end()) {
            key_a = dsu.find_const(it->second);
        } else {
            key_a = next_unique_a++;
        }
        size_t key_b;
        if (const auto it = other.var_to_id.find(v); it != other.var_to_id.end()) {
            key_b = other.dsu.find_const(it->second);
        } else {
            key_b = next_unique_b++;
        }
        key_groups[{key_a, key_b}].push_back(v);
    }

    // Build result
    TypeDomain result;
    for (const auto& [_, members] : key_groups) {
        // TypeSet = union of per-variable TypeSets from both operands
        TypeSet ts = TypeSet::empty();
        for (const Variable& v : members) {
            ts |= get_typeset(v);
            ts |= other.get_typeset(v);
        }

        // Register all members in the result, unified
        std::optional<size_t> first_id;
        for (const Variable& v : members) {
            const size_t id = result.ensure_var(v);
            result.class_types[id] = ts;
            if (first_id) {
                const size_t new_rep = result.dsu.unite(*first_id, id);
                result.class_types[new_rep] = ts;
            } else {
                first_id = id;
            }
        }
        // Maintain singleton-merging invariant in result.
        if (first_id) {
            result.merge_if_singleton(*first_id);
        }
    }

    return result;
}

void TypeDomain::operator|=(const TypeDomain& other) {
    if (other.is_bottom_) {
        return;
    }
    if (is_bottom_) {
        *this = other;
        return;
    }
    *this = join(other);
}

TypeDomain TypeDomain::operator|(const TypeDomain& other) const { return join(other); }

std::optional<TypeDomain> TypeDomain::meet(const TypeDomain& other) const {
    if (is_bottom_ || other.is_bottom_) {
        return std::nullopt;
    }

    TypeDomain result = *this;

    // Ensure all other variables exist in result
    for (const auto& [v, _] : other.var_to_id) {
        result.ensure_var(v);
    }

    // Merge equalities from other
    // Group other's variables by representative
    std::map<size_t, std::vector<Variable>> other_classes;
    for (const auto& [v, id] : other.var_to_id) {
        const size_t rep = other.dsu.find_const(id);
        other_classes[rep].push_back(v);
    }
    for (const auto& [_, members] : other_classes) {
        for (size_t i = 1; i < members.size(); i++) {
            result.unify(members[0], members[i]);
            if (result.is_bottom_) {
                return std::nullopt;
            }
        }
    }

    // Intersect TypeSets from other
    for (const auto& [v, _] : other.var_to_id) {
        result.restrict_var(v, other.get_typeset(v));
        if (result.is_bottom_) {
            return std::nullopt;
        }
    }

    return result;
}

bool TypeDomain::operator<=(const TypeDomain& other) const {
    if (is_bottom_) {
        return true;
    }
    if (other.is_bottom_) {
        return false;
    }

    // Check TypeSet refinement: S[v] in self must be subset of S[v] in other.
    // Check both directions: variables in self must refine other, AND
    // variables in other that are absent in self (top = all types) must also be all types.
    for (const auto& [v, id] : var_to_id) {
        const size_t rep = dsu.find_const(id);
        const TypeSet ts_self = class_types[rep];
        const TypeSet ts_other = other.get_typeset(v);
        if (!ts_self.is_subset_of(ts_other)) {
            return false;
        }
    }
    for (const auto& [v, id] : other.var_to_id) {
        if (!var_to_id.contains(v)) {
            // Variable absent in self means unconstrained (all types).
            // This is only subsumed if other also allows all types.
            const size_t rep = other.dsu.find_const(id);
            if (other.class_types[rep] != TypeSet::all()) {
                return false;
            }
        }
    }

    // Check equality preservation: other's equalities must hold in self.
    // With the singleton-merging invariant, DSU rep equality is the single
    // source of truth — no singleton fallback needed.
    std::map<size_t, std::vector<Variable>> other_classes;
    for (const auto& [v, id] : other.var_to_id) {
        const size_t rep = other.dsu.find_const(id);
        other_classes[rep].push_back(v);
    }
    for (const auto& [_, members] : other_classes) {
        if (members.size() <= 1) {
            continue;
        }
        const auto it0 = var_to_id.find(members[0]);
        if (it0 == var_to_id.end()) {
            // First variable unknown in self (top). All others must also be unknown.
            for (size_t i = 1; i < members.size(); i++) {
                if (var_to_id.contains(members[i])) {
                    return false;
                }
            }
            continue;
        }
        const size_t rep0 = dsu.find_const(it0->second);
        for (size_t i = 1; i < members.size(); i++) {
            const auto it = var_to_id.find(members[i]);
            if (it == var_to_id.end()) {
                return false;
            }
            if (dsu.find_const(it->second) != rep0) {
                return false;
            }
        }
    }

    return true;
}

TypeDomain TypeDomain::narrow(const TypeDomain& other) const {
    if (auto res = meet(other)) {
        return std::move(*res);
    }
    TypeDomain res;
    res.is_bottom_ = true;
    return res;
}

// -- Assignment --------------------------------------------------------------

void TypeDomain::assign_type(const Reg& lhs, const Reg& rhs) {
    if (is_bottom_) {
        return;
    }
    const Variable lhs_var = reg_type(lhs);
    const Variable rhs_var = reg_type(rhs);
    detach(lhs_var);
    const size_t rhs_id = ensure_var(rhs_var);
    const size_t lhs_id = var_to_id[lhs_var];
    const TypeSet rhs_ts = class_types[dsu.find(rhs_id)];
    const size_t new_rep = dsu.unite(lhs_id, rhs_id);
    class_types[new_rep] = rhs_ts;
    merge_if_singleton(lhs_id);
}

void TypeDomain::assign_from_expr(const Variable lhs, const LinearExpression& expr) {
    const auto& terms = expr.variable_terms();
    if (terms.empty()) {
        // Constant expression: assign that type encoding
        const int val = expr.constant_term().narrow<int>();
        detach(lhs);
        const size_t id = var_to_id[lhs];
        if (const auto te = int_to_type_encoding(val)) {
            class_types[id] = TypeSet::singleton(*te);
            merge_if_singleton(id);
        } else {
            class_types[id] = TypeSet::all();
        }
    } else if (terms.size() == 1) {
        const auto& [var, coeff] = *terms.begin();
        if (coeff == 1 && expr.constant_term() == 0) {
            // Simple variable copy: detach lhs, unify with rhs
            detach(lhs);
            const size_t rhs_id = ensure_var(var);
            const size_t lhs_id = var_to_id[lhs];
            const TypeSet rhs_ts = class_types[dsu.find(rhs_id)];
            const size_t new_rep = dsu.unite(lhs_id, rhs_id);
            class_types[new_rep] = rhs_ts;
            merge_if_singleton(lhs_id);
        } else {
            // Complex expression: havoc
            detach(lhs);
        }
    } else {
        // Multi-variable: havoc
        detach(lhs);
    }
}

void TypeDomain::assign_type(const Reg& lhs, const std::optional<LinearExpression>& rhs) {
    if (is_bottom_) {
        return;
    }
    const Variable lhs_var = reg_type(lhs);
    if (!rhs) {
        havoc_type(lhs_var);
        return;
    }
    assign_from_expr(lhs_var, *rhs);
}

void TypeDomain::assign_type(const std::optional<Variable> lhs, const LinearExpression& t) {
    if (is_bottom_ || !lhs) {
        return;
    }
    assign_from_expr(*lhs, t);
}

void TypeDomain::assign_type(const Reg& lhs, const TypeEncoding type) {
    if (is_bottom_) {
        return;
    }
    const Variable v = reg_type(lhs);
    detach(v);
    const size_t id = var_to_id[v];
    class_types[id] = TypeSet::singleton(type);
    merge_if_singleton(id);
}

// -- Constraint handling -----------------------------------------------------

void TypeDomain::add_constraint(const LinearConstraint& cst) {
    if (is_bottom_) {
        return;
    }
    if (cst.is_tautology()) {
        return;
    }
    if (cst.is_contradiction()) {
        is_bottom_ = true;
        return;
    }

    const auto& expr = cst.expression();
    const auto& terms = expr.variable_terms();
    const Number& constant = expr.constant_term();

    switch (cst.kind()) {
    case ConstraintKind::EQUALS_ZERO: {
        // expression == 0
        if (terms.size() == 1) {
            const auto& [var, coeff] = *terms.begin();
            if (coeff == 1) {
                // var + c == 0 → var == -c
                const int val = (-constant).narrow<int>();
                if (const auto te = int_to_type_encoding(val)) {
                    restrict_var(var, TypeSet::singleton(*te));
                } else {
                    is_bottom_ = true;
                }
            } else if (coeff == -1) {
                // -var + c == 0 → var == c
                const int val = constant.narrow<int>();
                if (const auto te = int_to_type_encoding(val)) {
                    restrict_var(var, TypeSet::singleton(*te));
                } else {
                    is_bottom_ = true;
                }
            }
        } else if (terms.size() == 2) {
            // var1 - var2 + c == 0 → if c == 0: unify var1, var2
            auto it = terms.begin();
            const auto& [v1, c1] = *it++;
            const auto& [v2, c2] = *it;
            if (constant == 0 && ((c1 == 1 && c2 == -1) || (c1 == -1 && c2 == 1))) {
                unify(v1, v2);
            }
        }
        break;
    }
    case ConstraintKind::NOT_ZERO: {
        // expression != 0
        if (terms.size() == 1) {
            const auto& [var, coeff] = *terms.begin();
            if (coeff == 1) {
                // var + c != 0 → var != -c
                const int val = (-constant).narrow<int>();
                if (const auto te = int_to_type_encoding(val)) {
                    const size_t id = ensure_var(var);
                    const size_t rep = dsu.find(id);
                    const TypeSet result = class_types[rep].remove(*te);
                    class_types[rep] = result;
                    if (result.is_empty()) {
                        is_bottom_ = true;
                    } else {
                        merge_if_singleton(id);
                    }
                }
            } else if (coeff == -1) {
                // -var + c != 0 → var != c
                const int val = constant.narrow<int>();
                if (const auto te = int_to_type_encoding(val)) {
                    const size_t id = ensure_var(var);
                    const size_t rep = dsu.find(id);
                    const TypeSet result = class_types[rep].remove(*te);
                    class_types[rep] = result;
                    if (result.is_empty()) {
                        is_bottom_ = true;
                    } else {
                        merge_if_singleton(id);
                    }
                }
            }
        }
        break;
    }
    case ConstraintKind::LESS_THAN_OR_EQUALS_ZERO:
    case ConstraintKind::LESS_THAN_ZERO:
        // Order comparisons on type encodings are not meaningful.
        CRAB_ERROR("Order comparison on type variable");
    }
}

void TypeDomain::restrict_to(const Variable v, const TypeSet mask) { restrict_var(v, mask); }

void TypeDomain::remove_type(const Variable v, const TypeEncoding te) {
    if (is_bottom_) {
        return;
    }
    const size_t id = ensure_var(v);
    const size_t rep = dsu.find(id);
    const TypeSet result = class_types[rep].remove(te);
    class_types[rep] = result;
    if (result.is_empty()) {
        is_bottom_ = true;
    } else {
        merge_if_singleton(id);
    }
}

// -- Havoc -------------------------------------------------------------------

void TypeDomain::havoc_type(const Reg& r) {
    if (is_bottom_) {
        return;
    }
    detach(reg_type(r));
}

void TypeDomain::havoc_type(const Variable& v) {
    if (is_bottom_) {
        return;
    }
    detach(v);
}

// -- Query methods -----------------------------------------------------------

bool TypeDomain::entail(const LinearConstraint& cst) const {
    if (is_bottom_) {
        return true;
    }
    if (cst.is_tautology()) {
        return true;
    }
    if (cst.is_contradiction()) {
        return false;
    }

    const auto& expr = cst.expression();
    const auto& terms = expr.variable_terms();
    const Number& constant = expr.constant_term();

    switch (cst.kind()) {
    case ConstraintKind::EQUALS_ZERO: {
        if (terms.size() == 1) {
            const auto& [var, coeff] = *terms.begin();
            if (coeff == 1) {
                // var == -c
                const int val = (-constant).narrow<int>();
                const TypeSet ts = get_typeset(var);
                if (const auto te = int_to_type_encoding(val)) {
                    return ts == TypeSet::singleton(*te);
                }
                return false;
            }
            if (coeff == -1) {
                // var == c
                const int val = constant.narrow<int>();
                const TypeSet ts = get_typeset(var);
                if (const auto te = int_to_type_encoding(val)) {
                    return ts == TypeSet::singleton(*te);
                }
                return false;
            }
        } else if (terms.size() == 2) {
            // var1 - var2 == 0 → same class check
            auto it = terms.begin();
            const auto& [v1, c1] = *it++;
            const auto& [v2, c2] = *it;
            if (constant == 0 && ((c1 == 1 && c2 == -1) || (c1 == -1 && c2 == 1))) {
                const auto it1 = var_to_id.find(v1);
                const auto it2 = var_to_id.find(v2);
                if (it1 != var_to_id.end() && it2 != var_to_id.end()) {
                    // With the singleton-merging invariant, DSU rep comparison
                    // is sufficient (same singletons share the sentinel rep).
                    return dsu.find_const(it1->second) == dsu.find_const(it2->second);
                }
                return false;
            }
        }
        return false;
    }
    case ConstraintKind::NOT_ZERO: {
        if (terms.size() == 1) {
            const auto& [var, coeff] = *terms.begin();
            if (coeff == 1) {
                // var != -c
                const int val = (-constant).narrow<int>();
                const TypeSet ts = get_typeset(var);
                if (const auto te = int_to_type_encoding(val)) {
                    return !ts.contains(*te);
                }
                return true;
            }
            if (coeff == -1) {
                // var != c
                const int val = constant.narrow<int>();
                const TypeSet ts = get_typeset(var);
                if (const auto te = int_to_type_encoding(val)) {
                    return !ts.contains(*te);
                }
                return true;
            }
        }
        return false;
    }
    case ConstraintKind::LESS_THAN_OR_EQUALS_ZERO:
    case ConstraintKind::LESS_THAN_ZERO:
        // Order comparisons on type encodings are not meaningful.
        CRAB_ERROR("Order comparison on type variable");
    }
    return false;
}

bool TypeDomain::type_is_pointer(const Reg& r) const {
    return get_typeset(reg_type(r)).is_subset_of(to_typeset(TypeGroup::pointer));
}

bool TypeDomain::type_is_number(const Reg& r) const { return get_typeset(reg_type(r)) == TypeSet::singleton(T_NUM); }

bool TypeDomain::type_is_not_stack(const Reg& r) const { return !get_typeset(reg_type(r)).contains(T_STACK); }

bool TypeDomain::type_is_not_number(const Reg& r) const { return !get_typeset(reg_type(r)).contains(T_NUM); }

std::vector<TypeEncoding> TypeDomain::iterate_types(const Reg& reg) const {
    if (is_bottom_) {
        return {};
    }
    const TypeSet ts = get_typeset(reg_type(reg));
    if (ts.contains(T_UNINIT)) {
        return {T_UNINIT};
    }
    return ts.remove(T_UNINIT).to_vector();
}

std::optional<TypeEncoding> TypeDomain::get_type(const Reg& r) const { return get_typeset(reg_type(r)).as_singleton(); }

bool TypeDomain::implies_group(const Reg& premise_reg, const TypeGroup premise_group, const Reg& conclusion_reg,
                               const TypeSet conclusion_set) const {
    if (is_bottom_) {
        return true;
    }
    TypeDomain restricted = *this;
    restricted.restrict_var(reg_type(premise_reg), to_typeset(premise_group));
    if (restricted.is_bottom_) {
        return true;
    }
    return restricted.get_typeset(reg_type(conclusion_reg)).is_subset_of(conclusion_set);
}

bool TypeDomain::implies_not_type(const Reg& premise_reg, const TypeEncoding excluded_type, const Reg& conclusion_reg,
                                  const TypeSet conclusion_set) const {
    if (is_bottom_) {
        return true;
    }
    TypeDomain restricted = *this;
    restricted.remove_type(reg_type(premise_reg), excluded_type);
    if (restricted.is_bottom_) {
        return true;
    }
    return restricted.get_typeset(reg_type(conclusion_reg)).is_subset_of(conclusion_set);
}

bool TypeDomain::entail_type(const Variable v, const TypeEncoding te) const {
    if (is_bottom_) {
        return true;
    }
    return get_typeset(v) == TypeSet::singleton(te);
}

bool TypeDomain::may_have_type(const Reg& r, const TypeEncoding type) const {
    return get_typeset(reg_type(r)).contains(type);
}

bool TypeDomain::may_have_type(const LinearExpression& expr, const TypeEncoding type) const {
    const auto& terms = expr.variable_terms();
    if (terms.empty()) {
        const int val = expr.constant_term().narrow<int>();
        return int_to_type_encoding(val) == type;
    }
    if (terms.size() == 1) {
        const auto& [var, coeff] = *terms.begin();
        if (coeff == 1 && expr.constant_term() == 0) {
            return get_typeset(var).contains(type);
        }
    }
    return true; // conservatively true for complex expressions
}

bool TypeDomain::may_have_type(const Variable v, const TypeEncoding type) const {
    return get_typeset(v).contains(type);
}

bool TypeDomain::is_initialized(const Reg& r) const { return !get_typeset(reg_type(r)).contains(T_UNINIT); }

bool TypeDomain::is_initialized(const LinearExpression& expr) const {
    const auto& terms = expr.variable_terms();
    if (terms.empty()) {
        const int val = expr.constant_term().narrow<int>();
        return int_to_type_encoding(val) != T_UNINIT;
    }
    if (terms.size() == 1) {
        const auto& [var, coeff] = *terms.begin();
        if (coeff == 1 && expr.constant_term() == 0) {
            return !get_typeset(var).contains(T_UNINIT);
        }
    }
    return false; // conservatively not initialized
}

/// With the singleton-merging invariant, this is a pure DSU rep comparison:
/// if both variables have a singleton TypeSet {te}, they are already merged
/// with the same sentinel.
bool TypeDomain::same_type(const Reg& a, const Reg& b) const {
    if (is_bottom_) {
        return true;
    }
    const auto it_a = var_to_id.find(reg_type(a));
    const auto it_b = var_to_id.find(reg_type(b));
    if (it_a != var_to_id.end() && it_b != var_to_id.end()) {
        return dsu.find_const(it_a->second) == dsu.find_const(it_b->second);
    }
    return false;
}

bool TypeDomain::is_in_group(const Reg& r, const TypeGroup group) const {
    return get_typeset(reg_type(r)).is_subset_of(to_typeset(group));
}

// -- Serialization -----------------------------------------------------------

StringInvariant TypeDomain::to_set() const {
    if (is_bottom_) {
        return StringInvariant::bottom();
    }

    // Group variables by DSU representative. With the singleton-merging invariant,
    // variables sharing a singleton TypeSet are already in the same DSU class.
    std::map<size_t, std::vector<Variable>> classes;
    for (const auto& [v, id] : var_to_id) {
        if (!id_to_var[id]) {
            continue; // orphaned
        }
        const size_t rep = dsu.find_const(id);
        classes[rep].push_back(v);
    }

    std::set<std::string> result;

    for (const auto& [_, members] : classes) {
        // Get TypeSet from the first member (all members in the group have the same TypeSet)
        const TypeSet ts = get_typeset(members[0]);
        if (ts == TypeSet::all()) {
            continue; // top = no constraint
        }

        // Sort members for deterministic output
        std::vector<Variable> sorted = members;
        std::sort(sorted.begin(), sorted.end(), variable_registry->printing_order);

        if (const auto te = ts.as_singleton()) {
            // Singleton TypeSet: emit concrete type for every member
            for (const Variable& m : sorted) {
                // Stack type variables with type=number are implicit (not printed)
                if (*te == T_NUM && variable_registry->is_in_stack(m)) {
                    continue;
                }
                result.insert(variable_registry->name(m) + "=" + ts.to_string());
            }
        } else {
            // Multi-valued TypeSet: emit set for first member, equality for rest
            const std::string first_name = variable_registry->name(sorted[0]);
            result.insert(first_name + " in " + ts.to_string());

            for (size_t i = 1; i < sorted.size(); i++) {
                result.insert(variable_registry->name(sorted[i]) + "=" + first_name);
            }
        }
    }

    return StringInvariant{std::move(result)};
}

std::ostream& operator<<(std::ostream& o, const TypeDomain& dom) { return o << dom.to_set(); }

} // namespace prevail

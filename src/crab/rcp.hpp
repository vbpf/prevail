// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "arith/variable.hpp"
#include "crab/add_bottom.hpp"
#include "crab/interval.hpp"
#include "crab/type_domain.hpp"

namespace prevail {

struct RegPack {
    Variable svalue; // int64_t value.
    Variable uvalue; // uint64_t value.
    Variable ctx_offset;
    Variable map_fd;
    Variable map_fd_programs;
    Variable packet_offset;
    Variable shared_offset;
    Variable stack_offset;
    Variable shared_region_size;
    Variable stack_numeric_size;
};

inline RegPack reg_pack(const int i) {
    return {
        .svalue = variable_registry->reg(DataKind::svalues, i),
        .uvalue = variable_registry->reg(DataKind::uvalues, i),
        .ctx_offset = variable_registry->reg(DataKind::ctx_offsets, i),
        .map_fd = variable_registry->reg(DataKind::map_fds, i),
        .map_fd_programs = variable_registry->reg(DataKind::map_fd_programs, i),
        .packet_offset = variable_registry->reg(DataKind::packet_offsets, i),
        .shared_offset = variable_registry->reg(DataKind::shared_offsets, i),
        .stack_offset = variable_registry->reg(DataKind::stack_offsets, i),
        .shared_region_size = variable_registry->reg(DataKind::shared_region_sizes, i),
        .stack_numeric_size = variable_registry->reg(DataKind::stack_numeric_sizes, i),
    };
}
inline RegPack reg_pack(const Reg r) { return reg_pack(r.v); }

inline const std::map<TypeEncoding, std::vector<DataKind>> type_to_kinds{
    {T_CTX, {DataKind::ctx_offsets}},
    {T_MAP, {DataKind::map_fds}},
    {T_MAP_PROGRAMS, {DataKind::map_fd_programs}},
    {T_PACKET, {DataKind::packet_offsets}},
    {T_SHARED, {DataKind::shared_offsets, DataKind::shared_region_sizes}},
    {T_STACK, {DataKind::stack_offsets, DataKind::stack_numeric_sizes}},
    {T_NUM, {}}, // TODO: DataKind::svalues
};

std::optional<Variable> get_type_offset_variable(const Reg& reg, int type);

/** TypeToNumDomain implements a Reduced Cardinal Power Domain between TypeDomain and NumAbsDomain.
 * This struct is used to represent the eBPF abstract domain where type information (TypeDomain) is used to guide the
 * precision of the numeric domain(NumAbsDomain). For example, if a register is known to be of type stack, then the
 * numeric domain can track its stack offset; if a register is known to be a number, the numeric domain can track its
 * signed integer value, etc. */
struct TypeToNumDomain {
    TypeDomain types{TypeDomain::top()};
    NumAbsDomain values{NumAbsDomain::top()};

    TypeToNumDomain() = default;
    TypeToNumDomain(const TypeDomain& t, const NumAbsDomain& n) : types(t), values(n) {}

    TypeToNumDomain(const TypeToNumDomain& other) = default;
    TypeToNumDomain(TypeToNumDomain&& other) noexcept = default;
    TypeToNumDomain& operator=(const TypeToNumDomain& other) = default;

    static TypeToNumDomain bottom() { return TypeToNumDomain{TypeDomain::top(), NumAbsDomain::bottom()}; }
    static TypeToNumDomain top() { return TypeToNumDomain{TypeDomain::top(), NumAbsDomain::top()}; }

    bool is_bottom() const { return values.is_bottom(); }
    bool is_top() const { return values.is_top(); }

    void set_to_top() {
        types.set_to_top();
        values.set_to_top();
    }
    void set_to_bottom() { values.set_to_bottom(); }

    /**
     * @brief Determines if this abstract state is subsumed by another (*this <= other).
     *
     * @details This is a type-aware subsumption check that correctly handles type-specific
     * "kind" variables (e.g., `packet_offset`). A standard numerical comparison is
     * insufficient due to the special role these variables play: a kind variable associated
     * with a type that is not active in `this` domain is conceptually Bottom.
     * To ensure a correct comparison, this function first identifies these "Bottom" variables.
     * It then `havoc`s them in a temporary copy of the `other` domain, which sets them to
     * Top. The final numerical check `values <= tmp.values` is then sound, as it
     * evaluates `x <= Top` for all irrelevant variables on the left-hand side.
     */
    bool operator<=(const TypeToNumDomain& other) const;

    void join_selective(const TypeToNumDomain& right);

    void operator|=(const TypeToNumDomain& other);

    TypeToNumDomain operator&(const TypeToNumDomain& other) const;

    std::optional<Variable> get_type_offset_variable(const Reg& reg) const;

    /**
     * @brief Identifies type-specific ("kind") variables that are meaningless for the given domain.
     *
     * @details This function is a helper for the type-aware subsumption check (`operator<=`).
     * The Core Principle: In EbpfDomain, a "kind" variable (e.g., `r1.packet_offset`) is
     * only meaningful if the register might have the corresponding type (`T_PACKET`). If the
     * type is absent, the kind variable is conceptually Bottom.
     *
     * Role in Subsumption: A standard numerical check would incorrectly treat these Bottom
     * variables as Top, failing correct checks like
     *      `{r1.type=T_NUM} <= {r1.type in {T_PACKET,T_NUM}, r1.packet_offset=5}`
     * Effectively meaning:
     *      `{r1.type=T_NUM, r1.packet_offset=BOT} <= {r1.type in {T_PACKET,T_NUM}, r1.packet_offset=5}`
     * Which is obviously true, since Bottom <= 5.
     * This function finds these variables so the `operator<=` can handle them correctly,
     * ensuring the subsumption check is sound.
     *
     * @return A vector of all kind variables that are meaningless (effectively Bottom) in `dom`.
     */
    std::vector<Variable> get_nonexistent_kind_variables() const;

    /**
     * @brief Collects type-specific constraints that are present in only one of two domains.
     *
     * @details This function is a helper for the type-aware join operation (`operator|`).
     *
     * The Core Principle: In EbpfDomain, a "kind" variable (e.g., `r1.packet_offset`) is
     * only meaningful if the register might have the corresponding type (`T_PACKET`). If the
     * type is absent, the kind variable is conceptually Bottom.
     *
     * Role in Join: During a join, if one branch has constraints on `packet_offset`
     * (because the type is `T_PACKET`) and the other doesn't, a naive join would lose
     * those constraints. This function identifies such constraints so that the `operator|`
     * can preserve them, creating a more precise union of the two states.
     *
     * @param[in] right The other domain of the join.
     * @return A vector containing the variable, which domain it came from (`true` if left),
     * and its interval value, for each type-specific constraint to be preserved.
     */
    std::vector<std::tuple<Variable, Interval>> collect_type_dependent_constraints(const TypeToNumDomain& right) const;

    /**
     * @brief Applies a transition function for each possible type of a given register.
     *
     * @details This function is useful for operations that depend on the type of a register.
     * It evaluates the possible types of the register and applies the provided `transition`
     * function for each type, accumulating the results into a single abstract state.
     *
     * The `transition` function should modify a `TypeToNumDomain` instance based on the
     * specific type being processed. This allows for type-specific handling of operations,
     * such as loads or stores, where the behavior may vary significantly depending on
     * whether the register is a pointer to stack, packet, map, etc.
     *
     * @param[in] reg The register whose types are to be evaluated.
     * @param[in] transition A function that takes a `TypeToNumDomain` reference and a `TypeEncoding`.
     *                       It modifies the domain based on the provided type.
     * @return A new `TypeToNumDomain` representing the join of all transitions applied
     *         for each possible type of the register.
     */
    TypeToNumDomain join_over_types(const Reg& reg,
                                    const std::function<void(TypeToNumDomain&, TypeEncoding)>& transition) const;

    void havoc_all_locations_having_type(TypeEncoding type);

    void assume_type(const LinearConstraint& cst);

    void assign(const Reg& lhs, const Reg& rhs);

    TypeToNumDomain widen(const TypeToNumDomain& other) const;

    TypeToNumDomain narrow(const TypeToNumDomain& rcp) const;

    StringInvariant to_set() const;
    friend std::ostream& operator<<(std::ostream& o, const TypeToNumDomain& dom);
};
} // namespace prevail
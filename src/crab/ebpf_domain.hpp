// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <limits>
#include <optional>
#include <span>

#include "analysis_context.hpp"
#include "arith/variable.hpp"
#include "config.hpp"
#include "crab/array_domain.hpp"
#include "crab/type_to_num.hpp"
#include "string_constraints.hpp"

namespace prevail {

// Pointers in the BPF VM are defined to be 64 bits.  Some contexts, like
// data, data_end, and meta in Linux's struct xdp_md are only 32 bit offsets
// from a base address not exposed to the program, but when a program is loaded,
// the offsets get replaced with 64-bit address pointers.  However, we currently
// need to do pointer arithmetic on 64-bit numbers so for now we cap the interval
// to 32 bits.
inline int64_t ptr_max(const int max_packet_size) noexcept {
    return std::numeric_limits<int32_t>::max() - max_packet_size;
}

class EbpfDomain;

struct VerificationError final : std::runtime_error {
    std::optional<Label> where;
    explicit VerificationError(const std::string& what) : std::runtime_error(what) {}
};
std::string to_string(const VerificationError& error);

void ebpf_domain_transform(EbpfDomain& inv, const Instruction& ins, const AnalysisContext& context);
std::optional<VerificationError> ebpf_domain_check(const EbpfDomain& dom, const Assertion& assertion,
                                                   const Label& where, const AnalysisContext& context);
std::optional<VerificationError> ebpf_domain_check(const EbpfDomain& dom, const Assertion& assertion,
                                                   const Label& where);

// TODO: make this an explicit instruction
void ebpf_domain_initialize_loop_counter(EbpfDomain& dom, const Label& label, const AnalysisContext& context);

class EbpfDomain final {
    friend class EbpfChecker;
    friend class EbpfTransformer;

    friend std::ostream& operator<<(std::ostream& o, const EbpfDomain& dom);

  public:
    EbpfDomain();
    EbpfDomain(TypeToNumDomain state, ArrayDomain stack);

    // Generic abstract domain operations
    static EbpfDomain top(const AnalysisContext& context);
    // Size-only overload, convenient when callers have a stack size but no full context
    // (e.g. tests that exercise pure domain semantics).
    static EbpfDomain top(size_t total_stack_size);
    static EbpfDomain bottom();
    void set_to_bottom();
    [[nodiscard]]
    bool is_bottom() const;
    [[nodiscard]]
    bool is_top() const;
    bool operator<=(const EbpfDomain& other) const;
    bool operator<=(EbpfDomain&& other) const;
    void operator|=(EbpfDomain&& other);
    void operator|=(const EbpfDomain& other);
    EbpfDomain operator|(EbpfDomain&& other) const;
    EbpfDomain operator|(const EbpfDomain& other) const&;
    EbpfDomain operator|(const EbpfDomain& other) &&;
    EbpfDomain operator&(const EbpfDomain& other) const;
    EbpfDomain widen(const EbpfDomain& other, bool to_constants, const AnalysisContext& context,
                     std::span<const Variable> loop_counters) const;
    EbpfDomain narrow(const EbpfDomain& other) const;

    /// Per-register clamping domain used by widen(to_constants=true) to bound
    /// signed/unsigned values to int32 range, stack offsets to total_stack_size,
    /// and so on. Inexpensive to compute (~100 constraints); not cached.
    /// `loop_counters` is the set of counter Variables for *this* program's
    /// loop heads — passed in rather than queried from variable_registry,
    /// because the registry has no notion of "this analysis."
    static EbpfDomain calculate_constant_limits(const AnalysisContext& context,
                                                std::span<const Variable> loop_counters);
    /// Maximum upper bound across the given loop counter variables in this
    /// domain. The caller supplies the counter set (per-program loop heads),
    /// not the registry — see calculate_constant_limits for the rationale.
    ExtendedNumber get_loop_count_upper_bound(std::span<const Variable> loop_counters) const;
    Interval get_r0() const;

    static EbpfDomain setup_entry(bool init_r1, const AnalysisContext& context);
    static EbpfDomain from_constraints(const std::set<std::string>& constraints, bool setup_constraints,
                                       const AnalysisContext& context);
    /// Direct construction from typed constraints. The stack remains top at the
    /// requested size; pure-semantics callers (tests) can omit it for the
    /// default-options size.
    static EbpfDomain from_constraints(const std::vector<std::pair<Variable, TypeSet>>& type_restrictions,
                                       const std::vector<LinearConstraint>& value_constraints,
                                       size_t total_stack_size = ebpf_verifier_options_t{}.total_stack_size());
    void initialize_packet(const AnalysisContext& context);

    StringInvariant to_set() const;

    /// Check if a register may be a stack pointer and return its stack offset if known.
    /// Used by failure slicing to detect stack accesses through derived pointers.
    /// @return The concrete stack offset if the register is definitely a stack pointer with a known offset,
    ///         std::nullopt otherwise.
    [[nodiscard]]
    std::optional<int64_t> get_stack_offset(const Reg& reg) const;

    [[nodiscard]]
    std::optional<uint32_t> get_map_type(const Reg& map_fd_reg, const ebpf_platform_t& platform) const;
    [[nodiscard]]
    std::optional<uint32_t> get_map_inner_map_fd(const Reg& map_fd_reg, const ebpf_platform_t& platform) const;
    [[nodiscard]]
    Interval get_map_key_size(const Reg& map_fd_reg, const ebpf_platform_t& platform) const;
    [[nodiscard]]
    Interval get_map_value_size(const Reg& map_fd_reg, const ebpf_platform_t& platform) const;
    [[nodiscard]]
    Interval get_map_max_entries(const Reg& map_fd_reg, const ebpf_platform_t& platform) const;

    bool get_map_fd_range(const Reg& map_fd_reg, int32_t* start_fd, int32_t* end_fd) const;

  private:
    // Generic domain mutators. All maintain the
    // `state.is_bottom() <=> !stack` invariant via normalize_after_state_mutation.
    void add_value_constraint(const LinearConstraint& cst);
    void assume_eq_types(Variable v1, Variable v2);
    void restrict_type(Variable v, const TypeSet& ts);
    void havoc(Variable var);

    // Restore the bottom invariant after a `state` mutation that may have
    // driven it to bottom.
    void normalize_after_state_mutation();

    /// Type + numeric tracking
    TypeToNumDomain state;

    /// Represents the stack as a memory region, i.e., an array of bytes,
    /// allowing mapping to variable in the m_inv numeric domains
    /// while dealing with overlapping byte ranges.
    ///
    /// Wrapped in `std::optional` to add an explicit bottom: ArrayDomain /
    /// BitsetDomain have no meaningful bottom of their own (AddBottom from
    /// outside). Invariant: `state.is_bottom() <=> !stack.has_value()`.
    /// The bitset inside a materialized `ArrayDomain` must be sized to the
    /// run's `total_stack_size` — enforced implicitly by every non-bottom
    /// construction path going through a context-aware factory.
    std::optional<ArrayDomain> stack;
};

} // namespace prevail

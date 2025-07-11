// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.
#include <optional>

#include "arith/variable.hpp"
#include "crab/array_domain.hpp"
#include "crab/type_equality_domain.hpp"
#include "string_constraints.hpp"

namespace prevail {

// Pointers in the BPF VM are defined to be 64 bits.  Some contexts, like
// data, data_end, and meta in Linux's struct xdp_md are only 32 bit offsets
// from a base address not exposed to the program, but when a program is loaded,
// the offsets get replaced with 64-bit address pointers.  However, we currently
// need to do pointer arithmetic on 64-bit numbers so for now we cap the interval
// to 32 bits.
constexpr int MAX_PACKET_SIZE = 0xffff;
constexpr int64_t PTR_MAX = std::numeric_limits<int32_t>::max() - MAX_PACKET_SIZE;

class EbpfDomain;

void ebpf_domain_transform(EbpfDomain& inv, const Instruction& ins);
void ebpf_domain_assume(EbpfDomain& dom, const Assertion& assertion);
std::vector<std::string> ebpf_domain_check(const EbpfDomain& dom, const Assertion& assertion);

// TODO: make this an explicit instruction
void ebpf_domain_initialize_loop_counter(EbpfDomain& dom, const Label& label);

class EbpfDomain final {
    friend class EbpfChecker;
    friend class EbpfTransformer;

    friend std::ostream& operator<<(std::ostream& o, const EbpfDomain& dom);

  public:
    EbpfDomain();
    EbpfDomain(NumAbsDomain inv, ArrayDomain stack);

    // Generic abstract domain operations
    static EbpfDomain top();
    static EbpfDomain bottom();
    void set_to_top();
    void set_to_bottom();
    [[nodiscard]]
    bool is_bottom() const;
    [[nodiscard]]
    bool is_top() const;
    bool operator<=(const EbpfDomain& other) const;
    bool operator==(const EbpfDomain& other) const;
    void add_extra_invariant(const NumAbsDomain& dst, std::map<Variable, Interval>& extra_invariants,
                             Variable type_variable, TypeEncoding type, DataKind kind, const NumAbsDomain& src);
    void selectively_join_based_on_type(NumAbsDomain& dst, NumAbsDomain&& src);
    void operator|=(EbpfDomain&& other);
    void operator|=(const EbpfDomain& other);
    EbpfDomain operator|(EbpfDomain&& other) const;
    EbpfDomain operator|(const EbpfDomain& other) const&;
    EbpfDomain operator|(const EbpfDomain& other) &&;
    EbpfDomain operator&(const EbpfDomain& other) const;
    EbpfDomain widen(const EbpfDomain& other, bool to_constants) const;
    EbpfDomain narrow(const EbpfDomain& other) const;

    static EbpfDomain calculate_constant_limits();
    ExtendedNumber get_loop_count_upper_bound() const;
    Interval get_r0() const;

    static EbpfDomain setup_entry(bool init_r1);
    static EbpfDomain from_constraints(const std::set<std::string>& constraints, bool setup_constraints);
    void initialize_packet();

    StringInvariant to_set() const;

  private:
    // private generic domain functions
    void add_constraint(const LinearConstraint& cst);
    void havoc(Variable var);

    [[nodiscard]]
    std::optional<uint32_t> get_map_type(const Reg& map_fd_reg) const;
    [[nodiscard]]
    std::optional<uint32_t> get_map_inner_map_fd(const Reg& map_fd_reg) const;
    [[nodiscard]]
    Interval get_map_key_size(const Reg& map_fd_reg) const;
    [[nodiscard]]
    Interval get_map_value_size(const Reg& map_fd_reg) const;
    [[nodiscard]]
    Interval get_map_max_entries(const Reg& map_fd_reg) const;

    static std::optional<Variable> get_type_offset_variable(const Reg& reg, int type);
    [[nodiscard]]
    std::optional<Variable> get_type_offset_variable(const Reg& reg, const NumAbsDomain& inv) const;
    [[nodiscard]]
    std::optional<Variable> get_type_offset_variable(const Reg& reg) const;

    bool get_map_fd_range(const Reg& map_fd_reg, int32_t* start_fd, int32_t* end_fd) const;

    /// Mapping from variables (including registers, types, offsets,
    /// memory locations, etc.) to numeric intervals or relationships
    /// to other variables.
    NumAbsDomain m_inv;

    /// Represents the stack as a memory region, i.e., an array of bytes,
    /// allowing mapping to variable in the m_inv numeric domains
    /// while dealing with overlapping byte ranges.
    ArrayDomain stack;

    EqualityTypeDomain type_inv;
};

} // namespace prevail

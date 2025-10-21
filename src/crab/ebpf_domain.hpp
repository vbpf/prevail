// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <optional>

#include "arith/variable.hpp"
#include "crab/array_domain.hpp"
#include "crab/rcp.hpp"
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

struct VerificationError final : std::runtime_error {
    explicit VerificationError(const std::string& what) : std::runtime_error(what) {}
};

void ebpf_domain_transform(EbpfDomain& inv, const Instruction& ins);
std::optional<VerificationError> ebpf_domain_check(const EbpfDomain& dom, const Assertion& assertion);

// TODO: make this an explicit instruction
void ebpf_domain_initialize_loop_counter(EbpfDomain& dom, const Label& label);

class EbpfDomain final {
    friend class EbpfChecker;
    friend class EbpfTransformer;

    friend std::ostream& operator<<(std::ostream& o, const EbpfDomain& dom);

  public:
    EbpfDomain();
    EbpfDomain(TypeToNumDomain rcp, ArrayDomain stack);

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
    static EbpfDomain from_constraints(const std::vector<LinearConstraint>& type_constraints,
                                       const std::vector<LinearConstraint>& value_constraints);
    friend void require_join(const std::vector<LinearConstraint>& a_csts, const std::vector<LinearConstraint>& b_csts,
                             const std::vector<LinearConstraint>& over_csts);
    void initialize_packet();

    StringInvariant to_set() const;

  private:
    // private generic domain functions
    void add_value_constraint(const LinearConstraint& cst);
    void add_type_constraint(const LinearConstraint& cst);
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

    bool get_map_fd_range(const Reg& map_fd_reg, int32_t* start_fd, int32_t* end_fd) const;

    TypeToNumDomain rcp;

    /// Represents the stack as a memory region, i.e., an array of bytes,
    /// allowing mapping to variable in the m_inv numeric domains
    /// while dealing with overlapping byte ranges.
    ArrayDomain stack;
};

} // namespace prevail

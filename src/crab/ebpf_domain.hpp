// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.
#include <optional>

#include "crab/array_domain.hpp"
#include "crab/split_dbm.hpp"
#include "crab/type_domain.hpp"
#include "crab/variable.hpp"
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

class ebpf_domain_t;

void ebpf_domain_transform(ebpf_domain_t& inv, const Instruction& ins);
void ebpf_domain_assume(ebpf_domain_t& dom, const Assertion& assertion);
std::vector<std::string> ebpf_domain_check(const ebpf_domain_t& dom, const Assertion& assertion);

// TODO: make this an explicit instruction
void ebpf_domain_initialize_loop_counter(ebpf_domain_t& dom, const label_t& label);

class ebpf_domain_t final {
    friend class ebpf_checker;
    friend class ebpf_transformer;

    friend std::ostream& operator<<(std::ostream& o, const ebpf_domain_t& dom);

  public:
    ebpf_domain_t();
    ebpf_domain_t(NumAbsDomain inv, array_domain_t stack);

    // Generic abstract domain operations
    static ebpf_domain_t top();
    static ebpf_domain_t bottom();
    void set_to_top();
    void set_to_bottom();
    [[nodiscard]]
    bool is_bottom() const;
    [[nodiscard]]
    bool is_top() const;
    bool operator<=(const ebpf_domain_t& other) const;
    bool operator==(const ebpf_domain_t& other) const;
    void operator|=(ebpf_domain_t&& other);
    void operator|=(const ebpf_domain_t& other);
    ebpf_domain_t operator|(ebpf_domain_t&& other) const;
    ebpf_domain_t operator|(const ebpf_domain_t& other) const&;
    ebpf_domain_t operator|(const ebpf_domain_t& other) &&;
    ebpf_domain_t operator&(const ebpf_domain_t& other) const;
    ebpf_domain_t widen(const ebpf_domain_t& other, bool to_constants) const;
    ebpf_domain_t widening_thresholds(const ebpf_domain_t& other, const thresholds_t& ts);
    ebpf_domain_t narrow(const ebpf_domain_t& other) const;

    static ebpf_domain_t calculate_constant_limits();
    extended_number get_loop_count_upper_bound() const;
    interval_t get_r0() const;

    static ebpf_domain_t setup_entry(bool init_r1);
    static ebpf_domain_t from_constraints(const std::set<std::string>& constraints, bool setup_constraints);
    void initialize_packet();

    string_invariant to_set() const;

  private:
    // private generic domain functions
    void add_constraint(const linear_constraint_t& cst);
    void havoc(variable_t var);

    [[nodiscard]]
    std::optional<uint32_t> get_map_type(const Reg& map_fd_reg) const;
    [[nodiscard]]
    std::optional<uint32_t> get_map_inner_map_fd(const Reg& map_fd_reg) const;
    [[nodiscard]]
    interval_t get_map_key_size(const Reg& map_fd_reg) const;
    [[nodiscard]]
    interval_t get_map_value_size(const Reg& map_fd_reg) const;
    [[nodiscard]]
    interval_t get_map_max_entries(const Reg& map_fd_reg) const;

    static std::optional<variable_t> get_type_offset_variable(const Reg& reg, int type);
    [[nodiscard]]
    std::optional<variable_t> get_type_offset_variable(const Reg& reg, const NumAbsDomain& inv) const;
    [[nodiscard]]
    std::optional<variable_t> get_type_offset_variable(const Reg& reg) const;

    bool get_map_fd_range(const Reg& map_fd_reg, int32_t* start_fd, int32_t* end_fd) const;

    /// Mapping from variables (including registers, types, offsets,
    /// memory locations, etc.) to numeric intervals or relationships
    /// to other variables.
    NumAbsDomain m_inv;

    /// Represents the stack as a memory region, i.e., an array of bytes,
    /// allowing mapping to variable in the m_inv numeric domains
    /// while dealing with overlapping byte ranges.
    array_domain_t stack;

    TypeDomain type_inv;
};

} // namespace prevail

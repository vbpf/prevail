// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/fwd_analyzer.hpp"
#include "program.hpp"
#include "spec_type_descriptors.hpp"
#include "string_constraints.hpp"

class Report final {
    std::map<label_t, std::vector<std::string>> warnings;
    std::map<label_t, std::vector<std::string>> reachability;
    friend class Invariants;

  public:
    friend void print_reachability(std::ostream& os, const Report& report);
    friend void print_warnings(std::ostream& os, const Report& report);
    friend void print_all_messages(std::ostream& os, const Report& report);

    std::set<std::string> all_messages() const {
        std::set<std::string> result = warning_set();
        for (const auto& note : reachability_set()) {
            result.insert(note);
        }
        return result;
    }

    std::set<std::string> reachability_set() const {
        std::set<std::string> result;
        for (const auto& [label, reach_warning] : reachability) {
            for (const auto& msg : reach_warning) {
                result.insert(to_string(label) + ": " + msg);
            }
        }
        return result;
    }

    std::set<std::string> warning_set() const {
        std::set<std::string> result;
        for (const auto& [label, warning_vec] : warnings) {
            for (const auto& msg : warning_vec) {
                result.insert(to_string(label) + ": " + msg);
            }
        }
        return result;
    }

    bool verified() const { return warnings.empty(); }
};

class Invariants final {
    prevail::invariant_table_t invariants;

  public:
    explicit Invariants(prevail::invariant_table_t&& invariants) : invariants(std::move(invariants)) {}
    Invariants(Invariants&& invariants) = default;
    Invariants(const Invariants& invariants) = default;

    bool is_valid_after(const label_t& label, const string_invariant& state) const;

    string_invariant invariant_at(const label_t& label) const;

    prevail::interval_t exit_value() const;

    int max_loop_count() const;
    bool verified(const Program& prog) const;
    Report check_assertions(const Program& prog) const;

    friend void print_invariants(std::ostream& os, const Program& prog, bool simplify, const Invariants& invariants);
};

Invariants analyze(const Program& prog);
Invariants analyze(const Program& prog, const string_invariant& entry_invariant);
inline bool verify(const Program& prog) { return analyze(prog).verified(prog); }

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
                    ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);

void ebpf_verifier_clear_thread_local_state();

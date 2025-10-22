// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/fwd_analyzer.hpp"
#include "ir/program.hpp"
#include "spec/type_descriptors.hpp"
#include "string_constraints.hpp"

namespace prevail {
class Report final {
    std::map<Label, std::vector<std::string>> errors;
    std::map<Label, std::vector<std::string>> reachability;
    friend class Invariants;

  public:
    friend void print_reachability(std::ostream& os, const Report& report);
    friend void print_errors(std::ostream& os, const Report& report);
    friend void print_all_messages(std::ostream& os, const Report& report);

    [[nodiscard]]
    std::set<std::string> all_messages() const {
        std::set<std::string> result = error_set();
        for (const auto& note : reachability_set()) {
            result.insert(note);
        }
        return result;
    }

    [[nodiscard]]
    std::set<std::string> reachability_set() const {
        std::set<std::string> result;
        for (const auto& [label, notes] : reachability) {
            for (const auto& msg : notes) {
                result.insert(to_string(label) + ": " + msg);
            }
        }
        return result;
    }

    [[nodiscard]]
    std::set<std::string> error_set() const {
        std::set<std::string> result;
        for (const auto& [label, error_vec] : errors) {
            for (const auto& msg : error_vec) {
                result.insert(to_string(label) + ": " + msg);
            }
        }
        return result;
    }

    [[nodiscard]]
    bool verified() const {
        return errors.empty();
    }
};

class Invariants final {
    InvariantTable invariants;

  public:
    explicit Invariants(InvariantTable&& invariants) : invariants(std::move(invariants)) {}
    Invariants(Invariants&& invariants) = default;
    Invariants(const Invariants& invariants) = default;

    bool is_valid_after(const Label& label, const StringInvariant& state) const;

    StringInvariant invariant_at(const Label& label) const;

    Interval exit_value() const;

    int max_loop_count() const;
    bool verified(const Program& prog) const;
    Report check_assertions(const Program& prog) const;

    friend void print_invariants(std::ostream& os, const Program& prog, bool simplify, const Invariants& invariants);
};

Invariants analyze(const Program& prog);
Invariants analyze(const Program& prog, const StringInvariant& entry_invariant);
inline bool verify(const Program& prog) { return analyze(prog).verified(prog); }

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
                    ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);

void ebpf_verifier_clear_thread_local_state();

struct ThreadLocalGuard {
    ThreadLocalGuard() = default;
    ~ThreadLocalGuard() { ebpf_verifier_clear_thread_local_state(); }
};

} // namespace prevail

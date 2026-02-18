// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// Bidirectional map between Variables and integer element IDs.
// Same pattern as ZoneDomain's VertMap/RevMap (Variable <-> VertId).

#include <map>
#include <optional>
#include <vector>

#include "arith/variable.hpp"

namespace prevail {

/// Bidirectional map between Variables and DSU element IDs.
///
/// Maintains a partial bijection: every live Variable maps to exactly one ID
/// and vice versa. Orphaned IDs (from detach) have no Variable but still
/// occupy a slot in id_to_var.
class VarIdMap {
    std::map<Variable, size_t> var_to_id_;
    std::vector<std::optional<Variable>> id_to_var_;

  public:
    VarIdMap() = default;

    /// Look up the DSU element ID for a variable, or nullopt if absent.
    [[nodiscard]]
    std::optional<size_t> find_id(const Variable v) const {
        if (const auto it = var_to_id_.find(v); it != var_to_id_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /// Look up the variable for a DSU element ID, or nullopt if orphaned.
    [[nodiscard]]
    std::optional<Variable> find_var(const size_t id) const {
        if (id < id_to_var_.size()) {
            return id_to_var_[id];
        }
        return std::nullopt;
    }

    /// Whether a variable is present.
    [[nodiscard]]
    bool contains(const Variable v) const {
        return var_to_id_.contains(v);
    }

    /// Insert or overwrite a bidirectional mapping. Grows id_to_var if needed.
    void insert(Variable v, const size_t id) {
        var_to_id_[v] = id;
        while (id_to_var_.size() <= id) {
            id_to_var_.push_back(std::nullopt);
        }
        id_to_var_[id] = v;
    }

    /// Orphan an ID: remove its variable mapping (if any), but keep the slot.
    void orphan(const size_t id) {
        if (id < id_to_var_.size()) {
            if (const auto& var = id_to_var_[id]) {
                var_to_id_.erase(*var);
            }
            id_to_var_[id] = std::nullopt;
        }
    }

    /// Orphan the old ID for a variable (if any) without removing the variable
    /// from var_to_id. Used by detach, which immediately re-inserts.
    void orphan_var(const Variable v) {
        if (const auto it = var_to_id_.find(v); it != var_to_id_.end()) {
            id_to_var_[it->second] = std::nullopt;
        }
    }

    /// Number of ID slots (including orphaned).
    [[nodiscard]]
    size_t id_capacity() const {
        return id_to_var_.size();
    }

    /// Iterate over all live (Variable, ID) pairs.
    [[nodiscard]]
    const std::map<Variable, size_t>& vars() const {
        return var_to_id_;
    }
};

} // namespace prevail

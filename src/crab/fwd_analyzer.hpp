// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <map>

#include "crab/ebpf_domain.hpp"
#include "ir/program.hpp"

namespace prevail {

struct InvariantMapPair {
    EbpfDomain pre;
    std::optional<VerificationError> error;
    EbpfDomain post;
};
using InvariantTable = std::map<Label, InvariantMapPair>;

InvariantTable run_forward_analyzer(const Program& prog, EbpfDomain entry_inv);

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <map>

#include "crab/ebpf_domain.hpp"
#include "program.hpp"

namespace prevail {

struct invariant_map_pair {
    ebpf_domain_t pre;
    ebpf_domain_t post;
};
using invariant_table_t = std::map<label_t, invariant_map_pair>;

invariant_table_t run_forward_analyzer(const Program& prog, ebpf_domain_t entry_inv);

} // namespace prevail

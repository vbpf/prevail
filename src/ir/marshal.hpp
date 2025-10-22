// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <vector>

#include "ebpf_vm_isa.hpp"
#include "ir/syntax.hpp"

namespace prevail {

std::vector<EbpfInst> marshal(const Instruction& ins, Pc pc);
// TODO marshal to ostream?

} // namespace prevail

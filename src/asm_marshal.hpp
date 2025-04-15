// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <vector>

#include "asm_syntax.hpp"
#include "ebpf_vm_isa.hpp"

namespace prevail {

std::vector<ebpf_inst> marshal(const Instruction& ins, pc_t pc);
// TODO marshal to ostream?

} // namespace prevail

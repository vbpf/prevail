// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <vector>

#include "ir/syntax.hpp"
#include "spec/vm_isa.hpp"

namespace prevail {

std::vector<EbpfInst> marshal(const Instruction& ins, Pc pc);
// TODO marshal to ostream?

} // namespace prevail

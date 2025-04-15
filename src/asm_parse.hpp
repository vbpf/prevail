// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <string>

#include "asm_syntax.hpp"

namespace prevail {

Instruction parse_instruction(const std::string& line, const std::map<std::string, label_t>& label_name_to_label);

}
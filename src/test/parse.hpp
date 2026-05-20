// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <set>
#include <string>
#include <vector>

#include "crab/interval.hpp"
#include "ir/syntax.hpp"
#include "spec/type_descriptors.hpp"
#include "string_constraints.hpp"

namespace prevail {

Instruction parse_instruction(const std::string& line, const std::map<std::string, Label>& label_name_to_label,
                              const EbpfProgramType& program_type);

TypeValueConstraints parse_linear_constraints(const std::set<std::string>& constraints,
                                              std::vector<Interval>& numeric_ranges);

} // namespace prevail

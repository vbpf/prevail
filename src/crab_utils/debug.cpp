// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "crab_utils/debug.hpp"

namespace prevail {
bool CrabLogFlag = false;
std::set<std::string> CrabLog;

unsigned CrabVerbosity = 0;

bool CrabWarningFlag = false;
void CrabEnableWarningMsg(const bool b) { CrabWarningFlag = b; }

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <stdlib.h>
#include <windows.h>

#include <Psapi.h>

namespace prevail {

inline long resident_set_size_kb() {
    PROCESS_MEMORY_COUNTERS info;
    BOOL ok = GetProcessMemoryInfo(GetCurrentProcess(), &info, sizeof(info));
    return (long)((ok) ? (info.WorkingSetSize / 1024) : 0);
}
} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

/* Logging and debug messages */
#include <cstdlib>
#include <iostream>
#include <sstream>

#include <iosfwd>
#include <set>
#include <stdarg.h>
#include <string>

namespace prevail {

#define CRAB_LOG(TAG, CODE)                          \
    do {                                             \
        if (CrabLogFlag && CrabLog.count(TAG) > 0) { \
            CODE;                                    \
        }                                            \
    } while (0)
extern bool CrabLogFlag;
extern std::set<std::string> CrabLog;

extern unsigned CrabVerbosity;
#define CRAB_VERBOSE_IF(LEVEL, CODE)  \
    do {                              \
        if (CrabVerbosity >= LEVEL) { \
            CODE;                     \
        }                             \
    } while (0)

template <typename... ArgTypes>
void ___print___(std::ostream& os, ArgTypes... args) {
    // trick to expand variadic argument pack without recursion
    using ExpandVariadicPack = int[];
    // first zero is to prevent empty braced-init-list
    // void() is to prevent Overloaded operator, messing things up
    // trick is to use the side effect of list-initializer to call a function
    // on every argument.
    // (void) is to suppress "statement has no effect" warnings
    (void)ExpandVariadicPack{0, ((os << args), void(), 0)...};
}

#define CRAB_ERROR(...)                                                \
    do {                                                               \
        std::ostringstream os;                                         \
        os << "CRAB ERROR: ";                                          \
        ___print___(os, __VA_ARGS__);                                  \
        ___print___(os, "; function ", __func__, ", line ", __LINE__); \
        os << "\n";                                                    \
        throw std::runtime_error(os.str());                            \
    } while (0)

extern bool CrabWarningFlag;
void CrabEnableWarningMsg(bool b);

#define CRAB_WARN(...)                           \
    do {                                         \
        if (CrabWarningFlag) {                   \
            std::cerr << "CRAB WARNING: ";       \
            ___print___(std::cerr, __VA_ARGS__); \
            std::cerr << "\n";                   \
        }                                        \
    } while (0)

constexpr bool CrabSanityCheckFlag = false;

} // end namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
//
// On MSVC Debug builds, CRT assertions (e.g. from STL iterator checks) show
// a dialog box and wait for user input.  In CI (headless), this hangs forever.
// This Catch2 listener routes CRT assertions to stderr and aborts, so CI gets
// a clear error message and a non-zero exit code.

#if defined(_MSC_VER) && defined(_DEBUG)

#include <catch2/catch_all.hpp>

#include <crtdbg.h>
#include <cstdio>
#include <cstdlib>

namespace {

int abort_on_crt_assert(int report_type, char* message, int* /* return_value */) {
    if (report_type == _CRT_ASSERT || report_type == _CRT_ERROR) {
        if (message) {
            std::fputs(message, stderr);
        }
        std::fflush(stderr);
        // Suppress the abort() dialog as well.
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
        std::abort();
    }
    return 0; // Let other hooks run for _CRT_WARN.
}

struct MsvcDebugListener : Catch::EventListenerBase {
    using EventListenerBase::EventListenerBase;

    void testRunStarting(Catch::TestRunInfo const&) override {
        _CrtSetReportHook2(_CRT_RPTHOOK_INSTALL, abort_on_crt_assert);
    }
};

} // namespace

CATCH_REGISTER_LISTENER(MsvcDebugListener)

#endif // _MSC_VER && _DEBUG

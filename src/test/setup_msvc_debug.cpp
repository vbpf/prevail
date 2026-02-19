// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
//
// On MSVC Debug builds, CRT assertions (e.g. from STL iterator checks) show
// a dialog box and wait for user input.  In CI (headless), this hangs forever.
// This Catch2 listener routes CRT assertions to stderr and aborts, so CI gets
// a clear error message, a stack trace, and a non-zero exit code.

#if defined(_MSC_VER) && defined(_DEBUG)

#include <catch2/catch_all.hpp>

#include <crtdbg.h>
#include <cstdio>
#include <cstdlib>

// clang-format off
#include <windows.h>
#include <dbghelp.h>
// clang-format on
#pragma comment(lib, "dbghelp.lib")

namespace {

void print_stack_trace() {
    constexpr int max_frames = 64;
    void* frames[max_frames];
    const HANDLE process = GetCurrentProcess();

    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
    SymInitialize(process, nullptr, TRUE);

    const WORD frame_count = CaptureStackBackTrace(2, // Skip this function and the hook itself.
                                                   max_frames, frames, nullptr);

    // SYMBOL_INFO needs trailing space for the name string.
    alignas(SYMBOL_INFO) char symbol_buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)]{};
    auto* symbol = reinterpret_cast<SYMBOL_INFO*>(symbol_buf);
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;

    IMAGEHLP_LINE64 line{};
    line.SizeOfStruct = sizeof(line);

    std::fputs("\n  Stack trace:\n", stderr);
    for (WORD i = 0; i < frame_count; ++i) {
        const auto address = reinterpret_cast<DWORD64>(frames[i]);
        DWORD displacement = 0;

        if (SymFromAddr(process, address, nullptr, symbol)) {
            if (SymGetLineFromAddr64(process, address, &displacement, &line)) {
                std::fprintf(stderr, "    %s  %s:%lu\n", symbol->Name, line.FileName, line.LineNumber);
            } else {
                std::fprintf(stderr, "    %s\n", symbol->Name);
            }
        } else {
            std::fprintf(stderr, "    0x%llx\n", static_cast<unsigned long long>(address));
        }
    }

    SymCleanup(process);
}

int abort_on_crt_assert(int report_type, char* message, int* /* return_value */) {
    if (report_type == _CRT_ASSERT || report_type == _CRT_ERROR) {
        std::fputs("\n=== CRT Debug Assertion Failed ===\n", stderr);
        if (message) {
            std::fputs(message, stderr);
        }
        print_stack_trace();
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

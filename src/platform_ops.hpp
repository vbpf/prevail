// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

/// @file Platform abstraction for the analysis engine.
/// Implementations provide platform-specific ELF validation, program enumeration,
/// TLS management, and verifier options. This allows the analysis engine to work
/// with different eBPF platforms (Linux, Windows) without compile-time dependencies.

// Undef Windows macros that conflict with PREVAIL headers (std::numeric_limits::min/max).
#undef FALSE
#undef TRUE
#undef min
#undef max

// Pre-define the include guard for bpf_conformance's ebpf_inst.h to prevent it
// from being included (its EbpfInst struct conflicts with prevail::EbpfInst).
#ifndef BPF_CONFORMANCE_CORE_EBPF_INST_H
#define BPF_CONFORMANCE_CORE_EBPF_INST_H
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4100) // Unreferenced formal parameter.
#pragma warning(disable : 4244) // Conversion, possible loss of data.
#pragma warning(disable : 4267) // Conversion from 'size_t' to 'int'.
#pragma warning(disable : 4458) // Declaration hides class member.
#pragma warning(disable : 26439) // Function may not throw.
#pragma warning(disable : 26450) // Arithmetic overflow.
#pragma warning(disable : 26451) // Arithmetic overflow.
#pragma warning(disable : 26495) // Always initialize a member variable.
#endif

#include "ebpf_verifier.hpp"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#ifdef _WIN32
#define FALSE 0
#define TRUE 1
#endif

#include <stdexcept>
#include <string>
#include <vector>

namespace prevail {

/// Entry in the program list returned by PlatformOps::list_programs().
struct ProgramEntry
{
    std::string section;
    std::string function;
};

/// Abstract interface for platform-specific operations.
/// The analysis engine calls through this interface instead of directly using
/// platform-specific APIs.
struct PlatformOps
{
    virtual ~PlatformOps() = default;

    /// Get the PREVAIL platform pointer for read_elf/unmarshal/analyze.
    [[nodiscard]] virtual const prevail::ebpf_platform_t*
    platform() const = 0;

    /// List all programs (sections + function names) in an ELF file.
    [[nodiscard]] virtual std::vector<ProgramEntry>
    list_programs(const std::string& elf_path) = 0;

    /// Validate ELF data before analysis.
    /// @return true if valid (or if no validation is available).
    virtual bool
    validate_elf(const std::string& /*data*/)
    {
        return true;
    }

    /// Prepare thread-local state before analysis.
    /// Clears any cached TLS data and optionally sets a program type override.
    virtual void
    prepare_tls(const std::string& type_override) = 0;

    /// Get default verifier options for this platform.
    [[nodiscard]] virtual prevail::ebpf_verifier_options_t
    default_options() = 0;

    /// Attempt fallback verification to produce a clean error message
    /// when direct PREVAIL analysis fails (e.g. due to access violation on Windows).
    /// @return Error message string, or empty string if no fallback is available.
    virtual std::string
    fallback_verify(
        const std::string& /*data*/,
        const std::string& /*section*/,
        const std::string& /*program*/,
        const std::string& /*type*/)
    {
        return "";
    }
};

} // namespace prevail

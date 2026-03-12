// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

/// @file Platform abstraction for the MCP server analysis engine.
/// Implementations provide platform-specific ELF validation, program enumeration,
/// TLS management, and verifier options. This allows the core MCP server to work
/// with different eBPF platforms (Linux, Windows) without compile-time dependencies.

#include "prevail_headers.hpp"

#include <stdexcept>
#include <string>
#include <vector>

namespace prevail_mcp {

/// Entry in the program list returned by PlatformOps::list_programs().
struct ProgramEntry
{
    std::string section;
    std::string function;
};

/// Abstract interface for platform-specific operations.
/// The analysis engine calls through this interface instead of directly using
/// ebpf-for-windows or PREVAIL platform-specific APIs.
struct PlatformOps
{
    virtual ~PlatformOps() = default;

    /// Get the PREVAIL platform pointer for read_elf/unmarshal/analyze.
    virtual const prevail::ebpf_platform_t*
    platform() const = 0;

    /// List all programs (sections + function names) in an ELF file.
    virtual std::vector<ProgramEntry>
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
    virtual prevail::ebpf_verifier_options_t
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

} // namespace prevail_mcp

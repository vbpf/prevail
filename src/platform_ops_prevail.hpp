// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

/// @file Linux/portable PlatformOps implementation using only PREVAIL APIs.

#include "platform_ops.hpp"

namespace prevail {

/// PlatformOps implementation using only PREVAIL's public API.
/// Works on Linux and Windows (when linking the PREVAIL library directly
/// without ebpf-for-windows).
class PrevailPlatformOps : public PlatformOps
{
  public:
    explicit PrevailPlatformOps(const prevail::ebpf_platform_t* platform) : platform_(platform) {}

    [[nodiscard]] const prevail::ebpf_platform_t*
    platform() const override
    {
        return platform_;
    }

    [[nodiscard]] std::vector<ProgramEntry>
    list_programs(const std::string& elf_path) override
    {
        prevail::ElfObject elf(elf_path, default_options(), platform_);
        std::vector<ProgramEntry> result;
        for (const auto& info : elf.list_programs()) {
            if (prevail::ElfObject::is_valid(info)) {
                result.push_back({info.section_name, info.function_name});
            }
        }
        return result;
    }

    void
    prepare_tls(const std::string& /*type_override*/) override
    {
        // PREVAIL's ThreadLocalGuard handles cleanup on scope exit.
        // The Linux platform resolves program types from section names
        // via the platform's get_program_type() callback, so no
        // global type override is needed.
        prevail::ebpf_verifier_clear_thread_local_state();
    }

    [[nodiscard]] prevail::ebpf_verifier_options_t
    default_options() override
    {
        prevail::ebpf_verifier_options_t opts{};
        // Match prevail defaults (termination not checked by default).
        opts.mock_map_fds = true;
        opts.setup_constraints = true;
        opts.allow_division_by_zero = true;
        opts.verbosity_opts.print_line_info = true;
        return opts;
    }

    // validate_elf: default (always true) — PREVAIL's read_elf handles
    // malformed ELFs via exceptions.

    // fallback_verify: default (empty) — no SEH recovery needed on Linux.

  private:
    const prevail::ebpf_platform_t* platform_;
};

} // namespace prevail

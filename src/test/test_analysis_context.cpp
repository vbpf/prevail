// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>

#include "crab/ebpf_domain.hpp"
#include "platform.hpp"
#include "verifier.hpp"

using namespace prevail;

TEST_CASE("explicit AnalysisContext options drive checker behavior", "[analysis_context]") {
    ThreadLocalGuard guard;
    variable_registry.clear();
    thread_local_options = {};
    thread_local_options.allow_division_by_zero = false;

    ProgramInfo info{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec"),
    };
    ebpf_verifier_options_t options = thread_local_options;
    options.allow_division_by_zero = true;
    AnalysisContext context{
        .program_info = info,
        .options = options,
        .platform = *info.platform,
    };

    const EbpfDomain dom =
        EbpfDomain::from_constraints({"r1.type=number", "r1.svalue=0", "r1.uvalue=0"}, false, context);

    REQUIRE_FALSE(ebpf_domain_check(dom, Assertion{ValidDivisor{Reg{1}, false}}, Label{0}, context).has_value());
}

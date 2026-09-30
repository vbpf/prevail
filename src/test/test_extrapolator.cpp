// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>

#include "arith/dsl_syntax.hpp"
#include "crab/extrapolator.hpp"
#include "ir/program.hpp"
#include "platform.hpp"

using namespace prevail;

namespace {

ProgramInfo default_info() {
    return ProgramInfo{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec"),
    };
}

LabeledInstruction at(const int index, Instruction instruction) {
    return {Label{index}, std::move(instruction), std::nullopt};
}

EbpfDomain make_domain(const TypeSet& types, const int upper_bound) {
    using namespace dsl_syntax;

    const RegPack r0 = reg_pack(0);
    return EbpfDomain::from_constraints({{reg_type(Reg{0}), types}}, {r0.svalue >= 0, r0.svalue <= upper_bound});
}

} // namespace

TEST_CASE("Extrapolator stops at a lattice-equivalent narrowing result", "[extrapolator][fixpoint]") {
    VerifierOptions options{};
    InstructionSeq sequence{at(0, Exit{})};
    AnalysisContext context{Program::from_sequence(sequence, default_info(), options), options};
    Extrapolator extrapolator{context, {}};

    const EbpfDomain initial = make_domain(TypeSet{T_NUM, T_STACK}, 10);
    const EbpfDomain ascending_result = make_domain(TypeSet{T_NUM, T_STACK}, 8);
    const EbpfDomain after_meet = make_domain(TypeSet{T_NUM, T_STACK}, 5);
    const EbpfDomain type_refinement = make_domain(TypeSet{T_NUM}, 4);
    const EbpfDomain stationary_numeric_refinement = make_domain(TypeSet{T_NUM}, 3);
    const EbpfDomain expected = make_domain(TypeSet{T_NUM}, 5);

    const auto equivalent = [](const EbpfDomain& left, const EbpfDomain& right) {
        return left <= right && right <= left;
    };

    size_t step_count = 0;
    const auto step = [&](const EbpfDomain& invariant) {
        ++step_count;
        if (step_count > 4) {
            FAIL("Equivalent narrowing must not repeat until the iteration limit");
        }

        if (equivalent(invariant, initial)) {
            // Complete the ascending phase with a strict transfer refinement.
            return ascending_result;
        }
        if (equivalent(invariant, ascending_result)) {
            // The first descending iteration uses meet.
            return after_meet;
        }
        if (equivalent(invariant, after_meet)) {
            // Type narrowing makes strict progress and must not stop iteration.
            return type_refinement;
        }
        if (equivalent(invariant, expected)) {
            // Numeric narrowing is a no-op for this finite ZoneDomain.
            return stationary_numeric_refinement;
        }

        FAIL("Unexpected invariant passed to the transfer function");
        return stationary_numeric_refinement;
    };

    const EbpfDomain result = extrapolator.compute_fixpoint(initial, step);

    REQUIRE(step_count == 4);
    REQUIRE(result <= expected);
    REQUIRE(expected <= result);
}

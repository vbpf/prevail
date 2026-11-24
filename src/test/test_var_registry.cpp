// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>

#include <chrono>
#include <string>
#include <vector>

#include "crab/var_registry.hpp"

using namespace prevail;

TEST_CASE("VariableRegistry gives each name one variable", "[var_registry]") {
    const VariableRegistry registry;

    // Names the registry starts with, and names it has not seen before.
    const Variable r0_svalue = registry.reg(DataKind::svalues, 0);
    const Variable r0_type = registry.type_reg(0);
    const Variable cell_type = registry.cell_var(DataKind::types, 4095, 1);
    const Variable saved_r6_type = registry.stack_frame_var(DataKind::types, 6, "7");

    REQUIRE(registry.name(r0_svalue) == "r0.svalue");
    REQUIRE(registry.name(r0_type) == "r0.type");
    REQUIRE(registry.name(cell_type) == "s[4095].type");
    REQUIRE(registry.name(saved_r6_type) == "7/r6.type");
    REQUIRE(registry.name(registry.packet_size()) == "packet_size");

    REQUIRE(r0_svalue != r0_type);
    REQUIRE(cell_type != saved_r6_type);

    // Asking again, by the same route or by another one, gives the same variable.
    REQUIRE(registry.reg(DataKind::svalues, 0) == r0_svalue);
    REQUIRE(registry.kind_var(DataKind::svalues, r0_type) == r0_svalue);
    REQUIRE(registry.cell_var(DataKind::types, 4095, 1) == cell_type);
    REQUIRE(registry.stack_frame_var(DataKind::types, 6, "7") == saved_r6_type);

    const Variable cell_packet_offset = registry.kind_var(DataKind::packet_offsets, cell_type);
    REQUIRE(registry.name(cell_packet_offset) == "s[4095].packet_offset");
    REQUIRE(registry.kind_var(DataKind::packet_offsets, cell_type) == cell_packet_offset);
    REQUIRE(registry.cell_var(DataKind::packet_offsets, 4095, 1) == cell_packet_offset);
}

// Regression test: a name was looked up by comparing it with every name created before it, and
// names are never removed. The analysed program decides how many there are (every inlined call
// leaves a set for the saved registers, every stack cell has its own), and the fixpoint asks for
// the kind variables of every stack cell at each loop head, so a few kilobytes of bytecode made
// the analysis, and every later analysis on the thread, several times slower. With that lookup
// this test case compares strings about 10^10 times.
TEST_CASE("VariableRegistry does not scan earlier names to find one", "[var_registry]") {
    constexpr int name_count = 100'000;

    const VariableRegistry registry;
    const Variable first_builtin = registry.reg(DataKind::svalues, 0);
    const Variable last_builtin = registry.data_meta_offset();

    const auto start = std::chrono::steady_clock::now();
    std::vector<Variable> variables;
    variables.reserve(name_count);
    for (int i = 0; i < name_count; ++i) {
        variables.push_back(registry.stack_frame_var(DataKind::svalues, 6, std::to_string(i)));
    }

    int stable = 0;
    int named = 0;
    int ordered = 0;
    for (int i = 0; i < name_count; ++i) {
        const std::string prefix = std::to_string(i);
        stable += registry.stack_frame_var(DataKind::svalues, 6, prefix) == variables[i];
        named += registry.name(variables[i]) == prefix + "/r6.svalue";
        // Distinct names have distinct variables, handed out in order of first use.
        ordered += i == 0 ? last_builtin < variables[i] : variables[i - 1] < variables[i];
    }
    // Tens of seconds with a lookup that scans, a fraction of a second with one that does not.
    REQUIRE(std::chrono::steady_clock::now() - start < std::chrono::seconds(10));
    REQUIRE(stable == name_count);
    REQUIRE(named == name_count);
    REQUIRE(ordered == name_count);

    // The names created since do not move the ones the registry started with.
    REQUIRE(registry.reg(DataKind::svalues, 0) == first_builtin);
    REQUIRE(registry.data_meta_offset() == last_builtin);
    REQUIRE(registry.name(last_builtin) == "data_meta_offset");
}

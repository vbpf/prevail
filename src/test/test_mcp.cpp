// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#ifdef PREVAIL_HAS_MCP

#include <catch2/catch_all.hpp>
#include <climits>
#include <filesystem>

#include "analysis_engine.hpp"
#include "mcp/json_serializers.hpp"
#include "mcp/mcp_server.hpp"
#include "mcp/mcp_transport.hpp"
#include "platform_ops_prevail.hpp"
#include "mcp/tools.hpp"

#include "linux/gpl/spec_type_descriptors.hpp"

using json = nlohmann::json;
using namespace prevail;

// ─── Test Harness ──────────────────────────────────────────────────────────────

/// Reusable test harness that sets up a complete MCP server with all tools.
struct McpTestHarness {
    prevail::PrevailPlatformOps ops;
    prevail::AnalysisEngine engine;
    prevail::McpServer server;

    McpTestHarness()
        : ops(&g_ebpf_platform_linux), engine(&ops), server("test-server", "0.0.1") {
        prevail::register_all_tools(server, engine);
    }

    /// Call a tool and return the parsed JSON result.
    json call_tool(const std::string& name, const json& args = {}) {
        auto response = server.dispatch("tools/call", {{"name", name}, {"arguments", args}});
        auto text = response["content"][0]["text"].get<std::string>();
        if (response.value("isError", false)) {
            throw std::runtime_error(text);
        }
        return json::parse(text);
    }

    /// Call a tool and return the raw MCP response (for testing isError wrapping).
    json call_tool_raw(const std::string& name, const json& args = {}) {
        return server.dispatch("tools/call", {{"name", name}, {"arguments", args}});
    }
};

/// Return sample path if the ELF file exists, otherwise SKIP.
static std::string require_sample(const std::string& relative_path) {
    if (!std::filesystem::exists(relative_path)) {
        SKIP("Sample not found: " << relative_path);
    }
    return relative_path;
}

// ─── Protocol Tests ────────────────────────────────────────────────────────────

TEST_CASE("MCP initialize returns protocol info", "[mcp][protocol]") {
    McpTestHarness h;
    auto result = h.server.dispatch("initialize", {});

    REQUIRE(result["protocolVersion"].get<std::string>() == "2024-11-05");
    REQUIRE(result["capabilities"]["tools"].is_object());
    REQUIRE(result["serverInfo"]["name"] == "test-server");
    REQUIRE(result["serverInfo"]["version"] == "0.0.1");
}

TEST_CASE("MCP tools/list returns all tools", "[mcp][protocol]") {
    McpTestHarness h;
    auto result = h.server.dispatch("tools/list", {});
    auto tools = result["tools"];

    REQUIRE(tools.is_array());

    // Verify all expected tool names are present.
    std::set<std::string> names;
    for (const auto& t : tools) {
        names.insert(t["name"].get<std::string>());
        REQUIRE(t.contains("description"));
        REQUIRE(t.contains("inputSchema"));
    }
    REQUIRE(names.count("list_programs"));
    REQUIRE(names.count("verify_program"));
    REQUIRE(names.count("get_invariant"));
    REQUIRE(names.count("get_instruction"));
    REQUIRE(names.count("get_errors"));
    REQUIRE(names.count("get_cfg"));
    REQUIRE(names.count("get_source_mapping"));
    REQUIRE(names.count("check_constraint"));
    REQUIRE(names.count("get_slice"));
    REQUIRE(names.count("get_disassembly"));
    REQUIRE(names.count("verify_assembly"));
}

TEST_CASE("MCP dispatch unknown method throws", "[mcp][protocol]") {
    McpTestHarness h;
    REQUIRE_THROWS_AS(h.server.dispatch("bogus/method", {}), std::runtime_error);
}

TEST_CASE("MCP dispatch unknown tool throws", "[mcp][protocol]") {
    McpTestHarness h;
    REQUIRE_THROWS_AS(
        h.server.dispatch("tools/call", {{"name", "nonexistent_tool"}, {"arguments", {}}}),
        std::runtime_error);
}

TEST_CASE("MCP notifications return null", "[mcp][protocol]") {
    McpTestHarness h;
    auto result = h.server.dispatch("notifications/initialized", {});
    REQUIRE(result.is_null());
}

TEST_CASE("MCP tool exception produces isError response", "[mcp][protocol]") {
    McpTestHarness h;
    // Trigger a tool handler exception (missing required field).
    auto response = h.call_tool_raw("verify_program", {});
    REQUIRE(response.value("isError", false) == true);
    auto text = response["content"][0]["text"].get<std::string>();
    REQUIRE(text.find("Error:") != std::string::npos);
}

// ─── JSON Serializer Tests ─────────────────────────────────────────────────────

TEST_CASE("label_to_json serializes correctly", "[mcp][serializer]") {
    SECTION("simple label") {
        Label label{5, -1, {}};
        auto j = prevail::label_to_json(label);
        REQUIRE(j["from"] == 5);
        REQUIRE(j["to"] == -1);
        REQUIRE_FALSE(j.contains("stack_frame_prefix"));
        REQUIRE_FALSE(j.contains("special_label"));
    }

    SECTION("jump edge label") {
        Label label{3, 10, {}};
        auto j = prevail::label_to_json(label);
        REQUIRE(j["from"] == 3);
        REQUIRE(j["to"] == 10);
    }

    SECTION("label with stack frame") {
        Label label{0, -1, "sub1/"};
        auto j = prevail::label_to_json(label);
        REQUIRE(j["stack_frame_prefix"] == "sub1/");
    }

    SECTION("exit label") {
        auto j = prevail::label_to_json(Label::exit);
        REQUIRE(j["from"] == INT_MAX);
        REQUIRE(j["to"] == -1);
    }
}

TEST_CASE("invariant_to_json serializes correctly", "[mcp][serializer]") {
    SECTION("bottom invariant") {
        auto j = prevail::invariant_to_json(StringInvariant::bottom());
        REQUIRE(j.is_array());
        REQUIRE(j.size() == 1);
        REQUIRE(j[0] == "_|_");
    }

    SECTION("top invariant") {
        auto j = prevail::invariant_to_json(StringInvariant::top());
        REQUIRE(j.is_array());
        REQUIRE(j.empty());
    }

    SECTION("non-empty invariant") {
        std::set<std::string> constraints = {"r0.type=number", "r0.svalue=[0, 100]"};
        auto j = prevail::invariant_to_json(StringInvariant{constraints});
        REQUIRE(j.is_array());
        REQUIRE(j.size() == 2);
    }
}

TEST_CASE("interval_to_json serializes correctly", "[mcp][serializer]") {
    auto j = prevail::interval_to_json(Interval::top());
    REQUIRE(j.contains("text"));
    REQUIRE(j["text"].is_string());
}

TEST_CASE("line_info_to_json serializes correctly", "[mcp][serializer]") {
    btf_line_info_t info{"test.c", "int x = 0;", 42, 5};
    auto j = prevail::line_info_to_json(info);
    REQUIRE(j["file"] == "test.c");
    REQUIRE(j["line"] == 42);
    REQUIRE(j["column"] == 5);
    REQUIRE(j["source"] == "int x = 0;");
}

TEST_CASE("error_to_json serializes correctly", "[mcp][serializer]") {
    SECTION("error with location") {
        VerificationError err("test error message");
        err.where = Label{7, -1, {}};
        auto j = prevail::error_to_json(err);
        REQUIRE(j["message"] == "test error message");
        REQUIRE(j["pc"] == 7);
        REQUIRE(j["label"]["from"] == 7);
    }

    SECTION("error without location") {
        VerificationError err("no location");
        auto j = prevail::error_to_json(err);
        REQUIRE(j["message"] == "no location");
        REQUIRE_FALSE(j.contains("pc"));
        REQUIRE_FALSE(j.contains("label"));
    }
}

TEST_CASE("instruction_to_json produces text field", "[mcp][serializer]") {
    Bin bin_add{Bin::Op::ADD, Reg{0}, Imm{1}, true, false};
    Instruction inst = bin_add;
    auto j = prevail::instruction_to_json(inst);
    REQUIRE(j.contains("text"));
    REQUIRE(j["text"].is_string());
    REQUIRE_FALSE(j["text"].get<std::string>().empty());
}

TEST_CASE("assertion_to_json produces text field", "[mcp][serializer]") {
    ValidDivisor vd{Reg{3}, false};
    Assertion assertion = vd;
    auto j = prevail::assertion_to_json(assertion);
    REQUIRE(j.contains("text"));
    REQUIRE(j["text"].is_string());
    REQUIRE_FALSE(j["text"].get<std::string>().empty());
}

// ─── verify_assembly Tests ─────────────────────────────────────────────────────
// These tests focus on tool-specific logic: assembly parsing, TLS/ProgramInfo setup,
// option forwarding, observe plumbing, and error handling. Verifier semantics
// (instruction behavior, type checking, map safety) are covered by the 726 YAML tests.

TEST_CASE("verify_assembly: simple passing program", "[mcp][assembly]") {
    McpTestHarness h;
    auto result = h.call_tool("verify_assembly", {{"code", "r0 = 0\nexit"}});

    REQUIRE(result["passed"] == true);
    REQUIRE(result["errors"].empty());
    REQUIRE(result["instruction_count"] == 2);
    REQUIRE(result["post_invariant"].is_array());
    REQUIRE(result["exit_value"].contains("text"));
}

TEST_CASE("verify_assembly: labels and jumps", "[mcp][assembly]") {
    McpTestHarness h;
    auto result = h.call_tool("verify_assembly", {
        {"code",
            "r0 = 1\n"
            "if r0 == 0 goto <skip>\n"
            "r0 = 42\n"
            "<skip>:\n"
            "exit"},
    });

    REQUIRE(result["passed"] == true);
    REQUIRE(result["instruction_count"] == 4); // Labels don't count as instructions.
}

TEST_CASE("verify_assembly: custom pre-invariant", "[mcp][assembly]") {
    McpTestHarness h;
    // Without custom pre, r3 is uninitialized. With it, we define r3 as a number.
    auto result = h.call_tool("verify_assembly", {
        {"code", "r0 = r3\nexit"},
        {"pre", json::array({"r3.type=number", "r3.svalue=99", "r3.uvalue=99"})},
    });

    REQUIRE(result["passed"] == true);
}

TEST_CASE("verify_assembly: observe at pc", "[mcp][assembly]") {
    McpTestHarness h;
    auto result = h.call_tool("verify_assembly", {
        {"code", "r0 = 42\nexit"},
        {"observe", json::array({
            {{"pc", 1}, {"constraints", json::array({"r0.type=number"})}},
        })},
    });

    REQUIRE(result["passed"] == true);
    REQUIRE(result["observations"].is_array());
    REQUIRE(result["observations"].size() == 1);
    REQUIRE(result["observations"][0]["ok"] == true);
}

TEST_CASE("verify_assembly: observe at exit label", "[mcp][assembly]") {
    McpTestHarness h;
    auto result = h.call_tool("verify_assembly", {
        {"code", "r0 = 0\nexit"},
        {"observe", json::array({
            {{"label", "exit"}, {"constraints", json::array({"r0.type=number"})}},
        })},
    });

    REQUIRE(result["observations"][0]["ok"] == true);
}

TEST_CASE("verify_assembly: lddw wide instruction", "[mcp][assembly]") {
    McpTestHarness h;
    // lddw occupies 2 bytecode slots but is one instruction in the parsed sequence.
    auto result = h.call_tool("verify_assembly", {
        {"code", "r0 = 42 ll\nexit"},
        {"observe", json::array({
            {{"pc", 0}, {"constraints", json::array({"r0.type=number"})}},
        })},
    });

    REQUIRE(result["passed"] == true);
    REQUIRE(result["instruction_count"].get<int>() == 2);
    REQUIRE(result["observations"].is_array());
    REQUIRE(result["observations"][0]["ok"] == true);
}

TEST_CASE("verify_assembly: observe with unknown mode", "[mcp][assembly]") {
    McpTestHarness h;
    auto result = h.call_tool("verify_assembly", {
        {"code", "r0 = 0\nexit"},
        {"observe", json::array({
            {{"pc", 0}, {"mode", "invalid_mode"}, {"constraints", json::array({"r0.type=number"})}},
        })},
    });

    // Unknown mode should produce an error observation, not crash.
    REQUIRE(result["observations"].is_array());
    REQUIRE(result["observations"].size() == 1);
    REQUIRE(result["observations"][0]["ok"] == false);
    REQUIRE(result["observations"][0]["message"].get<std::string>().find("Unknown mode") != std::string::npos);
}

TEST_CASE("verify_assembly: program_type parameter", "[mcp][assembly]") {
    McpTestHarness h;
    for (const auto& type : {"xdp", "sk_skb", "socket_filter"}) {
        DYNAMIC_SECTION("type: " << type) {
            auto result = h.call_tool("verify_assembly", {
                {"code", "r0 = 0\nexit"},
                {"program_type", type},
            });
            REQUIRE(result["passed"] == true);
        }
    }
}

TEST_CASE("verify_assembly: helper call resolution", "[mcp][assembly]") {
    McpTestHarness h;
    // Tests the call N regex interception and make_call(func, *platform) routing.
    auto result = h.call_tool("verify_assembly", {
        {"code",
            "r2 = r10\n"
            "r2 += -4\n"
            "*(u32 *)(r10 - 4) = r0\n"
            "r1 = 1\n"
            "r3 = r2\n"
            "r4 = 0\n"
            "call 2\n"  // bpf_map_update_elem
            "r0 = 0\n"
            "exit"},
    });

    REQUIRE(result.contains("passed"));
    REQUIRE(result["instruction_count"] == 9);
}

TEST_CASE("verify_assembly: empty code is an error", "[mcp][assembly]") {
    McpTestHarness h;
    REQUIRE_THROWS(h.call_tool("verify_assembly", {{"code", ""}}));
}

TEST_CASE("verify_assembly: invalid instruction is an error", "[mcp][assembly]") {
    McpTestHarness h;
    REQUIRE_THROWS(h.call_tool("verify_assembly", {{"code", "not_a_valid_instruction"}}));
}

TEST_CASE("verify_assembly: verification options forwarding", "[mcp][assembly]") {
    McpTestHarness h;

    SECTION("allow_division_by_zero=true (default)") {
        auto result = h.call_tool("verify_assembly", {
            {"code", "r0 = 0\nr1 = 0\nr0 /= r1\nexit"},
            {"pre", json::array({"r0.type=number", "r0.svalue=10", "r0.uvalue=10",
                                 "r1.type=number", "r1.svalue=0", "r1.uvalue=0"})},
            {"allow_division_by_zero", true},
        });
        REQUIRE(result["passed"] == true);
    }

    SECTION("allow_division_by_zero=false") {
        auto result = h.call_tool("verify_assembly", {
            {"code", "r0 = 0\nr1 = 0\nr0 /= r1\nexit"},
            {"pre", json::array({"r0.type=number", "r0.svalue=10", "r0.uvalue=10",
                                 "r1.type=number", "r1.svalue=0", "r1.uvalue=0"})},
            {"allow_division_by_zero", false},
        });
        REQUIRE(result["passed"] == false);
    }
}

TEST_CASE("verify_assembly: observe with unsupported label", "[mcp][assembly]") {
    McpTestHarness h;
    auto result = h.call_tool("verify_assembly", {
        {"code", "r0 = 0\nexit"},
        {"observe", json::array({
            {{"label", "bogus"}, {"constraints", json::array({"r0.type=number"})}},
        })},
    });

    // An unsupported label name is rejected with an error.
    REQUIRE(result["observations"].is_array());
    REQUIRE(result["observations"].size() == 1);
    REQUIRE(result["observations"][0]["ok"] == false);
    REQUIRE(result["observations"][0]["message"].get<std::string>().find("Unknown label") != std::string::npos);
}

// ─── list_programs ──────────────────────────────────────────────────────────────

TEST_CASE("list_programs enumerates sections and functions", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/twomaps.o");
    auto result = h.call_tool("list_programs", {{"elf_path", path}});

    REQUIRE(result["programs"].is_array());
    REQUIRE_FALSE(result["programs"].empty());
    for (const auto& prog : result["programs"]) {
        REQUIRE(prog.contains("section"));
        REQUIRE(prog.contains("function"));
    }
}

// ─── verify_program ────────────────────────────────────────────────────────────

TEST_CASE("verify_program on passing program", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("verify_program", {{"elf_path", path}});

    REQUIRE(result["passed"] == true);
    REQUIRE(result["error_count"] == 0);
    REQUIRE(result["instruction_count"] > 0);
    REQUIRE(result["max_loop_count"].is_number());
    REQUIRE(result["total_unreachable"].is_number());
    REQUIRE(result.contains("exit_value"));
    REQUIRE(result.contains("section"));
    REQUIRE(result.contains("function"));
    REQUIRE_FALSE(result.contains("first_error"));
}

TEST_CASE("verify_program on failing program", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/badmapptr.o");
    auto result = h.call_tool("verify_program", {{"elf_path", path}});

    REQUIRE(result["passed"] == false);
    REQUIRE(result["error_count"] > 0);
    auto& fe = result["first_error"];
    REQUIRE(fe.contains("message"));
    REQUIRE(fe.contains("pc"));
    REQUIRE(fe.contains("label"));
}

TEST_CASE("verify_program with nonexistent file is an error", "[mcp][elf]") {
    McpTestHarness h;
    REQUIRE_THROWS(h.call_tool("verify_program", {{"elf_path", "/nonexistent/file.o"}}));
}

TEST_CASE("verify_program with invalid section/program is an error", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    REQUIRE_THROWS(h.call_tool("verify_program", {
        {"elf_path", path},
        {"section", "nonexistent_section"},
        {"program", "nonexistent_function"},
    }));
}

TEST_CASE("verify_program: allow_division_by_zero option", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/divzero.o");

    SECTION("default allows division by zero") {
        auto result = h.call_tool("verify_program", {{"elf_path", path}});
        REQUIRE(result["passed"] == true);
    }

    SECTION("disabling division by zero causes failure") {
        auto result = h.call_tool("verify_program", {
            {"elf_path", path},
            {"allow_division_by_zero", false},
        });
        REQUIRE(result["passed"] == false);
    }
}

// ─── get_invariant ─────────────────────────────────────────────────────────────

TEST_CASE("get_invariant: single PC returns flat result", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("get_invariant", {{"elf_path", path}, {"pcs", json::array({0})}});

    // Single PC returns flat (not wrapped in "results").
    REQUIRE(result.contains("label"));
    REQUIRE(result.contains("point"));
    REQUIRE(result.contains("constraints"));
    REQUIRE(result["constraints"].is_array());
}

TEST_CASE("get_invariant: batch returns results array", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("get_invariant", {{"elf_path", path}, {"pcs", json::array({0, 1})}});

    REQUIRE(result["results"].is_array());
    REQUIRE(result["results"].size() == 2);
    for (const auto& r : result["results"]) {
        REQUIRE(r.contains("pc"));
    }
}

TEST_CASE("get_invariant: invalid PC returns error field", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("get_invariant", {{"elf_path", path}, {"pcs", json::array({9999})}});

    REQUIRE(result.contains("error"));
}

TEST_CASE("get_invariant: pre and post points", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");

    auto pre = h.call_tool("get_invariant", {{"elf_path", path}, {"pcs", json::array({0})}, {"point", "pre"}});
    auto post = h.call_tool("get_invariant", {{"elf_path", path}, {"pcs", json::array({0})}, {"point", "post"}});

    REQUIRE(pre["point"] == "pre");
    REQUIRE(post["point"] == "post");
}

TEST_CASE("get_invariant: branch PC returns multi-label", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/correlated_branch.o");
    // correlated_branch.o has branches — find a branch PC from the CFG.
    auto cfg = h.call_tool("get_cfg", {{"elf_path", path}, {"format", "json"}});
    // Find a block with multiple successors (a branch point).
    int branch_pc = -1;
    for (const auto& bb : cfg["basic_blocks"]) {
        if (bb["successors"].size() > 1) {
            branch_pc = bb["last_pc"].get<int>();
            break;
        }
    }
    REQUIRE(branch_pc >= 0);

    auto result = h.call_tool("get_invariant", {{"elf_path", path}, {"pcs", json::array({branch_pc})}});
    // A branch PC has both the sequential label and jump-edge label,
    // so it may return the multi-label format with a "labels" array,
    // or a single result if only one label has invariant data.
    REQUIRE((result.contains("constraints") || result.contains("labels")));
}

// ─── get_instruction ───────────────────────────────────────────────────────────

TEST_CASE("get_instruction: full response shape", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("get_instruction", {{"elf_path", path}, {"pcs", json::array({0})}});

    auto& inst = result["results"][0];
    REQUIRE(inst["pc"] == 0);
    REQUIRE(inst["text"].is_string());
    REQUIRE(inst["assertions"].is_array());
    REQUIRE(inst["pre_invariant"].is_array());
    REQUIRE(inst["successors"].is_array());
    REQUIRE(inst["predecessors"].is_array());
    // post_invariant is either array or null (null = bottom/unreachable).
    REQUIRE((inst["post_invariant"].is_array() || inst["post_invariant"].is_null()));
}

TEST_CASE("get_instruction: batch with valid and invalid PCs", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("get_instruction", {{"elf_path", path}, {"pcs", json::array({0, 9999})}});

    REQUIRE(result["results"].size() == 2);
    REQUIRE(result["results"][0].contains("text"));     // Valid PC succeeds.
    REQUIRE(result["results"][1].contains("error"));     // Invalid PC returns error.
}

TEST_CASE("get_instruction: error field on failing instruction", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/badmapptr.o");
    // First find the error PC.
    auto verify = h.call_tool("verify_program", {{"elf_path", path}});
    int error_pc = verify["first_error"]["pc"].get<int>();

    auto result = h.call_tool("get_instruction", {{"elf_path", path}, {"pcs", json::array({error_pc})}});
    auto& inst = result["results"][0];
    REQUIRE(inst.contains("error"));
    REQUIRE(inst["error"].is_string());
}

// ─── get_errors ────────────────────────────────────────────────────────────────

TEST_CASE("get_errors: passing program has empty arrays", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("get_errors", {{"elf_path", path}});

    REQUIRE(result["passed"] == true);
    REQUIRE(result["errors"].empty());
    REQUIRE(result["unreachable"].is_array());
}

TEST_CASE("get_errors: failing program error entry structure", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/badmapptr.o");
    auto result = h.call_tool("get_errors", {{"elf_path", path}});

    REQUIRE(result["passed"] == false);
    REQUIRE(result["unreachable"].is_array());
    auto& err = result["errors"][0];
    REQUIRE(err.contains("message"));
    REQUIRE(err.contains("pc"));
    REQUIRE(err.contains("label"));
    REQUIRE(err.contains("pre_invariant"));
    REQUIRE(err["pre_invariant"].is_array());
    REQUIRE(err.contains("instruction"));
    REQUIRE(err["instruction"].is_string());
}

// ─── get_cfg ───────────────────────────────────────────────────────────────────

TEST_CASE("get_cfg: json format with branching program", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/correlated_branch.o");
    auto result = h.call_tool("get_cfg", {{"elf_path", path}, {"format", "json"}});

    REQUIRE(result["format"] == "json");
    auto& blocks = result["basic_blocks"];
    REQUIRE(blocks.is_array());
    REQUIRE(blocks.size() > 1); // Branching program must have multiple blocks.

    // Every block has required fields.
    for (const auto& bb : blocks) {
        REQUIRE(bb.contains("first_pc"));
        REQUIRE(bb.contains("last_pc"));
        REQUIRE(bb["pcs"].is_array());
        REQUIRE_FALSE(bb["pcs"].empty());
        REQUIRE(bb["successors"].is_array());
    }

    // At least one block must have multiple successors (a branch).
    bool found_branch = false;
    for (const auto& bb : blocks) {
        if (bb["successors"].size() > 1) {
            found_branch = true;
            break;
        }
    }
    REQUIRE(found_branch);
}

TEST_CASE("get_cfg: dot format", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("get_cfg", {{"elf_path", path}, {"format", "dot"}});

    REQUIRE(result["format"] == "dot");
    auto dot = result["dot"].get<std::string>();
    REQUIRE(dot.find("digraph program") != std::string::npos);
    REQUIRE(dot.find("->") != std::string::npos); // Must have edges.
}

// ─── get_disassembly ───────────────────────────────────────────────────────────

TEST_CASE("get_disassembly: full listing", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("get_disassembly", {{"elf_path", path}});

    REQUIRE(result["instructions"].is_array());
    REQUIRE(result["count"].get<int>() == static_cast<int>(result["instructions"].size()));
    REQUIRE(result["count"] > 0);

    // PCs must be monotonically non-decreasing.
    int prev_pc = -1;
    for (const auto& inst : result["instructions"]) {
        REQUIRE(inst.contains("pc"));
        REQUIRE(inst.contains("text"));
        REQUIRE(inst["pc"].get<int>() > prev_pc);
        prev_pc = inst["pc"].get<int>();
    }
}

TEST_CASE("get_disassembly: range filtering", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("get_disassembly", {{"elf_path", path}, {"from_pc", 1}, {"to_pc", 3}});

    for (const auto& inst : result["instructions"]) {
        int pc = inst["pc"].get<int>();
        REQUIRE(pc >= 1);
        REQUIRE(pc <= 3);
    }
}

// ─── get_source_mapping ────────────────────────────────────────────────────────

TEST_CASE("get_source_mapping: full map with BTF", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/twomaps_btf.o");
    auto result = h.call_tool("get_source_mapping", {{"elf_path", path}});

    REQUIRE(result.contains("entries"));
    REQUIRE(result["entries"].is_array());
    REQUIRE_FALSE(result["entries"].empty());
    auto& first = result["entries"][0];
    REQUIRE(first.contains("pc"));
    REQUIRE(first["source"].contains("file"));
    REQUIRE(first["source"].contains("line"));
}

TEST_CASE("get_source_mapping: query by PC", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/twomaps_btf.o");

    SECTION("PC with BTF info") {
        auto result = h.call_tool("get_source_mapping", {{"elf_path", path}, {"pc", 0}});
        REQUIRE(result["pc"] == 0);
        REQUIRE(result["source"].contains("file"));
        REQUIRE(result["source"].contains("line"));
        REQUIRE(result.contains("instruction"));
    }

    SECTION("PC without BTF info") {
        // Use a high PC that likely has no line info.
        auto result = h.call_tool("get_source_mapping", {{"elf_path", path}, {"pc", 9999}});
        REQUIRE(result["source"].is_null());
        REQUIRE(result.contains("note"));
    }
}

TEST_CASE("get_source_mapping: query by source line", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/twomaps_btf.o");
    // First get the full map to find a real line number.
    auto full = h.call_tool("get_source_mapping", {{"elf_path", path}});
    REQUIRE_FALSE(full["entries"].empty());
    int line = full["entries"][0]["source"]["line"].get<int>();

    auto result = h.call_tool("get_source_mapping", {{"elf_path", path}, {"source_line", line}});
    REQUIRE(result["source_line"] == line);
    REQUIRE(result["matches"].is_array());
    REQUIRE_FALSE(result["matches"].empty());
    REQUIRE(result["matches"][0].contains("pc"));
}

TEST_CASE("get_source_mapping: no-BTF program returns note", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("get_source_mapping", {{"elf_path", path}});

    // stackok.o has no BTF — should get note + empty entries.
    REQUIRE(result.contains("entries"));
    REQUIRE(result["entries"].is_array());
    if (result["entries"].empty()) {
        REQUIRE(result.contains("note"));
    }
}

// ─── check_constraint ──────────────────────────────────────────────────────────

TEST_CASE("check_constraint: consistent mode true", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("check_constraint", {
        {"elf_path", path}, {"pc", 0},
        {"constraints", json::array({"r1.type=ctx"})},
        {"mode", "consistent"},
    });

    REQUIRE(result["ok"] == true);
    REQUIRE(result.contains("invariant"));
    REQUIRE(result["invariant"].is_array());
}

TEST_CASE("check_constraint: proven mode", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");

    SECTION("proven true") {
        auto result = h.call_tool("check_constraint", {
            {"elf_path", path}, {"pc", 0},
            {"constraints", json::array({"r1.type=ctx"})},
            {"mode", "proven"},
        });
        REQUIRE(result["ok"] == true);
    }

    SECTION("proven false") {
        auto result = h.call_tool("check_constraint", {
            {"elf_path", path}, {"pc", 0},
            {"constraints", json::array({"r1.type=number"})},
            {"mode", "proven"},
        });
        REQUIRE(result["ok"] == false);
        REQUIRE_FALSE(result["message"].get<std::string>().empty());
    }
}

TEST_CASE("check_constraint: post point", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("check_constraint", {
        {"elf_path", path}, {"pc", 0}, {"point", "post"},
        {"constraints", json::array({"r10.type=stack"})},
    });

    REQUIRE(result["ok"] == true);
}

TEST_CASE("check_constraint: entailed mode", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("check_constraint", {
        {"elf_path", path}, {"pc", 0},
        {"constraints", json::array({"r1.type=ctx"})},
        {"mode", "entailed"},
    });

    // Entailed checks if observation is a sub-state of the invariant.
    REQUIRE(result.contains("ok"));
    REQUIRE(result["ok"].is_boolean());
}

TEST_CASE("check_constraint: batch with per-check overrides", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("check_constraint", {
        {"elf_path", path},
        {"checks", json::array({
            {{"pc", 0}, {"constraints", json::array({"r1.type=ctx"})}, {"mode", "proven"}},
            {{"pc", 0}, {"constraints", json::array({"r1.type=number"})}, {"mode", "proven"}},
            {{"pc", 0}, {"constraints", json::array({"r10.type=stack"})}, {"point", "post"}},
        })},
    });

    REQUIRE(result["results"].size() == 3);
    REQUIRE(result["results"][0]["ok"] == true);   // r1 is ctx (proven).
    REQUIRE(result["results"][1]["ok"] == false);   // r1 is not number.
    REQUIRE(result["results"][2]["ok"] == true);     // r10 is stack at post.
}

TEST_CASE("check_constraint: invalid PC returns structured error", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("check_constraint", {
        {"elf_path", path}, {"pc", 9999},
        {"constraints", json::array({"r0.type=number"})},
    });

    REQUIRE(result["ok"] == false);
    REQUIRE_FALSE(result["message"].get<std::string>().empty());
}

// ─── get_slice ─────────────────────────────────────────────────────────────────

TEST_CASE("get_slice: error slice structure", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/badmapptr.o");
    auto result = h.call_tool("get_slice", {{"elf_path", path}});

    // Top-level fields.
    REQUIRE(result["pc"].is_number());
    REQUIRE(result["instruction"].is_string());
    REQUIRE(result["pre_invariant"].is_array());
    REQUIRE(result["assertions"].is_array());
    REQUIRE(result["error"]["message"].is_string());
    REQUIRE(result["error"].contains("pc"));

    // Failure slice entries.
    auto& slice = result["failure_slice"];
    REQUIRE(slice.is_array());
    REQUIRE_FALSE(slice.empty());
    for (const auto& step : slice) {
        REQUIRE(step.contains("pc"));
        REQUIRE(step.contains("text"));
        REQUIRE(step["text"].is_string());
        // post_invariant is optional but when present must be array.
        if (step.contains("post_invariant")) {
            REQUIRE(step["post_invariant"].is_array());
        }
    }
}

TEST_CASE("get_slice: pc query on passing program", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    auto result = h.call_tool("get_slice", {{"elf_path", path}, {"pc", 0}});

    REQUIRE(result["pc"] == 0);
    REQUIRE(result.contains("instruction"));
    REQUIRE(result.contains("pre_invariant"));
    REQUIRE(result.contains("failure_slice"));
    REQUIRE_FALSE(result.contains("error")); // No error on passing program.
}

TEST_CASE("get_slice: invalid error_index throws", "[mcp][elf]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/badmapptr.o");
    REQUIRE_THROWS(h.call_tool("get_slice", {{"elf_path", path}, {"error_index", 999}}));
}

// ─── Engine Session Tests ──────────────────────────────────────────────────────

TEST_CASE("engine reuses session for same program", "[mcp][engine]") {
    auto path = require_sample("ebpf-samples/build/stackok.o");

    prevail::PrevailPlatformOps ops(&g_ebpf_platform_linux);
    prevail::AnalysisEngine engine(&ops);

    const auto& s1 = engine.analyze(path);
    const auto& s2 = engine.analyze(path);

    // Same reference means same session object (no re-analysis).
    REQUIRE(&s1 == &s2);
}

TEST_CASE("engine invalidates session for different program", "[mcp][engine]") {
    auto path1 = require_sample("ebpf-samples/build/stackok.o");
    auto path2 = require_sample("ebpf-samples/build/badmapptr.o");

    prevail::PrevailPlatformOps ops(&g_ebpf_platform_linux);
    prevail::AnalysisEngine engine(&ops);

    const auto& s1 = engine.analyze(path1);
    auto elf1 = s1.elf_path;  // Save before session is replaced.

    const auto& s2 = engine.analyze(path2);
    REQUIRE(elf1 != s2.elf_path);
}

TEST_CASE("engine invalidates session when options change", "[mcp][engine]") {
    auto path = require_sample("ebpf-samples/build/divzero.o");

    prevail::PrevailPlatformOps ops(&g_ebpf_platform_linux);
    prevail::AnalysisEngine engine(&ops);

    const auto& s1 = engine.analyze(path);
    bool failed1 = s1.failed;  // Save before session is replaced.
    REQUIRE(failed1 == false);  // Default: allow_division_by_zero = true.

    prevail::ebpf_verifier_options_t opts2 = ops.default_options();
    opts2.allow_division_by_zero = false;
    opts2.verbosity_opts.print_failures = true;
    opts2.verbosity_opts.collect_instruction_deps = true;
    const auto& s2 = engine.analyze(path, "", "", "", &opts2);
    REQUIRE(s2.failed == true);  // Now: allow_division_by_zero = false.
}

TEST_CASE("engine session_options reflects current state", "[mcp][engine]") {
    prevail::PrevailPlatformOps ops(&g_ebpf_platform_linux);
    prevail::AnalysisEngine engine(&ops);

    const auto& initial = engine.session_options();
    REQUIRE(initial.allow_division_by_zero == true);
}

// ─── Error Handling Tests ──────────────────────────────────────────────────────

TEST_CASE("verify_assembly: missing required 'code' field", "[mcp][error]") {
    McpTestHarness h;
    REQUIRE_THROWS(h.call_tool("verify_assembly", {}));
}

TEST_CASE("get_invariant: missing required fields", "[mcp][error]") {
    McpTestHarness h;
    auto path = require_sample("ebpf-samples/build/stackok.o");
    REQUIRE_THROWS(h.call_tool("get_invariant", {{"elf_path", path}}));
}

// ─── Transport Tests ───────────────────────────────────────────────────────────

/// RAII helper to redirect std::cin to a string and restore it afterward.
/// Not thread-safe: modifies the global std::cin streambuf.
struct CinRedirect {
    std::istringstream fake_in;
    std::streambuf* original;

    explicit CinRedirect(const std::string& input) : fake_in(input), original(std::cin.rdbuf(fake_in.rdbuf())) {}
    ~CinRedirect() {
        std::cin.rdbuf(original);
        std::cin.clear(); // Reset EOF/error flags set by the fake stream.
    }
    CinRedirect(const CinRedirect&) = delete;
    CinRedirect& operator=(const CinRedirect&) = delete;
};

/// RAII wrapper for a temporary FILE* (from tmpfile()).
struct TempFile {
    FILE* f;
    TempFile() : f(tmpfile()) {}
    ~TempFile() { if (f) fclose(f); }
    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;
    operator FILE*() const { return f; }
};

/// Read all content from a FILE* (rewound to start).
static std::string read_file(FILE* f) {
    fflush(f);
    rewind(f);
    std::string result;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        result.append(buf, n);
    }
    return result;
}

TEST_CASE("transport: NDJSON read and write", "[mcp][transport]") {
    json msg = {{"jsonrpc", "2.0"}, {"method", "test"}, {"id", 1}};
    std::string input = msg.dump() + "\n";

    CinRedirect redir(input);
    TempFile out;
    REQUIRE(out.f != nullptr);

    prevail::McpTransport transport(out);

    auto read = transport.read_message();
    REQUIRE_FALSE(read.is_null());
    REQUIRE(read["method"] == "test");
    REQUIRE(read["id"] == 1);

    json response = {{"jsonrpc", "2.0"}, {"id", 1}, {"result", "ok"}};
    transport.write_message(response);

    std::string written = read_file(out);
    REQUIRE_FALSE(written.empty());
    REQUIRE(written.back() == '\n');
    auto parsed = json::parse(written);
    REQUIRE(parsed["result"] == "ok");
}

TEST_CASE("transport: Content-Length read and write", "[mcp][transport]") {
    json msg = {{"jsonrpc", "2.0"}, {"method", "test"}, {"id", 2}};
    std::string body = msg.dump();
    std::string input = "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;

    CinRedirect redir(input);
    TempFile out;
    REQUIRE(out.f != nullptr);

    prevail::McpTransport transport(out);

    auto read = transport.read_message();
    REQUIRE_FALSE(read.is_null());
    REQUIRE(read["method"] == "test");

    json response = {{"jsonrpc", "2.0"}, {"id", 2}, {"result", "ok"}};
    transport.write_message(response);

    std::string written = read_file(out);
    REQUIRE(written.find("Content-Length: ") == 0);
    REQUIRE(written.find("\r\n\r\n") != std::string::npos);
    auto body_start = written.find("\r\n\r\n") + 4;
    auto parsed = json::parse(written.substr(body_start));
    REQUIRE(parsed["result"] == "ok");
}

TEST_CASE("transport: EOF returns null", "[mcp][transport]") {
    CinRedirect redir("");
    TempFile out;
    REQUIRE(out.f != nullptr);

    prevail::McpTransport transport(out);
    auto read = transport.read_message();
    REQUIRE(read.is_null());
}

TEST_CASE("transport: NDJSON skips blank lines", "[mcp][transport]") {
    json msg = {{"jsonrpc", "2.0"}, {"method", "test"}, {"id", 1}};
    std::string input = "\n\n" + msg.dump() + "\n";

    CinRedirect redir(input);
    TempFile out;
    REQUIRE(out.f != nullptr);

    prevail::McpTransport transport(out);
    auto read = transport.read_message();
    REQUIRE_FALSE(read.is_null());
    REQUIRE(read["method"] == "test");
}

TEST_CASE("transport: Content-Length ignores extra headers", "[mcp][transport]") {
    json msg = {{"jsonrpc", "2.0"}, {"method", "test"}, {"id", 1}};
    std::string body = msg.dump();
    std::string input = "Content-Type: application/json\r\n"
                        "Content-Length: " + std::to_string(body.size()) + "\r\n"
                        "X-Custom: ignored\r\n"
                        "\r\n" + body;

    CinRedirect redir(input);
    TempFile out;
    REQUIRE(out.f != nullptr);

    prevail::McpTransport transport(out);
    auto read = transport.read_message();
    REQUIRE_FALSE(read.is_null());
    REQUIRE(read["method"] == "test");
}

TEST_CASE("transport: Content-Length with truncated body returns null", "[mcp][transport]") {
    // Declare 100 bytes but only provide 10.
    std::string input = "Content-Length: 100\r\n\r\n0123456789";

    CinRedirect redir(input);
    TempFile out;
    REQUIRE(out.f != nullptr);

    prevail::McpTransport transport(out);
    auto read = transport.read_message();
    REQUIRE(read.is_null());
}

TEST_CASE("transport: malformed JSON returns null", "[mcp][transport]") {
    std::string input = "not valid json\n";

    CinRedirect redir(input);
    TempFile out;
    REQUIRE(out.f != nullptr);

    prevail::McpTransport transport(out);
    auto read = transport.read_message();
    REQUIRE(read.is_null());
}

TEST_CASE("transport: run dispatches requests and writes responses", "[mcp][transport]") {
    json req1 = {{"jsonrpc", "2.0"}, {"id", 1}, {"method", "echo"}, {"params", {{"x", 42}}}};
    json req2 = {{"jsonrpc", "2.0"}, {"method", "notify"}, {"params", {}}};
    std::string input = req1.dump() + "\n" + req2.dump() + "\n";

    CinRedirect redir(input);
    TempFile out;
    REQUIRE(out.f != nullptr);

    prevail::McpTransport transport(out);

    int call_count = 0;
    transport.run([&](const std::string& method, const json& params) -> json {
        call_count++;
        if (method == "echo") {
            return {{"echoed", params["x"]}};
        }
        return nullptr;
    });

    REQUIRE(call_count == 2);

    std::string written = read_file(out);
    std::istringstream lines(written);
    std::string line;
    int response_count = 0;
    while (std::getline(lines, line)) {
        if (line.empty()) continue;
        auto resp = json::parse(line);
        REQUIRE(resp["jsonrpc"] == "2.0");
        REQUIRE(resp["id"] == 1);
        REQUIRE(resp["result"]["echoed"] == 42);
        response_count++;
    }
    REQUIRE(response_count == 1);
}

TEST_CASE("transport: run sends error response on handler throw", "[mcp][transport]") {
    json req = {{"jsonrpc", "2.0"}, {"id", 5}, {"method", "fail"}, {"params", {}}};
    std::string input = req.dump() + "\n";

    CinRedirect redir(input);
    TempFile out;
    REQUIRE(out.f != nullptr);

    prevail::McpTransport transport(out);
    transport.run([&](const std::string&, const json&) -> json {
        throw std::runtime_error("test error");
    });

    std::string written = read_file(out);
    auto resp = json::parse(written);
    REQUIRE(resp["id"] == 5);
    REQUIRE(resp["error"]["code"] == -32603);
    REQUIRE(resp["error"]["message"] == "test error");
}

#endif // PREVAIL_HAS_MCP

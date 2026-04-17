// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "tools.hpp"
#include "json_serializers.hpp"

#include <algorithm>
#include <iostream>
#include <regex>
#include <set>
#include <sstream>

#include "ir/parse.hpp"

using json = nlohmann::json;

namespace prevail {

/// Build verifier options from JSON args, starting from engine defaults.
/// Applies check_termination, allow_division_by_zero, strict, and
/// sets verbosity flags needed for MCP tools (print_failures, print_line_info,
/// collect_instruction_deps).
static prevail::ebpf_verifier_options_t build_options(const json& args, AnalysisEngine& engine) {
    prevail::ebpf_verifier_options_t options = engine.ops()->default_options();
    if (args.contains("check_termination")) {
        options.cfg_opts.check_for_termination = args["check_termination"].get<bool>();
    }
    if (args.contains("allow_division_by_zero")) {
        options.allow_division_by_zero = args["allow_division_by_zero"].get<bool>();
    }
    if (args.contains("strict")) {
        options.strict = args["strict"].get<bool>();
    }
    options.verbosity_opts.print_failures = true;
    options.verbosity_opts.print_line_info = true;
    options.verbosity_opts.collect_instruction_deps = true;
    return options;
}

// Helper: find the primary label for a given PC in the analysis session.
// Returns the first label with .to == -1 (sequential flow), or the first available label.
static prevail::Label find_label_for_pc(const AnalysisSession& session, int pc) {
    auto it = session.pc_to_labels.find(pc);
    if (it == session.pc_to_labels.end() || it->second.empty()) {
        throw std::runtime_error("No label found for PC " + std::to_string(pc));
    }
    // Prefer the sequential (non-jump) label.
    for (const auto& label : it->second) {
        if (label.to == -1) {
            return label;
        }
    }
    return it->second.front();
}

// Helper: get all labels for a PC (may include jump edge labels).
static const std::vector<prevail::Label>& find_labels_for_pc(const AnalysisSession& session, int pc) {
    auto it = session.pc_to_labels.find(pc);
    if (it == session.pc_to_labels.end()) {
        static const std::vector<prevail::Label> empty;
        return empty;
    }
    return it->second;
}

// ─── Tool: list_programs ───────────────────────────────────────────────────────

static json handle_list_programs(const json& args, AnalysisEngine& engine) {
    const std::string elf_path = args.at("elf_path").get<std::string>();
    auto entries = engine.list_programs(elf_path);

    json programs = json::array();
    for (const auto& entry : entries) {
        programs.push_back({
            {"section", entry.section},
            {"function", entry.function},
        });
    }
    return {{"programs", programs}};
}

// ─── Tool: verify_program ──────────────────────────────────────────────────────

static json handle_verify_program(const json& args, AnalysisEngine& engine) {
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");
    auto options = build_options(args, engine);

    const auto& session = engine.analyze(elf_path, section, program, type, &options);

    // Count errors.
    int error_count = 0;
    for (const auto& [label, inv_pair] : session.invariants) {
        if (!inv_pair.pre_is_bottom && inv_pair.error_message.has_value()) {
            error_count++;
        }
    }

    // Count unreachable: post is bottom and instruction is Assume with no error.
    int total_unreachable = 0;
    for (const auto& [label, inv_pair] : session.invariants) {
        if (inv_pair.pre_is_bottom) {
            continue;
        }
        if (inv_pair.post.is_bottom() && !inv_pair.error_message.has_value()) {
            if (std::get_if<prevail::Assume>(&session.program.instruction_at(label))) {
                total_unreachable++;
            }
        }
    }

    json j = {
        {"passed", !session.failed},
        {"max_loop_count", session.max_loop_count},
        {"exit_value", interval_to_json(session.exit_value)},
        {"error_count", error_count},
        {"total_unreachable", total_unreachable},
        {"instruction_count", static_cast<int>(session.inst_seq.size())},
        {"section", session.section},
        {"function", session.program_name},
    };

    // Scan invariants for first error.
    for (const auto& [label, inv_pair] : session.invariants) {
        if (!inv_pair.pre_is_bottom && inv_pair.error_message.has_value()) {
            json fe;
            if (inv_pair.error_label.has_value()) {
                fe["label"] = label_to_json(*inv_pair.error_label);
                fe["pc"] = inv_pair.error_label->from;
            }
            fe["message"] = *inv_pair.error_message;
            // Add source mapping if available.
            if (inv_pair.error_label.has_value()) {
                auto src_it = session.pc_to_source.find(inv_pair.error_label->from);
                if (src_it != session.pc_to_source.end()) {
                    fe["source"] = line_info_to_json(src_it->second);
                }
            }
            j["first_error"] = fe;
            break;
        }
    }

    return j;
}

// ─── Tool: get_invariant ───────────────────────────────────────────────────────

static json handle_get_invariant(const json& args, AnalysisEngine& engine) {
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string point_str = args.value("point", "pre");
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);
    const auto pcs = args.at("pcs").get<std::vector<int>>();

    // Helper: get invariant results for a single PC.
    auto get_invariant_for_pc = [&](int pc) -> json {
        const auto& labels = find_labels_for_pc(session, pc);
        if (labels.empty()) {
            return {{"pc", pc}, {"error", "No label found for PC " + std::to_string(pc)}};
        }

        json results = json::array();
        for (const auto& label : labels) {
            auto inv_it = session.invariants.find(label);
            if (inv_it == session.invariants.end()) {
                continue;
            }
            const auto& inv_pair = inv_it->second;
            const auto& domain = (point_str == "post") ? inv_pair.post : inv_pair.pre;

            json entry = {
                {"label", label_to_json(label)},
                {"point", point_str},
                {"constraints", invariant_to_json(domain)},
            };
            results.push_back(entry);
        }

        if (results.size() == 1) {
            return results[0];
        }
        return {{"pc", pc}, {"labels", results}};
    };

    if (pcs.size() == 1) {
        return get_invariant_for_pc(pcs[0]);
    }

    json batch_results = json::array();
    for (int pc : pcs) {
        json result = get_invariant_for_pc(pc);
        result["pc"] = pc;
        batch_results.push_back(result);
    }
    return {{"results", batch_results}};
}

// ─── Tool: get_instruction ─────────────────────────────────────────────────────

static json handle_get_instruction(const json& args, AnalysisEngine& engine) {
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);

    const auto pcs = args.at("pcs").get<std::vector<int>>();

    // Helper: get instruction detail for a single PC.
    auto get_instruction_for_pc = [&](int pc) -> json {
        const auto label = find_label_for_pc(session, pc);
        json j = {{"pc", pc}, {"label", label_to_json(label)}};

        // Instruction text.
        j["text"] = instruction_to_json(session.program.instruction_at(label))["text"];

        // Assertions.
        json assertions = json::array();
        for (const auto& a : session.program.assertions_at(label)) {
            assertions.push_back(assertion_to_json(a)["text"]);
        }
        j["assertions"] = assertions;

        // Invariants.
        auto inv_it = session.invariants.find(label);
        if (inv_it != session.invariants.end()) {
            j["pre_invariant"] = invariant_to_json(inv_it->second.pre);
            if (!inv_it->second.post.is_bottom()) {
                j["post_invariant"] = invariant_to_json(inv_it->second.post);
            } else {
                j["post_invariant"] = nullptr;
            }
            if (inv_it->second.error_message.has_value()) {
                j["error"] = *inv_it->second.error_message;
            }
        }

        // Source mapping.
        auto src_it = session.pc_to_source.find(pc);
        if (src_it != session.pc_to_source.end()) {
            j["source"] = line_info_to_json(src_it->second);
        }

        // CFG neighbors.
        json successors = json::array();
        for (const auto& child : session.program.cfg().children_of(label)) {
            successors.push_back(child.from);
        }
        j["successors"] = successors;

        json predecessors = json::array();
        for (const auto& parent : session.program.cfg().parents_of(label)) {
            predecessors.push_back(parent.from);
        }
        j["predecessors"] = predecessors;

        return j;
    };

    // Build results, returning structured errors for invalid PCs.
    json batch_results = json::array();
    for (int pc : pcs) {
        try {
            batch_results.push_back(get_instruction_for_pc(pc));
        } catch (const std::runtime_error& e) {
            batch_results.push_back({{"pc", pc}, {"error", e.what()}});
        }
    }
    return {{"results", batch_results}};
}

// ─── Tool: get_errors ──────────────────────────────────────────────────────────

static json handle_get_errors(const json& args, AnalysisEngine& engine) {
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);

    json errors = json::array();
    for (const auto& [label, inv_pair] : session.invariants) {
        if (inv_pair.pre_is_bottom) {
            continue;
        }
        if (inv_pair.error_message.has_value()) {
            json e;
            if (inv_pair.error_label.has_value()) {
                e["label"] = label_to_json(*inv_pair.error_label);
                e["pc"] = inv_pair.error_label->from;
            }
            e["message"] = *inv_pair.error_message;
            e["pre_invariant"] = invariant_to_json(inv_pair.pre);
            e["instruction"] = instruction_to_json(session.program.instruction_at(label))["text"];

            auto src_it = session.pc_to_source.find(label.from);
            if (src_it != session.pc_to_source.end()) {
                e["source"] = line_info_to_json(src_it->second);
            }
            errors.push_back(e);
        }
    }

    json unreachable = json::array();
    for (const auto& [label, inv_pair] : session.invariants) {
        if (inv_pair.pre_is_bottom) {
            continue;
        }
        if (inv_pair.post.is_bottom() && !inv_pair.error_message.has_value()) {
            if (const auto passume = std::get_if<prevail::Assume>(&session.program.instruction_at(label))) {
                std::string msg =
                    prevail::to_string(label) + ": Code becomes unreachable (" + prevail::to_string(*passume) + ")";
                unreachable.push_back({{"label", label_to_json(label)}, {"message", msg}});
            }
        }
    }

    return {
        {"passed", !session.failed},
        {"errors", errors},
        {"unreachable", unreachable},
    };
}

// ─── Tool: get_cfg ─────────────────────────────────────────────────────────────

static json handle_get_cfg(const json& args, AnalysisEngine& engine) {
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string format = args.value("format", "json");
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);

    if (format == "dot") {
        // Generate DOT format inline (same logic as print_dot in printing.cpp).
        std::ostringstream dot;
        dot << "digraph program {\n";
        dot << "    node [shape = rectangle];\n";
        for (const auto& label : session.program.labels()) {
            dot << "    \"" << label << "\"[label=\"";
            for (const auto& pre : session.program.assertions_at(label)) {
                dot << "assert " << pre << "\\l";
            }
            dot << session.program.instruction_at(label) << "\\l";
            dot << "\"];\n";
            for (const auto& next : session.program.cfg().children_of(label)) {
                dot << "    \"" << label << "\" -> \"" << next << "\";\n";
            }
            dot << "\n";
        }
        dot << "}\n";
        return {{"format", "dot"}, {"dot", dot.str()}};
    }

    // JSON mode: serialize basic blocks.
    auto basic_blocks = prevail::BasicBlock::collect_basic_blocks(session.program.cfg(), true);
    json blocks = json::array();
    for (const auto& bb : basic_blocks) {
        json block;
        block["first_pc"] = bb.first_label().from;
        block["last_pc"] = bb.last_label().from;

        json pcs = json::array();
        for (const auto& label : bb) {
            pcs.push_back(label.from);
        }
        block["pcs"] = pcs;

        json succs = json::array();
        for (const auto& child : session.program.cfg().children_of(bb.last_label())) {
            succs.push_back(child.from);
        }
        block["successors"] = succs;

        blocks.push_back(block);
    }

    return {{"format", "json"}, {"basic_blocks", blocks}};
}

// ─── Tool: get_source_mapping ──────────────────────────────────────────────────

static json handle_get_source_mapping(const json& args, AnalysisEngine& engine) {
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);

    if (args.contains("pc")) {
        const int pc = args["pc"].get<int>();
        auto it = session.pc_to_source.find(pc);
        if (it == session.pc_to_source.end()) {
            return {{"pc", pc}, {"source", nullptr}, {"note", "No BTF line info for this PC"}};
        }
        json j = {{"pc", pc}, {"source", line_info_to_json(it->second)}};
        // Also include instruction text.
        auto labels = find_labels_for_pc(session, pc);
        if (!labels.empty()) {
            j["instruction"] = instruction_to_json(session.program.instruction_at(labels.front()))["text"];
        }
        return j;
    }

    if (args.contains("source_line")) {
        const int source_line = args["source_line"].get<int>();
        const std::string source_file = args.value("source_file", "");

        // Search all source mappings for matching line.
        json matches = json::array();
        for (const auto& [key, pcs] : session.source_to_pcs) {
            if (key.second == source_line &&
                (source_file.empty() || key.first == source_file || key.first.find(source_file) != std::string::npos)) {
                for (int matched_pc : pcs) {
                    json m = {{"pc", matched_pc}};
                    auto labels = find_labels_for_pc(session, matched_pc);
                    if (!labels.empty()) {
                        m["instruction"] = instruction_to_json(session.program.instruction_at(labels.front()))["text"];
                    }
                    auto src_it = session.pc_to_source.find(matched_pc);
                    if (src_it != session.pc_to_source.end()) {
                        m["source"] = line_info_to_json(src_it->second);
                    }
                    matches.push_back(m);
                }
            }
        }
        return {{"source_line", source_line}, {"matches", matches}};
    }

    // Return entire source map.
    if (session.pc_to_source.empty()) {
        return {
            {"note", "No BTF line info available. Compile with -g to enable source mapping."},
            {"entries", json::array()},
        };
    }

    json entries = json::array();
    for (const auto& [pc, info] : session.pc_to_source) {
        entries.push_back({{"pc", pc}, {"source", line_info_to_json(info)}});
    }
    return {{"entries", entries}};
}

// ─── Tool: check_constraint ────────────────────────────────────────────────────

static json handle_check_constraint(const json& args, AnalysisEngine& engine) {
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string point_str = args.value("point", "pre");
    const std::string mode_str = args.value("mode", "consistent");
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    auto point = (point_str == "post") ? prevail::InvariantPoint::post : prevail::InvariantPoint::pre;

    // Support single-check or batch-check.
    // Single: { "pc": N, "constraints": [...] }
    // Batch:  { "checks": [{ "pc": N, "constraints": [...], "mode": "...", "point": "..." }, ...] }
    struct CheckQuery {
        int pc{};
        prevail::InvariantPoint pt{prevail::InvariantPoint::pre};
        std::string md;
        std::vector<std::string> constraints;
    };

    std::vector<CheckQuery> queries;

    if (args.contains("checks")) {
        // Batch mode.
        for (const auto& check : args["checks"]) {
            CheckQuery q;
            q.pc = check.at("pc").get<int>();
            q.constraints = check.at("constraints").get<std::vector<std::string>>();
            auto qs = check.value("point", point_str);
            q.pt = (qs == "post") ? prevail::InvariantPoint::post : prevail::InvariantPoint::pre;
            q.md = check.value("mode", mode_str);
            queries.push_back(std::move(q));
        }
    } else {
        // Single mode.
        CheckQuery q;
        q.pc = args.at("pc").get<int>();
        q.constraints = args.at("constraints").get<std::vector<std::string>>();
        q.pt = point;
        q.md = mode_str;
        queries.push_back(std::move(q));
    }

    // Run analysis once (engine caches the live session for reuse across calls).
    // We need the AnalysisSession for label lookup.
    const auto& session = engine.analyze(elf_path, section, program, type);

    // Process all queries against the same analysis.
    json results = json::array();
    for (const auto& q : queries) {
        json entry = {{"pc", q.pc}};
        try {
            auto label = find_label_for_pc(session, q.pc);

            std::set<std::string> constraint_set(q.constraints.begin(), q.constraints.end());
            prevail::StringInvariant observation{std::move(constraint_set)};

            auto check_result =
                engine.check_constraint(elf_path, section, program, type, label, q.pt, observation, q.md);
            entry["ok"] = check_result.ok;
            entry["message"] = check_result.message;

            // Include the invariant so agents can see what the verifier knows.
            auto inv = engine.get_live_invariant(label, q.pt);
            if (!inv.is_bottom()) {
                entry["invariant"] = invariant_to_json(inv);
            }
        } catch (const std::runtime_error& e) {
            entry["ok"] = false;
            entry["message"] = e.what();
        }
        results.push_back(std::move(entry));
    }

    // Single-query returns the result directly; batch returns array.
    if (!args.contains("checks") && results.size() == 1) {
        return results[0];
    }
    return {{"results", results}};
}

// ─── Tool: get_slice ───────────────────────────────────────────────────

// Serialize a failure slice into JSON.
static json serialize_slice(const prevail::FailureSlice& slice, const AnalysisSession& session,
                            const prevail::Label& target_label) {
    json contributing = json::array();
    auto impacted = slice.impacted_labels();
    for (const auto& label : impacted) {
        if (label == target_label) {
            continue;
        }
        json step = {
            {"pc", label.from},
            {"text", instruction_to_json(session.program.instruction_at(label))["text"]},
        };
        auto rel_it = slice.relevance.find(label);
        if (rel_it != slice.relevance.end()) {
            json relevant_regs = json::array();
            for (const auto& reg : rel_it->second.registers) {
                relevant_regs.push_back("r" + std::to_string(reg.v));
            }
            if (!relevant_regs.empty()) {
                step["relevant_registers"] = relevant_regs;
            }
        }
        auto inv_it = session.invariants.find(label);
        if (inv_it != session.invariants.end() && !inv_it->second.post.is_bottom()) {
            step["post_invariant"] = invariant_to_json(inv_it->second.post);
        }
        auto trace_src = session.pc_to_source.find(label.from);
        if (trace_src != session.pc_to_source.end()) {
            step["source"] = line_info_to_json(trace_src->second);
        }
        contributing.push_back(step);
    }
    return contributing;
}

static json handle_get_slice(const json& args, AnalysisEngine& engine) {
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");
    const size_t trace_depth = std::min(args.value("trace_depth", static_cast<size_t>(200)), static_cast<size_t>(10000));
    auto options = build_options(args, engine);

    const auto& session = engine.analyze(elf_path, section, program, type, &options);

    prevail::Label target_label = prevail::Label::entry;

    if (args.contains("pc")) {
        const int pc = args["pc"].get<int>();
        target_label = find_label_for_pc(session, pc);
    } else {
        const int error_index = args.value("error_index", 0);
        int idx = 0;
        bool found_error = false;
        for (const auto& [label, inv_pair] : session.invariants) {
            if (inv_pair.pre_is_bottom) {
                continue;
            }
            if (inv_pair.error_message.has_value()) {
                if (idx == error_index) {
                    target_label = label;
                    found_error = true;
                    break;
                }
                idx++;
            }
        }
        if (!found_error) {
            throw std::runtime_error("Error index " + std::to_string(error_index) + " not found");
        }
    }

    const auto& inv = session.invariants.at(target_label);

    json j = {{"pc", target_label.from}};
    j["instruction"] = instruction_to_json(session.program.instruction_at(target_label))["text"];
    j["pre_invariant"] = invariant_to_json(inv.pre);

    if (inv.error_message.has_value()) {
        json error_json;
        if (inv.error_label.has_value()) {
            error_json["label"] = label_to_json(*inv.error_label);
            error_json["pc"] = inv.error_label->from;
        }
        error_json["message"] = *inv.error_message;
        j["error"] = error_json;
    }

    json assertions = json::array();
    for (const auto& a : session.program.assertions_at(target_label)) {
        assertions.push_back(assertion_to_json(a)["text"]);
    }
    j["assertions"] = assertions;

    auto src_it = session.pc_to_source.find(target_label.from);
    if (src_it != session.pc_to_source.end()) {
        j["source"] = line_info_to_json(src_it->second);
    }

    // Use backward slicing from the target label.
    // compute_slice_from_label seeds from the instruction's read registers.
    try {
        auto slice = engine.compute_slice_from_label(elf_path, section, program, type, session.program, target_label,
                                                     {}, trace_depth);
        j["failure_slice"] = serialize_slice(slice, session, target_label);
    } catch (const std::exception& e) {
        std::cerr << "prevail: slicing failed: " << e.what() << std::endl;
        j["failure_slice"] = json::array();
    }

    return j;
}

// ─── Tool: verify_assembly ─────────────────────────────────────────────────────

/// Parse a code string into labeled blocks and build an InstructionSeq.
/// Labels are lines matching `<name>:` (angle brackets required).
/// All code before the first explicit label is placed in the `<start>` block.
static prevail::InstructionSeq parse_assembly(const std::string& code, const prevail::ebpf_platform_t* platform) {
    // Split code into lines.
    std::vector<std::string> lines;
    std::istringstream stream(code);
    std::string line;
    while (std::getline(stream, line)) {
        // Trim whitespace.
        const auto start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) {
            continue; // Skip blank lines.
        }
        const auto end = line.find_last_not_of(" \t\r\n");
        lines.push_back(line.substr(start, end - start + 1));
    }

    // First pass: split into labeled blocks and count instructions for label resolution.
    struct Block {
        std::string label;  // With angle brackets (e.g., "<loop>").
        std::vector<std::string> instructions;
    };
    std::vector<Block> blocks;
    static const std::regex label_regex(R"(<(\w+)>:\s*)");

    Block current_block{"<start>", {}};
    for (const auto& l : lines) {
        std::smatch m;
        if (std::regex_match(l, m, label_regex)) {
            if (!current_block.instructions.empty()) {
                blocks.push_back(std::move(current_block));
            }
            current_block = Block{"<" + m[1].str() + ">", {}};
        } else {
            // Strip trailing comments ("; ...").
            auto comment_pos = l.find(';');
            std::string inst_text = (comment_pos != std::string::npos) ? l.substr(0, comment_pos) : l;
            auto trimmed_end = inst_text.find_last_not_of(" \t");
            if (trimmed_end != std::string::npos) {
                current_block.instructions.push_back(inst_text.substr(0, trimmed_end + 1));
            }
        }
    }
    if (!current_block.instructions.empty()) {
        blocks.push_back(std::move(current_block));
    }

    // Build label → PC map.
    std::map<std::string, prevail::Label> label_map;
    int pc = 0;
    for (const auto& block : blocks) {
        label_map.emplace(block.label, prevail::Label{pc, -1, {}});
        pc += static_cast<int>(block.instructions.size());
    }

    // Second pass: parse each instruction.
    // Intercept "call N" to resolve helpers through the server's platform (which may
    // have platform-specific helpers not available on g_ebpf_platform_linux).
    prevail::InstructionSeq result;
    int label_index = 0;
    static const std::regex call_regex(R"(call\s+(\d+).*)");
    for (const auto& block : blocks) {
        for (const auto& inst_text : block.instructions) {
            try {
                prevail::Instruction inst;
                std::smatch call_match;
                if (std::regex_match(inst_text, call_match, call_regex) && platform != nullptr) {
                    const int func = std::stoi(call_match[1].str());
                    inst = prevail::make_call(func, *platform);
                } else {
                    inst = prevail::parse_instruction(inst_text, label_map);
                }
                result.emplace_back(prevail::Label{label_index, -1, {}}, inst, std::optional<prevail::btf_line_info_t>());
            } catch (const std::exception& e) {
                throw std::runtime_error("Parse error at instruction " + std::to_string(label_index) + " (\"" +
                                         inst_text + "\"): " + e.what());
            }
            label_index++;
        }
    }

    if (result.empty()) {
        throw std::runtime_error("No instructions parsed from code");
    }

    return result;
}

static json handle_verify_assembly(const json& args, AnalysisEngine& engine) {
    const std::string code = args.at("code").get<std::string>();
    const auto pre_vec = args.value("pre", std::vector<std::string>{});
    const std::string type_name = args.value("program_type", "xdp");
    const int map_key_size = args.value("map_key_size", 4);
    const int map_value_size = args.value("map_value_size", 4);
    if (map_key_size <= 0 || map_value_size <= 0) {
        throw std::runtime_error("map_key_size and map_value_size must be positive");
    }

    // Set up verification options from the current session (or platform defaults).
    prevail::ebpf_verifier_options_t options = engine.session_options();
    if (args.contains("check_termination")) {
        options.cfg_opts.check_for_termination = args["check_termination"].get<bool>();
    }
    if (args.contains("allow_division_by_zero")) {
        options.allow_division_by_zero = args["allow_division_by_zero"].get<bool>();
    }
    if (args.contains("strict")) {
        options.strict = args["strict"].get<bool>();
    }
    if (args.contains("big_endian")) {
        options.big_endian = args["big_endian"].get<bool>();
    }
    options.verbosity_opts.print_failures = true;
    options.verbosity_opts.collect_instruction_deps = true;

    // Set up pre-invariant.
    const bool custom_pre = !pre_vec.empty();
    options.setup_constraints = !custom_pre;
    // Assembly snippets don't need to end with exit (matching YAML test behavior).
    options.cfg_opts.must_have_exit = false;

    prevail::StringInvariant pre_invariant = prevail::StringInvariant::top();
    if (custom_pre) {
        std::set<std::string> pre_set(pre_vec.begin(), pre_vec.end());
        pre_invariant = prevail::StringInvariant{std::move(pre_set)};
    }

    // Create a local platform copy with callx conformance group enabled
    // (assembly testing should support all instruction types).
    prevail::ebpf_platform_t local_platform = *engine.platform();
    local_platform.supported_conformance_groups =
        local_platform.supported_conformance_groups | bpf_conformance_groups_t::callx;

    // Build ProgramInfo with default map descriptors.
    // Two maps: index 0 (fd 0) and index 1 (fd 1) to support both map_by_idx(0) and map_fd 1.
    prevail::EbpfMapDescriptor map_desc0{};
    map_desc0.original_fd = 0;
    map_desc0.type = 0;
    map_desc0.key_size = static_cast<unsigned int>(map_key_size);
    map_desc0.value_size = static_cast<unsigned int>(map_value_size);
    map_desc0.max_entries = 4;
    map_desc0.inner_map_fd = 0;

    prevail::EbpfMapDescriptor map_desc1{};
    map_desc1.original_fd = 1;
    map_desc1.type = 0;
    map_desc1.key_size = static_cast<unsigned int>(map_key_size);
    map_desc1.value_size = static_cast<unsigned int>(map_value_size);
    map_desc1.max_entries = 4;
    map_desc1.inner_map_fd = 0;

    // Set up TLS for analysis. Unlike the normal ELF path (which calls prepare_tls
    // then read_elf), we set up thread-local state directly since there's no ELF.
    // NOTE: We deliberately do NOT call prepare_tls here because it clears the
    // _program_info_cache which is needed for is_helper_usable_windows. Instead,
    // we get the program type (which populates the cache) and set TLS manually.
    prevail::ThreadLocalGuard tls_guard;
    prevail::thread_local_options = options;

    const prevail::EbpfProgramType prog_type = local_platform.get_program_type(type_name, type_name);
    const ebpf_context_descriptor_t* ctx_desc = prog_type.context_descriptor;
    static const ebpf_context_descriptor_t fallback_ctx{64, 0, 4, -1};
    prevail::EbpfProgramType effective_type = prog_type;
    if (ctx_desc == nullptr) {
        effective_type.name = type_name;
        effective_type.context_descriptor = &fallback_ctx;
    }

    prevail::ProgramInfo info{&local_platform, {map_desc0, map_desc1}, effective_type};
    prevail::thread_local_program_info = info;

    // Parse assembly text into InstructionSeq (with TLS program info available).
    prevail::InstructionSeq inst_seq = parse_assembly(code, &local_platform);

    // Run analysis.
    prevail::Program prog = prevail::Program::from_sequence(inst_seq, info, options);
    prevail::AnalysisResult result = prevail::analyze(prog, pre_invariant);

    // Build response.
    json j = {
        {"passed", !result.failed},
        {"instruction_count", static_cast<int>(inst_seq.size())},
    };

    // Exit invariant.
    prevail::StringInvariant exit_inv = result.invariant_at(prevail::Label::exit);
    j["post_invariant"] = invariant_to_json(exit_inv);
    j["exit_value"] = interval_to_json(result.exit_value);

    // Collect errors.
    json errors = json::array();
    for (const auto& [label, inv_pair] : result.invariants) {
        if (inv_pair.pre.is_bottom()) {
            continue;
        }
        if (inv_pair.error.has_value()) {
            json e;
            e["pc"] = inv_pair.error->where.has_value() ? inv_pair.error->where->from : label.from;
            e["message"] = inv_pair.error->what();
            e["pre_invariant"] = invariant_to_json(inv_pair.pre.to_set());
            errors.push_back(e);
        }
    }
    j["errors"] = errors;

    // Process observe assertions (check intermediate invariants).
    if (args.contains("observe")) {
        json obs_results = json::array();
        for (const auto& obs : args["observe"]) {
            const std::string point_str = obs.value("point", "pre");
            const std::string mode_str = obs.value("mode", "consistent");
            if (!obs.contains("constraints")) {
                throw std::runtime_error("observe entry missing required 'constraints' field");
            }
            const auto constraints_vec = obs.at("constraints").get<std::vector<std::string>>();

            // Determine the label: either "pc" (integer) or "label" (string, e.g. "exit").
            prevail::Label label = prevail::Label::entry;
            json obs_entry = json::object();
            if (obs.contains("pc")) {
                const int obs_pc = obs["pc"].get<int>();
                if (obs_pc < 0) {
                    throw std::runtime_error("Invalid observation PC: " + std::to_string(obs_pc));
                }
                label = prevail::Label{obs_pc, -1, {}};
                obs_entry = {{"pc", obs_pc}};
            } else if (obs.contains("label")) {
                const std::string label_str = obs["label"].get<std::string>();
                if (label_str == "exit") {
                    label = prevail::Label::exit;
                } else {
                    obs_entry["ok"] = false;
                    obs_entry["message"] = "Unknown label: " + label_str + " (supported: \"exit\")";
                    obs_results.push_back(obs_entry);
                    continue;
                }
                obs_entry = {{"label", label_str}};
            }

            try {
                auto point = (point_str == "post") ? prevail::InvariantPoint::post : prevail::InvariantPoint::pre;
                prevail::ObservationCheckMode mode;
                if (mode_str == "entailed") {
                    mode = prevail::ObservationCheckMode::entailed;
                } else if (mode_str == "consistent") {
                    mode = prevail::ObservationCheckMode::consistent;
                } else {
                    obs_entry["ok"] = false;
                    obs_entry["message"] = "Unknown mode: " + mode_str;
                    obs_results.push_back(obs_entry);
                    continue;
                }
                std::set<std::string> constraint_set(constraints_vec.begin(), constraints_vec.end());
                prevail::StringInvariant observation{std::move(constraint_set)};

                auto check = result.check_observation_at_label(label, point, observation, mode);
                obs_entry["ok"] = check.ok;
                obs_entry["message"] = check.message;

                // Include the invariant at this point.
                auto it = result.invariants.find(label);
                if (it != result.invariants.end()) {
                    const auto& state = (point == prevail::InvariantPoint::post) ? it->second.post : it->second.pre;
                    if (!state.is_bottom()) {
                        obs_entry["invariant"] = invariant_to_json(state.to_set());
                    }
                }
            } catch (const std::exception& e) {
                obs_entry["ok"] = false;
                obs_entry["message"] = e.what();
            }
            obs_results.push_back(obs_entry);
        }
        j["observations"] = obs_results;
    }

    return j;
}

// ─── Tool: get_disassembly ─────────────────────────────────────────────────────

static json handle_get_disassembly(const json& args, AnalysisEngine& engine) {
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");
    const int from_pc = args.value("from_pc", -1);
    const int to_pc = args.value("to_pc", -1);

    const auto& session = engine.analyze(elf_path, section, program, type);

    json instructions = json::array();
    int pc = 0;
    for (const auto& [label, inst, line_info] : session.inst_seq) {
        if ((from_pc >= 0 && pc < from_pc) || (to_pc >= 0 && pc > to_pc)) {
            pc += prevail::size(inst);
            continue;
        }

        json entry = {{"pc", pc}};
        std::ostringstream os;
        os << inst;
        entry["text"] = os.str();

        if (line_info.has_value()) {
            entry["source"] = line_info_to_json(*line_info);
        }

        instructions.push_back(entry);
        pc += prevail::size(inst);
    }

    return {{"instructions", instructions}, {"count", static_cast<int>(instructions.size())}};
}

// ─── Tool Registration ─────────────────────────────────────────────────────────

void register_all_tools(McpServer& server, AnalysisEngine& engine) {
    server.register_tool({
        "list_programs",
        "List all eBPF programs (sections and function names) in an ELF file.",
        {{"type", "object"},
         {"properties", {{"elf_path", {{"type", "string"}, {"description", "Path to .o ELF file"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_list_programs(args, engine); },
    });

    server.register_tool({
        "verify_program",
        "Quick pass/fail check. Returns verification result, error count, exit value range, and instruction count. "
        "Use this first to confirm whether a program passes or fails before deeper analysis with get_slice.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}, {"description", "Path to .o ELF file"}}},
           {"section", {{"type", "string"}, {"description", "ELF section name (optional)"}}},
           {"program", {{"type", "string"}, {"description", "Program/function name (optional)"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}},
           {"check_termination",
            {{"type", "boolean"},
             {"description",
              "Check for termination (loop bounds). Default: platform-specific. Only override by user request."}}},
           {"allow_division_by_zero",
            {{"type", "boolean"},
             {"description",
              "Allow division by zero per BPF ISA semantics. Default: true. Only override by user request."}}},
           {"strict",
            {{"type", "boolean"},
             {"description",
              "Enable strict mode (additional runtime failure checks). Default: false. "
              "Only override by user request."}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_verify_program(args, engine); },
    });

    server.register_tool({
        "get_invariant",
        "Get the pre or post invariant (abstract state) at one or more BPF instructions. Shows register types, value "
        "ranges, and all constraints the verifier has proven at that point.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"pcs",
            {{"type", "array"}, {"items", {{"type", "integer"}}}, {"description", "Program counter(s) to query"}}},
           {"point", {{"type", "string"}, {"enum", json::array({"pre", "post"})}, {"default", "pre"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path", "pcs"})}},
        [&engine](const json& args) { return handle_get_invariant(args, engine); },
    });

    server.register_tool({
        "get_instruction",
        "Deep dive on specific instructions: disassembly text, safety assertions, pre/post invariants, "
        "verification error (if any), source line, and CFG neighbors. Use after get_slice to inspect "
        "individual instructions in detail, especially to compare pre vs post invariants across a helper call.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"pcs",
            {{"type", "array"}, {"items", {{"type", "integer"}}}, {"description", "Program counter(s) to query"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path", "pcs"})}},
        [&engine](const json& args) { return handle_get_instruction(args, engine); },
    });

    server.register_tool({
        "get_errors",
        "List all verification errors with pre-invariants and source lines, plus unreachable code. "
        "Use for a quick overview of all errors in a multi-error program. Does NOT include failure slices — "
        "use get_slice with error_index for detailed causal analysis of a specific error.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_get_errors(args, engine); },
    });

    server.register_tool({
        "get_cfg",
        "Get the control-flow graph: basic blocks with instruction PCs and edges. Supports JSON or DOT format.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"format", {{"type", "string"}, {"enum", json::array({"json", "dot"})}, {"default", "json"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_get_cfg(args, engine); },
    });

    server.register_tool({
        "get_source_mapping",
        "Map between C source lines and BPF instructions. Query by PC to find source, by source_line to find BPF "
        "instructions, or omit both to get the full map. Requires ELF compiled with -g.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"pc", {{"type", "integer"}, {"description", "BPF instruction PC to look up"}}},
           {"source_line", {{"type", "integer"}, {"description", "C source line number to look up"}}},
           {"source_file", {{"type", "string"}, {"description", "Source file name filter (optional)"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_get_source_mapping(args, engine); },
    });

    server.register_tool({
        "check_constraint",
        "Test hypotheses about the verifier's abstract state at a given instruction. "
        "Use 'proven' mode to test if the verifier guarantees a constraint (e.g., 'is packet_size >= 42 proven?'). "
        "Use 'consistent' mode to test if a constraint is possible (not contradicted). "
        "WARNING: 'consistent' returns ok=true for variables absent from the invariant (vacuously true) — "
        "always check the 'invariant' field in the response to confirm the variable is tracked. "
        "Supports batch mode: pass 'checks' array to test multiple hypotheses in a single call.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"pc", {{"type", "integer"}}},
           {"constraints",
            {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Constraint strings to check"}}},
           {"checks",
            {{"type", "array"},
             {"description", "Batch mode: array of checks to run in a single analysis pass. "
                             "Each check has pc, constraints, and optional mode/point overrides."},
             {"items",
              {{"type", "object"},
               {"properties",
                {{"pc", {{"type", "integer"}}},
                 {"constraints", {{"type", "array"}, {"items", {{"type", "string"}}}}},
                 {"mode", {{"type", "string"}, {"enum", json::array({"consistent", "entailed", "proven"})}}},
                 {"point", {{"type", "string"}, {"enum", json::array({"pre", "post"})}}}}},
               {"required", json::array({"pc", "constraints"})}}}}},
           {"point", {{"type", "string"}, {"enum", json::array({"pre", "post"})}, {"default", "pre"}}},
           {"mode",
            {{"type", "string"},
             {"enum", json::array({"consistent", "entailed", "proven"})},
             {"default", "consistent"},
             {"description",
              "consistent: constraints are possible (not contradicted). "
              "proven: verifier guarantees the constraints (invariant implies observation). "
              "entailed: observation is a sub-state of invariant (requires near-complete constraint set)."}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_check_constraint(args, engine); },
    });

    server.register_tool({
        "get_slice",
        "START HERE for failure diagnosis or understanding any instruction. Returns the pre-invariant, assertions, "
        "source line, and a backward slice of only the instructions that causally contributed — with per-instruction "
        "register relevance tracking. For errors: omit 'pc' to slice the first error. For passing programs: set 'pc' "
        "to slice backward from any instruction (e.g., to understand why a read is safe or what feeds a helper call). "
        "Read the pre-invariant directly: if a register is listed, it is proven; if absent, it was invalidated.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"error_index",
            {{"type", "integer"}, {"default", 0}, {"description", "Which error to examine (0 = first)"}}},
           {"pc",
            {{"type", "integer"},
             {"description", "Slice backward from this PC instead of an error (overrides error_index)"}}},
           {"trace_depth",
            {{"type", "integer"},
             {"default", 200},
             {"description", "Maximum backward steps for slicing (default: 200)"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}},
           {"check_termination",
            {{"type", "boolean"},
             {"description",
              "Check for termination (loop bounds). Default: platform-specific. Only override by user request."}}},
           {"allow_division_by_zero",
            {{"type", "boolean"},
             {"description",
              "Allow division by zero per BPF ISA semantics. Default: true. Only override by user request."}}},
           {"strict",
            {{"type", "boolean"},
             {"description",
              "Enable strict mode (additional runtime failure checks). Default: false. "
              "Only override by user request."}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_get_slice(args, engine); },
    });

    server.register_tool({
        "get_disassembly",
        "Get the disassembly listing for a range of instructions. Returns instruction text and source lines. "
        "Use from_pc/to_pc to limit the range, or omit for the full listing.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"from_pc", {{"type", "integer"}, {"description", "Start PC (inclusive, default: 0)"}}},
           {"to_pc", {{"type", "integer"}, {"description", "End PC (inclusive, default: last)"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_get_disassembly(args, engine); },
    });

    server.register_tool({
        "verify_assembly",
        "Verify a block of BPF assembly text without needing a compiled ELF file. "
        "Useful for quickly testing instruction sequences, validating fix ideas, or exploring verifier behavior. "
        "Syntax: one instruction per line (e.g., 'r0 = r1', 'call 1', 'if r0 == 0 goto <done>', 'exit'). "
        "Labels: '<name>:' on a separate line. Helper IDs: 1=map_lookup, 2=map_update. "
        "If 'pre' is omitted, uses standard program entry state (r1=ctx, r10=stack). "
        "If 'pre' is provided, only those constraints apply (for testing specific register states).",
        {{"type", "object"},
         {"properties",
          {{"code",
            {{"type", "string"},
             {"description",
              "BPF assembly instructions, one per line. "
              "Example: \"r0 = 0\\nexit\". Labels: \"<loop>:\\nr0 += 1\\nif r0 < 10 goto <loop>\\nexit\"."}}},
           {"pre",
            {{"type", "array"},
             {"items", {{"type", "string"}}},
             {"description",
              "Pre-invariant constraints (e.g., [\"r1.type=map_fd\", \"r1.map_fd=1\"]). "
              "If omitted, uses standard entry state (r1=ctx, r10=stack)."}}},
           {"program_type",
            {{"type", "string"},
             {"default", "xdp"},
             {"description",
              "Program type name (e.g., \"xdp\", \"bind\"). Determines available helpers and context layout. "
              "Default: \"xdp\"."}}},
           {"map_key_size", {{"type", "integer"}, {"default", 4}, {"description", "Map key size in bytes."}}},
           {"map_value_size", {{"type", "integer"}, {"default", 4}, {"description", "Map value size in bytes."}}},
           {"check_termination",
            {{"type", "boolean"},
             {"description", "Check for termination. Default: platform-specific. Only override by user request."}}},
           {"allow_division_by_zero",
            {{"type", "boolean"},
             {"description",
              "Allow division by zero per BPF ISA semantics. Default: true. Only override by user request."}}},
           {"strict",
            {{"type", "boolean"},
             {"description",
              "Enable strict mode. Default: false. Only override by user request."}}},
           {"big_endian",
            {{"type", "boolean"},
             {"default", false},
             {"description", "Analyze as big-endian BPF program. Default: false (little-endian)."}}},
           {"observe",
            {{"type", "array"},
             {"description",
              "Check intermediate invariants at specific PCs. Each entry has pc, constraints, "
              "and optional point (pre/post) and mode (consistent/entailed)."},
             {"items",
              {{"type", "object"},
               {"properties",
                {{"pc", {{"type", "integer"}, {"description", "Instruction PC to observe"}}},
                 {"label", {{"type", "string"}, {"description", "Label to observe (e.g. \"exit\")"}}},
                 {"constraints", {{"type", "array"}, {"items", {{"type", "string"}}}}},
                 {"point", {{"type", "string"}, {"enum", json::array({"pre", "post"})}, {"default", "pre"}}},
                 {"mode",
                  {{"type", "string"},
                   {"enum", json::array({"consistent", "entailed"})},
                   {"default", "consistent"}}}}},
               {"required", json::array({"constraints"})}}}}}}},
         {"required", json::array({"code"})}},
        [&engine](const json& args) { return handle_verify_assembly(args, engine); },
    });
}

} // namespace prevail
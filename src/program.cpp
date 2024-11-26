// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <cassert>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "asm_syntax.hpp"
#include "crab/cfg.hpp"
#include "crab/cfg_builder.hpp"
#include "crab/wto.hpp"
#include "program.hpp"

using std::optional;
using std::set;
using std::string;
using std::to_string;
using std::vector;

using crab::basic_block_t;
using crab::cfg_builder_t;
using crab::cfg_t;

/// Get the inverse of a given comparison operation.
static Condition::Op reverse(const Condition::Op op) {
    switch (op) {
    case Condition::Op::EQ: return Condition::Op::NE;
    case Condition::Op::NE: return Condition::Op::EQ;

    case Condition::Op::GE: return Condition::Op::LT;
    case Condition::Op::LT: return Condition::Op::GE;

    case Condition::Op::SGE: return Condition::Op::SLT;
    case Condition::Op::SLT: return Condition::Op::SGE;

    case Condition::Op::LE: return Condition::Op::GT;
    case Condition::Op::GT: return Condition::Op::LE;

    case Condition::Op::SLE: return Condition::Op::SGT;
    case Condition::Op::SGT: return Condition::Op::SLE;

    case Condition::Op::SET: return Condition::Op::NSET;
    case Condition::Op::NSET: return Condition::Op::SET;
    }
    assert(false);
    return {};
}

/// Get the inverse of a given comparison condition.
static Condition reverse(const Condition& cond) {
    return {.op = reverse(cond.op), .left = cond.left, .right = cond.right, .is64 = cond.is64};
}

static bool has_fall(const Instruction& ins) {
    if (std::holds_alternative<Exit>(ins)) {
        return false;
    }

    if (const auto pins = std::get_if<Jmp>(&ins)) {
        if (!pins->cond) {
            return false;
        }
    }

    return true;
}

/// Update a control-flow graph to inline function macros.
static void add_cfg_nodes(cfg_builder_t& cfg, std::map<label_t, Instruction>& instructions, const label_t& caller_label,
                          const label_t& entry_label) {
    bool first = true;

    // Get the label of the node to go to on returning from the macro.
    label_t exit_to_label = cfg.cfg.get_child(caller_label);

    // Construct the variable prefix to use for the new stack frame,
    // and store a copy in the CallLocal instruction since the instruction-specific
    // labels may only exist until the CFG is simplified.
    const std::string stack_frame_prefix = to_string(caller_label);
    if (const auto pcall = std::get_if<CallLocal>(&instructions.at(caller_label))) {
        pcall->stack_frame_prefix = stack_frame_prefix;
    }

    // Walk the transitive closure of CFG nodes starting at entry_label and ending at
    // any exit instruction.
    std::set macro_labels{entry_label};
    std::set seen_labels{entry_label};
    while (!macro_labels.empty()) {
        label_t macro_label = *macro_labels.begin();
        macro_labels.erase(macro_label);

        if (stack_frame_prefix == macro_label.stack_frame_prefix) {
            throw crab::InvalidControlFlow{stack_frame_prefix + ": illegal recursion"};
        }

        // Clone the macro block into a new block with the new stack frame prefix.
        const label_t label{macro_label.from, macro_label.to, stack_frame_prefix};
        auto inst = instructions.at(macro_label);
        if (const auto pexit = std::get_if<Exit>(&inst)) {
            pexit->stack_frame_prefix = label.stack_frame_prefix;
        } else if (const auto pcall = std::get_if<Call>(&inst)) {
            pcall->stack_frame_prefix = label.stack_frame_prefix;
        }
        cfg.insert(label);
        instructions.emplace(label, inst);

        if (first) {
            // Add an edge from the caller to the new block.
            first = false;
            cfg.add_child(caller_label, label);
        }

        // Add an edge from any other predecessors.
        for (const auto& prev_macro_nodes = cfg.cfg.parents_of(macro_label);
             const auto& prev_macro_label : prev_macro_nodes) {
            const label_t prev_label(prev_macro_label.from, prev_macro_label.to, to_string(caller_label));
            if (const auto& labels = cfg.cfg.labels(); std::ranges::find(labels, prev_label) != labels.end()) {
                cfg.add_child(prev_label, label);
            }
        }

        // Walk all successor nodes.
        for (const auto& next_macro_nodes = cfg.cfg.children_of(macro_label);
             const auto& next_macro_label : next_macro_nodes) {
            if (next_macro_label == cfg.cfg.exit_label()) {
                // This is an exit transition, so add edge to the block to execute
                // upon returning from the macro.
                cfg.add_child(label, exit_to_label);
            } else if (!seen_labels.contains(next_macro_label)) {
                // Push any other unprocessed successor label onto the list to be processed.
                if (!macro_labels.contains(next_macro_label)) {
                    macro_labels.insert(next_macro_label);
                }
                seen_labels.insert(macro_label);
            }
        }
    }

    // Remove the original edge from the caller node to its successor,
    // since processing now goes through the function macro instead.
    cfg.remove_child(caller_label, exit_to_label);

    // Finally, recurse to replace any nested function macros.
    string caller_label_str = to_string(caller_label);
    const long stack_frame_depth = std::ranges::count(caller_label_str, STACK_FRAME_DELIMITER) + 2;
    for (const auto& macro_label : seen_labels) {
        const label_t label(macro_label.from, macro_label.to, caller_label_str);
        if (const auto pins = std::get_if<CallLocal>(&instructions.at(label))) {
            if (stack_frame_depth >= MAX_CALL_STACK_FRAMES) {
                throw crab::InvalidControlFlow{"too many call stack frames"};
            }
            add_cfg_nodes(cfg, instructions, label, pins->target);
        }
    }
}

/// Convert an instruction sequence to a control-flow graph (CFG).
static std::tuple<cfg_builder_t, std::map<label_t, Instruction>> instruction_seq_to_cfg(const InstructionSeq& insts,
                                                                                        const bool must_have_exit) {
    cfg_builder_t builder;
    std::map<label_t, Instruction> instructions;

    // First add all instructions to the CFG without connecting
    for (const auto& [label, inst, _] : insts) {
        if (std::holds_alternative<Undefined>(inst)) {
            continue;
        }
        builder.insert(label);
        instructions.insert_or_assign(label, inst);
    }

    if (insts.size() == 0) {
        throw crab::InvalidControlFlow{"empty instruction sequence"};
    } else {
        const auto& [label, inst, _0] = insts[0];
        builder.add_child(builder.cfg.entry_label(), label);
    }

    // Do a first pass ignoring all function macro calls.
    for (size_t i = 0; i < insts.size(); i++) {
        const auto& [label, inst, _0] = insts[i];

        if (std::holds_alternative<Undefined>(inst)) {
            continue;
        }

        label_t fallthrough{builder.cfg.exit_label()};
        if (i + 1 < insts.size()) {
            fallthrough = std::get<0>(insts[i + 1]);
        } else {
            if (has_fall(inst) && must_have_exit) {
                throw crab::InvalidControlFlow{"fallthrough in last instruction"};
            }
        }
        if (const auto jmp = std::get_if<Jmp>(&inst)) {
            if (const auto cond = jmp->cond) {
                label_t target_label = jmp->target;
                if (target_label == fallthrough) {
                    builder.add_child(label, fallthrough);
                    continue;
                }
                if (!builder.cfg.contains(target_label)) {
                    throw crab::InvalidControlFlow{"jump to undefined label " + to_string(target_label)};
                }
                const label_t if_true = builder.make_jump(label, target_label);
                instructions.emplace(if_true, Assume{.cond = *cond, .is_implicit = true});
                const label_t if_false = builder.make_jump(label, fallthrough);
                instructions.emplace(if_false, Assume{.cond = reverse(*cond), .is_implicit = true});
            } else {
                builder.add_child(label, jmp->target);
            }
        } else {
            if (has_fall(inst)) {
                builder.add_child(label, fallthrough);
            }
        }
        if (std::holds_alternative<Exit>(inst)) {
            builder.add_child(label, builder.cfg.exit_label());
        }
    }

    // Now replace macros. We have to do this as a second pass so that
    // we only add new nodes that are actually reachable, based on the
    // results of the first pass.
    for (const auto& [label, inst, _] : insts) {
        if (const auto pins = std::get_if<CallLocal>(&inst)) {
            add_cfg_nodes(builder, instructions, label, pins->target);
        }
    }

    return {std::move(builder), instructions};
}

/// Annotate the CFG by adding explicit assertions for all the preconditions
/// of any instruction. For example, jump instructions are asserted not to
/// compare numbers and pointers, or pointers to potentially distinct memory
/// regions. The verifier will use these assertions to treat the program as
/// unsafe unless it can prove that the assertions can never fail.
// static void explicate_assertions(std::map<label_t, Instruction>& instructions, const program_info& info) {
//     for (auto& [label, ins] : instructions) {
//         assertions = get_assertions(ins, info, label);
//     }
// }

std::vector<Assertion> Program::assertions_at(const label_t& label) const {
    return get_assertions(instruction_at(label), thread_local_program_info.get(), label);
}

Program Program::construct(const InstructionSeq& instruction_seq, const program_info& info,
                           const prepare_cfg_options& options) {
    thread_local_program_info.set(info);

    // Convert the instruction sequence to a deterministic control-flow graph.
    auto [builder, instructions] = instruction_seq_to_cfg(instruction_seq, options.must_have_exit);

    // Detect loops using Weak Topological Ordering (WTO) and insert counters at loop entry points. WTO provides a
    // hierarchical decomposition of the CFG that identifies all strongly connected components (cycles) and their entry
    // points. These entry points serve as natural locations for loop counters that help verify program termination.
    if (options.check_for_termination) {
        const crab::wto_t wto{builder.cfg};
        wto.for_each_loop_head([&](const label_t& label) -> void {
            const label_t inclabel = label_t::make_increment_counter(label);
            builder.insert_after(label, inclabel);
            instructions.emplace(inclabel, IncrementLoopCounter{label});
        });
    }

    // Annotate the CFG by adding in assertions before every memory instruction.
    // explicate_assertions(instructions, info);

    return Program(std::move(builder.cfg), std::move(instructions));
}

std::set<basic_block_t> basic_block_t::collect_basic_blocks(const cfg_t& cfg, const bool simplify) {
    if (!simplify) {
        std::set<basic_block_t> res;
        for (const label_t& label : cfg.labels()) {
            if (label != cfg.entry_label() && label != cfg.exit_label()) {
                res.insert(basic_block_t{label});
            }
        }
        return res;
    }

    std::set<basic_block_t> res;
    std::set<label_t> worklist;
    for (const label_t& label : cfg.labels()) {
        // if (label != cfg.entry_label() && label != cfg.exit_label()) {
        worklist.insert(label);
        // }
    }
    std::set<label_t> seen;
    while (!worklist.empty()) {
        label_t label = *worklist.begin();
        worklist.erase(label);
        if (seen.contains(label)) {
            continue;
        }
        seen.insert(label);

        if (cfg.in_degree(label) == 1 && cfg.num_siblings(label) == 1) {
            continue;
        }
        basic_block_t bb{label};
        while (cfg.out_degree(label) == 1) {
            const label_t& next_label = cfg.get_child(bb.last_label());

            if (seen.contains(next_label) || next_label == cfg.exit_label() || cfg.in_degree(next_label) != 1) {
                break;
            }

            if (bb.first_label() == cfg.entry_label()) {
                // Entry instruction is Undefined. We want to start with 0
                bb.m_ts.clear();
            }
            bb.m_ts.push_back(next_label);

            worklist.erase(next_label);
            seen.insert(next_label);

            label = next_label;
        }
        res.emplace(std::move(bb));
    }
    return res;
}

/// Get the type of given Instruction.
/// Most of these type names are also statistics header labels.
static std::string instype(Instruction ins) {
    if (const auto pcall = std::get_if<Call>(&ins)) {
        if (pcall->is_map_lookup) {
            return "call_1";
        }
        if (pcall->pairs.empty()) {
            if (std::ranges::all_of(pcall->singles,
                                    [](const ArgSingle kr) { return kr.kind == ArgSingle::Kind::ANYTHING; })) {
                return "call_nomem";
            }
        }
        return "call_mem";
    } else if (std::holds_alternative<Callx>(ins)) {
        return "callx";
    } else if (const auto pimm = std::get_if<Mem>(&ins)) {
        return pimm->is_load ? "load" : "store";
    } else if (std::holds_alternative<Atomic>(ins)) {
        return "load_store";
    } else if (std::holds_alternative<Packet>(ins)) {
        return "packet_access";
    } else if (const auto pins = std::get_if<Bin>(&ins)) {
        switch (pins->op) {
        case Bin::Op::MOV:
        case Bin::Op::MOVSX8:
        case Bin::Op::MOVSX16:
        case Bin::Op::MOVSX32: return "assign";
        default: return "arith";
        }
    } else if (std::holds_alternative<Un>(ins)) {
        return "arith";
    } else if (std::holds_alternative<LoadMapFd>(ins)) {
        return "assign";
    } else if (std::holds_alternative<Assume>(ins)) {
        return "assume";
    } else {
        return "other";
    }
}

std::vector<std::string> Program::stats_headers() {
    return {
        "instructions", "joins",      "other",      "jumps",         "assign",  "arith",
        "load",         "store",      "load_store", "packet_access", "call_1",  "call_mem",
        "call_nomem",   "reallocate", "map_in_map", "arith64",       "arith32",
    };
}

std::map<std::string, int> Program::collect_stats() const {
    std::map<std::string, int> res;
    for (const auto& h : stats_headers()) {
        res[h] = 0;
    }
    for (const auto& [label, ins] : instructions) {
        res["instructions"]++;
        if (const auto pins = std::get_if<LoadMapFd>(&ins)) {
            if (pins->mapfd == -1) {
                res["map_in_map"] = 1;
            }
        }
        if (const auto pins = std::get_if<Call>(&ins)) {
            if (pins->reallocate_packet) {
                res["reallocate"] = 1;
            }
        }
        if (const auto pins = std::get_if<Bin>(&ins)) {
            res[pins->is64 ? "arith64" : "arith32"]++;
        }
        res[instype(ins)]++;
        if (cfg.in_degree(label) > 1) {
            res["joins"]++;
        }
        if (cfg.out_degree(label) > 1) {
            res["jumps"]++;
        }
    }
    return res;
}

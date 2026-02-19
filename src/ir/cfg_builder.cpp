// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <cassert>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "cfg/cfg.hpp"
#include "cfg/wto.hpp"
#include "config.hpp"
#include "linux/kfunc.hpp"
#include "ir/program.hpp"
#include "ir/syntax.hpp"
#include "platform.hpp"

using std::optional;
using std::set;
using std::string;
using std::to_string;
using std::vector;

namespace prevail {
struct CfgBuilder final {
    Program prog;

    // TODO: ins should be inserted elsewhere
    void insert_after(const Label& prev_label, const Label& new_label, const Instruction& ins) {
        if (prev_label == new_label) {
            CRAB_ERROR("Cannot insert after the same label ", to_string(new_label));
        }
        std::set<Label> prev_children;
        std::swap(prev_children, prog.m_cfg.get_node(prev_label).children);

        for (const Label& next_label : prev_children) {
            prog.m_cfg.get_node(next_label).parents.erase(prev_label);
        }

        insert(new_label, ins);
        for (const Label& next_label : prev_children) {
            add_child(prev_label, new_label);
            add_child(new_label, next_label);
        }
    }

    // TODO: ins should be inserted elsewhere
    void insert(const Label& _label, const Instruction& ins) {
        if (const auto it = prog.m_cfg.neighbours.find(_label); it != prog.m_cfg.neighbours.end()) {
            CRAB_ERROR("Label ", to_string(_label), " already exists");
        }
        prog.m_cfg.neighbours.emplace(_label, Cfg::Adjacent{});
        prog.m_instructions.emplace(_label, ins);
    }

    // TODO: ins should be inserted elsewhere
    Label insert_jump(const Label& from, const Label& to, const Instruction& ins) {
        const Label jump_label = Label::make_jump(from, to);
        if (prog.m_cfg.contains(jump_label)) {
            CRAB_ERROR("Jump label ", to_string(jump_label), " already exists");
        }
        insert(jump_label, ins);
        add_child(from, jump_label);
        add_child(jump_label, to);
        return jump_label;
    }

    void add_child(const Label& a, const Label& b) {
        assert(b != Label::entry);
        assert(a != Label::exit);
        prog.m_cfg.neighbours.at(a).children.insert(b);
        prog.m_cfg.neighbours.at(b).parents.insert(a);
    }

    void remove_child(const Label& a, const Label& b) {
        prog.m_cfg.get_node(a).children.erase(b);
        prog.m_cfg.get_node(b).parents.erase(a);
    }

    void set_assertions(const Label& label, const std::vector<Assertion>& assertions) {
        if (!prog.m_cfg.contains(label)) {
            CRAB_ERROR("Label ", to_string(label), " not found in the CFG: ");
        }
        prog.m_assertions.insert_or_assign(label, assertions);
    }
};

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

enum class RejectKind {
    NotImplemented,
    Capability,
};

struct RejectionReason {
    RejectKind kind{};
    std::string detail;
};

static bool supports(const ebpf_platform_t& platform, const bpf_conformance_groups_t group) {
    return platform.supports_group(group);
}

static bool un_requires_base64(const Un& un) {
    switch (un.op) {
    case Un::Op::BE64:
    case Un::Op::LE64:
    case Un::Op::SWAP64: return true;
    default: return false;
    }
}

static std::optional<RejectionReason> check_instruction_feature_support(const Instruction& ins,
                                                                        const ebpf_platform_t& platform) {
    auto reject_not_implemented = [](std::string detail) {
        return RejectionReason{.kind = RejectKind::NotImplemented, .detail = std::move(detail)};
    };
    auto reject_capability = [](std::string detail) {
        return RejectionReason{.kind = RejectKind::Capability, .detail = std::move(detail)};
    };

    if (const auto p = std::get_if<CallBtf>(&ins)) {
        std::string why_not;
        if (!make_kfunc_call(p->btf_id, &thread_local_program_info.get(), &why_not)) {
            return reject_not_implemented(std::move(why_not));
        }
    }
    if (const auto p = std::get_if<Call>(&ins)) {
        if (!p->is_supported) {
            return reject_capability(p->unsupported_reason);
        }
    }
    if (std::holds_alternative<Callx>(ins) && !supports(platform, bpf_conformance_groups_t::callx)) {
        return reject_capability("requires conformance group callx");
    }
    if ((std::holds_alternative<Call>(ins) || std::holds_alternative<CallLocal>(ins) ||
         std::holds_alternative<Callx>(ins) || std::holds_alternative<CallBtf>(ins) ||
         std::holds_alternative<Exit>(ins)) &&
        !supports(platform, bpf_conformance_groups_t::base32)) {
        return reject_capability("requires conformance group base32");
    }
    if (const auto p = std::get_if<Bin>(&ins)) {
        if (!supports(platform, p->is64 ? bpf_conformance_groups_t::base64 : bpf_conformance_groups_t::base32)) {
            return reject_capability(p->is64 ? "requires conformance group base64"
                                             : "requires conformance group base32");
        }
        if ((p->op == Bin::Op::MUL || p->op == Bin::Op::UDIV || p->op == Bin::Op::UMOD || p->op == Bin::Op::SDIV ||
             p->op == Bin::Op::SMOD) &&
            !supports(platform, p->is64 ? bpf_conformance_groups_t::divmul64 : bpf_conformance_groups_t::divmul32)) {
            return reject_capability(p->is64 ? "requires conformance group divmul64"
                                             : "requires conformance group divmul32");
        }
    }
    if (const auto p = std::get_if<Un>(&ins)) {
        const bool need_base64 = p->is64 || un_requires_base64(*p);
        if (!supports(platform, need_base64 ? bpf_conformance_groups_t::base64 : bpf_conformance_groups_t::base32)) {
            return reject_capability(need_base64 ? "requires conformance group base64"
                                                 : "requires conformance group base32");
        }
    }
    if (const auto p = std::get_if<Jmp>(&ins)) {
        if (!supports(platform,
                      p->cond ? (p->cond->is64 ? bpf_conformance_groups_t::base64 : bpf_conformance_groups_t::base32)
                              : bpf_conformance_groups_t::base32)) {
            return reject_capability((p->cond && p->cond->is64) ? "requires conformance group base64"
                                                                : "requires conformance group base32");
        }
    }
    if (const auto p = std::get_if<LoadPseudo>(&ins)) {
        if (!supports(platform, bpf_conformance_groups_t::base64)) {
            return reject_capability("requires conformance group base64");
        }
        switch (p->addr.kind) {
        case PseudoAddress::Kind::VARIABLE_ADDR:
        case PseudoAddress::Kind::CODE_ADDR:
        case PseudoAddress::Kind::MAP_BY_IDX:
        case PseudoAddress::Kind::MAP_VALUE_BY_IDX: break; // Resolved during CFG construction.
        default: return reject_not_implemented("lddw unknown pseudo");
        }
    }
    if ((std::holds_alternative<LoadMapFd>(ins) || std::holds_alternative<LoadMapAddress>(ins)) &&
        !supports(platform, bpf_conformance_groups_t::base64)) {
        return reject_capability("requires conformance group base64");
    }
    if (const auto p = std::get_if<Mem>(&ins)) {
        if (!supports(platform,
                      (p->access.width == 8) ? bpf_conformance_groups_t::base64 : bpf_conformance_groups_t::base32)) {
            return reject_capability((p->access.width == 8) ? "requires conformance group base64"
                                                            : "requires conformance group base32");
        }
        if (p->is_signed && !supports(platform, bpf_conformance_groups_t::base64)) {
            return reject_capability("requires conformance group base64");
        }
    }
    if (std::holds_alternative<Packet>(ins) && !supports(platform, bpf_conformance_groups_t::packet)) {
        return reject_capability("requires conformance group packet");
    }
    if (const auto p = std::get_if<Atomic>(&ins)) {
        const auto group =
            (p->access.width == 8) ? bpf_conformance_groups_t::atomic64 : bpf_conformance_groups_t::atomic32;
        if (!supports(platform, group)) {
            return reject_capability((group == bpf_conformance_groups_t::atomic64)
                                         ? "requires conformance group atomic64"
                                         : "requires conformance group atomic32");
        }
    }
    return {};
}

// Validate instruction-level feature support before CFG construction.
// This is the user-facing rejection point for unsupported or unavailable features.
static void validate_instruction_feature_support(const InstructionSeq& insts, const ebpf_platform_t& platform) {
    for (const auto& [label, inst, _] : insts) {
        if (const auto reason = check_instruction_feature_support(inst, platform)) {
            if (reason->kind == RejectKind::NotImplemented) {
                throw InvalidControlFlow{"not implemented: " + reason->detail + " (at " + to_string(label) + ")"};
            }
            throw InvalidControlFlow{"rejected: " + reason->detail + " (at " + to_string(label) + ")"};
        }
    }
}

/// Update a control-flow graph to inline function macros.
static void add_cfg_nodes(CfgBuilder& builder, const Label& caller_label, const Label& entry_label) {
    bool first = true;

    // Get the label of the node to go to on returning from the macro.
    Label exit_to_label = builder.prog.cfg().get_child(caller_label);

    // Construct the variable prefix to use for the new stack frame
    // and store a copy in the CallLocal instruction since the instruction-specific
    // labels may only exist until the CFG is simplified.
    const std::string stack_frame_prefix = to_string(caller_label);
    if (const auto pcall = std::get_if<CallLocal>(&builder.prog.instruction_at(caller_label))) {
        pcall->stack_frame_prefix = stack_frame_prefix;
    }

    // Walk the transitive closure of CFG nodes starting at entry_label and ending at
    // any exit instruction.
    std::set macro_labels{entry_label};
    std::set seen_labels{entry_label};
    while (!macro_labels.empty()) {
        Label macro_label = *macro_labels.begin();
        macro_labels.erase(macro_label);

        if (stack_frame_prefix == macro_label.stack_frame_prefix) {
            throw InvalidControlFlow{stack_frame_prefix + ": illegal recursion"};
        }

        // Clone the macro block into a new block with the new stack frame prefix.
        const Label label{macro_label.from, macro_label.to, stack_frame_prefix};
        auto inst = builder.prog.instruction_at(macro_label);
        if (const auto pexit = std::get_if<Exit>(&inst)) {
            pexit->stack_frame_prefix = label.stack_frame_prefix;
        } else if (const auto pcall = std::get_if<Call>(&inst)) {
            pcall->stack_frame_prefix = label.stack_frame_prefix;
        }
        builder.insert(label, inst);

        if (first) {
            // Add an edge from the caller to the new block.
            first = false;
            builder.add_child(caller_label, label);
        }

        // Add an edge from any other predecessors.
        for (const auto& prev_macro_nodes = builder.prog.cfg().parents_of(macro_label);
             const auto& prev_macro_label : prev_macro_nodes) {
            const Label prev_label(prev_macro_label.from, prev_macro_label.to, to_string(caller_label));
            if (const auto& labels = builder.prog.cfg().labels();
                std::ranges::find(labels, prev_label) != labels.end()) {
                builder.add_child(prev_label, label);
            }
        }

        // Walk all successor nodes.
        for (const auto& next_macro_nodes = builder.prog.cfg().children_of(macro_label);
             const auto& next_macro_label : next_macro_nodes) {
            if (next_macro_label == builder.prog.cfg().exit_label()) {
                // This is an exit transition, so add edge to the block to execute
                // upon returning from the macro.
                builder.add_child(label, exit_to_label);
            } else if (!seen_labels.contains(next_macro_label)) {
                // Push any other unprocessed successor label onto the list to be processed.
                if (!macro_labels.contains(next_macro_label)) {
                    macro_labels.insert(next_macro_label);
                }
                seen_labels.insert(next_macro_label);
            }
        }
    }

    // Remove the original edge from the caller node to its successor,
    // since processing now goes through the function macro instead.
    builder.remove_child(caller_label, exit_to_label);

    // Finally, recurse to replace any nested function macros.
    string caller_label_str = to_string(caller_label);
    const long stack_frame_depth = std::ranges::count(caller_label_str, STACK_FRAME_DELIMITER) + 2;
    for (const auto& macro_label : seen_labels) {
        const Label label{macro_label.from, macro_label.to, caller_label_str};
        if (const auto pins = std::get_if<CallLocal>(&builder.prog.instruction_at(label))) {
            if (stack_frame_depth >= MAX_CALL_STACK_FRAMES) {
                throw InvalidControlFlow{"too many call stack frames"};
            }
            add_cfg_nodes(builder, label, pins->target);
        }
    }
}

struct Imm64Parts {
    int32_t lo{};
    int32_t hi{};
};

static uint64_t merge_imm32_to_u64(const Imm64Parts parts) {
    return static_cast<uint64_t>(static_cast<uint32_t>(parts.lo)) |
           (static_cast<uint64_t>(static_cast<uint32_t>(parts.hi)) << 32);
}

/// Resolve a LoadPseudo to a concrete instruction before abstract interpretation.
/// VARIABLE_ADDR and CODE_ADDR are lowered to immediate scalar loads.
static Instruction resolve_pseudo_load(const LoadPseudo& pseudo) {
    if (pseudo.addr.kind == PseudoAddress::Kind::VARIABLE_ADDR || pseudo.addr.kind == PseudoAddress::Kind::CODE_ADDR) {
        return Bin{
            .op = Bin::Op::MOV,
            .dst = pseudo.dst,
            .v = Imm{merge_imm32_to_u64({.lo = pseudo.addr.imm, .hi = pseudo.addr.next_imm})},
            .is64 = true,
            .lddw = true,
        };
    }

    const auto& descriptors = thread_local_program_info->map_descriptors;
    if (pseudo.addr.imm < 0 || static_cast<size_t>(pseudo.addr.imm) >= descriptors.size()) {
        throw InvalidControlFlow{"invalid map index " + std::to_string(pseudo.addr.imm) + " (have " +
                                 std::to_string(descriptors.size()) + " maps)"};
    }
    const auto map_idx = static_cast<size_t>(pseudo.addr.imm);
    const int mapfd = descriptors.at(map_idx).original_fd;
    switch (pseudo.addr.kind) {
    case PseudoAddress::Kind::MAP_BY_IDX: return LoadMapFd{.dst = pseudo.dst, .mapfd = mapfd};
    case PseudoAddress::Kind::MAP_VALUE_BY_IDX:
        return LoadMapAddress{.dst = pseudo.dst, .mapfd = mapfd, .offset = pseudo.addr.next_imm};
    default: CRAB_ERROR("Invalid address kind: ", static_cast<int>(pseudo.addr.kind));
    }
}

/// Convert an instruction sequence to a control-flow graph (CFG).
static CfgBuilder instruction_seq_to_cfg(const InstructionSeq& insts, const bool must_have_exit) {
    CfgBuilder builder;
    assert(thread_local_program_info->platform != nullptr && "platform must be set before CFG construction");

    // First, add all instructions to the CFG without connecting
    for (const auto& [label, inst, _] : insts) {
        assert(!check_instruction_feature_support(inst, *thread_local_program_info->platform).has_value() &&
               "instruction support must be validated before CFG construction");
        if (std::holds_alternative<Undefined>(inst)) {
            continue;
        }
        if (const auto* call_btf = std::get_if<CallBtf>(&inst)) {
            std::string why_not;
            const auto call = make_kfunc_call(call_btf->btf_id, &thread_local_program_info.get(), &why_not);
            if (!call) {
                throw InvalidControlFlow{"not implemented: " + why_not + " (at " + to_string(label) + ")"};
            }
            builder.insert(label, *call);
        } else if (const auto* pseudo = std::get_if<LoadPseudo>(&inst)) {
            builder.insert(label, resolve_pseudo_load(*pseudo));
        } else {
            builder.insert(label, inst);
        }
    }

    if (insts.empty()) {
        throw InvalidControlFlow{"empty instruction sequence"};
    } else {
        const auto& [label, inst, _0] = insts[0];
        builder.add_child(builder.prog.cfg().entry_label(), label);
    }

    // Do a first pass ignoring all function macro calls.
    for (size_t i = 0; i < insts.size(); i++) {
        const auto& [label, inst, _0] = insts[i];

        if (std::holds_alternative<Undefined>(inst)) {
            continue;
        }
        Label fallthrough{builder.prog.cfg().exit_label()};
        if (i + 1 < insts.size()) {
            fallthrough = std::get<0>(insts[i + 1]);
        } else {
            if (has_fall(inst) && must_have_exit) {
                throw InvalidControlFlow{"fallthrough in last instruction"};
            }
        }
        if (const auto jmp = std::get_if<Jmp>(&inst)) {
            if (const auto cond = jmp->cond) {
                Label target_label = jmp->target;
                if (target_label == fallthrough) {
                    builder.add_child(label, fallthrough);
                    continue;
                }
                if (!builder.prog.cfg().contains(target_label)) {
                    throw InvalidControlFlow{"jump to undefined label " + to_string(target_label)};
                }
                builder.insert_jump(label, target_label, Assume{.cond = *cond, .is_implicit = true});
                builder.insert_jump(label, fallthrough, Assume{.cond = reverse(*cond), .is_implicit = true});
            } else {
                builder.add_child(label, jmp->target);
            }
        } else {
            if (has_fall(inst)) {
                builder.add_child(label, fallthrough);
            }
        }
        if (std::holds_alternative<Exit>(inst)) {
            builder.add_child(label, builder.prog.cfg().exit_label());
        }
    }

    // Now replace macros. We have to do this as a second pass so that
    // we only add new nodes that are actually reachable, based on the
    // results of the first pass.
    for (const auto& [label, inst, _] : insts) {
        if (const auto pins = std::get_if<CallLocal>(&inst)) {
            add_cfg_nodes(builder, label, pins->target);
        }
    }

    return builder;
}

static bool is_tail_call_helper(const Call& call, const ebpf_platform_t& platform) {
    return platform.get_helper_prototype(call.func).return_type == EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED;
}

static bool is_tail_call_site(const Instruction& ins, const ebpf_platform_t& platform) {
    if (const auto* call = std::get_if<Call>(&ins)) {
        return is_tail_call_helper(*call, platform);
    }
    if (std::holds_alternative<Callx>(ins)) {
        // At CFG-construction time, callx target ids are not available.
        // Conservatively treat callx as a potential tail-call site.
        return true;
    }
    return false;
}

static void collect_wto_labels(const CycleOrLabel& component, std::set<Label>& labels) {
    if (const auto plabel = std::get_if<Label>(&component)) {
        labels.insert(*plabel);
        return;
    }
    for (const auto& nested_component : *std::get<std::shared_ptr<WtoCycle>>(component)) {
        collect_wto_labels(nested_component, labels);
    }
}

/// Enforce a global upper bound on tail-call chain length.
/// Count tail-call sites over the reachable maximal-SCC DAG so cycles do not inflate depth.
/// Maximal SCCs are obtained from WTO nesting: all labels in the same outermost WTO cycle
/// are mutually reachable and therefore belong to the same maximal SCC.
static void validate_tail_call_chain_depth(const Program& prog, const Wto& wto, const ebpf_platform_t& platform) {
    constexpr int tail_call_chain_limit = 33;

    // WTO only covers labels reachable from entry.
    std::set<Label> reachable;
    for (const auto& component : wto) {
        collect_wto_labels(component, reachable);
    }

    // Partition reachable labels by maximal SCC representative:
    // the outermost containing WTO head, or the label itself if not in a cycle.
    std::map<Label, Label> maximal_scc_of;
    std::set<Label> maximal_scc_ids;
    for (const auto& label : reachable) {
        const Label scc_id = wto.nesting(label).outermost_head().value_or(label);
        maximal_scc_of.emplace(label, scc_id);
        maximal_scc_ids.insert(scc_id);
    }

    std::map<Label, int> tail_sites_per_scc;
    std::map<Label, std::optional<Label>> representative_tail_label;
    std::map<Label, std::set<Label>> dag_successors;
    std::map<Label, int> indegree;
    for (const auto& scc_id : maximal_scc_ids) {
        tail_sites_per_scc.emplace(scc_id, 0);
        representative_tail_label.emplace(scc_id, std::nullopt);
        dag_successors.emplace(scc_id, std::set<Label>{});
        indegree.emplace(scc_id, 0);
    }

    for (const auto& label : reachable) {
        const Label src_scc = maximal_scc_of.at(label);
        if (is_tail_call_site(prog.instruction_at(label), platform)) {
            ++tail_sites_per_scc.at(src_scc);
            auto& representative = representative_tail_label.at(src_scc);
            if (!representative.has_value()) {
                representative = label;
            }
        }
        for (const auto& child : prog.cfg().children_of(label)) {
            if (!reachable.contains(child)) {
                continue;
            }
            const Label dst_scc = maximal_scc_of.at(child);
            if (src_scc != dst_scc && dag_successors[src_scc].insert(dst_scc).second) {
                ++indegree.at(dst_scc);
            }
        }
    }

    std::map<Label, int> indegree_for_sources = indegree;
    std::vector<Label> topo_order;
    topo_order.reserve(maximal_scc_ids.size());
    for (const auto& scc_id : maximal_scc_ids) {
        if (indegree.at(scc_id) == 0) {
            topo_order.push_back(scc_id);
        }
    }
    for (size_t index = 0; index < topo_order.size(); ++index) {
        const Label scc_id = topo_order[index];
        for (const auto& succ : dag_successors.at(scc_id)) {
            --indegree.at(succ);
            if (indegree.at(succ) == 0) {
                topo_order.push_back(succ);
            }
        }
    }
    if (topo_order.size() != maximal_scc_ids.size()) {
        CRAB_ERROR("WTO-derived SCC graph must be acyclic");
    }

    // Longest path over maximal SCC DAG by tail-call site count.
    constexpr int uninitialized_depth = std::numeric_limits<int>::min();
    std::map<Label, int> max_tail_depth;
    std::map<Label, std::optional<Label>> depth_label;
    for (const auto& scc_id : maximal_scc_ids) {
        max_tail_depth.emplace(scc_id, uninitialized_depth);
        depth_label.emplace(scc_id, std::nullopt);
        if (indegree_for_sources.at(scc_id) == 0) {
            max_tail_depth.at(scc_id) = tail_sites_per_scc.at(scc_id);
            depth_label.at(scc_id) = representative_tail_label.at(scc_id);
        }
    }

    for (const auto& scc_id : topo_order) {
        const int current_depth = max_tail_depth.at(scc_id);
        if (current_depth == uninitialized_depth) {
            continue;
        }
        if (current_depth > tail_call_chain_limit) {
            const Label at = depth_label.at(scc_id).value_or(scc_id);
            throw InvalidControlFlow{"tail call chain depth exceeds " + std::to_string(tail_call_chain_limit) +
                                     " (at " + to_string(at) + ")"};
        }
        for (const auto& succ : dag_successors.at(scc_id)) {
            const int candidate_depth = current_depth + tail_sites_per_scc.at(succ);
            if (candidate_depth > max_tail_depth.at(succ)) {
                max_tail_depth.at(succ) = candidate_depth;
                depth_label.at(succ) = representative_tail_label.at(succ).has_value()
                                           ? representative_tail_label.at(succ)
                                           : depth_label.at(scc_id);
            }
        }
    }
}

Program Program::from_sequence(const InstructionSeq& inst_seq, const ProgramInfo& info,
                               const ebpf_verifier_options_t& options) {
    thread_local_program_info.set(info);
    thread_local_options = options;
    assert(info.platform != nullptr && "platform must be set before instruction feature validation");
    validate_instruction_feature_support(inst_seq, *info.platform);

    // Convert the instruction sequence to a deterministic control-flow graph.
    CfgBuilder builder = instruction_seq_to_cfg(inst_seq, options.cfg_opts.must_have_exit);

    const Wto wto{builder.prog.cfg()};
    validate_tail_call_chain_depth(builder.prog, wto, *info.platform);

    // Detect loops using Weak Topological Ordering (WTO) and insert counters at loop entry points. WTO provides a
    // hierarchical decomposition of the CFG that identifies all strongly connected components (cycles) and their entry
    // points. These entry points serve as natural locations for loop counters that help verify program termination.
    if (options.cfg_opts.check_for_termination) {
        wto.for_each_loop_head([&](const Label& label) -> void {
            builder.insert_after(label, Label::make_increment_counter(label), IncrementLoopCounter{label});
        });
    }

    // Annotate the CFG by explicitly adding in assertions before every memory instruction.
    for (const auto& label : builder.prog.labels()) {
        builder.set_assertions(label, get_assertions(builder.prog.instruction_at(label), info, label));
    }
    return std::move(builder.prog);
}

std::set<BasicBlock> BasicBlock::collect_basic_blocks(const Cfg& cfg, const bool simplify) {
    if (!simplify) {
        std::set<BasicBlock> res;
        for (const Label& label : cfg.labels()) {
            if (label != cfg.entry_label() && label != cfg.exit_label()) {
                res.insert(BasicBlock{label});
            }
        }
        return res;
    }

    std::set<BasicBlock> res;
    std::set<Label> worklist;
    for (const Label& label : cfg.labels()) {
        worklist.insert(label);
    }
    std::set<Label> seen;
    while (!worklist.empty()) {
        Label label = *worklist.begin();
        worklist.erase(label);
        if (seen.contains(label)) {
            continue;
        }
        seen.insert(label);

        if (cfg.in_degree(label) == 1 && cfg.num_siblings(label) == 1) {
            continue;
        }
        BasicBlock bb{label};
        while (cfg.out_degree(label) == 1) {
            const Label& next_label = cfg.get_child(bb.last_label());

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
    } else if (std::holds_alternative<CallBtf>(ins)) {
        return "call_btf";
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
    } else if (std::holds_alternative<LoadMapAddress>(ins)) {
        return "assign";
    } else if (std::holds_alternative<LoadPseudo>(ins)) {
        return "assign";
    } else if (std::holds_alternative<Assume>(ins)) {
        return "assume";
    } else {
        return "other";
    }
}

std::vector<std::string> stats_headers() {
    return {
        "instructions", "joins",      "other",      "jumps",         "assign",  "arith",
        "load",         "store",      "load_store", "packet_access", "call_1",  "call_mem",
        "call_nomem",   "reallocate", "map_in_map", "arith64",       "arith32",
    };
}

std::map<std::string, int> collect_stats(const Program& prog) {
    std::map<std::string, int> res;
    for (const auto& h : stats_headers()) {
        res[h] = 0;
    }
    for (const auto& label : prog.labels()) {
        res["instructions"]++;
        const auto& cmd = prog.instruction_at(label);
        if (const auto pins = std::get_if<LoadMapFd>(&cmd)) {
            if (pins->mapfd == -1) {
                res["map_in_map"] = 1;
            }
        }
        if (const auto pins = std::get_if<Call>(&cmd)) {
            if (pins->reallocate_packet) {
                res["reallocate"] = 1;
            }
        }
        if (const auto pins = std::get_if<Bin>(&cmd)) {
            res[pins->is64 ? "arith64" : "arith32"]++;
        }
        res[instype(cmd)]++;
        if (prog.cfg().in_degree(label) > 1) {
            res["joins"]++;
        }
        if (prog.cfg().out_degree(label) > 1) {
            res["jumps"]++;
        }
    }
    return res;
}

Cfg cfg_from_adjacency_list(const std::map<Label, std::vector<Label>>& AdjList) {
    CfgBuilder builder;
    for (const auto& label : std::views::keys(AdjList)) {
        if (label == Label::entry || label == Label::exit) {
            continue;
        }
        builder.insert(label, Undefined{});
    }
    for (const auto& [label, children] : AdjList) {
        for (const auto& child : children) {
            builder.add_child(label, child);
        }
    }
    return builder.prog.cfg();
}
} // namespace prevail

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
#include "ir/program.hpp"
#include "ir/syntax.hpp"
#include "platform.hpp"

using std::optional;
using std::set;
using std::string;
using std::to_string;
using std::vector;

namespace prevail {
struct CallbackMetadata {
    std::set<int32_t> target_labels;
    std::set<int32_t> targets_with_exit;
};

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

    void set_callback_metadata(CallbackMetadata md) {
        prog.m_callback_target_labels = std::move(md.target_labels);
        prog.m_callback_targets_with_exit = std::move(md.targets_with_exit);
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
    std::unreachable();
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

static std::optional<Call> resolve_kfunc_call(const CallBtf& call_btf, const ProgramInfo& info, std::string* why_not) {
    if (!info.platform || !info.platform->resolve_kfunc_call) {
        if (why_not) {
            *why_not = "kfunc resolution is unavailable on this platform";
        }
        return std::nullopt;
    }
    return info.platform->resolve_kfunc_call(call_btf.btf_id, info.type, why_not);
}

using ResolvedKfuncCalls = std::map<Label, Call>;

static std::optional<RejectionReason> check_instruction_feature_support(const Instruction& ins,
                                                                        const ebpf_platform_t& platform) {
    auto reject_not_implemented = [](std::string detail) {
        return RejectionReason{.kind = RejectKind::NotImplemented, .detail = std::move(detail)};
    };
    auto reject_capability = [](std::string detail) {
        return RejectionReason{.kind = RejectKind::Capability, .detail = std::move(detail)};
    };

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

// Pass: ValidateInstructionSupport
// Reads    : instruction sequence, platform conformance groups.
// Writes   : nothing.
// Throws   : InvalidControlFlow on any instruction the platform cannot run.
// Invariant: must run before CFG construction; pass_populate_nodes assumes
//            every instruction has been vetted here.
static void pass_validate_instruction_support(const InstructionSeq& insts, const ebpf_platform_t& platform) {
    for (const auto& [label, inst, _] : insts) {
        if (const auto reason = check_instruction_feature_support(inst, platform)) {
            const std::string prefix =
                (reason->kind == RejectKind::NotImplemented) ? "not implemented: " : "rejected: ";
            throw InvalidControlFlow{prefix + reason->detail + " (at " + to_string(label) + ")"};
        }
    }
}

// Pass: ResolveKfuncCalls
// Reads    : instruction sequence, platform kfunc resolver.
// Writes   : returns a Label -> Call map for every CallBtf in the sequence.
// Throws   : InvalidControlFlow if any CallBtf cannot be resolved for this platform.
// Invariant: pass_populate_nodes consults this map to replace CallBtf with the resolved Call.
static ResolvedKfuncCalls pass_resolve_kfunc_calls(const InstructionSeq& insts, const ProgramInfo& info) {
    ResolvedKfuncCalls resolved;
    for (const auto& [label, inst, _] : insts) {
        const auto* call_btf = std::get_if<CallBtf>(&inst);
        if (!call_btf) {
            continue;
        }
        std::string why_not;
        const auto call = resolve_kfunc_call(*call_btf, info, &why_not);
        if (!call) {
            throw InvalidControlFlow{"not implemented: " + why_not + " (at " + to_string(label) + ")"};
        }
        resolved.insert_or_assign(label, *call);
    }
    return resolved;
}

/// Update a control-flow graph to inline function macros.
static void add_cfg_nodes(CfgBuilder& builder, const Label& caller_label, const Label& entry_label,
                          const int max_call_stack_frames) {
    const string caller_label_str = to_string(caller_label);
    const long stack_frame_depth = std::ranges::count(caller_label_str, STACK_FRAME_DELIMITER) + 2;
    if (stack_frame_depth > max_call_stack_frames) {
        throw InvalidControlFlow{"too many call stack frames"};
    }

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
    for (const auto& macro_label : seen_labels) {
        const Label label{macro_label.from, macro_label.to, caller_label_str};
        if (const auto pins = std::get_if<CallLocal>(&builder.prog.instruction_at(label))) {
            add_cfg_nodes(builder, label, pins->target, max_call_stack_frames);
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

/// Lower a single LoadPseudo to a concrete instruction.
/// VARIABLE_ADDR is lowered to an immediate scalar MOV; MAP_BY_IDX / MAP_VALUE_BY_IDX are
/// rewritten against the current map descriptor table. CODE_ADDR is kept as LoadPseudo by
/// pass_lower_pseudo_loads so the abstract transformer can type it as T_FUNC; this helper
/// is never called for CODE_ADDR.
static Instruction lower_pseudo_load(const LoadPseudo& pseudo, const ProgramInfo& info) {
    if (pseudo.addr.kind == PseudoAddress::Kind::VARIABLE_ADDR) {
        return Bin{
            .op = Bin::Op::MOV,
            .dst = pseudo.dst,
            .v = Imm{merge_imm32_to_u64({.lo = pseudo.addr.imm, .hi = pseudo.addr.next_imm})},
            .is64 = true,
            .lddw = true,
        };
    }

    const auto& descriptors = info.map_descriptors;
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

using LoweredPseudoLoads = std::map<Label, Instruction>;

// Pass: LowerPseudoLoads
// Reads    : instruction sequence, program info (map_descriptors).
// Writes   : returns a Label -> Instruction map with the concrete replacement for every
//            LoadPseudo that is lowered. CODE_ADDR LoadPseudo instructions are intentionally
//            excluded so they remain observable to the abstract transformer (which types
//            them as T_FUNC); every other kind is replaced.
// Throws   : InvalidControlFlow if a MAP_BY_IDX / MAP_VALUE_BY_IDX references an out-of-range
//            map descriptor.
// Invariant: pass_populate_nodes consults this map to substitute LoadPseudo with its lowered
//            form while inserting CFG nodes.
static LoweredPseudoLoads pass_lower_pseudo_loads(const InstructionSeq& insts, const ProgramInfo& info) {
    LoweredPseudoLoads lowered;
    for (const auto& [label, inst, _] : insts) {
        const auto* pseudo = std::get_if<LoadPseudo>(&inst);
        if (!pseudo || pseudo->addr.kind == PseudoAddress::Kind::CODE_ADDR) {
            continue;
        }
        lowered.insert_or_assign(label, lower_pseudo_load(*pseudo, info));
    }
    return lowered;
}

// Pass: BuildInitialCfg -- populate_nodes step.
// Reads    : instruction sequence, program info, resolved kfunc map, lowered pseudo-load map.
// Writes   : inserts one CFG node per live instruction into builder (labels + instructions).
//            CallBtf is replaced with the resolved Call; non-CODE_ADDR LoadPseudo is replaced
//            with its lowered form; every other instruction is inserted verbatim.
// Throws   : InvalidControlFlow if either substitution map is inconsistent with the sequence
//            (internal error; indicates a missing prior pass).
// Invariant: pass_validate_instruction_support, pass_resolve_kfunc_calls and
//            pass_lower_pseudo_loads have been applied on the same instruction sequence.
static void pass_populate_nodes(CfgBuilder& builder, const InstructionSeq& insts, const ProgramInfo& info,
                                const ResolvedKfuncCalls& resolved_kfunc_calls,
                                const LoweredPseudoLoads& lowered_pseudo_loads) {
    for (const auto& [label, inst, _] : insts) {
        assert(!check_instruction_feature_support(inst, *info.platform).has_value() &&
               "instruction support must be validated before CFG construction");
        if (std::holds_alternative<Undefined>(inst)) {
            continue;
        }
        if (std::holds_alternative<CallBtf>(inst)) {
            const auto it = resolved_kfunc_calls.find(label);
            if (it == resolved_kfunc_calls.end()) {
                throw InvalidControlFlow{"internal error: missing validated kfunc resolution (at " + to_string(label) +
                                         ")"};
            }
            builder.insert(label, it->second);
            continue;
        }
        if (const auto it = lowered_pseudo_loads.find(label); it != lowered_pseudo_loads.end()) {
            builder.insert(label, it->second);
            continue;
        }
        builder.insert(label, inst);
    }
}

// Pass: BuildInitialCfg -- connect_edges step (also performs InsertAssumeEdges).
// Reads    : instruction sequence, must_have_exit flag.
// Writes   : CFG edges from entry, and for every populated node to its successors.
//            Conditional Jmp instructions are materialised as two synthetic Assume
//            jump-labels (insert_jump) carrying the positive and negated conditions.
// Throws   : InvalidControlFlow on empty sequence, fallthrough past the final instruction,
//            or a jump whose target label is not in the CFG.
// Invariant: pass_populate_nodes has been applied (all nodes exist before edges are added).
static void pass_connect_edges(CfgBuilder& builder, const InstructionSeq& insts, const bool must_have_exit) {
    if (insts.empty()) {
        throw InvalidControlFlow{"empty instruction sequence"};
    }
    // Ordering check: pass_populate_nodes must run first so that every non-Undefined label
    // referenced below (the entry's target, jump targets, fallthrough labels) already exists.
    assert(std::holds_alternative<Undefined>(std::get<1>(insts[0])) ||
           builder.prog.cfg().contains(std::get<0>(insts[0])));
    builder.add_child(builder.prog.cfg().entry_label(), std::get<0>(insts[0]));

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
}

// Pass: InlineLocalCalls
// Reads    : instruction sequence, max_call_stack_frames bound.
// Writes   : for every CallLocal in the sequence, clones the callee region into the CFG
//            under a unique stack-frame prefix. Recurses into nested calls.
// Throws   : InvalidControlFlow on illegal recursion or exceeding the call-stack frame bound.
// Invariant: pass_connect_edges has been applied -- inlining walks existing parents/children.
//            Restricted to callees that are reachable after edge connection, which is why
//            this runs as a separate second pass rather than during population.
static void pass_inline_local_calls(CfgBuilder& builder, const InstructionSeq& insts, const int max_call_stack_frames) {
    // Ordering check: pass_connect_edges must have run. When insts is non-empty, its first
    // label has been wired as a child of Label::entry, so entry has at least one successor.
    assert(insts.empty() || !builder.prog.cfg().children_of(Label::entry).empty());
    for (const auto& [label, inst, _] : insts) {
        if (const auto pins = std::get_if<CallLocal>(&inst)) {
            add_cfg_nodes(builder, label, pins->target, max_call_stack_frames);
        }
    }
}

static bool is_tail_call_helper(const Call& call, const ebpf_platform_t& platform,
                                const EbpfProgramType& program_type) {
    if (call.kind != CallKind::helper) {
        return false;
    }
    if (!platform.is_helper_usable(call.func, program_type)) {
        return false;
    }
    return platform.get_helper_prototype(call.func, program_type).return_type ==
           EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED;
}

static bool is_tail_call_site(const Instruction& ins, const ebpf_platform_t& platform,
                              const EbpfProgramType& program_type) {
    if (const auto* call = std::get_if<Call>(&ins)) {
        return is_tail_call_helper(*call, platform, program_type);
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

// Pass: ValidateTailCallDepth
// Reads    : Program (CFG + instructions), Wto, platform, program type.
// Writes   : nothing.
// Throws   : InvalidControlFlow if the reachable tail-call chain exceeds the fixed limit.
// Notes    : Counts tail-call sites along the longest path through the reachable maximal-SCC DAG
//            so cycles do not inflate depth. Maximal SCCs are derived from WTO nesting: labels in
//            the same outermost WTO cycle are mutually reachable and form one maximal SCC.
static void pass_validate_tail_call_depth(const Program& prog, const Wto& wto, const ebpf_platform_t& platform,
                                          const EbpfProgramType& program_type) {
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
        if (is_tail_call_site(prog.instruction_at(label), platform, program_type)) {
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

// Pass: ComputeCallbackMetadata
// Reads    : Program (CFG + instructions).
// Writes   : builder.prog's callback metadata (via CfgBuilder::set_callback_metadata): the set
//            of top-level concrete-instruction labels eligible as PTR_TO_FUNC targets, and the
//            subset whose body can reach a top-level Exit.
// Notes    : Excludes Label::entry/Label::exit, synthetic jump labels, labels under an inlined
//            stack-frame prefix, and Exit instructions themselves. The result is stored on
//            Program, not on ProgramInfo -- it is an analysis-prep fact derived from the CFG,
//            not a loader input.
static void pass_compute_callback_metadata(CfgBuilder& builder) {
    const Program& prog = builder.prog;
    CallbackMetadata md;
    for (const Label& label : prog.labels()) {
        if (label == Label::entry || label == Label::exit || label.isjump() || !label.stack_frame_prefix.empty()) {
            continue;
        }
        if (std::holds_alternative<Exit>(prog.instruction_at(label))) {
            continue;
        }
        md.target_labels.insert(label.from);
    }

    const auto has_reachable_top_level_exit = [&](const Label& start) {
        std::set<Label> seen;
        std::vector<Label> worklist{start};
        while (!worklist.empty()) {
            Label label = worklist.back();
            worklist.pop_back();
            if (seen.contains(label)) {
                continue;
            }
            seen.insert(label);
            if (label == Label::exit) {
                return true;
            }
            if (label != Label::entry && prog.cfg().contains(label) &&
                std::holds_alternative<Exit>(prog.instruction_at(label)) && label.stack_frame_prefix.empty()) {
                return true;
            }
            for (const Label& child : prog.cfg().children_of(label)) {
                worklist.push_back(child);
            }
        }
        return false;
    };
    for (const int32_t label_num : md.target_labels) {
        const Label label{gsl::narrow<int>(label_num)};
        if (has_reachable_top_level_exit(label)) {
            md.targets_with_exit.insert(label_num);
        }
    }
    builder.set_callback_metadata(std::move(md));
}

// Pass: InsertTerminationCounters
// Reads    : WTO of the current CFG.
// Writes   : For each WTO loop head, inserts an IncrementLoopCounter at a synthetic
//            increment-counter label placed between the head and its successors (CFG edges and
//            instructions are both mutated via CfgBuilder::insert_after).
// Notes    : WTO identifies every strongly connected component and its entry point(s), which
//            are the natural locations for counters that help verify program termination.
static void pass_insert_termination_counters(CfgBuilder& builder, const Wto& wto) {
    wto.for_each_loop_head([&](const Label& label) -> void {
        builder.insert_after(label, Label::make_increment_counter(label), IncrementLoopCounter{label});
    });
}

// Pass: ExtractAssertions
// Reads    : Program instructions, ProgramInfo, options.
// Writes   : Populates builder.prog.m_assertions with the per-label precondition vector
//            (memory bounds, type guards, etc.) produced by get_assertions.
// Notes    : Runs for every label in the CFG, including synthetic ones (Assume / counters).
static void pass_extract_assertions(CfgBuilder& builder, const ProgramInfo& info,
                                    const ebpf_verifier_options_t& options) {
    for (const auto& label : builder.prog.labels()) {
        builder.set_assertions(label, get_assertions(builder.prog.instruction_at(label), info, options, label));
    }
}

// from_sequence orchestrates the preparation pipeline. Each pass has a documented
// pre/postcondition; this function's job is just to sequence them and hand the
// result off as a finalised Program.
Program Program::from_sequence(const InstructionSeq& inst_seq, const ProgramInfo& info,
                               const ebpf_verifier_options_t& options) {
    // --- Pass: ValidateOptions --------------------------------------------
    options.validate();
    // Preserves the platform-non-null invariant for every subsequent pass in this pipeline.
    assert(info.platform != nullptr && "info.platform must be set before Program::from_sequence");

    // --- Pass: ValidateInstructionSupport ---------------------------------
    pass_validate_instruction_support(inst_seq, *info.platform);

    // --- Pass: ResolveKfuncCalls ------------------------------------------
    const ResolvedKfuncCalls resolved_kfunc_calls = pass_resolve_kfunc_calls(inst_seq, info);

    // --- Pass: LowerPseudoLoads -------------------------------------------
    const LoweredPseudoLoads lowered_pseudo_loads = pass_lower_pseudo_loads(inst_seq, info);

    // --- Pass: BuildInitialCfg (nodes, then edges with InsertAssumeEdges) -
    CfgBuilder builder;
    pass_populate_nodes(builder, inst_seq, info, resolved_kfunc_calls, lowered_pseudo_loads);
    pass_connect_edges(builder, inst_seq, options.cfg_opts.must_have_exit);

    // --- Pass: InlineLocalCalls -------------------------------------------
    pass_inline_local_calls(builder, inst_seq, options.max_call_stack_frames);

    // --- Pass: ValidateTailCallDepth --------------------------------------
    const Wto wto{builder.prog.cfg()};
    pass_validate_tail_call_depth(builder.prog, wto, *info.platform, info.type);

    // --- Pass: ComputeCallbackMetadata ------------------------------------
    pass_compute_callback_metadata(builder);

    // --- Pass: InsertTerminationCounters ----------------------------------
    if (options.cfg_opts.check_for_termination) {
        pass_insert_termination_counters(builder, wto);
    }

    // --- Pass: ExtractAssertions ------------------------------------------
    pass_extract_assertions(builder, info, options);

    builder.prog.m_info = info;
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

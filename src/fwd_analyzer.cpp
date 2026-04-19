// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include <cassert>
#include <ranges>
#include <utility>
#include <variant>

#include "analysis_context.hpp"
#include "cfg/cfg.hpp"
#include "cfg/wto.hpp"
#include "config.hpp"
#include "crab/ebpf_domain.hpp"
#include "ir/program.hpp"
#include "result.hpp"
#include "verifier.hpp"

namespace prevail {

static void clear_analysis_thread_local_state() { clear_thread_local_state(); }

void ebpf_verifier_clear_thread_local_state() {
    clear_thread_local_state();
    ZoneDomain::clear_thread_local_state();
}

class InterleavedFwdFixpointIterator final {
    const Program& _prog;
    const Cfg& _cfg;
    const Wto _wto;
    const AnalysisContext& context;
    AnalysisResult& result;
    /// Counter Variables for *this* program's loop heads. Computed once
    /// from `_wto`. Used wherever we previously asked the registry "what
    /// loop counters exist?" — that's analysis-specific, not registry data.
    std::vector<Variable> _loop_counters;

    /// number of narrowing iterations. If the narrowing operator is
    /// indeed a narrowing operator this parameter is not
    /// needed. However, there are abstract domains for which an actual
    /// narrowing operation is not available so we must enforce
    /// termination.
    static constexpr unsigned int _descending_iterations = 2000000;

    /// Used to skip the analysis until _entry is found
    bool _skip{true};

    [[nodiscard]]
    bool has_error(const Label& node) const {
        return result.invariants.at(node).error.has_value();
    }

    void set_error(const Label& node, VerificationError&& error) {
        result.failed = true;
        result.invariants.at(node).error = std::move(error);
    }

    void set_pre(const Label& label, EbpfDomain&& v) { result.invariants.at(label).pre = std::move(v); }
    void set_pre(const Label& label, const EbpfDomain& v) { result.invariants.at(label).pre = v; }

    EbpfDomain get_pre(const Label& node) const { return result.invariants.at(node).pre; }

    EbpfDomain get_post(const Label& node) const { return result.invariants.at(node).post; }

    void transform_to_post(const Label& label, EbpfDomain pre) {
        const auto& ins = _prog.instruction_at(label);

        // Dependency extraction intentionally runs on the pre-state *before*
        // ebpf_domain_transform mutates it, because extract_instruction_deps
        // needs the unmodified domain to resolve stack offsets.  We use .at()
        // (result.invariants.at(label).deps) because the entry was already
        // created during initialization.  This must also run before assertion
        // checks so that failing instructions still have deps recorded —
        // compute_failure_slices seeds its backward worklist from them.
        if (context.options.verbosity_opts.collect_instruction_deps) {
            result.invariants.at(label).deps = extract_instruction_deps(ins, pre, context.options.total_stack_size());
        }

        if (!std::holds_alternative<IncrementLoopCounter>(ins)) {
            if (has_error(label)) {
                return;
            }
            for (const auto& assertion : _prog.assertions_at(label)) {
                // Avoid redundant errors.
                if (auto error = ebpf_domain_check(pre, assertion, label, context)) {
                    set_error(label, std::move(*error));
                    return;
                }
            }
        }
        ebpf_domain_transform(pre, ins, context);

        result.invariants.at(label).post = std::move(pre);
    }

    EbpfDomain join_all_prevs(const Label& node) const {
        if (node == _cfg.entry_label()) {
            return get_pre(node);
        }
        EbpfDomain res = EbpfDomain::bottom();
        for (const Label& prev : _cfg.parents_of(node)) {
            res |= get_post(prev);
        }
        return res;
    }

    explicit InterleavedFwdFixpointIterator(const Program& prog, const AnalysisContext& context, AnalysisResult& result)
        : _prog(prog), _cfg(prog.cfg()), _wto(prog.cfg()), context(context), result(result) {
        for (const auto& label : _cfg.labels()) {
            result.invariants.emplace(label, InvariantMapPair{EbpfDomain::bottom(), {}, EbpfDomain::bottom()});
        }
        if (context.options.cfg_opts.check_for_termination) {
            _wto.for_each_loop_head([&](const Label& label) {
                _loop_counters.push_back(variable_registry.loop_counter(to_string(label)));
            });
        }
    }

    static std::optional<VerificationError> check_loop_bound(const Program& prog, const Label& label,
                                                             const EbpfDomain& pre, const AnalysisContext& context) {
        if (std::holds_alternative<IncrementLoopCounter>(prog.instruction_at(label))) {
            const auto assertions = prog.assertions_at(label);
            if (assertions.size() != 1) {
                CRAB_ERROR("Expected exactly 1 assertion for IncrementLoopCounter");
            }
            return ebpf_domain_check(pre, assertions.front(), label, context);
        }
        return {};
    }

    void find_termination_errors(const Program& prog) {
        for (const auto& [label, inv_pair] : result.invariants) {
            if (inv_pair.pre.is_bottom()) {
                continue;
            }
            if (auto error = check_loop_bound(prog, label, inv_pair.pre, context)) {
                set_error(label, std::move(*error));
            }
        }
    }

    int max_loop_count() const {
        ExtendedNumber loop_count{0};
        // Gather the upper bound of loop counts from post-invariants.
        for (const auto& inv_pair : std::views::values(result.invariants)) {
            loop_count = std::max(loop_count, inv_pair.post.get_loop_count_upper_bound(_loop_counters));
        }
        const auto m = loop_count.number();
        if (m && m->fits<int32_t>()) {
            return m->cast_to<int32_t>();
        }
        return std::numeric_limits<int>::max();
    }

  public:
    void operator()(const Label& node);

    void operator()(const std::shared_ptr<WtoCycle>& cycle);

    static AnalysisResult run(const Program& prog, const AnalysisContext& context, EbpfDomain entry_inv);
};

static AnalysisContext make_context(const Program& prog, const ebpf_verifier_options_t& options) {
    const auto& info = prog.info();
    return AnalysisContext{info, options, *info.platform};
}

AnalysisResult analyze(const Program& prog, const ebpf_verifier_options_t& options) {
    return analyze(prog, make_context(prog, options));
}

AnalysisResult analyze(const Program& prog, const StringInvariant& entry_invariant,
                       const ebpf_verifier_options_t& options) {
    return analyze(prog, entry_invariant, make_context(prog, options));
}

AnalysisResult analyze(const Program& prog, const AnalysisContext& context) {
    clear_analysis_thread_local_state();
    return InterleavedFwdFixpointIterator::run(prog, context,
                                               EbpfDomain::setup_entry(context.options.setup_constraints, context));
}

AnalysisResult analyze(const Program& prog, const StringInvariant& entry_invariant, const AnalysisContext& context) {
    clear_analysis_thread_local_state();
    return InterleavedFwdFixpointIterator::run(
        prog, context,
        EbpfDomain::from_constraints(entry_invariant.value(), context.options.setup_constraints, context));
}

static EbpfDomain extrapolate(const EbpfDomain& before, const EbpfDomain& after, const unsigned int iteration,
                              const AnalysisContext& context, const std::span<const Variable> loop_counters) {
    /// number of iterations until triggering widening
    constexpr auto _widening_delay = 2;

    if (iteration < _widening_delay) {
        return before | after;
    }
    return before.widen(after, iteration == _widening_delay, context, loop_counters);
}

static EbpfDomain refine(const EbpfDomain& before, const EbpfDomain& after, const unsigned int iteration) {
    if (iteration == 1) {
        return before & after;
    } else {
        return before.narrow(after);
    }
}

void InterleavedFwdFixpointIterator::operator()(const Label& node) {
    /** decide whether skip vertex or not **/
    if (_skip && node == _cfg.entry_label()) {
        _skip = false;
    }
    if (_skip) {
        return;
    }

    EbpfDomain pre = join_all_prevs(node);

    set_pre(node, pre);
    transform_to_post(node, std::move(pre));
}

void InterleavedFwdFixpointIterator::operator()(const std::shared_ptr<WtoCycle>& cycle) {
    const Label head = cycle->head();

    /** decide whether to skip cycle or not **/
    bool entry_in_this_cycle = false;
    if (_skip) {
        // We only skip the analysis of cycle if entry_label is not a
        // component of it, included nested components.
        entry_in_this_cycle = is_component_member(_cfg.entry_label(), cycle);
        _skip = !entry_in_this_cycle;
        if (_skip) {
            return;
        }
    }

    EbpfDomain invariant = EbpfDomain::bottom();
    if (entry_in_this_cycle) {
        invariant = get_pre(_cfg.entry_label());
    } else {
        const WtoNesting cycle_nesting = _wto.nesting(head);
        for (const Label& prev : _cfg.parents_of(head)) {
            if (!(_wto.nesting(prev) > cycle_nesting)) {
                invariant |= get_post(prev);
            }
        }
    }

    for (unsigned int iteration = 1;; ++iteration) {
        // Increasing iteration sequence with widening
        set_pre(head, invariant);
        transform_to_post(head, invariant);
        for (const auto& component : *cycle) {
            const auto plabel = std::get_if<Label>(&component);
            if (!plabel || *plabel != head) {
                std::visit(*this, component);
            }
        }
        EbpfDomain new_pre = join_all_prevs(head);
        if (new_pre <= invariant) {
            // Post-fixpoint reached
            set_pre(head, new_pre);
            invariant = std::move(new_pre);
            break;
        } else {
            invariant = extrapolate(invariant, new_pre, iteration, context, _loop_counters);
        }
    }

    for (unsigned int iteration = 1;; ++iteration) {
        // Decreasing iteration sequence with narrowing
        transform_to_post(head, invariant);

        for (const auto& component : *cycle) {
            const auto plabel = std::get_if<Label>(&component);
            if (!plabel || *plabel != head) {
                std::visit(*this, component);
            }
        }
        EbpfDomain new_pre = join_all_prevs(head);
        if (invariant <= new_pre) {
            // No more refinement possible(pre == new_pre)
            break;
        } else {
            if (iteration > _descending_iterations) {
                break;
            }
            invariant = refine(invariant, std::move(new_pre), iteration);
            set_pre(head, std::move(invariant));
        }
    }
}
AnalysisResult InterleavedFwdFixpointIterator::run(const Program& prog, const AnalysisContext& context,
                                                   EbpfDomain entry_inv) {
    // Go over the CFG in weak topological order (accounting for loops).
    AnalysisResult result;
    InterleavedFwdFixpointIterator analyzer(prog, context, result);
    if (context.options.cfg_opts.check_for_termination) {
        // Initialize loop counters for potential loop headers.
        // This enables enforcement of upper bounds on loop iterations
        // during program verification.
        // TODO: Consider making this an instruction instead of an explicit call.
        analyzer._wto.for_each_loop_head(
            [&](const Label& label) { ebpf_domain_initialize_loop_counter(entry_inv, label, context); });
    }
    analyzer.set_pre(prog.cfg().entry_label(), std::move(entry_inv));
    for (const auto& component : analyzer._wto) {
        std::visit(analyzer, component);
    }
    if (!result.failed && context.options.cfg_opts.check_for_termination) {
        analyzer.find_termination_errors(prog);
        if (!result.failed) {
            result.max_loop_count = analyzer.max_loop_count();
        }
    }
    result.exit_value = analyzer.get_post(Label::exit).get_r0();
    return result;
}

} // namespace prevail

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include <utility>
#include <variant>

#include "cfg/cfg.hpp"
#include "cfg/wto.hpp"
#include "config.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"
#include "program.hpp"

namespace prevail {

class InterleavedFwdFixpointIterator final {
    const Program& _prog;
    const Cfg& _cfg;
    const Wto _wto;
    InvariantTable _inv;

    /// number of narrowing iterations. If the narrowing operator is
    /// indeed a narrowing operator this parameter is not
    /// needed. However, there are abstract domains for which an actual
    /// narrowing operation is not available so we must enforce
    /// termination.
    static constexpr unsigned int _descending_iterations = 2000000;

    /// Used to skip the analysis until _entry is found
    bool _skip{true};

    void set_pre(const Label& label, const EbpfDomain& v) { _inv.at(label).pre = v; }

    EbpfDomain get_pre(const Label& node) const { return _inv.at(node).pre; }

    EbpfDomain get_post(const Label& node) const { return _inv.at(node).post; }

    void transform_to_post(const Label& label, EbpfDomain pre) {
        if (_inv.at(label).error) {
            return;
        }
        for (const auto& assertion : _prog.assertions_at(label)) {
            // Avoid redundant errors.
            if (auto error = ebpf_domain_check(pre, assertion)) {
                _inv.at(label).error = std::move(error);
                return;
            }
        }
        ebpf_domain_transform(pre, _prog.instruction_at(label));

        _inv.at(label).post = std::move(pre);
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

    explicit InterleavedFwdFixpointIterator(const Program& prog) : _prog(prog), _cfg(prog.cfg()), _wto(prog.cfg()) {
        for (const auto& label : _cfg.labels()) {
            _inv.emplace(label, InvariantMapPair{EbpfDomain::bottom(), {}, EbpfDomain::bottom()});
        }
    }

  public:
    void operator()(const Label& node);

    void operator()(const std::shared_ptr<WtoCycle>& cycle);

    friend InvariantTable run_forward_analyzer(const Program& prog, EbpfDomain entry_inv);
};

InvariantTable run_forward_analyzer(const Program& prog, EbpfDomain entry_inv) {
    // Go over the CFG in weak topological order (accounting for loops).
    InterleavedFwdFixpointIterator analyzer(prog);
    if (thread_local_options.cfg_opts.check_for_termination) {
        // Initialize loop counters for potential loop headers.
        // This enables enforcement of upper bounds on loop iterations
        // during program verification.
        // TODO: Consider making this an instruction instead of an explicit call.
        analyzer._wto.for_each_loop_head(
            [&](const Label& label) { ebpf_domain_initialize_loop_counter(entry_inv, label); });
    }
    analyzer.set_pre(prog.cfg().entry_label(), entry_inv);
    for (const auto& component : analyzer._wto) {
        std::visit(analyzer, component);
    }
    return std::move(analyzer._inv);
}

static EbpfDomain extrapolate(const EbpfDomain& before, const EbpfDomain& after, const unsigned int iteration) {
    /// number of iterations until triggering widening
    constexpr auto _widening_delay = 2;

    if (iteration < _widening_delay) {
        return before | after;
    }
    return before.widen(after, iteration == _widening_delay);
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
            invariant = extrapolate(invariant, std::move(new_pre), iteration);
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
            set_pre(head, invariant);
        }
    }
}

} // namespace prevail

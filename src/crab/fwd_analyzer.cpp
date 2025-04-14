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

class interleaved_fwd_fixpoint_iterator_t final {
    const Program& _prog;
    const cfg_t& _cfg;
    const wto_t _wto;
    invariant_table_t _inv;

    /// number of narrowing iterations. If the narrowing operator is
    /// indeed a narrowing operator this parameter is not
    /// needed. However, there are abstract domains for which an actual
    /// narrowing operation is not available so we must enforce
    /// termination.
    static constexpr unsigned int _descending_iterations = 2000000;

    /// Used to skip the analysis until _entry is found
    bool _skip{true};

    void set_pre(const label_t& label, const ebpf_domain_t& v) { _inv.at(label).pre = v; }

    ebpf_domain_t get_pre(const label_t& node) const { return _inv.at(node).pre; }

    ebpf_domain_t get_post(const label_t& node) const { return _inv.at(node).post; }

    void transform_to_post(const label_t& label, ebpf_domain_t pre) {
        if (thread_local_options.assume_assertions) {
            for (const auto& assertion : _prog.assertions_at(label)) {
                // avoid redundant errors
                ebpf_domain_assume(pre, assertion);
            }
        }
        ebpf_domain_transform(pre, _prog.instruction_at(label));

        _inv.at(label).post = std::move(pre);
    }

    ebpf_domain_t join_all_prevs(const label_t& node) const {
        if (node == _cfg.entry_label()) {
            return get_pre(node);
        }
        ebpf_domain_t res = ebpf_domain_t::bottom();
        for (const label_t& prev : _cfg.parents_of(node)) {
            res |= get_post(prev);
        }
        return res;
    }

    explicit interleaved_fwd_fixpoint_iterator_t(const Program& prog)
        : _prog(prog), _cfg(prog.cfg()), _wto(prog.cfg()) {
        for (const auto& label : _cfg.labels()) {
            _inv.emplace(label, invariant_map_pair{ebpf_domain_t::bottom(), ebpf_domain_t::bottom()});
        }
    }

  public:
    void operator()(const label_t& node);

    void operator()(const std::shared_ptr<wto_cycle_t>& cycle);

    friend invariant_table_t run_forward_analyzer(const Program& prog, ebpf_domain_t entry_inv);
};

invariant_table_t run_forward_analyzer(const Program& prog, ebpf_domain_t entry_inv) {
    // Go over the CFG in weak topological order (accounting for loops).
    interleaved_fwd_fixpoint_iterator_t analyzer(prog);
    if (thread_local_options.cfg_opts.check_for_termination) {
        // Initialize loop counters for potential loop headers.
        // This enables enforcement of upper bounds on loop iterations
        // during program verification.
        // TODO: Consider making this an instruction instead of an explicit call.
        analyzer._wto.for_each_loop_head(
            [&](const label_t& label) { ebpf_domain_initialize_loop_counter(entry_inv, label); });
    }
    analyzer.set_pre(prog.cfg().entry_label(), entry_inv);
    for (const auto& component : analyzer._wto) {
        std::visit(analyzer, component);
    }
    return std::move(analyzer._inv);
}

static ebpf_domain_t extrapolate(const ebpf_domain_t& before, const ebpf_domain_t& after,
                                 const unsigned int iteration) {
    /// number of iterations until triggering widening
    constexpr auto _widening_delay = 2;

    if (iteration < _widening_delay) {
        return before | after;
    }
    return before.widen(after, iteration == _widening_delay);
}

static ebpf_domain_t refine(const ebpf_domain_t& before, const ebpf_domain_t& after, const unsigned int iteration) {
    if (iteration == 1) {
        return before & after;
    } else {
        return before.narrow(after);
    }
}

void interleaved_fwd_fixpoint_iterator_t::operator()(const label_t& node) {
    /** decide whether skip vertex or not **/
    if (_skip && node == _cfg.entry_label()) {
        _skip = false;
    }
    if (_skip) {
        return;
    }

    ebpf_domain_t pre = join_all_prevs(node);

    set_pre(node, pre);
    transform_to_post(node, std::move(pre));
}

void interleaved_fwd_fixpoint_iterator_t::operator()(const std::shared_ptr<wto_cycle_t>& cycle) {
    const label_t head = cycle->head();

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

    ebpf_domain_t invariant = ebpf_domain_t::bottom();
    if (entry_in_this_cycle) {
        invariant = get_pre(_cfg.entry_label());
    } else {
        const wto_nesting_t cycle_nesting = _wto.nesting(head);
        for (const label_t& prev : _cfg.parents_of(head)) {
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
            const auto plabel = std::get_if<label_t>(&component);
            if (!plabel || *plabel != head) {
                std::visit(*this, component);
            }
        }
        ebpf_domain_t new_pre = join_all_prevs(head);
        if (new_pre <= invariant) {
            // Post-fixpoint reached
            set_pre(head, new_pre);
            invariant = std::move(new_pre);
            break;
        } else {
            invariant = extrapolate(invariant, new_pre, iteration);
        }
    }

    for (unsigned int iteration = 1;; ++iteration) {
        // Decreasing iteration sequence with narrowing
        transform_to_post(head, invariant);

        for (const auto& component : *cycle) {
            const auto plabel = std::get_if<label_t>(&component);
            if (!plabel || *plabel != head) {
                std::visit(*this, component);
            }
        }
        ebpf_domain_t new_pre = join_all_prevs(head);
        if (invariant <= new_pre) {
            // No more refinement possible(pre == new_pre)
            break;
        } else {
            if (iteration > _descending_iterations) {
                break;
            }
            invariant = refine(invariant, new_pre, iteration);
            set_pre(head, invariant);
        }
    }
}

} // namespace prevail

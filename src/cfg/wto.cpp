// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <map>
#include <ranges>
#include <variant>

#include "cfg/cfg.hpp"
#include "cfg/label.hpp"
#include "cfg/wto.hpp"

// This file contains an iterative implementation of the recursive algorithm in
// Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993
// http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.38.3574
// where _visit_stack is roughly equivalent to a stack trace in the recursive algorithm.
// However, this scales much higher since it does not run out of stack memory.

namespace prevail {

bool is_component_member(const Label& label, const CycleOrLabel& component) {
    if (const auto plabel = std::get_if<Label>(&component)) {
        return *plabel == label;
    }
    const auto cycle = std::get<std::shared_ptr<WtoCycle>>(component);
    if (cycle->head() == label) {
        return true;
    }
    for (const auto& sub_component : *cycle) {
        if (is_component_member(label, sub_component)) {
            return true;
        }
    }
    return false;
}

bool WtoNesting::operator>(const WtoNesting& nesting) const {
    const size_t this_size = this->_heads.size();
    const size_t other_size = nesting._heads.size();
    if (this_size <= other_size) {
        // Can't be a superset.
        return false;
    }

    // Compare entries one at a time starting from the outermost
    // (i.e., end of the vectors).
    for (size_t index = 0; index < other_size; index++) {
        if (this->_heads[this_size - 1 - index] != nesting._heads[other_size - 1 - index]) {
            return false;
        }
    }
    return true;
}

enum class VisitTaskType {
    PushSuccessors = 0,
    StartVisit = 1, // Start of the Visit() function defined in Figure 4 of the paper.
    ContinueVisit = 2,
};

struct VisitArgs {
    VisitTaskType type;
    Label vertex;
    WtoPartition& partition;
    std::weak_ptr<WtoCycle> containing_cycle;

    VisitArgs(const VisitTaskType t, Label v, WtoPartition& p, std::weak_ptr<WtoCycle> cc)
        : type(t), vertex(std::move(v)), partition(p), containing_cycle(std::move(cc)) {}
};

struct WtoVertexData {
    // Bourdoncle's thesis (reference [4]) is all in French but expands
    // DFN as "depth first number".
    int dfn{};
    int head_dfn{}; // Head value returned from Visit() in the paper.

    std::shared_ptr<WtoCycle> containing_cycle;
};
constexpr static int DFN_INF = std::numeric_limits<decltype(WtoVertexData::dfn)>::max();

class WtoBuilder final {
    // Original control-flow graph.
    const Cfg& _cfg;

    // The following members are named to match the names in the paper.
    std::map<Label, WtoVertexData> _vertex_data;
    int _num; // Highest DFN used so far.
    std::stack<Label> _stack;

    std::stack<VisitArgs> _visit_stack;

    void push_successors(const Label& vertex, WtoPartition& partition, const std::weak_ptr<WtoCycle>& containing_cycle);
    void start_visit(const Label& vertex, WtoPartition& partition, const std::weak_ptr<WtoCycle>& containing_cycle);
    void continue_visit(const Label& vertex, WtoPartition& partition, const std::weak_ptr<WtoCycle>& containing_cycle);

  public:
    Wto wto;
    // Construct a Weak Topological Ordering from a control-flow graph using
    // the algorithm of figure 4 in the paper, where this constructor matches
    // what is shown there as the Partition function.
    explicit WtoBuilder(const Cfg& cfg);
};

void WtoBuilder::push_successors(const Label& vertex, WtoPartition& partition,
                                 const std::weak_ptr<WtoCycle>& containing_cycle) {
    if (_vertex_data[vertex].dfn != 0) {
        // We found an alternate path to a node already visited, so nothing to do.
        return;
    }
    _vertex_data[vertex].dfn = ++_num;
    _stack.push(vertex);

    // Schedule the next task for this vertex once we're done with anything else.
    _visit_stack.emplace(VisitTaskType::StartVisit, vertex, partition, containing_cycle);

    for (const Label& succ : std::ranges::reverse_view(_cfg.children_of(vertex))) {
        if (_vertex_data[succ].dfn == 0) {
            _visit_stack.emplace(VisitTaskType::PushSuccessors, succ, partition, containing_cycle);
        }
    }
}

void WtoBuilder::start_visit(const Label& vertex, WtoPartition& partition,
                             const std::weak_ptr<WtoCycle>& containing_cycle) {
    WtoVertexData& vertex_data = _vertex_data[vertex];
    int head_dfn = vertex_data.dfn;
    bool loop = false;
    for (const Label& succ : _cfg.children_of(vertex)) {
        const WtoVertexData& data = _vertex_data[succ];
        int min_dfn = data.dfn;
        if (data.head_dfn != 0 && data.dfn != DFN_INF) {
            min_dfn = data.head_dfn;
        }
        if (min_dfn <= head_dfn) {
            head_dfn = min_dfn;
            loop = true;
        }
    }

    // Create a new cycle component inside the containing cycle.
    const auto cycle = std::make_shared<WtoCycle>(containing_cycle);

    if (head_dfn == vertex_data.dfn) {
        vertex_data.dfn = DFN_INF;
        Label element = _stack.top();
        _stack.pop();
        if (loop) {
            while (element != vertex) {
                _vertex_data[element].dfn = 0;
                _vertex_data[element].head_dfn = 0;
                element = _stack.top();
                _stack.pop();
            }
            vertex_data.head_dfn = head_dfn;

            // Stash a reference to the cycle.
            _vertex_data[vertex].containing_cycle = cycle;

            // Schedule the next task for this vertex once we're done with anything else.
            _visit_stack.emplace(VisitTaskType::ContinueVisit, vertex, partition, cycle);

            // Walk the control flow graph, adding nodes to this cycle.
            // This is the Component() function described in figure 4 of the paper.
            for (const Label& succ : std::ranges::reverse_view(_cfg.children_of(vertex))) {
                if (_vertex_data.at(succ).dfn == 0) {
                    _visit_stack.emplace(VisitTaskType::PushSuccessors, succ, cycle->_components, cycle);
                }
            }
            return;
        }
        // Insert a new vertex component vertex into the current partition.
        partition.emplace_back(vertex);

        // Remember that we put the vertex into the caller's cycle.
        wto._containing_cycle.emplace(vertex, containing_cycle);
    }
    vertex_data.head_dfn = head_dfn;
}

void WtoBuilder::continue_visit(const Label& vertex, WtoPartition& partition,
                                const std::weak_ptr<WtoCycle>& containing_cycle) {
    // Add the vertex at the start of the cycle
    // (end of the vector which stores the cycle in reverse order).
    auto cycle = containing_cycle.lock();

    cycle->_components.push_back(vertex);

    // Insert the component into the current partition.
    partition.emplace_back(cycle);

    // Remember that we put the vertex into the new cycle.
    wto._containing_cycle.emplace(vertex, cycle);
}

WtoBuilder::WtoBuilder(const Cfg& cfg) : _cfg(cfg) {
    // Create a map for holding a "depth-first number (DFN)" for each vertex.
    for (const Label& label : cfg.labels()) {
        _vertex_data.emplace(label, 0);
    }

    // Initialize the DFN counter.
    _num = 0;

    // Push the entry vertex on the stack to process.
    _visit_stack.emplace(VisitArgs(VisitTaskType::PushSuccessors, cfg.entry_label(), wto._components, {}));

    // Keep processing tasks until we're done.
    while (!_visit_stack.empty()) {
        VisitArgs args2 = _visit_stack.top();
        _visit_stack.pop();
        switch (args2.type) {
        case VisitTaskType::PushSuccessors:
            push_successors(args2.vertex, args2.partition, args2.containing_cycle);
            break;
        case VisitTaskType::StartVisit: start_visit(args2.vertex, args2.partition, args2.containing_cycle); break;
        case VisitTaskType::ContinueVisit: continue_visit(args2.vertex, args2.partition, args2.containing_cycle); break;
        default: break;
        }
    }
}

class PrintVisitor {
    std::ostream& o;

  public:
    explicit PrintVisitor(std::ostream& o) : o(o) {}

    void operator()(const Label& label) { o << label; }

    void operator()(const WtoCycle& cycle) {
        o << "( ";
        for (const auto& component : cycle) {
            std::visit(*this, component);
            o << " ";
        }
        o << ")";
    }

    void operator()(const std::shared_ptr<WtoCycle>& e) {
        if (e != nullptr) {
            (*this)(*e);
        }
    }

    void operator()(const WtoPartition& partition) {
        for (const auto& p : std::ranges::reverse_view(partition)) {
            std::visit(*this, p);
            o << " ";
        }
    }

    // Output the nesting in order from outermost to innermost.
    void operator()(const WtoNesting& nesting) {
        for (const auto& _head : std::ranges::reverse_view(nesting._heads)) {
            o << _head << " ";
        }
    }
};

std::ostream& operator<<(std::ostream& o, const Wto& wto) {
    PrintVisitor{o}(wto._components);
    return o << std::endl;
}

// Get the vertex at the head of the component containing a given
// label, as discussed in section 4.2 of the paper.  If the label
// is itself a head of a component, we want the head of whatever
// contains that entire component.  Returns nullopt if the label is
// not nested, i.e., the head is logically the entry point of the CFG.
std::optional<Label> Wto::head(const Label& label) const {
    const auto it = _containing_cycle.find(label);
    if (it == _containing_cycle.end()) {
        // Label is not in any cycle.
        return {};
    }
    const std::shared_ptr<WtoCycle> cycle = it->second.lock();
    if (cycle == nullptr) {
        return {};
    }
    if (const Label& first = cycle->head(); first != label) {
        // Return the head of the cycle the label is inside.
        return first;
    }

    // This label is already the head of a cycle, so get the cycle's parent.
    if (const auto parent = cycle->_containing_cycle.lock()) {
        return parent->head();
    }
    return {};
}

Wto::Wto(const Cfg& cfg) : Wto{std::move(WtoBuilder(cfg).wto)} {}

std::vector<Label> Wto::collect_heads(const Label& label) const {
    std::vector<Label> heads;
    for (auto h = head(label); h; h = head(*h)) {
        heads.push_back(*h);
    }
    return heads;
}

// Compute the set of heads of the nested components containing a given label.
// See section 3.1 of the paper for discussion, which uses the notation w(c).
const WtoNesting& Wto::nesting(const Label& label) const {
    if (!_nesting.contains(label)) {
        // Not found in the cache yet, so construct the list of heads of the
        // nested components containing the label, stored in reverse order.
        _nesting.emplace(label, collect_heads(label));
    }
    return _nesting.at(label);
}
} // namespace prevail

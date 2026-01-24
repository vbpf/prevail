# Control Flow Graph

This document describes CFG construction and weak topological ordering in Prevail.

## CFG Structure

**Files**: `src/cfg/cfg.hpp`, `src/ir/cfg_builder.cpp`

The CFG represents program control flow:

```cpp
struct Cfg {
    std::map<Label, Adjacent> neighbours;
    
    struct Adjacent {
        std::set<Label> parents;    // Predecessor nodes
        std::set<Label> children;   // Successor nodes
    };
};

struct Program {
    Cfg m_cfg;
    std::map<Label, Instruction> m_instructions;
    std::map<Label, std::vector<Assertion>> m_assertions;
};
```

### Special Labels

- `Label::entry` (-1): Virtual entry node, predecessor of first instruction
- `Label::exit` (INT_MAX): Virtual exit node, successor of all exit instructions

## CFG Construction

The CFG builder processes instructions in two passes:

### Pass 1: Node Creation

```cpp
void build_cfg(const InstructionSeq& insts) {
    // Add entry edge
    cfg.add_edge(Label::entry, first_label);
    
    // Create node for each instruction
    for (auto& [label, inst] : insts) {
        instructions[label] = inst;
        cfg.add_node(label);
    }
}
```

### Pass 2: Edge Creation

```cpp
void connect_edges(const InstructionSeq& insts) {
    for (auto& [label, inst] : insts) {
        if (is_exit(inst)) {
            cfg.add_edge(label, Label::exit);
        } else if (is_unconditional_jump(inst)) {
            cfg.add_edge(label, inst.target);
        } else if (is_conditional_jump(inst)) {
            // Create two edges: taken and fallthrough
            Label taken = make_jump_label(label, inst.target);
            Label fallthrough = make_jump_label(label, next_label);
            
            cfg.add_edge(label, taken);
            cfg.add_edge(label, fallthrough);
            cfg.add_edge(taken, inst.target);
            cfg.add_edge(fallthrough, next_label);
            
            // Insert Assume instructions
            instructions[taken] = Assume{inst.condition, true};
            instructions[fallthrough] = Assume{reverse(inst.condition), true};
        } else {
            // Sequential flow
            cfg.add_edge(label, next_label);
        }
    }
}
```

## Conditional Jump Transformation

Conditional jumps are split into separate paths:

**Before**:
```
5: if (r1 > 0) goto 10
6: mov r0, 0
```

**After**:
```
       ┌──────────────┐
       │  5: jgt r1,0 │
       └──────┬───────┘
              │
     ┌────────┴────────┐
     │                 │
     ▼                 ▼
┌─────────────┐  ┌─────────────┐
│ 5:10 Assume │  │ 5:6 Assume  │
│ (r1 > 0)    │  │ (r1 <= 0)   │
└──────┬──────┘  └──────┬──────┘
       │                │
       ▼                ▼
┌─────────────┐  ┌─────────────┐
│ 10: ...     │  │ 6: mov r0,0 │
└─────────────┘  └─────────────┘
```

The intermediate `Assume` nodes ensure branch conditions are reflected in the abstract state.

## Function Inlining

Local function calls (`CallLocal`) are inlined with stack frame prefixes:

```cpp
void inline_function(Label call_site, Label target) {
    string prefix = to_string(call_site) + "/";
    
    // Clone all instructions with prefixed labels
    for (auto& [label, inst] : function_body) {
        Label new_label = prefix + label;
        instructions[new_label] = inst;
    }
    
    // Connect call site to function entry
    cfg.add_edge(call_site, prefix + function_entry);
    
    // Connect function exit to instruction after call
    cfg.add_edge(prefix + function_exit, next_label(call_site));
}
```

## Basic Block Simplification

Basic blocks can be merged for efficiency:

```cpp
BasicBlock collect_basic_blocks(bool simplify) {
    if (!simplify) {
        // Each instruction is its own block
        return single_instruction_blocks();
    }
    
    // Merge sequential instructions
    for (label in cfg.nodes()) {
        if (can_merge_with_next(label)) {
            merge_into_block(label, next_label);
        }
    }
}

bool can_merge_with_next(Label label) {
    return cfg.children(label).size() == 1 &&
           cfg.parents(next).size() == 1 &&
           next != Label::exit;
}
```

## Weak Topological Ordering (WTO)

**File**: `src/cfg/wto.hpp`, `src/cfg/wto.cpp`

WTO provides an efficient iteration order for fixpoint computation.

### The Problem

Consider this CFG with nested loops:

```
1 → 2 → 3 → 4 → 5 → 6 → exit
    ↑   ↓   ↑       │
    └───┘   └───────┘
```

Naive iteration might process nodes in order 1,2,3,4,5,6, but:
- Node 3 depends on node 2 (back edge)
- Node 4 depends on node 5 (back edge)

We need to iterate inner loops to fixpoint before outer loops.

### WTO Representation

WTO represents this as:

```
1 (2 3) (4 5 6) exit

Where:
- (2 3) is a component with head 2
- (4 5 6) is a component with head 4
- Parentheses denote strongly connected components
```

More complex nesting:

```
1 (2 (3 4) 5) 6

Means:
- Outer loop: 2,3,4,5 with head 2
- Inner loop: 3,4 with head 3
- Process inner loop to fixpoint, then outer loop
```

### Bourdoncle's Algorithm

The algorithm identifies SCCs hierarchically:

```cpp
class WtoBuilder {
    int num = 0;
    stack<Label> S;
    map<Label, int> dfn;
    map<Label, int> head;
    
    void visit(Label v) {
        S.push(v);
        dfn[v] = head[v] = ++num;
        
        for (Label w : successors(v)) {
            if (dfn[w] == 0) {
                visit(w);
            }
            head[v] = min(head[v], dfn[w]);
        }
        
        if (head[v] == dfn[v]) {
            // v is the head of an SCC
            wto.add_component(v);
            
            // Pop and recursively process SCC members
            while (S.top() != v) {
                Label w = S.pop();
                component(w);  // Recursive decomposition
            }
            S.pop();
        }
    }
};
```

### WTO Nesting

Each node tracks its nesting—the loop heads containing it:

```cpp
struct WtoNesting {
    std::vector<Label> heads;  // Innermost to outermost
    
    Label head() const {
        return heads.empty() ? Label::entry : heads.front();
    }
};
```

Example:
```
Node 3 in (2 (3 4) 5):
  nesting = [3, 2]  // head=3, contained in head=2
```

### Iteration with WTO

The fixpoint iterator uses WTO:

```cpp
void iterate() {
    for (WtoElement elem : wto) {
        if (elem.is_vertex()) {
            process_node(elem.vertex);
        } else {
            // elem is a component
            do {
                changed = false;
                for (Label node : elem.component) {
                    if (process_node(node)) {
                        changed = true;
                    }
                }
            } while (changed);
        }
    }
}
```

### Widening at Loop Heads

Widening is applied only at loop heads:

```cpp
void apply_widening(Label node, EbpfDomain& pre, int iteration) {
    if (is_loop_head(node) && iteration >= WIDENING_THRESHOLD) {
        pre = old_pre.widen(pre);
    }
}

bool is_loop_head(Label node) {
    return wto.get_nesting(node).head() == node;
}
```

## Loop Termination

Loop heads get `IncrementLoopCounter` instructions:

```cpp
void insert_loop_counters(Program& prog) {
    wto.for_each_loop_head([&](Label head) {
        prog.insert_before(head, IncrementLoopCounter{head});
    });
}
```

The checker verifies bounded iteration:

```cpp
void check_loop_bound(const IncrementLoopCounter& inc) {
    if (loop_count[inc.label] > MAX_LOOP_COUNT) {
        throw VerificationError("loop may not terminate");
    }
}
```

## CFG Queries

Common CFG operations:

```cpp
// Get predecessors
std::set<Label> predecessors(Label node) {
    return cfg.neighbours[node].parents;
}

// Get successors
std::set<Label> successors(Label node) {
    return cfg.neighbours[node].children;
}

// Check if edge exists
bool has_edge(Label from, Label to) {
    return cfg.neighbours[from].children.contains(to);
}

// Get all nodes in reverse postorder
std::vector<Label> reverse_postorder() {
    // Useful for forward dataflow analysis
    return wto.linearize();
}
```

## Example

```asm
0: mov r0, 0
1: mov r1, 10
2: jge r1, r0, 5    ; loop head
3: add r0, 1
4: ja 2             ; back edge
5: exit
```

**CFG**:
```
entry → 0 → 1 → 2 ─→ 2:5 → 5 → exit
               ↑ ←─ 4 ← 3
               └────────┘
                  (loop)
```

**WTO**: `entry 0 1 (2 2:3 3 4) 2:5 5 exit`

**Nesting**:
- Nodes 0, 1, 5: nesting = []
- Nodes 2, 3, 4: nesting = [2] (head is 2)

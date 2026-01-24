# Abstract Domains

This document describes the abstract domain hierarchy used in Prevail.

## Domain Hierarchy

Prevail uses a composite domain structure:

```
EbpfDomain
├── TypeToNumDomain (Reduced Cardinal Power)
│   ├── TypeDomain (pointer type tracking)
│   └── NumAbsDomain (numeric constraints)
│       └── FiniteDomain
│           └── SplitDBM (Difference Bound Matrix)
└── ArrayDomain (stack memory modeling)
```

## EbpfDomain

**File**: `src/crab/ebpf_domain.hpp`

The top-level domain combining all tracking:

```cpp
struct EbpfDomain {
    TypeToNumDomain rcp;   // Type + numeric tracking per register
    ArrayDomain stack;      // Stack memory model
    
    // Domain operations
    EbpfDomain operator|(const EbpfDomain&) const;  // Join
    EbpfDomain operator&(const EbpfDomain&) const;  // Meet
    EbpfDomain widen(const EbpfDomain&) const;
    EbpfDomain narrow(const EbpfDomain&) const;
    bool operator<=(const EbpfDomain&) const;       // Ordering
};
```

### Entry State Setup

```cpp
EbpfDomain EbpfDomain::setup_entry(bool check_termination) {
    EbpfDomain inv;
    
    // R1 = context pointer
    inv.assign_type(R1, T_CTX);
    inv.assign(R1.ctx_offset, 0);
    
    // R10 = stack frame pointer
    inv.assign_type(R10, T_STACK);
    inv.assign(R10.stack_offset, EBPF_TOTAL_STACK_SIZE);
    
    // R0, R2-R9 = uninitialized
    for (r in {R0, R2..R9}) {
        inv.assign_type(r, T_UNINIT);
    }
    
    return inv;
}
```

## TypeToNumDomain (Reduced Cardinal Power)

**File**: `src/crab/rcp.hpp`

This domain implements a *reduced cardinal power* construction:

```
TypeToNumDomain = TypeDomain × NumAbsDomain
```

The key insight: **type information guides numeric precision**.

### Type-Dependent Variables

Each register has multiple associated variables:

| Variable | When Meaningful | Purpose |
|----------|-----------------|---------|
| `svalue` | type = NUM | Signed 64-bit value |
| `uvalue` | type = NUM | Unsigned 64-bit value |
| `ctx_offset` | type = CTX | Offset into context struct |
| `stack_offset` | type = STACK | Offset from stack base |
| `packet_offset` | type = PACKET | Offset into packet buffer |
| `shared_offset` | type = SHARED | Offset into shared memory |
| `map_fd` | type = MAP_FD | Map file descriptor |

### Reduction

When type changes, irrelevant variables are havocked:

```cpp
void TypeToNumDomain::assign_type(Reg r, Type t) {
    type_domain.assign(r, t);
    
    // Havoc variables not meaningful for this type
    if (t != T_CTX) num_domain.havoc(r.ctx_offset);
    if (t != T_STACK) num_domain.havoc(r.stack_offset);
    // ... etc
}
```

## TypeDomain

**File**: `src/crab/type_domain.hpp`

Tracks the type of each register:

```cpp
enum class Type {
    T_UNINIT,    // Uninitialized
    T_NUM,       // Numeric value (not a pointer)
    T_CTX,       // Context pointer
    T_STACK,     // Stack pointer
    T_PACKET,    // Packet data pointer
    T_SHARED,    // Shared memory pointer
    T_MAP,       // Map pointer
    T_MAP_FD,    // Map file descriptor
};
```

### Type Lattice

```
           T_TOP (any type)
         /   |   \    \
    T_CTX T_STACK T_NUM ...
         \   |   /    /
          T_BOTTOM (unreachable)
```

### Operations

```cpp
// Join: if types differ, go to top
Type join(Type a, Type b) {
    if (a == b) return a;
    return T_TOP;
}

// Meet: if types differ, go to bottom
Type meet(Type a, Type b) {
    if (a == b) return a;
    if (a == T_TOP) return b;
    if (b == T_TOP) return a;
    return T_BOTTOM;  // Contradiction
}
```

## NumAbsDomain

**File**: `src/crab/finite_domain.hpp`

Wraps the SplitDBM with arithmetic operations:

### Supported Constraints

1. **Interval bounds**: `x ∈ [lo, hi]`
2. **Difference constraints**: `x - y ≤ k`
3. **Equality**: `x = y + k` (via bidirectional difference)

### Arithmetic Operations

```cpp
// Addition: dst = src1 + src2
void add(Var dst, Var src1, Var src2) {
    // Use interval arithmetic + difference propagation
    Interval i1 = get_interval(src1);
    Interval i2 = get_interval(src2);
    set_interval(dst, i1 + i2);
    
    // Propagate differences if known
    if (src2 is constant k) {
        // dst - src1 = k
        add_constraint(dst - src1 <= k);
        add_constraint(src1 - dst <= -k);
    }
}
```

### Bitwise Operations

Bitwise operations are handled conservatively:

```cpp
void bitwise_and(Var dst, Var src1, Var src2) {
    Interval i1 = get_interval(src1);
    Interval i2 = get_interval(src2);
    
    // Result bounded by minimum of inputs
    uint64_t max = min(i1.ub, i2.ub);
    set_interval(dst, Interval(0, max));
}
```

## SplitDBM (Split Difference Bound Matrix)

**File**: `src/crab/split_dbm.hpp`

The core relational numeric domain.

### Representation

A DBM represents constraints of the form `x - y ≤ k`:

```
       x      y      z
x   [  0,    3,     5  ]    // x - x ≤ 0, x - y ≤ 3, x - z ≤ 5
y   [ -2,    0,     2  ]    // y - x ≤ -2, y - y ≤ 0, y - z ≤ 2
z   [ ∞,    ∞,     0  ]    // z - x ≤ ∞, z - y ≤ ∞, z - z ≤ 0
```

### Split Representation

"Split" means the matrix is stored as:
- **Potential function**: Maps each variable to a value
- **Difference graph**: Sparse graph of non-trivial constraints

This is more efficient than a full matrix for sparse constraint sets.

### Key Operations

```cpp
// Add constraint x - y <= k
void add_constraint(Var x, Var y, Weight k);

// Check if x - y <= k is implied
bool check_constraint(Var x, Var y, Weight k);

// Close the graph (compute all implied constraints)
void close();

// Join: element-wise max
SplitDBM join(const SplitDBM& a, const SplitDBM& b);

// Widening: jump to infinity for unstable constraints
SplitDBM widen(const SplitDBM& a, const SplitDBM& b);
```

### Closure Algorithm

After adding constraints, compute the transitive closure:

```cpp
// Floyd-Warshall style
for k in variables:
    for i in variables:
        for j in variables:
            m[i][j] = min(m[i][j], m[i][k] + m[k][j])
```

## ArrayDomain

**File**: `src/crab/array_domain.hpp`

Models stack memory as an array of cells.

### Cell-Based Representation

The stack is divided into cells, where each cell tracks:
- **Offset range**: `[lb, ub]` byte range
- **Type**: What kind of value is stored
- **Value constraints**: Numeric bounds if applicable

```cpp
struct Cell {
    Interval offset;    // Byte range covered
    Type type;          // Type of stored value
    Var value;          // Variable tracking the value
};
```

### Overlapping Cells

eBPF allows unaligned access, so cells may overlap:

```
Stack layout:
[0-3]  : 32-bit value A
  [2-5]: 32-bit value B (overlaps A!)
[0-7]  : 64-bit value C (contains both)
```

When a store overlaps existing cells:
1. Remove cells that are completely overwritten
2. Invalidate cells that are partially overwritten
3. Add new cell for the store

### Load Operation

```cpp
Value load(Offset offset, Width width) {
    // Find cell exactly matching [offset, offset+width)
    Cell* cell = find_exact_cell(offset, width);
    
    if (cell) {
        return cell->value;  // Return tracked value
    } else {
        return TOP;  // Unknown value
    }
}
```

### Store Operation

```cpp
void store(Offset offset, Width width, Value val, Type type) {
    // Kill overlapping cells
    remove_overlapping(offset, width);
    
    // Create new cell
    cells.insert(Cell{
        .offset = [offset, offset+width),
        .type = type,
        .value = val
    });
}
```

## Domain Composition

### Join Example

When joining two domains at a merge point:

```cpp
EbpfDomain join(EbpfDomain a, EbpfDomain b) {
    EbpfDomain result;
    
    // Type domain: join each register's type
    for (r in registers) {
        Type ta = a.get_type(r);
        Type tb = b.get_type(r);
        if (ta == tb) {
            result.set_type(r, ta);
        } else {
            result.set_type(r, T_TOP);
            // Havoc all type-specific variables
            result.havoc(r.ctx_offset, r.stack_offset, ...);
        }
    }
    
    // Numeric domain: join constraints
    result.num = a.num | b.num;
    
    // Array domain: join cells
    result.stack = a.stack | b.stack;
    
    return result;
}
```

### Widening Example

At loop heads, prevent infinite ascending chains:

```cpp
SplitDBM widen(SplitDBM old, SplitDBM new) {
    SplitDBM result;
    
    for each constraint (x - y <= k) in new:
        if (old has x - y <= k' where k' < k) {
            // Constraint got weaker - jump to infinity
            // (don't add constraint)
        } else {
            // Constraint stable - keep it
            result.add(x - y <= k);
        }
    
    return result;
}
```

## Performance Considerations

### Variable Packing

Registers pack multiple variables:

```cpp
struct RegPack {
    Var svalue;           // Signed value
    Var uvalue;           // Unsigned value  
    Var ctx_offset;       // CTX offset
    Var stack_offset;     // Stack offset
    Var packet_offset;    // Packet offset
    Var shared_offset;    // Shared offset
    Var map_fd;           // Map FD
    // ... more
};
```

This is managed by a thread-local variable registry.

### Sparse Representation

The SplitDBM uses sparse graph representation:
- Only non-trivial constraints stored
- Lazy closure computation
- Incremental updates where possible

### Type-Guided Havocking

When types are known, irrelevant variables are discarded:
- Reduces DBM size
- Speeds up closure computation
- Improves precision of remaining constraints

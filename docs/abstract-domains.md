# Abstract Domains

This document describes the abstract domain hierarchy used in Prevail.

## Domain Hierarchy

Prevail uses a composite domain structure:

```text
EbpfDomain
├── TypeToNumDomain (type-guided numeric constraints)
│   ├── TypeDomain (pointer type tracking)
│   └── NumAbsDomain = AddBottom<FiniteDomain>
│       └── FiniteDomain (finite-width arithmetic)
│           └── ZoneDomain (Variable↔VertId mapping)
│               └── splitdbm::SplitDBM (Split Difference Bound Matrix)
└── ArrayDomain (stack memory modeling)
```

## EbpfDomain

**File**: `src/crab/ebpf_domain.hpp`

The top-level domain combining all tracking:

```cpp
struct EbpfDomain {
    TypeToNumDomain state;  // Type + numeric tracking
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

## TypeToNumDomain (Type-Guided Numeric Constraints)

**File**: `src/crab/type_to_num.hpp`

`TypeToNumDomain` tracks two things: the possible type of each register (number vs different pointer kinds), and numeric constraints (intervals / DBM constraints) over per-register variables.

Some numeric variables are type-dependent ("kind variables") such as `packet_offset`, `stack_offset`, `ctx_offset`, etc. A kind variable is only meaningful when the type domain says the register may have the corresponding type; otherwise that variable is inactive / not applicable.

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

### Type-Aware Domain Operations

This affects the main domain operations:

* **Subsumption (A ⊆ B)** is type-aware: kind variables that are inactive in A are treated as "don't care" during numeric comparison, so states like `{r is NUM}` can be subsumed by `{r is NUM or PACKET, r.packet_offset = 5}` without failing on `packet_offset`.

* **Join** is type-aware: constraints on kind variables that exist only on the branch where the guarding type is possible are preserved instead of being dropped by a naive numeric join.

Intuitively, this behaves like "splitting the numeric state by possible types", but it's implemented compactly as one relational numeric domain plus type-aware subsumption and join.

### Type Assignment

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

Tracks the possible types and must-equalities of register type variables using a
disjoint-set union (DSU) with per-class type set annotations.

### Type Encoding

```cpp
enum class TypeEncoding {
    T_UNINIT = 0, T_MAP_PROGRAMS = 1, T_MAP = 2, T_NUM = 3,
    T_CTX = 4, T_PACKET = 5, T_STACK = 6, T_SHARED = 7,
};
```

### Representation

Each type variable maps to a DSU element. The DSU partitions variables into equivalence
classes (must-equal groups). Each class has a `TypeSet` -- a `std::bitset<8>` recording
the set of types that the class might have.

```text
Top:    each variable is its own class, TypeSet = all 8 types
Bottom: is_bottom_ flag (contradiction detected)
```

### Sentinel-Merging Invariant

The DSU pre-allocates 8 sentinel elements (IDs 0..7), one per TypeEncoding value.
Whenever a class's TypeSet narrows to a singleton `{te}`, the class is merged with
the sentinel for `te`. This guarantees that all variables known to have the same
singleton type are in the same equivalence class, making equality queries a single
DSU representative comparison.

### Operations

- **Join (|)**: For each variable, take the union of type sets from both sides. Two
  variables are in the same class in the result only if they were in the same class
  on both sides (DSU representatives must match on both). The sentinel-merging
  invariant ensures that variables with the same singleton type on both sides are
  detected as equal without special-casing.

- **Meet (&)**: For each variable, intersect type sets. Variables equal on either side
  are unified. Empty intersection -> bottom.

- **Subsumption (<=)**: `A <= B` iff every type set in A is a subset of the
  corresponding set in B, and every equality in A is also present in B.

- **Unify (add_constraint x == y)**: Merge the classes of x and y; intersect their
  type sets. Transitive: unify(x,y) then unify(y,z) narrows all three.

- **restrict_to(v, mask)**: Intersect v's type set with mask (non-convex narrowing).

- **remove_type(v, te)**: Remove a single type from v's set.

## NumAbsDomain

**File**: `src/crab/add_bottom.hpp`

`NumAbsDomain = AddBottom<FiniteDomain>`, where `FiniteDomain` wraps `ZoneDomain` with finite-width arithmetic:

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

## ZoneDomain

**File**: `src/crab/zone_domain.hpp`

A zone abstract domain backed by a Split DBM. Provides a Variable-level interface over `splitdbm::SplitDBM`, maintaining Variable-to-VertId mappings and handling variable-pair relationships (upper/lower bounds as two separate edges via `Side`).

### Key Responsibilities

- Maps `Variable` to graph vertices (`VertId`) via `vert_map_` / `rev_map_`
- Translates linear expressions into difference constraints
- Delegates graph operations (closure, join, widen, meet) to `splitdbm::SplitDBM`

## splitdbm::SplitDBM (Split Difference Bound Matrix)

**File**: `src/crab/splitdbm/split_dbm.hpp`

The actual Split DBM implementation: a sparse weighted graph with a potential function for efficient constraint propagation. Operates on vertices and sides (edge directions relative to vertex 0). Has no concept of Variable -- only `VertId` and `Side`.

### Representation

A DBM represents constraints of the form `x - y <= k`:

```text
         x       y       z
x   [    0,      3,      5  ]    // x - x <= 0, x - y <= 3, x - z <= 5
y   [   -2,      0,      2  ]    // y - x <= -2, y - y <= 0, y - z <= 2
z   [    inf,    inf,    0  ]    // z - x <= inf, z - y <= inf, z - z <= 0
```

### Split Representation

The name "Split" refers to the conceptual separation between interval constraints and difference constraints. While both kinds of constraints are physically stored in the DBM, the algorithms (transfer functions) work differently on each set. Importantly, the transfer functions ensure that the DBM does not contain explicit difference constraints that can be represented by intervals, since those would be redundant.

The matrix is stored as:
- **Potential function**: Maps each vertex to a value (enables fast satisfiability checks)
- **Difference graph**: Sparse graph of non-trivial constraints

This is more efficient than a full matrix for sparse constraint sets.

### Side Enum

Each vertex `v` has two bounds via edge direction relative to vertex 0:
- `Side::LEFT` (edge v->0): lower bound = -weight
- `Side::RIGHT` (edge 0->v): upper bound = weight

### AlignedPair

When performing binary operations (join, widen, meet), two `SplitDBM`s are aligned into a common vertex space via `AlignedPair`, which holds permutation vectors mapping each operand's vertices to aligned indices.

### Key Operations

```cpp
// Get/set bounds for a vertex on a given side
ExtendedNumber get_bound(VertId v, Side side) const;
void set_bound(VertId v, Side side, const Weight& bound_value);

// Add a difference constraint: dest - src <= k
bool add_difference_constraint(VertId src, VertId dest, const Weight& k);

// Static lattice operations on aligned pairs
static SplitDBM join(const AlignedPair& aligned);
static SplitDBM widen(const AlignedPair& aligned);
static optional<SplitDBM> meet(AlignedPair& aligned);
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
ZoneDomain widen(ZoneDomain old, ZoneDomain new) {
    ZoneDomain result;
    
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

The `splitdbm::SplitDBM` uses sparse graph representation:
- Only non-trivial constraints stored
- Lazy closure computation
- Incremental updates where possible

### Type-Guided Havocking

When types are known, irrelevant variables are discarded:
- Reduces DBM size
- Speeds up closure computation
- Improves precision of remaining constraints

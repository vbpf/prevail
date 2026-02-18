# Glossary

This glossary defines key terms used in the Prevail eBPF verifier documentation.

## Abstract Interpretation

### Abstract Domain

A mathematical structure representing sets of concrete program states. Domains support operations like join, meet, widening, and narrowing.

### Abstract Value

A representation of a set of concrete values. For example, the interval `[0, 10]` represents all integers from 0 to 10.

### Bottom (⊥)

The smallest element in a lattice, representing an empty set of states (unreachable code).

### Fixpoint

A state where further iteration produces no change. The analysis converges when the abstract state at every program point reaches a fixpoint.

### Galois Connection

A pair of functions (abstraction α and concretization γ) relating concrete and abstract domains. While not strictly required for soundness (e.g., Polyhedra is not a Galois connection), having a Galois connection is desirable because it ensures that transfer functions can be optimal—as precise as the abstract domain allows.

### Join (⊔)

An operation combining two abstract values into one that includes all behaviors of both. Used at merge points in the CFG.

### Lattice

A partially ordered set where every pair of elements has a least upper bound (join) and greatest lower bound (meet).

### Meet (⊓)

An operation finding the intersection of two abstract values. Used to refine states based on conditions.

### Narrowing (Δ)

An operation that recovers precision after widening by using information from a more precise state.

### Widening (∇)

An operation that accelerates convergence by jumping to a stable approximation, ensuring termination for infinite-height domains.

### Soundness

The property that if the analysis says a program is safe, it truly is safe for all possible executions.

### Top (⊤)

The largest element in a lattice, representing all possible states (no information).

### Transfer Function

A function modeling how an instruction transforms the abstract state.

## eBPF

### BPF

Berkeley Packet Filter - the original packet filtering mechanism. Extended BPF (eBPF) generalizes this to a general-purpose in-kernel virtual machine.

### Context

A pointer to program-specific data passed in R1 at entry. For XDP programs, this is `xdp_md`; for socket filters, it's `__sk_buff`.

### eBPF

Extended Berkeley Packet Filter - a virtual machine in the Linux kernel (and now Windows) for running sandboxed programs.

### Helper Function

A kernel function that eBPF programs can call (e.g., `bpf_map_lookup_elem`).

### JIT

Just-In-Time compilation - compiling eBPF bytecode to native machine code.

### Map

A key-value data structure for storing persistent state and sharing data between eBPF programs and userspace.

### Program Type

The type of eBPF program (XDP, socket filter, tracepoint, etc.), which determines available helpers and context format.

### Register

eBPF has 11 registers: R0 (return value), R1-R5 (arguments), R6-R9 (callee-saved), R10 (stack frame pointer).

### Verifier

A static analyzer that checks eBPF programs for safety before loading into the kernel.

### XDP

eXpress Data Path - a high-performance packet processing framework using eBPF.

## Control Flow

### Back Edge

An edge in the CFG that goes from a later node to an earlier node, creating a loop.

### Basic Block

A sequence of instructions with a single entry point and single exit point (no branches in the middle).

### CFG

Control Flow Graph - a directed graph where nodes are instructions and edges represent possible control flow.

### Loop Head

The entry point of a loop - the first node reached when entering the loop.

### SCC

Strongly Connected Component - a maximal set of nodes where every node is reachable from every other.

### WTO

Weak Topological Ordering - a hierarchical ordering of CFG nodes that identifies loop structure for efficient fixpoint computation.

## Domains (Prevail-specific)

### ArrayDomain

Abstract domain modeling stack memory as an array of typed cells.

### DBM

Difference Bound Matrix - a data structure representing constraints of the form `x - y ≤ k`.

### EbpfDomain

The top-level composite domain combining type, numeric, and memory tracking.

### FiniteDomain

A numeric domain wrapping ZoneDomain with finite-width arithmetic operations (overflow, bitwise ops, signed/unsigned conversions).

### NumAbsDomain

Numeric abstract domain tracking intervals and relational constraints.

### Reduced Cardinal Power

A domain construction where type information guides which numeric variables to track precisely.

### ZoneDomain

Zone abstract domain -- Variable-level interface over the Split DBM. Maps Variables to graph vertices.

### splitdbm::SplitDBM

Split Difference Bound Matrix -- sparse graph + potential function implementation. Operates on VertId and Side, with no concept of Variable.

### TypeDomain

Abstract domain tracking the type (CTX, STACK, PACKET, etc.) of each register using a disjoint-set union (DSU) with per-class `TypeSet` annotations. Tracks both possible types (as bitsets) and must-equalities (as equivalence classes).

## Memory Regions

### Context Memory

The structure pointed to by R1 at entry, containing program-type-specific fields.

### Map Value

Memory returned by `bpf_map_lookup_elem`, containing the value associated with a key.

### Packet Memory

Network packet data, accessed via pointers derived from context fields.

### Shared Memory

Memory regions shared between programs or with userspace.

### Stack Memory

The program's private stack, accessed via R10 and negative offsets.

## Types (Prevail-specific)

### T_CTX

Type indicating a pointer to the program context structure.

### T_MAP

Type indicating a pointer to a map value.

### T_MAP_FD

Type indicating a map file descriptor (not a pointer).

### T_NUM

Type indicating a numeric value (not a pointer).

### T_PACKET

Type indicating a pointer to packet data.

### T_SHARED

Type indicating a pointer to shared memory.

### T_STACK

Type indicating a pointer to stack memory.

### T_UNINIT

Type indicating an uninitialized register.

## Verification

### Assertion

A safety property to be verified at a program point (e.g., memory access is in bounds).

### Invariant

A property that holds at a program point across all possible executions.

### Postcondition

The state guaranteed after an instruction or program executes.

### Precondition

The state required before an instruction or program executes.

### Safety Property

A property stating that "nothing bad happens" (e.g., no buffer overflows).

### Verification Condition

A logical formula that must be true for the program to be safe.

## Instructions

### ALU

Arithmetic Logic Unit operations - arithmetic and bitwise instructions.

### ARSH

Arithmetic right shift - shifts right while preserving the sign bit.

### BPF_CALL

Instruction to call a helper function.

### JMP/JMP32

Jump instructions (64-bit or 32-bit comparison).

### LDX

Load from memory.

### MOV

Move (copy) a value between registers or load an immediate.

### MOVSX

Move with sign extension.

### STX

Store to memory.

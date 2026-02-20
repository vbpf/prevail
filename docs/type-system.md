# Type System

This document describes the type system used in Prevail.

## Overview

Prevail uses types to:
1. **Track pointer provenance**: Know which memory region a pointer references
2. **Guide numeric precision**: Track different variables for different pointer types
3. **Enforce safety rules**: Prevent mixing incompatible pointer types

## Type Lattice

```text
                    T_TOP (any type, imprecise)
                   /  |  \  \  \  \  \  \
                  /   |   \  \  \  \  \  \
            T_CTX T_STACK T_PACKET T_SHARED T_MAP T_MAP_FD T_NUM T_UNINIT
                  \   |   /  /  /  /  /  /
                   \  |  /  /  /  /  /  /
                    T_BOTTOM (contradiction)
```

### Type Definitions

```cpp
enum class Type {
    T_UNINIT,     // Uninitialized (no valid value)
    T_NUM,        // Numeric value (not a pointer)
    T_CTX,        // Context structure pointer
    T_STACK,      // Stack frame pointer
    T_PACKET,     // Packet data pointer
    T_SHARED,     // Shared memory pointer
    T_MAP,        // Map value pointer
    T_MAP_FD,     // Map file descriptor
    T_MAP_PROG,   // Map programs array
    T_SOCKET,     // Socket structure pointer
    T_BTF_ID,     // BTF-typed kernel object pointer
    T_ALLOC_MEM,  // Helper-allocated memory pointer
    T_FUNC,       // BPF function pointer (callback)
    T_TOP,        // Unknown type (any of the above)
    T_BOTTOM,     // Contradiction (unreachable)
};
```

## Type Domain Operations

**File**: `src/crab/type_domain.hpp`

### Join (⊔)

When paths merge, types are joined:

```cpp
Type join(Type a, Type b) {
    if (a == b) return a;
    if (a == T_BOTTOM) return b;
    if (b == T_BOTTOM) return a;
    return T_TOP;  // Different types -> unknown
}
```

**Example**:

```cpp
// Path 1: R1 = ctx
// Path 2: R1 = stack_ptr
// After merge: R1 type = T_TOP
```

### Meet (⊓)

When refining, types are intersected:

```cpp
Type meet(Type a, Type b) {
    if (a == b) return a;
    if (a == T_TOP) return b;
    if (b == T_TOP) return a;
    return T_BOTTOM;  // Contradiction
}
```

**Example**:

```cpp
// State: R1 type = T_TOP
// Assume: R1 is pointer (not null check passed)
// After: R1 type = T_TOP (still uncertain which pointer type)
```

### Ordering (⊑)

```cpp
bool operator<=(Type a, Type b) {
    if (a == b) return true;
    if (a == T_BOTTOM) return true;  // Bottom ⊑ anything
    if (b == T_TOP) return true;     // Anything ⊑ Top
    return false;
}
```

## Type-Guided Variable Tracking

Each pointer type has associated numeric variables:

| Type | Tracked Variables |
|------|-------------------|
| T_NUM | svalue, uvalue |
| T_CTX | ctx_offset |
| T_STACK | stack_offset, stack_numeric_size |
| T_PACKET | packet_offset |
| T_SHARED | shared_offset, shared_region_size |
| T_MAP | map_value_size |
| T_MAP_FD | map_fd |
| T_SOCKET | socket_offset |
| T_BTF_ID | btf_id_offset |
| T_ALLOC_MEM | alloc_mem_offset, alloc_mem_size |
| T_FUNC | *(none)* |

> **Note:** `T_FUNC` intentionally has no associated offset or size variables. Function pointers (callback targets) are treated as opaque numeric values; see the empty mapping in `src/crab/type_to_num.hpp`.

### Register Pack

```cpp
struct RegPack {
    // Common to all types
    Var svalue;              // Signed interpretation
    Var uvalue;              // Unsigned interpretation
    
    // Type-specific offsets
    Var ctx_offset;          // For T_CTX
    Var stack_offset;        // For T_STACK
    Var packet_offset;       // For T_PACKET
    Var shared_offset;       // For T_SHARED
    Var socket_offset;       // For T_SOCKET
    Var btf_id_offset;       // For T_BTF_ID
    Var alloc_mem_offset;    // For T_ALLOC_MEM
    
    // Size tracking
    Var shared_region_size;  // For T_SHARED
    Var stack_numeric_size;  // For T_STACK spills
    Var alloc_mem_size;      // For T_ALLOC_MEM
    
    // Map-related
    Var map_fd;              // For T_MAP_FD
    Var map_value_size;      // For T_MAP
};
```

### Reduction

When type changes, irrelevant variables are havocked:

```cpp
void assign_type(Reg r, Type t) {
    Type old_type = get_type(r);
    type_domain.assign(r, t);
    
    // Havoc variables not relevant to new type
    if (t != T_CTX && old_type == T_CTX) {
        num_domain.havoc(r.ctx_offset);
    }
    if (t != T_STACK && old_type == T_STACK) {
        num_domain.havoc(r.stack_offset);
    }
    // ... etc
}
```

## Type Checking Rules

### Memory Access

```cpp
void check_valid_access(Reg base, int offset, int width) {
    Type t = get_type(base);
    
    switch (t) {
        case T_CTX:
            check_context_bounds(base, offset, width);
            break;
        case T_STACK:
            check_stack_bounds(base, offset, width);
            break;
        case T_PACKET:
            check_packet_bounds(base, offset, width);
            break;
        case T_MAP:
            check_map_bounds(base, offset, width);
            break;
        case T_NUM:
            fail("cannot dereference number");
            break;
        case T_UNINIT:
            fail("dereference of uninitialized register");
            break;
        case T_TOP:
            fail("dereference of unknown pointer type");
            break;
    }
}
```

### Pointer Arithmetic

```cpp
void check_addable(Reg ptr, Value offset) {
    Type t = get_type(ptr);
    
    // Only pointers can have offsets added
    if (t == T_NUM) {
        fail("cannot add offset to number");
    }
    
    // Offset must be numeric
    if (is_register(offset)) {
        require(get_type(offset.reg) == T_NUM);
    }
}
```

### Comparison Rules

```cpp
void check_comparable(Reg left, Value right) {
    Type lt = get_type(left);
    Type rt = is_register(right) ? get_type(right.reg) : T_NUM;
    
    // Same type: OK
    if (lt == rt) return;
    
    // Pointer vs number: OK (null checks)
    if (lt != T_NUM && rt == T_NUM) return;
    if (lt == T_NUM && rt != T_NUM) return;
    
    // Different pointer types: error
    fail("comparing incompatible pointer types");
}
```

## Type Inference

Types are inferred from operations:

### From Instructions

```cpp
void infer_types(const Instruction& inst) {
    visit(inst, [&](const LoadMapFd& lmf) {
        assign_type(lmf.dst, T_MAP_FD);
    });
    
    visit(inst, [&](const Mem& mem) {
        if (mem.is_load) {
            Type base_type = get_type(mem.access.basereg);
            if (base_type == T_CTX) {
                // Load from ctx might return pointer
                assign_type(mem.valuereg, infer_ctx_field_type(...));
            } else {
                // Other loads return numbers
                assign_type(mem.valuereg, T_NUM);
            }
        }
    });
}
```

### From Helper Calls

```cpp
void apply_helper_types(int func) {
    switch (func) {
        case BPF_FUNC_map_lookup_elem:
            // Returns T_MAP (value pointer) or null (T_NUM with 0)
            assign_type(R0, T_MAP);
            // Actually: type might be null, tracked separately
            break;
            
        case BPF_FUNC_get_current_pid_tgid:
            assign_type(R0, T_NUM);
            break;
            
        case BPF_FUNC_skb_load_bytes:
            // Copies to stack, returns error code
            assign_type(R0, T_NUM);
            break;
    }
}
```

## Nullable Pointers

Some operations return nullable pointers:

```cpp
// map_lookup_elem returns NULL on miss
void* val = bpf_map_lookup_elem(&map, &key);
if (val == NULL) return 0;
// After null check, val is definitely T_MAP
```

### Null Tracking

```cpp
void check_null_dereference(Reg ptr) {
    Type t = get_type(ptr);
    
    if (t == T_MAP) {
        // Map pointers may be null
        require(entails(ptr.svalue > 0), 
                "possible null pointer dereference");
    }
}

void assume_nonnull(Reg ptr) {
    // After: if (ptr != NULL)
    assume(ptr.svalue > 0);
    // Now safe to dereference
}
```

## Type Assertions

Generated assertions verify type rules:

### ValidAccess

```cpp
struct ValidAccess {
    Reg reg;
    int offset;
    int width;
    AccessType access_type;  // READ or WRITE
    
    // Checked by:
    // 1. reg has pointer type (not NUM, UNINIT, or TOP)
    // 2. offset is within bounds for that pointer type
};
```

### ValidStore

```cpp
struct ValidStore {
    Reg mem_reg;    // Destination pointer
    Reg val_reg;    // Value being stored
    
    // Checked by:
    // 1. mem_reg is valid pointer
    // 2. val_reg type is compatible with destination
    //    (e.g., can't store random number to ctx field expecting pointer)
};
```

### TypeConstraint

```cpp
struct TypeConstraint {
    Reg reg;
    TypeGroup expected;  // Set of acceptable types
    
    // Examples:
    // - "must be pointer" -> {CTX, STACK, PACKET, SHARED, MAP}
    // - "must be numeric" -> {NUM}
};
```

## Examples

### Example 1: Context Load

```asm
; R1 = ctx (T_CTX, ctx_offset=0)
ldxdw R2, [R1+0]    ; Load data pointer
; R2 = T_PACKET, packet_offset=0
```

### Example 2: Stack Spill

```asm
; R1 = ctx (T_CTX)
stxdw [R10-8], R1   ; Spill to stack
; Stack[-8] contains T_CTX pointer

ldxdw R2, [R10-8]   ; Reload
; R2 = T_CTX (type preserved!)
```

### Example 3: Map Lookup

```asm
; R1 = &map (T_MAP_FD)
; R2 = &key (T_STACK)
call bpf_map_lookup_elem
; R0 = T_MAP or null

jeq R0, 0, error    ; Null check
; After branch: R0.svalue > 0 (not null)

ldxdw R1, [R0+0]    ; Safe dereference
```

### Example 4: Type Error

```asm
; R1 = 42 (T_NUM)
ldxdw R2, [R1+0]    ; ERROR: cannot dereference number
```

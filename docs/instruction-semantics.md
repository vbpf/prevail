# Instruction Semantics

This document describes how Prevail models eBPF instruction semantics.

## Instruction Representation

**File**: `src/ir/syntax.hpp`

eBPF instructions are represented as a variant type:

```cpp
using Instruction = std::variant<
    Bin,                  // Binary operations
    Un,                   // Unary operations
    Mem,                  // Memory operations
    Jmp,                  // Jump (control flow)
    Call,                 // Helper function call
    CallLocal,            // Local function call
    Callx,                // Indirect call
    Exit,                 // Program exit
    Packet,               // Legacy packet access
    Atomic,               // Atomic memory operations
    Assume,               // Branch condition assumption
    LoadMapFd,            // Load map file descriptor
    LoadMapAddress,       // Load map address
    IncrementLoopCounter  // Loop termination tracking
>;
```

## Binary Operations (Bin)

Binary operations take two operands and produce a result:

```cpp
struct Bin {
    enum class Op {
        MOV, ADD, SUB, MUL, UDIV, UMOD,  // Arithmetic
        SDIV, SMOD,                        // Signed arithmetic
        OR, AND, XOR, LSH, RSH, ARSH,     // Bitwise
        MOVSX8, MOVSX16, MOVSX32          // Sign extension
    };
    
    Op op;
    Reg dst;              // Destination register
    Value src;            // Source: register or immediate
    bool is64;            // 64-bit (true) or 32-bit (false)
    bool lddw;            // Wide load (64-bit immediate)
};
```

### Arithmetic Semantics

**ADD**: `dst = dst + src`

```cpp
void EbpfTransformer::operator()(const Bin& bin) {
    if (bin.op == Bin::Op::ADD) {
        // Get source value
        auto src_val = get_value(bin.src);
        
        // For pointers: add to offset
        if (is_pointer(bin.dst)) {
            add_to_offset(bin.dst, src_val);
        } else {
            // For numbers: update svalue and uvalue
            inv.add(dst.svalue, dst.svalue, src_val);
            inv.add(dst.uvalue, dst.uvalue, src_val);
        }
    }
}
```

**SDIV/SMOD**: Signed division with zero-divisor handling

Per RFC 9669, division/modulo by zero produces:
- SDIV: `dst = 0`
- SMOD: `dst = dst` (unchanged)

```cpp
void do_signed_div_mod(const Bin& bin) {
    if (bin.op == Bin::Op::SDIV) {
        // dst = (src != 0) ? (dst / src) : 0
        assume_nonzero_or_zero_result(bin.src, bin.dst);
    } else if (bin.op == Bin::Op::SMOD) {
        // dst = (src != 0) ? (dst % src) : dst
        assume_nonzero_or_unchanged(bin.src, bin.dst);
    }
}
```

### 32-bit Operations

32-bit operations zero the upper 32 bits:

```cpp
void apply_32bit(Reg dst) {
    // Upper 32 bits are cleared
    inv.assume(dst.uvalue <= 0xFFFFFFFF);
    inv.assume(dst.svalue >= -0x80000000LL);
    inv.assume(dst.svalue <= 0x7FFFFFFFLL);
}
```

### Sign Extension (MOVSX)

Sign extension expands smaller values:

```cpp
void do_movsx(const Bin& bin) {
    switch (bin.op) {
        case MOVSX8:  // Sign-extend 8-bit to 32 or 64
            inv.sign_extend(dst, src, 8, bin.is64 ? 64 : 32);
            break;
        case MOVSX16: // Sign-extend 16-bit
            inv.sign_extend(dst, src, 16, bin.is64 ? 64 : 32);
            break;
        case MOVSX32: // Sign-extend 32-bit to 64
            inv.sign_extend(dst, src, 32, 64);
            break;
    }
    
    if (!bin.is64) {
        // 32-bit MOVSX: upper 32 bits are zeroed
        apply_32bit(dst);
    }
}
```

## Unary Operations (Un)

```cpp
struct Un {
    enum class Op {
        NEG,          // Negation
        LE16, LE32, LE64,  // Little-endian conversion
        BE16, BE32, BE64,  // Big-endian conversion
        SWAP16, SWAP32, SWAP64  // Byte swap
    };
    
    Op op;
    Reg dst;
    bool is64;
};
```

### Negation

```cpp
void operator()(const Un& un) {
    if (un.op == Un::Op::NEG) {
        // dst = -dst
        inv.neg(dst.svalue, dst.svalue);
        inv.neg(dst.uvalue, dst.uvalue);  // Two's complement
    }
}
```

### Byte Swaps

Byte swaps are conservatively handled:

```cpp
void do_byte_swap(const Un& un) {
    // Result bounds depend on input
    // For BE16/LE16: result ∈ [0, 0xFFFF]
    // For BE32/LE32: result ∈ [0, 0xFFFFFFFF]
    // For BE64/LE64: full range
    
    havoc(dst);
    apply_width_constraint(dst, width);
}
```

## Memory Operations (Mem)

```cpp
struct Mem {
    struct MemAccess {
        Reg basereg;        // Base register (pointer)
        int offset;         // Constant offset
        int width;          // Access width: 1, 2, 4, or 8 bytes
    };
    
    MemAccess access;
    Reg valuereg;           // Value register (for load/store)
    bool is_load;           // true = load, false = store
};
```

### Load Semantics

```cpp
void do_load(const Mem& mem) {
    Type ptr_type = inv.get_type(mem.access.basereg);
    int offset = mem.access.offset;
    int width = mem.access.width;
    
    switch (ptr_type) {
        case T_STACK:
            // Read from stack array domain
            inv.load_from_stack(mem.valuereg, offset, width);
            break;
            
        case T_CTX:
            // Read from context - result type depends on field
            inv.load_from_context(mem.valuereg, offset, width);
            break;
            
        case T_PACKET:
            // Read from packet - numeric value
            inv.assign_type(mem.valuereg, T_NUM);
            inv.havoc(mem.valuereg);  // Unknown value
            break;
            
        case T_MAP:
            // Read from map value
            inv.load_from_map(mem.valuereg, offset, width);
            break;
    }
}
```

### Store Semantics

```cpp
void do_store(const Mem& mem) {
    Type ptr_type = inv.get_type(mem.access.basereg);
    
    if (ptr_type == T_STACK) {
        // Store to stack array domain
        inv.store_to_stack(
            get_offset(mem.access.basereg) + mem.access.offset,
            mem.access.width,
            mem.valuereg
        );
    } else {
        // Other pointer types: just verify access is valid
        // (no need to track values)
    }
}
```

## Jump Operations (Jmp)

Jumps don't modify state directly but affect control flow:

```cpp
struct Jmp {
    enum class Op {
        EQ, NE, GT, GE, LT, LE,      // Unsigned comparisons
        SGT, SGE, SLT, SLE,          // Signed comparisons
        SET,                          // Bitwise AND != 0
        JSET = SET                    // Alias
    };
    
    Op op;
    Reg left;
    Value right;
    Label target;       // Jump target
    bool is64;          // 64-bit comparison
};
```

### Assume (Branch Conditions)

When a branch is taken, the condition is assumed:

```cpp
struct Assume {
    Condition cond;
    bool is64;
};

void operator()(const Assume& a) {
    // Refine domain with condition
    switch (a.cond.op) {
        case Condition::Op::EQ:
            inv.assume(left == right);
            break;
        case Condition::Op::GT:
            inv.assume(left.uvalue > right);
            break;
        case Condition::Op::SGT:
            inv.assume(left.svalue > right);
            break;
        // ... etc
    }
}
```

## Function Calls (Call)

```cpp
struct Call {
    int func;           // Helper function number
};
```

### Calling Convention

Before call:
- R1-R5 contain arguments
- R0 will be return value
- R1-R5 are caller-saved (clobbered)
- R6-R9 are callee-saved (preserved)

```cpp
void operator()(const Call& call) {
    // Save callee-saved registers (R6-R9)
    // They're already preserved - no action needed
    
    // Havoc caller-saved registers
    for (r in {R1, R2, R3, R4, R5}) {
        inv.havoc(r);
        inv.assign_type(r, T_UNINIT);
    }
    
    // Set return value based on helper semantics
    apply_helper_contract(call.func);
}
```

### Helper Contracts

Different helpers have different postconditions:

```cpp
void apply_helper_contract(int func) {
    switch (func) {
        case BPF_FUNC_map_lookup_elem:
            // Returns pointer to map value or NULL
            inv.assign_type(R0, T_MAP | T_NUM);
            inv.assume(R0.svalue >= 0);  // NULL or valid
            break;
            
        case BPF_FUNC_get_prandom_u32:
            // Returns random 32-bit value
            inv.assign_type(R0, T_NUM);
            inv.assume(R0.uvalue <= 0xFFFFFFFF);
            break;
            
        // ... many more helpers
    }
}
```

## Atomic Operations (Atomic)

```cpp
struct Atomic {
    enum class Op {
        ADD, OR, AND, XOR,  // Atomic RMW
        XCHG,               // Exchange
        CMPXCHG             // Compare and exchange
    };
    
    Op op;
    MemAccess access;
    Reg valreg;
    bool fetch;         // Return old value in valreg
};
```

### Atomic Semantics

```cpp
void operator()(const Atomic& atomic) {
    // Memory location is updated atomically
    // For FETCH variants, old value is returned in valreg
    
    if (atomic.fetch) {
        inv.havoc(atomic.valreg);
        inv.assign_type(atomic.valreg, T_NUM);
    }
    
    // Stack content at access location becomes unknown
    inv.havoc_stack_range(
        get_offset(atomic.access.basereg) + atomic.access.offset,
        atomic.access.width
    );
}
```

## Register Model

Each register (R0-R10) is tracked with multiple variables:

```cpp
struct RegPack {
    Var svalue;              // Signed 64-bit value
    Var uvalue;              // Unsigned 64-bit value
    Var ctx_offset;          // Offset if CTX pointer
    Var stack_offset;        // Offset if STACK pointer
    Var packet_offset;       // Offset if PACKET pointer
    Var shared_offset;       // Offset if SHARED pointer
    Var shared_region_size;  // Size of shared region
    Var map_fd;              // Map FD if MAP_FD type
    Var stack_numeric_size;  // Stack numeric tracking
};
```

### Dual Value Tracking

Both signed and unsigned interpretations are tracked:

```cpp
// Example: after "mov r1, -1"
R1.svalue = [-1, -1]
R1.uvalue = [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]

// Example: after "mov32 r1, -1"
R1.svalue = [-1, -1]  // or [0xFFFFFFFF, 0xFFFFFFFF] as unsigned 32-bit
R1.uvalue = [0xFFFFFFFF, 0xFFFFFFFF]  // Upper bits zeroed
```

## Assertions Generated

Each instruction type generates specific assertions:

| Instruction | Assertions |
|-------------|------------|
| Load/Store | `ValidAccess` (bounds check) |
| Store | `ValidStore` (type check) |
| DIV/MOD | `ValidDivisor` (non-zero) |
| Call | `ValidCall` (signature) |
| Pointer arith | `Addable` (valid operands) |
| Comparison | `Comparable` (compatible types) |

Example:

```cpp
void generate_assertions(const Mem& mem) {
    if (mem.is_load) {
        add_assertion(ValidAccess{
            .reg = mem.access.basereg,
            .offset = mem.access.offset,
            .width = mem.access.width,
            .access_type = AccessType::READ
        });
    } else {
        add_assertion(ValidAccess{...});
        add_assertion(ValidStore{
            .mem_reg = mem.access.basereg,
            .val_reg = mem.valuereg
        });
    }
}
```

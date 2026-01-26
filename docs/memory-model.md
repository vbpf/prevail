# Memory Model

This document describes how Prevail models memory regions.

## Memory Regions

eBPF programs can access several memory regions:

| Region | Register | Description |
|--------|----------|-------------|
| Stack | R10 | Private stack (512 bytes per frame) |
| Context | R1 | Program context (varies by type) |
| Packet | Derived | Network packet data |
| Shared | Derived | Shared memory regions |
| Map Values | Derived | BPF map contents |

## Stack Memory

### Stack Layout

```text
R10 (frame pointer) ────────────────┐
                                    │
    ┌───────────────────────────────▼───────┐
    │  Subprogram frame (512 bytes)         │  offset: -512 to 0
    ├───────────────────────────────────────┤
    │  Parent frame (512 bytes)             │  offset: -1024 to -512
    ├───────────────────────────────────────┤
    │  ...                                  │
    └───────────────────────────────────────┘
    
Total: 512 bytes × max_call_depth
```

### Stack Tracking

The stack is modeled using `ArrayDomain`:

```cpp
class ArrayDomain {
    std::set<Cell> cells;    // Non-overlapping cells
    std::bitset initialized; // Which bytes are written
    
    struct Cell {
        Interval offset;     // Byte range [lb, ub)
        Var value;           // Variable tracking cell value
        Type type;           // Type of stored value
    };
};
```

### Stack Store

```cpp
void store_to_stack(int offset, int width, Reg value) {
    // Kill overlapping cells
    cells.erase_if([&](Cell& c) {
        return c.offset.overlaps(offset, offset + width);
    });
    
    // Create new cell
    Var cell_var = fresh_variable();
    inv.assign(cell_var, value.svalue);
    
    cells.insert(Cell{
        .offset = {offset, offset + width},
        .value = cell_var,
        .type = inv.get_type(value)
    });
    
    // Mark bytes as initialized
    initialized.set(offset, offset + width);
}
```

### Stack Load

```cpp
void load_from_stack(Reg dest, int offset, int width) {
    // Find exact matching cell
    Cell* cell = find_cell(offset, width);
    
    if (cell && cell->offset == Interval{offset, offset + width}) {
        // Exact match - copy value
        inv.assign(dest.svalue, cell->value);
        inv.assign_type(dest, cell->type);
    } else {
        // Partial match or uninitialized - unknown value
        inv.havoc(dest);
        inv.assign_type(dest, T_NUM);  // Must be numeric
    }
}
```

### Stack Access Validation

```cpp
void check_stack_access(Reg base, int offset, int width) {
    // base must be stack pointer
    require(inv.get_type(base) == T_STACK);
    
    // Compute absolute offset
    Interval stack_off = inv.get_interval(base.stack_offset);
    int abs_offset = stack_off.lb + offset;
    
    // Check bounds: must be within current frame
    require(abs_offset >= EBPF_TOTAL_STACK_SIZE - EBPF_SUBPROGRAM_STACK_SIZE);
    require(abs_offset + width <= EBPF_TOTAL_STACK_SIZE);
}
```

## Context Memory

The context is a structure passed to the eBPF program.

### Context Types

Different program types have different contexts:

| Program Type | Context | Example Fields |
|--------------|---------|----------------|
| XDP | `xdp_md` | data, data_end, data_meta |
| Socket Filter | `__sk_buff` | data, data_end, protocol |
| Tracepoint | varies | Architecture-specific |

### Context Access

```cpp
void load_from_context(Reg dest, int offset, int width) {
    // Look up field in context descriptor
    ContextField* field = ctx_descriptor.find(offset, width);
    
    if (field) {
        switch (field->type) {
            case FIELD_DATA:
                // Returns packet data pointer
                inv.assign_type(dest, T_PACKET);
                inv.assign(dest.packet_offset, 0);
                break;
                
            case FIELD_DATA_END:
                // Returns packet end pointer
                inv.assign_type(dest, T_PACKET);
                // packet_offset set to packet length
                break;
                
            case FIELD_NUMERIC:
                // Returns numeric value
                inv.assign_type(dest, T_NUM);
                inv.assume(dest.svalue >= field->min);
                inv.assume(dest.svalue <= field->max);
                break;
        }
    } else {
        // Unknown field - conservative
        inv.havoc(dest);
        inv.assign_type(dest, T_NUM);
    }
}
```

### Context Bounds

Context access is bounds-checked:

```cpp
void check_context_access(Reg base, int offset, int width) {
    require(inv.get_type(base) == T_CTX);
    
    Interval ctx_off = inv.get_interval(base.ctx_offset);
    
    require(ctx_off.lb + offset >= 0);
    require(ctx_off.ub + offset + width <= CTX_SIZE);
}
```

## Packet Memory

Packet data is accessed via pointers derived from context.

### Packet Pointer Derivation

```asm
R1 = ctx                    ; type: CTX
R2 = *(u32*)(R1 + data)     ; type: PACKET, offset: 0
R3 = *(u32*)(R1 + data_end) ; type: PACKET, offset: packet_len
```

### Safe Packet Access

Packet access requires bounds checking:

```cpp
// Safe pattern:
// if (data + 14 > data_end) return XDP_DROP;
// eth = (struct ethhdr*)data;

void check_packet_access(Reg ptr, int offset, int width) {
    require(inv.get_type(ptr) == T_PACKET);
    
    Interval pkt_off = inv.get_interval(ptr.packet_offset);
    
    // Must have proven: ptr + offset + width <= data_end
    require(pkt_off.ub + offset + width <= inv.packet_size);
}
```

### Packet Bounds Tracking

Branch conditions refine packet bounds:

```cpp
// Before: data in [0, ?], data_end in [0, ?]
if (data + 14 > data_end) return;
// After: packet_size >= 14

void assume_packet_bounds(Condition cond) {
    if (cond == "data + N <= data_end") {
        inv.assume(packet_size >= N);
    }
}
```

## Shared Memory

Shared memory regions are similar to packet data:

```cpp
struct SharedRegion {
    Reg base;           // Base pointer
    Interval size;      // Region size bounds
};

void check_shared_access(Reg ptr, int offset, int width) {
    require(inv.get_type(ptr) == T_SHARED);
    
    Interval off = inv.get_interval(ptr.shared_offset);
    Interval size = inv.get_interval(ptr.shared_region_size);
    
    // Access must be within region
    require(off.lb + offset >= 0);
    require(off.ub + offset + width <= size.lb);
}
```

## Map Memory

BPF maps provide key-value storage.

### Map Lookup

```cpp
// r1 = map_fd
// r2 = &key (stack pointer)
// r0 = bpf_map_lookup_elem(r1, r2)

void handle_map_lookup() {
    // Return value is either NULL (0) or pointer to value.
    // The analysis splits into two states:
    //
    // Non-null branch (R0 != 0):
    inv.assign_type(R0, T_MAP);
    inv.assume(R0.svalue > 0);
    inv.assume(R0.map_value_size == map_descriptor.value_size);

    // Null branch (R0 == 0):
    // inv.assign_type(R0, T_NUM);
    // inv.assume(R0.svalue == 0);
    //
    // Programs must check for NULL before dereferencing.
}
```

### Map Value Access

```cpp
void check_map_access(Reg ptr, int offset, int width) {
    // Must be non-null
    require(inv.entails(ptr.svalue > 0));
    
    // Must be within value bounds
    Interval val_size = inv.get_interval(ptr.map_value_size);
    require(offset >= 0);
    require(offset + width <= val_size.lb);
}
```

## Pointer Arithmetic

### Valid Operations

| Base Type | Operation | Result Type |
|-----------|-----------|-------------|
| STACK | + number | STACK |
| PACKET | + number | PACKET |
| CTX | + number | CTX (if valid field) |
| MAP | + number | MAP |
| SHARED | + number | SHARED |
| NUMBER | + pointer | Same as pointer |
| Pointer | - pointer | NUMBER (if same type) |

### Offset Tracking

```cpp
void do_pointer_add(Reg dst, Reg ptr, Value offset) {
    Type ptr_type = inv.get_type(ptr);
    
    switch (ptr_type) {
        case T_STACK:
            inv.add(dst.stack_offset, ptr.stack_offset, offset);
            inv.assign_type(dst, T_STACK);
            break;
            
        case T_PACKET:
            inv.add(dst.packet_offset, ptr.packet_offset, offset);
            inv.assign_type(dst, T_PACKET);
            // Also update distance to data_end
            break;
            
        // Similar for other pointer types
    }
}
```

## Uninitialized Memory

### Detection

Uninitialized reads are detected:

```cpp
void check_initialized(int offset, int width) {
    for (int i = offset; i < offset + width; i++) {
        if (!initialized.test(i)) {
            throw VerificationError("read of uninitialized stack");
        }
    }
}
```

### Spilled Registers

When registers are spilled to stack, their types are preserved:

```cpp
// Store pointer to stack
stxdw [r10-8], r1    ; r1 is CTX pointer

// Load pointer from stack
ldxdw r2, [r10-8]    ; r2 becomes CTX pointer

// The array domain preserves type information
```

## Memory Aliasing

Prevail assumes no aliasing between:
- Stack and other memory regions
- Different map values
- Packet and context

This simplifies analysis but matches eBPF semantics.

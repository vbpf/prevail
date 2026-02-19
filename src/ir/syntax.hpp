// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <ostream>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "cfg/label.hpp"
#include "crab/type_encoding.hpp"
#include "crab_utils/num_safety.hpp"
#include "spec/type_descriptors.hpp"

// Assembly syntax.
namespace prevail {

/// Immediate argument.
struct Imm {
    uint64_t v{};
    constexpr bool operator==(const Imm&) const = default;
};

/// Register argument.
struct Reg {
    uint8_t v{};
    constexpr bool operator==(const Reg&) const = default;
    constexpr auto operator<=>(const Reg&) const = default;
};

using Value = std::variant<Imm, Reg>;

/// Binary operation.
struct Bin {
    enum class Op {
        MOV,
        ADD,
        SUB,
        MUL,
        UDIV,
        UMOD,
        OR,
        AND,
        LSH,
        RSH,
        ARSH,
        XOR,
        SDIV,
        SMOD,
        MOVSX8,
        MOVSX16,
        MOVSX32,
    };

    Op op;
    Reg dst; ///< Destination.
    Value v;
    bool is64{};
    bool lddw{};
    constexpr bool operator==(const Bin&) const = default;
};

/// Unary operation.
struct Un {
    enum class Op {
        BE16,   // dst = htobe16(dst)
        BE32,   // dst = htobe32(dst)
        BE64,   // dst = htobe64(dst)
        LE16,   // dst = htole16(dst)
        LE32,   // dst = htole32(dst)
        LE64,   // dst = htole64(dst)
        SWAP16, // dst = bswap16(dst)
        SWAP32, // dst = bswap32(dst)
        SWAP64, // dst = bswap64(dst)
        NEG,    // dst = -dst
    };

    Op op{};
    Reg dst;
    bool is64{};
    constexpr bool operator==(const Un&) const = default;
};

/// This instruction is encoded similarly to LDDW.
/// See comment in makeLddw() at asm_unmarshal.cpp
struct LoadMapFd {
    Reg dst;
    int32_t mapfd{};
    constexpr bool operator==(const LoadMapFd&) const = default;
};

// Load the address of a map value into a register.
struct LoadMapAddress {
    Reg dst;          // Destination register to store the address of the map value.
    int32_t mapfd{};  // File descriptor of the map to load the address from.
    int32_t offset{}; // Offset within the map, must be within bounds.

    constexpr bool operator==(const LoadMapAddress&) const = default;
};

/// Addressing payload for LDDW pseudo forms.
struct PseudoAddress {
    enum class Kind {
        VARIABLE_ADDR,    // src=3
        CODE_ADDR,        // src=4
        MAP_BY_IDX,       // src=5
        MAP_VALUE_BY_IDX, // src=6
    } kind{};
    int32_t imm{};
    int32_t next_imm{};
    constexpr bool operator==(const PseudoAddress&) const = default;
};

/// This instruction is encoded similarly to LDDW pseudo forms.
struct LoadPseudo {
    Reg dst;
    PseudoAddress addr;
    constexpr bool operator==(const LoadPseudo&) const = default;
};

struct Condition {
    enum class Op {
        EQ,
        NE,
        SET,
        NSET, // NSET does not exist in ebpf
        LT,
        LE,
        GT,
        GE,
        SLT,
        SLE,
        SGT,
        SGE,
    };

    Op op;
    Reg left;
    Value right;
    bool is64{};
    constexpr bool operator==(const Condition&) const = default;
};

struct Jmp {
    std::optional<Condition> cond;
    Label target;
    bool operator==(const Jmp&) const = default;
};

struct ArgSingle {
    enum class Kind {
        MAP_FD,
        MAP_FD_PROGRAMS,
        PTR_TO_MAP_KEY,
        PTR_TO_MAP_VALUE,
        PTR_TO_CTX,
        PTR_TO_STACK,
        PTR_TO_FUNC,
        ANYTHING,
        PTR_TO_SOCKET,
        PTR_TO_BTF_ID,
        PTR_TO_ALLOC_MEM,
        PTR_TO_SPIN_LOCK,
        PTR_TO_TIMER,
        CONST_SIZE_OR_ZERO,
        PTR_TO_WRITABLE_LONG,
        PTR_TO_WRITABLE_INT,
    } kind{};
    bool or_null{}; ///< true for PTR_TO_CTX_OR_NULL
    Reg reg;
    constexpr bool operator==(const ArgSingle&) const = default;
};

/// Pair of arguments to a function for pointer and size.
struct ArgPair {
    enum class Kind {
        PTR_TO_READABLE_MEM,
        PTR_TO_WRITABLE_MEM,
    } kind{};
    bool or_null{}; ///< true for PTR_TO_READABLE_MEM_OR_NULL and for PTR_TO_WRITABLE_MEM_OR_NULL
    Reg mem;        ///< Pointer.
    Reg size;       ///< Size of space pointed to.
    bool can_be_zero{};
    constexpr bool operator==(const ArgPair&) const = default;
};

enum class CallKind {
    helper,
    kfunc,
};

struct Call {
    int32_t func{};
    CallKind kind{CallKind::helper};
    // Equality intentionally matches only functional identity (call source + id).
    // Metadata such as is_supported/unsupported_reason is diagnostic-only.
    constexpr bool operator==(const Call& other) const { return func == other.func && kind == other.kind; }

    // TODO: move name and signature information somewhere else
    std::string name;
    bool is_supported{true};
    std::string unsupported_reason;
    bool is_map_lookup{};
    bool reallocate_packet{};
    std::optional<TypeEncoding> return_ptr_type{}; ///< Non-integer return pointer type, if any.
    bool return_nullable{};                        ///< Whether the return pointer may be null.
    std::vector<ArgSingle> singles;
    std::vector<ArgPair> pairs;
    std::string stack_frame_prefix; ///< Variable prefix at point of call.
};

/// Call a "function" (macro) within the same program.
struct CallLocal {
    Label target;
    std::string stack_frame_prefix; ///< Variable prefix to be used within the call.
    bool operator==(const CallLocal& other) const noexcept = default;
};

struct Exit {
    std::string stack_frame_prefix; ///< Variable prefix to clean up when exiting.
    bool operator==(const Exit& other) const noexcept = default;
};

/// Experimental callx instruction.
struct Callx {
    Reg func;
    constexpr bool operator==(const Callx&) const = default;
};

/// Call helper by BTF ID (CALL src=2).
struct CallBtf {
    int32_t btf_id{};
    constexpr bool operator==(const CallBtf&) const = default;
};

struct Deref {
    int32_t width{};
    Reg basereg;
    int32_t offset{};
    constexpr bool operator==(const Deref&) const = default;
};

/// Load/store instruction.
struct Mem {
    Deref access;
    Value value;
    bool is_load{};
    bool is_signed{};
    constexpr bool operator==(const Mem&) const = default;
};

/// A deprecated instruction for checked access to packets; it is actually a
/// function call, and analyzed as one, e.g., by scratching caller-saved
/// registers after it is performed.
struct Packet {
    int32_t width{};
    int32_t offset{};
    std::optional<Reg> regoffset;
    constexpr bool operator==(const Packet&) const = default;
};

/// Special instruction for atomically updating values inside shared memory.
/// The analysis just treats an atomic operation as a series of consecutive
/// operations, and the atomicity itself is not significant.
struct Atomic {
    enum class Op {
        ADD = 0x00,
        OR = 0x40,
        AND = 0x50,
        XOR = 0xa0,
        XCHG = 0xe0,    // Only valid with fetch=true.
        CMPXCHG = 0xf0, // Only valid with fetch=true.
    };

    Op op{};
    bool fetch{};
    Deref access;
    Reg valreg;
    constexpr bool operator==(const Atomic&) const = default;
};

/// Not an instruction, just used for failure cases.
struct Undefined {
    int opcode{};
    constexpr bool operator==(const Undefined&) const = default;
};

/// When a CFG is translated to its nondeterministic form, Conditional Jump
/// instructions are replaced by two Assume instructions, immediately after
/// the branch and before each jump target.
struct Assume {
    Condition cond;

    // True if the condition is implicitly written in the program (False for tests).
    bool is_implicit{true};

    constexpr bool operator==(const Assume&) const = default;
};

struct IncrementLoopCounter {
    Label name;
    bool operator==(const IncrementLoopCounter&) const = default;
};

using Instruction = std::variant<Undefined, Bin, Un, LoadMapFd, LoadMapAddress, LoadPseudo, Call, CallLocal, Callx,
                                 CallBtf, Exit, Jmp, Mem, Packet, Atomic, Assume, IncrementLoopCounter>;

using LabeledInstruction = std::tuple<Label, Instruction, std::optional<btf_line_info_t>>;
using InstructionSeq = std::vector<LabeledInstruction>;

/// Condition check whether something is a valid size.
struct ValidSize {
    Reg reg;
    bool can_be_zero{};
    constexpr bool operator==(const ValidSize&) const = default;
};

/// Condition check whether two registers can be compared with each other.
/// For example, one is not allowed to compare a number with a pointer,
/// or compare pointers to different memory regions.
struct Comparable {
    Reg r1;
    Reg r2;
    bool or_r2_is_number{}; ///< true for subtraction, false for comparison
    constexpr bool operator==(const Comparable&) const = default;
};

// ptr: ptr -> num : num
struct Addable {
    Reg ptr;
    Reg num;
    constexpr bool operator==(const Addable&) const = default;
};

// Condition check whether a register contains a non-zero number.
struct ValidDivisor {
    Reg reg;
    bool is_signed{};
    constexpr bool operator==(const ValidDivisor&) const = default;
};

enum class AccessType {
    compare,
    read,  // Memory pointed to must be initialized.
    write, // Memory pointed to must be writable.
};

struct ValidAccess {
    int call_stack_depth{};
    Reg reg;
    int32_t offset{};
    Value width{Imm{0}};
    bool or_null{};
    AccessType access_type{};
    constexpr bool operator==(const ValidAccess&) const = default;
};

/// Condition check whether something is a valid key value.
struct ValidMapKeyValue {
    Reg access_reg;
    Reg map_fd_reg;
    bool key{};
    constexpr bool operator==(const ValidMapKeyValue&) const = default;
};

/// Condition check whether a callback target register holds a valid top-level code label.
struct ValidCallbackTarget {
    Reg reg;
    constexpr bool operator==(const ValidCallbackTarget&) const = default;
};

// "if mem is not stack, val is num"
struct ValidStore {
    Reg mem;
    Reg val;
    constexpr bool operator==(const ValidStore&) const = default;
};

struct TypeConstraint {
    Reg reg;
    TypeGroup types;
    constexpr bool operator==(const TypeConstraint&) const = default;
};

struct FuncConstraint {
    Reg reg;
    constexpr bool operator==(const FuncConstraint&) const = default;
};

/// Condition check whether something is a valid size.
struct ZeroCtxOffset {
    Reg reg;
    bool or_null{};
    constexpr bool operator==(const ZeroCtxOffset&) const = default;
};

struct BoundedLoopCount {
    Label name;
    bool operator==(const BoundedLoopCount&) const = default;
    // Maximum number of loop iterations allowed during verification.
    // This prevents infinite loops while allowing reasonable bounded loops.
    // When exceeded, verification fails as the loop might not terminate.
    static constexpr int limit = 100000;
};

using Assertion = std::variant<Comparable, Addable, ValidDivisor, ValidAccess, ValidStore, ValidSize, ValidMapKeyValue,
                               ValidCallbackTarget, TypeConstraint, FuncConstraint, ZeroCtxOffset, BoundedLoopCount>;

std::ostream& operator<<(std::ostream& os, Instruction const& ins);
std::string to_string(Instruction const& ins);

std::ostream& operator<<(std::ostream& os, Bin::Op op);
std::ostream& operator<<(std::ostream& os, Condition::Op op);

inline std::ostream& operator<<(std::ostream& os, const Imm imm) { return os << to_signed(imm.v); }
inline std::ostream& operator<<(std::ostream& os, Reg const& a) { return os << "r" << gsl::narrow<int>(a.v); }
inline std::ostream& operator<<(std::ostream& os, Value const& a) {
    if (const auto pa = std::get_if<Imm>(&a)) {
        return os << *pa;
    }
    return os << std::get<Reg>(a);
}

std::ostream& operator<<(std::ostream& os, const Assertion& a);
std::string to_string(const Assertion& constraint);

void print(const InstructionSeq& insts, std::ostream& out, const std::optional<const Label>& label_to_print,
           bool print_line_info = false);

int size(const Instruction& inst);

template <class... Ts>
struct Overloaded : Ts... {
    using Ts::operator()...;
};

} // namespace prevail

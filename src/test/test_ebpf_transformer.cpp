// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>

#include <cstdint>
#include <limits>
#include <stdexcept>

#include "asm_syntax.hpp"
#include "asm_unmarshal.hpp"
#include "config.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/type_domain.hpp"
#include "crab/var_registry.hpp"
#include "platform.hpp"

namespace prevail {
class EbpfDomainInspector {
  public:
    static NumAbsDomain& numeric(EbpfDomain& dom) { return dom.m_inv; }
    static const NumAbsDomain& numeric(const EbpfDomain& dom) { return dom.m_inv; }
    static TypeDomain& type(EbpfDomain& dom) { return dom.type_inv; }
    static const TypeDomain& type(const EbpfDomain& dom) { return dom.type_inv; }
    static ArrayDomain& stack(EbpfDomain& dom) { return dom.stack; }
    static const ArrayDomain& stack(const EbpfDomain& dom) { return dom.stack; }
};
extern ebpf_platform_t g_platform_test;
} // namespace prevail

using namespace prevail;

namespace {

ProgramInfo make_program_info(const ebpf_platform_t& platform) {
    return ProgramInfo{
        .platform = &platform,
        .map_descriptors = {},
        .type = platform.get_program_type("unspec", "unspec"),
        .cache = {},
        .line_info = {},
    };
}

ProgramInfo default_program_info() { return make_program_info(g_ebpf_platform_linux); }

struct TransformerTestEnvironment {
    explicit TransformerTestEnvironment(const ProgramInfo& program_info = default_program_info()) {
        thread_local_options = {};
        thread_local_program_info.set(program_info);
    }

    ~TransformerTestEnvironment() {
        thread_local_program_info.clear();
        thread_local_options = {};
    }
};

struct ScopedMapDescriptor {
    explicit ScopedMapDescriptor(int map_fd) : map_fd(map_fd), original(g_platform_test.get_map_descriptor(map_fd)) {}

    ~ScopedMapDescriptor() { g_platform_test.get_map_descriptor(map_fd) = original; }

    EbpfMapDescriptor& descriptor() { return g_platform_test.get_map_descriptor(map_fd); }

  private:
    int map_fd;
    EbpfMapDescriptor original;
};

template <typename T>
void apply(EbpfDomain& dom, T instruction) {
    ebpf_domain_transform(dom, Instruction{std::move(instruction)});
}

Interval interval(const EbpfDomain& dom, Variable var) { return EbpfDomainInspector::numeric(dom).eval_interval(var); }

TypeEncoding reg_type(const EbpfDomain& dom, const Reg reg) {
    return EbpfDomainInspector::type(dom).get_type(EbpfDomainInspector::numeric(dom), reg);
}

bool has_type(const EbpfDomain& dom, const Reg reg, const TypeEncoding type) {
    return EbpfDomainInspector::type(dom).has_type(EbpfDomainInspector::numeric(dom), reg, type);
}

Number expect_singleton(const Interval& interval) {
    const auto singleton = interval.singleton();
    REQUIRE(singleton.has_value());
    return singleton.value();
}

Number expect_singleton(const EbpfDomain& dom, Variable var) { return expect_singleton(interval(dom, var)); }

constexpr Reg r(int value) { return Reg{gsl::narrow_cast<uint8_t>(value)}; }

void set_scalar(EbpfDomain& dom, const Reg reg, const int64_t value) {
    const uint64_t magnitude = value < 0 ? static_cast<uint64_t>(-value) : static_cast<uint64_t>(value);
    apply(dom, Bin{.op = Bin::Op::MOV, .dst = reg, .v = Imm{magnitude}, .is64 = true, .lddw = false});
    if (value < 0) {
        apply(dom, Un{.op = Un::Op::NEG, .dst = reg, .is64 = true});
    }
}

void expect_scalar(const EbpfDomain& dom, const Reg reg, const int64_t expected) {
    const auto pack = reg_pack(reg);
    CHECK(expect_singleton(dom, pack.svalue).cast_to<int64_t>() == expected);
    CHECK(expect_singleton(dom, pack.uvalue).cast_to<uint64_t>() == static_cast<uint64_t>(expected));
    CHECK(reg_type(dom, reg) == T_NUM);
}

} // namespace

TEST_CASE("MOV immediate assigns numeric type", "[transformer][bin]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(1), .v = Imm{42}, .is64 = true, .lddw = false});

    const auto pack = reg_pack(r(1));
    CHECK(interval(dom, pack.svalue) == Interval(42));
    CHECK(interval(dom, pack.uvalue) == Interval(42));
    CHECK(reg_type(dom, r(1)) == T_NUM);
    CHECK(interval(dom, pack.ctx_offset).is_top());
}

TEST_CASE("MOV register copies pointer metadata", "[transformer][bin]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(6), .v = r(R10_STACK_POINTER), .is64 = true, .lddw = false});

    const auto dst = reg_pack(r(6));
    const auto src = reg_pack(r(R10_STACK_POINTER));
    CHECK(has_type(dom, r(6), T_STACK));
    CHECK(interval(dom, dst.stack_offset) == interval(dom, src.stack_offset));
    CHECK(interval(dom, dst.svalue) == interval(dom, src.svalue));
    CHECK(interval(dom, dst.uvalue) == interval(dom, src.uvalue));
}

TEST_CASE("SUB immediate updates stack offset", "[transformer][bin]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(6), .v = r(R10_STACK_POINTER), .is64 = true, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::SUB, .dst = r(6), .v = Imm{32}, .is64 = true, .lddw = false});

    const auto dst = reg_pack(r(6));
    CHECK(expect_singleton(dom, dst.stack_offset).narrow<int>() == EBPF_TOTAL_STACK_SIZE - 32);
}

TEST_CASE("Pointer subtraction yields numeric difference", "[transformer][bin]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(6), .v = r(R10_STACK_POINTER), .is64 = true, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(7), .v = r(R10_STACK_POINTER), .is64 = true, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::SUB, .dst = r(7), .v = Imm{32}, .is64 = true, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::SUB, .dst = r(6), .v = r(7), .is64 = true, .lddw = false});

    const auto dst = reg_pack(r(6));
    CHECK(reg_type(dom, r(6)) == T_NUM);
    CHECK(expect_singleton(dom, dst.svalue).narrow<int>() == 32);
    CHECK(interval(dom, dst.stack_offset).is_top());
}

TEST_CASE("Scalar arithmetic with immediates is precise", "[transformer][bin]") {
    TransformerTestEnvironment env;

    SECTION("addition updates the register") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 5);

        apply(dom, Bin{.op = Bin::Op::ADD, .dst = r(1), .v = Imm{7}, .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 12);
    }

    SECTION("subtraction tracks signed results") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 20);

        apply(dom, Bin{.op = Bin::Op::SUB, .dst = r(1), .v = Imm{6}, .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 14);
    }

    SECTION("multiplication keeps exact products") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 3);

        apply(dom, Bin{.op = Bin::Op::MUL, .dst = r(1), .v = Imm{4}, .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 12);
    }

    SECTION("unsigned division yields floor quotient") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 100);

        apply(dom, Bin{.op = Bin::Op::UDIV, .dst = r(1), .v = Imm{4}, .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 25);
    }

    SECTION("unsigned modulus keeps the remainder") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 100);

        apply(dom, Bin{.op = Bin::Op::UMOD, .dst = r(1), .v = Imm{32}, .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 4);
    }

    SECTION("signed division obeys operand signs") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), -9);

        apply(dom, Bin{.op = Bin::Op::SDIV, .dst = r(1), .v = Imm{3}, .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), -3);
    }

    SECTION("signed modulus preserves the numerator sign") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), -10);

        apply(dom, Bin{.op = Bin::Op::SMOD, .dst = r(1), .v = Imm{4}, .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), -2);
    }
}

TEST_CASE("Scalar arithmetic with registers is precise", "[transformer][bin]") {
    TransformerTestEnvironment env;

    SECTION("addition accumulates both operands") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 5);
        set_scalar(dom, r(2), 11);

        apply(dom, Bin{.op = Bin::Op::ADD, .dst = r(1), .v = r(2), .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 16);
    }

    SECTION("subtraction can produce negative results") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 20);
        set_scalar(dom, r(2), 50);

        apply(dom, Bin{.op = Bin::Op::SUB, .dst = r(1), .v = r(2), .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), -30);
    }

    SECTION("multiplication remains exact") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 7);
        set_scalar(dom, r(2), 6);

        apply(dom, Bin{.op = Bin::Op::MUL, .dst = r(1), .v = r(2), .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 42);
    }

    SECTION("unsigned division truncates toward zero") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 100);
        set_scalar(dom, r(2), 8);

        apply(dom, Bin{.op = Bin::Op::UDIV, .dst = r(1), .v = r(2), .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 12);
    }

    SECTION("unsigned modulus returns the remainder") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 100);
        set_scalar(dom, r(2), 33);

        apply(dom, Bin{.op = Bin::Op::UMOD, .dst = r(1), .v = r(2), .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 1);
    }

    SECTION("signed division handles mixed signs") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), -18);
        set_scalar(dom, r(2), 6);

        apply(dom, Bin{.op = Bin::Op::SDIV, .dst = r(1), .v = r(2), .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), -3);
    }

    SECTION("signed modulus mirrors C semantics") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), -17);
        set_scalar(dom, r(2), 5);

        apply(dom, Bin{.op = Bin::Op::SMOD, .dst = r(1), .v = r(2), .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), -2);
    }
}

TEST_CASE("Pointer addition with scalar register adjusts stack offset", "[transformer][bin]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(6), .v = r(R10_STACK_POINTER), .is64 = true, .lddw = false});
    set_scalar(dom, r(1), -32);

    apply(dom, Bin{.op = Bin::Op::ADD, .dst = r(6), .v = r(1), .is64 = true, .lddw = false});

    const auto pack = reg_pack(r(6));
    CHECK(has_type(dom, r(6), T_STACK));
    CHECK(expect_singleton(dom, pack.stack_offset).narrow<int>() == EBPF_TOTAL_STACK_SIZE - 32);
}

TEST_CASE("MOV32 from pointer yields unknown scalar", "[transformer][bin]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(6), .v = r(R10_STACK_POINTER), .is64 = true, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(1), .v = r(6), .is64 = false, .lddw = false});

    const auto pack = reg_pack(r(1));
    CHECK(interval(dom, pack.svalue) == Interval::unsigned_int(32));
    CHECK(interval(dom, pack.uvalue) == Interval::unsigned_int(32));
    CHECK(interval(dom, pack.stack_offset).is_top());
    CHECK(reg_type(dom, r(1)) == T_UNINIT);
}

TEST_CASE("Bitwise immediates produce exact results", "[transformer][bin]") {
    TransformerTestEnvironment env;

    SECTION("bitwise and applies the mask") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 13);

        apply(dom, Bin{.op = Bin::Op::AND, .dst = r(1), .v = Imm{7}, .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 5);
    }

    SECTION("bitwise or merges bits") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 1);

        apply(dom, Bin{.op = Bin::Op::OR, .dst = r(1), .v = Imm{6}, .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 7);
    }

    SECTION("bitwise xor toggles bits") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        set_scalar(dom, r(1), 5);

        apply(dom, Bin{.op = Bin::Op::XOR, .dst = r(1), .v = Imm{3}, .is64 = true, .lddw = false});

        expect_scalar(dom, r(1), 6);
    }
}

TEST_CASE("LSH immediate masks shift amount", "[transformer][bin]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(1), .v = Imm{1}, .is64 = false, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::LSH, .dst = r(1), .v = Imm{40}, .is64 = false, .lddw = false});

    const auto pack = reg_pack(r(1));
    CHECK(expect_singleton(dom, pack.svalue).narrow<int>() == 256);
    CHECK(expect_singleton(dom, pack.uvalue).narrow<int>() == 256);
    CHECK(reg_type(dom, r(1)) == T_NUM);
}

TEST_CASE("Variable shift count falls back to unknown result", "[transformer][bin]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    set_scalar(dom, r(1), 1024);

    const auto src_pack = reg_pack(r(2));
    auto& numeric = EbpfDomainInspector::numeric(dom);
    numeric.set(src_pack.svalue, Interval(0, 8));
    numeric.set(src_pack.uvalue, Interval(0, 8));
    numeric.assign(src_pack.type, static_cast<int>(T_NUM));

    apply(dom, Bin{.op = Bin::Op::RSH, .dst = r(1), .v = r(2), .is64 = true, .lddw = false});

    const auto dst_pack = reg_pack(r(1));
    CHECK(interval(dom, dst_pack.svalue).is_top());
    CHECK(interval(dom, dst_pack.uvalue).is_top());
    CHECK(reg_type(dom, r(1)) == T_NUM);
}

TEST_CASE("Arithmetic shift right with register preserves sign", "[transformer][bin]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    set_scalar(dom, r(1), -8);
    set_scalar(dom, r(2), 1);

    apply(dom, Bin{.op = Bin::Op::ARSH, .dst = r(1), .v = r(2), .is64 = true, .lddw = false});

    expect_scalar(dom, r(1), -4);
}

TEST_CASE("MOVSX sign-extends values", "[transformer][bin]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(2), .v = Imm{0xffff}, .is64 = true, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::MOVSX16, .dst = r(2), .v = r(2), .is64 = true, .lddw = false});

    const auto pack = reg_pack(r(2));
    CHECK(expect_singleton(dom, pack.svalue).narrow<int>() == -1);
    CHECK(expect_singleton(dom, pack.uvalue).cast_to<uint64_t>() == std::numeric_limits<uint64_t>::max());
}

TEST_CASE("Byte swapping obeys endianness", "[transformer][un]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);
    const auto pack = reg_pack(r(1));

    SECTION("little-endian host performs swap") {
        thread_local_options.big_endian = false;
        apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(1), .v = Imm{0x12345678}, .is64 = true, .lddw = false});
        apply(dom, Un{.op = Un::Op::SWAP32, .dst = r(1), .is64 = true});
        CHECK(expect_singleton(dom, pack.uvalue).narrow<int>() == 0x78563412);
    }

    SECTION("big-endian host leaves value unchanged") {
        thread_local_options.big_endian = true;
        apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(1), .v = Imm{0x12345678}, .is64 = true, .lddw = false});
        apply(dom, Un{.op = Un::Op::BE32, .dst = r(1), .is64 = true});
        CHECK(expect_singleton(dom, pack.uvalue).narrow<int>() == 0x12345678);
    }
}

TEST_CASE("NEG makes value negative and clears offsets", "[transformer][un]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(1), .v = Imm{5}, .is64 = true, .lddw = false});
    apply(dom, Un{.op = Un::Op::NEG, .dst = r(1), .is64 = true});

    const auto pack = reg_pack(r(1));
    CHECK(expect_singleton(dom, pack.svalue).narrow<int>() == -5);
    CHECK(interval(dom, pack.ctx_offset).is_top());
}

TEST_CASE("Assume narrows numeric interval", "[transformer][assume]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    const auto pack = reg_pack(r(1));
    auto& numeric = EbpfDomainInspector::numeric(dom);
    numeric.set(pack.svalue, Interval(0, 10));
    numeric.set(pack.uvalue, Interval(0, 10));
    numeric.assign(pack.type, static_cast<int>(T_NUM));

    apply(dom, Assume{.cond = Condition{.op = Condition::Op::GE, .left = r(1), .right = Imm{5}, .is64 = true}});

    auto result = interval(dom, pack.svalue);
    CHECK(result.lb().narrow<int>() == 5);
    CHECK(result.ub().narrow<int>() == 10);
}

TEST_CASE("Packet helper resets caller-saved registers", "[transformer][packet]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(1), .v = Imm{7}, .is64 = true, .lddw = false});
    apply(dom, Packet{.width = 4, .offset = 0, .regoffset = {}});

    const auto r0 = reg_pack(r(0));
    CHECK(reg_type(dom, r(0)) == T_NUM);
    CHECK(interval(dom, r0.svalue).is_top());
    for (int reg = R1_ARG; reg <= R5_ARG; ++reg) {
        CHECK(interval(dom, reg_pack(r(reg)).svalue).is_top());
    }
}

TEST_CASE("Stack store and load round trip", "[transformer][mem]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    const Deref access{.width = 8, .basereg = r(R10_STACK_POINTER), .offset = -8};
    apply(dom, Mem{.access = access, .value = Imm{7}, .is_load = false});
    apply(dom, Mem{.access = access, .value = r(1), .is_load = true});

    const auto pack = reg_pack(r(1));
    CHECK(reg_type(dom, r(1)) == T_NUM);
    CHECK(expect_singleton(dom, pack.svalue).narrow<int>() == 7);
    CHECK(expect_singleton(dom, pack.uvalue).narrow<int>() == 7);
}

TEST_CASE("Stack load restores pointer metadata", "[transformer][mem]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(6), .v = r(R10_STACK_POINTER), .is64 = true, .lddw = false});

    const Deref slot{.width = 8, .basereg = r(R10_STACK_POINTER), .offset = -16};
    apply(dom, Mem{.access = slot, .value = r(6), .is_load = false});
    apply(dom, Mem{.access = slot, .value = r(1), .is_load = true});

    const auto r1_pack = reg_pack(r(1));
    const auto r6_pack = reg_pack(r(6));
    CHECK(has_type(dom, r(1), T_STACK));
    CHECK(interval(dom, r1_pack.stack_offset) == interval(dom, r6_pack.stack_offset));
    CHECK(interval(dom, r1_pack.stack_numeric_size) == interval(dom, r6_pack.stack_numeric_size));
}

TEST_CASE("Increment loop counter", "[transformer][loops]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    const Label label{0};
    ebpf_domain_initialize_loop_counter(dom, label);
    const Variable counter = variable_registry->loop_counter(to_string(label));
    CHECK(expect_singleton(dom, counter).narrow<int>() == 0);

    apply(dom, IncrementLoopCounter{label});
    CHECK(expect_singleton(dom, counter).narrow<int>() == 1);
}

TEST_CASE("LoadMapFd records map identifier", "[transformer][maps]") {
    TransformerTestEnvironment env{make_program_info(g_platform_test)};
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    constexpr int map_fd = 7;
    ScopedMapDescriptor descriptor_guard{map_fd};
    auto& descriptor = descriptor_guard.descriptor();
    descriptor.type = 1; // Regular data map.

    apply(dom, LoadMapFd{.dst = r(1), .mapfd = map_fd});

    const auto pack = reg_pack(r(1));
    CHECK(reg_type(dom, r(1)) == T_MAP);
    CHECK(interval(dom, pack.map_fd) == Interval(map_fd));
}

TEST_CASE("LoadMapFd recognizes program map arrays", "[transformer][maps]") {
    TransformerTestEnvironment env{make_program_info(g_platform_test)};
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    constexpr int map_fd = 8;
    ScopedMapDescriptor descriptor_guard{map_fd};
    auto& descriptor = descriptor_guard.descriptor();
    descriptor.type = 3; // BPF_MAP_TYPE_PROG_ARRAY -> program maps.

    apply(dom, LoadMapFd{.dst = r(2), .mapfd = map_fd});

    CHECK(reg_type(dom, r(2)) == T_MAP_PROGRAMS);
    CHECK(interval(dom, reg_pack(r(2)).map_fd) == Interval(map_fd));
}

TEST_CASE("LoadMapAddress sets shared pointer metadata", "[transformer][maps]") {
    TransformerTestEnvironment env{make_program_info(g_platform_test)};
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    constexpr int map_fd = 5;
    ScopedMapDescriptor descriptor_guard{map_fd};
    auto& descriptor = descriptor_guard.descriptor();
    descriptor.type = 1;
    descriptor.value_size = 64;

    apply(dom, LoadMapAddress{.dst = r(3), .mapfd = map_fd, .offset = 8});

    const auto pack = reg_pack(r(3));
    CHECK(has_type(dom, r(3), T_SHARED));
    CHECK(interval(dom, pack.shared_offset) == Interval(8));
    CHECK(interval(dom, pack.shared_region_size) == Interval(descriptor.value_size));
}

TEST_CASE("LoadMapAddress rejects program map addresses", "[transformer][maps]") {
    TransformerTestEnvironment env{make_program_info(g_platform_test)};
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    constexpr int map_fd = 9;
    ScopedMapDescriptor descriptor_guard{map_fd};
    auto& descriptor = descriptor_guard.descriptor();
    descriptor.type = 3; // Program array is unsupported for LoadMapAddress.

    CHECK_THROWS_AS(apply(dom, LoadMapAddress{.dst = r(4), .mapfd = map_fd, .offset = 0}), std::invalid_argument);
}

TEST_CASE("Map lookup returns shared value pointers", "[transformer][maps]") {
    TransformerTestEnvironment env{make_program_info(g_platform_test)};
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    constexpr int map_fd = 10;
    ScopedMapDescriptor descriptor_guard{map_fd};
    auto& descriptor = descriptor_guard.descriptor();
    descriptor.type = 1;
    descriptor.value_size = 80;
    descriptor.inner_map_fd = 0;

    apply(dom, LoadMapFd{.dst = r(1), .mapfd = map_fd});

    Call lookup = make_call(1, *thread_local_program_info->platform);
    apply(dom, lookup);

    const auto r0_pack = reg_pack(r(0));
    CHECK(has_type(dom, r(0), T_SHARED));
    CHECK(interval(dom, r0_pack.shared_offset) == Interval(0));
    CHECK(interval(dom, r0_pack.shared_region_size) == Interval(descriptor.value_size));
}

TEST_CASE("Map lookup from map-of-maps yields inner map fd", "[transformer][maps]") {
    TransformerTestEnvironment env{make_program_info(g_platform_test)};
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    constexpr int outer_map_fd = 11;
    constexpr int inner_map_fd = 42;
    ScopedMapDescriptor descriptor_guard{outer_map_fd};
    auto& descriptor = descriptor_guard.descriptor();
    descriptor.type = 12; // ARRAY_OF_MAPS -> returns another map fd.
    descriptor.inner_map_fd = inner_map_fd;

    apply(dom, LoadMapFd{.dst = r(1), .mapfd = outer_map_fd});

    Call lookup = make_call(1, *thread_local_program_info->platform);
    apply(dom, lookup);

    const auto r0_pack = reg_pack(r(0));
    CHECK(has_type(dom, r(0), T_MAP));
    CHECK(interval(dom, r0_pack.map_fd) == Interval(inner_map_fd));
}

TEST_CASE("Callx dispatches helper id stored in register", "[transformer][maps]") {
    TransformerTestEnvironment env{make_program_info(g_platform_test)};
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    constexpr int map_fd = 12;
    ScopedMapDescriptor descriptor_guard{map_fd};
    auto& descriptor = descriptor_guard.descriptor();
    descriptor.type = 1;
    descriptor.value_size = 32;

    apply(dom, LoadMapFd{.dst = r(1), .mapfd = map_fd});
    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(5), .v = Imm{1}, .is64 = true, .lddw = false});

    apply(dom, Callx{.func = r(5)});

    const auto r0_pack = reg_pack(r(0));
    CHECK(has_type(dom, r(0), T_SHARED));
    CHECK(interval(dom, r0_pack.shared_region_size) == Interval(descriptor.value_size));
}

TEST_CASE("Writable stack arguments become numeric after call", "[transformer][call]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    const Deref slot{.width = 8, .basereg = r(R10_STACK_POINTER), .offset = -16};
    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(6), .v = r(R10_STACK_POINTER), .is64 = true, .lddw = false});
    apply(dom, Mem{.access = slot, .value = r(6), .is_load = false});

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(1), .v = r(R10_STACK_POINTER), .is64 = true, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::SUB, .dst = r(1), .v = Imm{16}, .is64 = true, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(2), .v = Imm{8}, .is64 = true, .lddw = false});

    Call call{
        .func = 0,
        .name = "test",
        .is_map_lookup = false,
        .reallocate_packet = false,
        .singles = {},
        .pairs = {ArgPair{.kind = ArgPair::Kind::PTR_TO_WRITABLE_MEM, .mem = r(1), .size = r(2), .can_be_zero = false}},
        .stack_frame_prefix = {},
    };
    apply(dom, call);

    apply(dom, Mem{.access = slot, .value = r(3), .is_load = true});
    CHECK(reg_type(dom, r(3)) == T_NUM);
}

TEST_CASE("Call with packet reallocation forgets packet registers", "[transformer][call]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    auto& numeric = EbpfDomainInspector::numeric(dom);
    auto& type_dom = EbpfDomainInspector::type(dom);
    const auto r1_pack = reg_pack(r(1));
    numeric.assign(r1_pack.packet_offset, 32);
    type_dom.assign_type(numeric, r(1), T_PACKET);

    Call call{
        .func = 0,
        .name = "realloc_packet",
        .is_map_lookup = false,
        .reallocate_packet = true,
        .singles = {},
        .pairs = {},
        .stack_frame_prefix = {},
    };
    apply(dom, call);

    CHECK(reg_type(dom, r(1)) == T_UNINIT);
    CHECK(interval(dom, r1_pack.packet_offset).is_top());

    const Interval packet_size = interval(dom, variable_registry->packet_size());
    CHECK(packet_size.lb().narrow<int>() == 0);
    CHECK(packet_size.ub().narrow<int>() == MAX_PACKET_SIZE - 1);
    const Interval meta_offset = interval(dom, variable_registry->meta_offset());
    CHECK(meta_offset.lb().narrow<int>() == -4098);
    CHECK(meta_offset.ub().narrow<int>() == 0);
}

TEST_CASE("Call scratches caller-saved registers", "[transformer][call]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(1), .v = Imm{13}, .is64 = true, .lddw = false});

    Call helper = make_call(7, *thread_local_program_info->platform);
    apply(dom, helper);

    CHECK(reg_type(dom, r(0)) == T_NUM);
    for (int reg = R1_ARG; reg <= R5_ARG; ++reg) {
        CHECK(interval(dom, reg_pack(r(reg)).svalue).is_top());
    }
}

TEST_CASE("CallLocal snapshots callee-saved registers", "[transformer][subprogram]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(6), .v = Imm{5}, .is64 = true, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(7), .v = Imm{17}, .is64 = true, .lddw = false});

    const auto r6_pack = reg_pack(r(6));
    const auto r7_pack = reg_pack(r(7));
    const auto r6_before = interval(dom, r6_pack.svalue);
    const auto r7_before = interval(dom, r7_pack.svalue);

    const std::string frame = "inline";
    const Variable saved_r6_value = variable_registry->stack_frame_var(DataKind::svalues, R6, frame);
    const Variable saved_r7_value = variable_registry->stack_frame_var(DataKind::svalues, R7, frame);
    const Variable saved_r8_value = variable_registry->stack_frame_var(DataKind::svalues, R8, frame);
    const Variable saved_r6_type = variable_registry->stack_frame_var(DataKind::types, R6, frame);

    CHECK(interval(dom, saved_r6_value).is_top());
    CHECK(interval(dom, saved_r7_value).is_top());

    CallLocal call{.target = Label{1}, .stack_frame_prefix = frame};
    apply(dom, call);

    const auto r10_pack = reg_pack(r(R10_STACK_POINTER));
    CHECK(expect_singleton(dom, r10_pack.stack_offset).narrow<int>() ==
          EBPF_TOTAL_STACK_SIZE - EBPF_SUBPROGRAM_STACK_SIZE);
    CHECK(interval(dom, r6_pack.svalue) == r6_before);
    CHECK(interval(dom, r7_pack.svalue) == r7_before);
    CHECK(interval(dom, saved_r6_value) == r6_before);
    CHECK(interval(dom, saved_r7_value) == r7_before);
    CHECK(expect_singleton(dom, saved_r6_type).narrow<int>() == static_cast<int>(T_NUM));
    CHECK(interval(dom, saved_r8_value).is_top());
}

TEST_CASE("Exit restores callee-saved registers from snapshot", "[transformer][subprogram]") {
    TransformerTestEnvironment env;
    EbpfDomain dom = EbpfDomain::setup_entry(false);

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(6), .v = Imm{5}, .is64 = true, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(7), .v = Imm{9}, .is64 = true, .lddw = false});

    const std::string frame = "inline";
    const Variable saved_r6_value = variable_registry->stack_frame_var(DataKind::svalues, R6, frame);
    const Variable saved_r7_value = variable_registry->stack_frame_var(DataKind::svalues, R7, frame);
    const Variable saved_r6_type = variable_registry->stack_frame_var(DataKind::types, R6, frame);

    CallLocal call{.target = Label{1}, .stack_frame_prefix = frame};
    apply(dom, call);

    const int expected_r6 = expect_singleton(dom, reg_pack(r(6)).svalue).narrow<int>();
    const int expected_r7 = expect_singleton(dom, reg_pack(r(7)).svalue).narrow<int>();
    CHECK(expect_singleton(dom, saved_r6_type).narrow<int>() == static_cast<int>(T_NUM));

    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(6), .v = Imm{99}, .is64 = true, .lddw = false});
    apply(dom, Bin{.op = Bin::Op::MOV, .dst = r(7), .v = Imm{123}, .is64 = true, .lddw = false});

    apply(dom, Exit{.stack_frame_prefix = frame});

    CHECK(expect_singleton(dom, reg_pack(r(6)).svalue).narrow<int>() == expected_r6);
    CHECK(expect_singleton(dom, reg_pack(r(7)).svalue).narrow<int>() == expected_r7);
    CHECK(interval(dom, saved_r6_value).is_top());
    CHECK(interval(dom, saved_r7_value).is_top());
    CHECK(interval(dom, saved_r6_type).is_top());
    CHECK(expect_singleton(dom, reg_pack(r(R10_STACK_POINTER)).stack_offset).narrow<int>() == EBPF_TOTAL_STACK_SIZE);
}

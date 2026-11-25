// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// The transformer of an unchecked (implicit) Assume, as reached by privileged programs, whose
// comparisons the checker does not restrict. Pruning a branch is a claim about every execution,
// so it must not rest on where a region lies in memory, which the analysis does not know.

#include <catch2/catch_all.hpp>

#include "arith/dsl_syntax.hpp"
#include "crab/ebpf_domain.hpp"
#include "ir/program.hpp"
#include "platform.hpp"
#include "test/parse.hpp"
#include "verifier.hpp"

using namespace prevail;

namespace {

constexpr int64_t ptr_max_default = 2147418112;
constexpr int shared_size = 8;
const int stack_size = RuntimeConfig{}.total_stack_size();
const int max_packet_size = RuntimeConfig{}.max_packet_size;
const Number two_to_63{"9223372036854775808"};

ProgramInfo default_info() {
    return ProgramInfo{
        .platform = &g_ebpf_platform_linux,
        .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec"),
    };
}

std::vector<LinearConstraint> nonnull_address(const RegPack& r) {
    using namespace dsl_syntax;
    return {r.uvalue >= 1, r.uvalue <= ptr_max_default};
}

AnalysisContext default_context() {
    VerifierOptions options{};
    const InstructionSeq sequence{{Label{0}, Exit{}, std::nullopt}};
    return AnalysisContext{Program::from_sequence(sequence, default_info(), options), options};
}

bool is_feasible(const EbpfDomain& pre, const Condition& cond) {
    const AnalysisContext context = default_context();
    EbpfDomain post = pre;
    ebpf_domain_transform(post, Assume{.cond = cond, .is_implicit = true}, context);
    return !post.is_bottom();
}

// Whether the checker lets an unprivileged program compare the pointer in `reg`.
bool checker_admits_comparison(const EbpfDomain& pre, const uint8_t reg) {
    const AnalysisContext context = default_context();
    return !ebpf_domain_check(pre, ValidAccess{.call_stack_depth = 1, .reg = Reg{reg}}, Label{0}, context);
}

Condition reg_cond(const Condition::Op op, const uint8_t left, const uint8_t right, const bool is64 = true) {
    return Condition{.op = op, .left = Reg{left}, .right = Reg{right}, .is64 = is64};
}

Condition imm_cond(const Condition::Op op, const uint8_t left, const uint64_t imm, const bool is64 = true) {
    return Condition{.op = op, .left = Reg{left}, .right = Imm{imm}, .is64 = is64};
}

EbpfDomain ctx_and_number(const int64_t number) {
    using namespace dsl_syntax;
    const RegPack r1 = reg_pack(1);
    const RegPack r2 = reg_pack(2);
    std::vector<LinearConstraint> csts = nonnull_address(r1);
    csts.push_back(r1.ctx_offset == 0);
    csts.push_back(r2.svalue == number);
    csts.push_back(r2.uvalue == number);
    return EbpfDomain::from_constraints({{reg_type(Reg{1}), TypeSet{T_CTX}}, {reg_type(Reg{2}), TypeSet{T_NUM}}}, csts);
}

// r1 and r2 are non-null pointers of one type at the given offsets. r10 is the stack pointer of the entry
// function, the packet has no metadata, and a map value is `shared_size` bytes: what the bounds of the
// regions are stated in terms of.
EbpfDomain same_type_pointers(const TypeEncoding type, const Variable left_offset, const Variable right_offset,
                              const Number& left, const Number& right) {
    using namespace dsl_syntax;
    std::vector<LinearConstraint> csts = nonnull_address(reg_pack(1));
    const auto r2_address = nonnull_address(reg_pack(2));
    csts.insert(csts.end(), r2_address.begin(), r2_address.end());
    csts.push_back(left_offset == left);
    csts.push_back(right_offset == right);
    csts.push_back(reg_pack(R10_STACK_POINTER).stack_offset == stack_size);
    csts.push_back(variable_registry.meta_offset() == 0);
    csts.push_back(reg_pack(1).shared_region_size == shared_size);
    csts.push_back(reg_pack(2).shared_region_size == shared_size);
    return EbpfDomain::from_constraints({{reg_type(Reg{1}), TypeSet{type}},
                                         {reg_type(Reg{2}), TypeSet{type}},
                                         {reg_type(Reg{R10_STACK_POINTER}), TypeSet{T_STACK}}},
                                        csts);
}

// Whether a kprobe program passes that runs `guard`, which ends in a jump to <out> (the final `r0 = 0`),
// and behind it stores through a number. A privileged program is never let to do that, so the program
// passes only if the analysis takes the fall-through of the jump to be unreachable.
bool accepts_store_behind(std::vector<std::string> guard) {
    guard.emplace_back("r3 = 0x41414141");
    guard.emplace_back("*(u64 *)(r3 + 0) = r3");
    const std::map<std::string, Label> labels{{"<out>", Label{static_cast<int>(guard.size())}}};
    guard.emplace_back("r0 = 0");
    guard.emplace_back("exit");
    const ProgramInfo info{.platform = &g_ebpf_platform_linux,
                           .type = g_ebpf_platform_linux.get_program_type("kprobe/x", "")};
    InstructionSeq instructions;
    for (size_t i = 0; i < guard.size(); ++i) {
        instructions.emplace_back(Label{static_cast<int>(i)}, parse_instruction(guard[i], labels, info.type),
                                  std::nullopt);
    }
    return !analyze({Program::from_sequence(instructions, info, {}), {}}).failed;
}

} // namespace

// The checker asserts nothing about the comparisons of a privileged program, so the transformer alone
// stands between a comparison whose outcome it gets wrong and code that is then never checked
// (ANT-2026-C3129787).
TEST_CASE("Code behind a comparison of a pointer outside its region is verified", "[assume][pointer]") {
    const std::string two_to_63 = "r2 = -9223372036854775808 ll";
    // In 64 bits r6 is r10 again, so the fall-through is taken on every run.
    CHECK_FALSE(accepts_store_behind({"r6 = r10", two_to_63, "r6 += r2", "r6 += r2", "if r6 != r10 goto <out>"}));
    CHECK_FALSE(accepts_store_behind({"r6 = r1", two_to_63, "r6 += r2", "r6 += r2", "if r6 != r1 goto <out>"}));
    // The sum wraps to below r10 wherever the stack lies in the upper half of the address space.
    CHECK_FALSE(accepts_store_behind({"r6 = r10", "r2 = 0x7fffffffffffffff ll", "r6 += r2", "if r6 > r10 goto <out>"}));
    CHECK_FALSE(
        accepts_store_behind({"r6 = r10", "r2 = 0x4000000000000000 ll", "r6 += r2", "if r6 >= r10 goto <out>"}));
    // The sum is zero for a context at 0xffffc90000000000.
    const std::string addend = "r2 = 0x370000000000 ll";
    CHECK_FALSE(accepts_store_behind({"r6 = r1", addend, "r6 += r2", "if r6 != 0 goto <out>"}));
    CHECK_FALSE(accepts_store_behind({"r6 = r10", addend, "r6 += r2", "r7 = 0", "if r6 != r7 goto <out>"}));
    CHECK_FALSE(accepts_store_behind({"r6 = r10", addend, "r6 -= r2", "if r6 != 0 goto <out>"}));

    // Within the region the outcome is known, and the unreachable store is not held against the program.
    CHECK(accepts_store_behind({"r6 = r10", "r6 += -8", "if r6 != r10 goto <out>"}));
    CHECK(accepts_store_behind({"r6 = r1", "r6 += 8", "if r6 > r1 goto <out>"}));
    CHECK(accepts_store_behind({"r6 = r10", "r6 += -8", "if r6 != 0 goto <out>"}));
}

TEST_CASE("Pointer compared with a nonzero number keeps both branches", "[assume][pointer]") {
    using Op = Condition::Op;
    const EbpfDomain pre = ctx_and_number(4027836164);
    CHECK(is_feasible(pre, reg_cond(Op::GE, 1, 2)));
    CHECK(is_feasible(pre, reg_cond(Op::LT, 1, 2)));
    CHECK(is_feasible(pre, reg_cond(Op::EQ, 1, 2)));
    CHECK(is_feasible(pre, reg_cond(Op::SGT, 1, 2)));
}

TEST_CASE("Pointer compared with a nonzero immediate keeps both branches", "[assume][pointer]") {
    using Op = Condition::Op;
    const EbpfDomain pre = ctx_and_number(0);
    CHECK(is_feasible(pre, imm_cond(Op::GT, 1, 0x80000000)));
    CHECK(is_feasible(pre, imm_cond(Op::LE, 1, 0x80000000)));
    CHECK(is_feasible(pre, imm_cond(Op::EQ, 1, 0x1000)));
}

TEST_CASE("Non-null pointer compared with zero is a null check", "[assume][pointer]") {
    using Op = Condition::Op;
    const EbpfDomain pre = ctx_and_number(0);
    CHECK_FALSE(is_feasible(pre, reg_cond(Op::EQ, 1, 2)));
    CHECK(is_feasible(pre, reg_cond(Op::NE, 1, 2)));
    CHECK_FALSE(is_feasible(pre, imm_cond(Op::EQ, 1, 0)));
    CHECK(is_feasible(pre, imm_cond(Op::GT, 1, 0)));
}

TEST_CASE("Signed or 32-bit comparison of a pointer with zero keeps both branches", "[assume][pointer]") {
    using Op = Condition::Op;
    const EbpfDomain pre = ctx_and_number(0);
    CHECK(is_feasible(pre, reg_cond(Op::SLT, 1, 2)));
    CHECK(is_feasible(pre, reg_cond(Op::SGE, 1, 2)));
    CHECK(is_feasible(pre, reg_cond(Op::EQ, 1, 2, false)));
    CHECK(is_feasible(pre, imm_cond(Op::SLT, 1, 0)));
    CHECK(is_feasible(pre, imm_cond(Op::EQ, 1, 0, false)));
}

TEST_CASE("Pointers into one singleton region are ordered by offset", "[assume][pointer]") {
    using Op = Condition::Op;
    const EbpfDomain pre = same_type_pointers(T_CTX, reg_pack(1).ctx_offset, reg_pack(2).ctx_offset, 4, 0);
    CHECK_FALSE(is_feasible(pre, reg_cond(Op::LT, 1, 2)));
    CHECK_FALSE(is_feasible(pre, reg_cond(Op::EQ, 1, 2)));
    CHECK(is_feasible(pre, reg_cond(Op::GT, 1, 2)));
    // A signed or 32-bit view of two addresses depends on where the region lies.
    CHECK(is_feasible(pre, reg_cond(Op::SLT, 1, 2)));
    CHECK(is_feasible(pre, reg_cond(Op::LT, 1, 2, false)));
}

TEST_CASE("Pointers that may have left their region are not compared by offset", "[assume][pointer]") {
    using Op = Condition::Op;
    const Variable left = reg_pack(1).stack_offset;
    const Variable right = reg_pack(2).stack_offset;

    const EbpfDomain within = same_type_pointers(T_STACK, left, right, stack_size - 8, stack_size);
    CHECK(is_feasible(within, reg_cond(Op::LT, 1, 2)));
    CHECK_FALSE(is_feasible(within, reg_cond(Op::GE, 1, 2)));
    CHECK_FALSE(is_feasible(within, reg_cond(Op::EQ, 1, 2)));

    // An address is taken modulo 2^64 and an offset is not: r1 = r2; r1 += 2^63; r1 += 2^63 is r2 again.
    const EbpfDomain wrapped =
        same_type_pointers(T_STACK, left, right, Number{stack_size} - two_to_63 - two_to_63, stack_size);
    CHECK(is_feasible(wrapped, reg_cond(Op::EQ, 1, 2)));
    CHECK(is_feasible(wrapped, reg_cond(Op::NE, 1, 2)));

    // Half way around, which of the two is the lower address depends on where the stack lies.
    const EbpfDomain far = same_type_pointers(T_STACK, left, right, Number{stack_size} + two_to_63, stack_size);
    CHECK(is_feasible(far, reg_cond(Op::LT, 1, 2)));
    CHECK(is_feasible(far, reg_cond(Op::GT, 1, 2)));
    CHECK(is_feasible(far, reg_cond(Op::EQ, 1, 2)));

    // One operand outside its region is enough, whichever it is.
    const EbpfDomain right_outside = same_type_pointers(T_STACK, left, right, stack_size, -1);
    CHECK(is_feasible(right_outside, reg_cond(Op::LT, 1, 2)));
    CHECK(is_feasible(right_outside, reg_cond(Op::EQ, 1, 2)));

    const EbpfDomain wrapped_ctx =
        same_type_pointers(T_CTX, reg_pack(1).ctx_offset, reg_pack(2).ctx_offset, two_to_63 + two_to_63, 0);
    CHECK(is_feasible(wrapped_ctx, reg_cond(Op::EQ, 1, 2)));
    CHECK(is_feasible(wrapped_ctx, reg_cond(Op::LT, 1, 2)));

    const EbpfDomain far_packet = same_type_pointers(T_PACKET, reg_pack(1).packet_offset, reg_pack(2).packet_offset,
                                                     Number{max_packet_size} + 1, 0);
    CHECK(is_feasible(far_packet, reg_cond(Op::EQ, 1, 2)));
    CHECK(is_feasible(far_packet, reg_cond(Op::LT, 1, 2)));
}

TEST_CASE("Pointer that may have left its region is not null-checked", "[assume][pointer]") {
    using Op = Condition::Op;
    const struct {
        TypeEncoding type;
        Variable left;
        Variable right;
        Number end;
    } regions[] = {
        {T_STACK, reg_pack(1).stack_offset, reg_pack(2).stack_offset, Number{stack_size}},
        {T_CTX, reg_pack(1).ctx_offset, reg_pack(2).ctx_offset, Number{default_info().type.ctx_descriptor->size}},
        {T_PACKET, reg_pack(1).packet_offset, reg_pack(2).packet_offset, Number{max_packet_size}},
        {T_SHARED, reg_pack(1).shared_offset, reg_pack(2).shared_offset, Number{shared_size}},
    };
    for (const auto& [type, left, right, end] : regions) {
        CAPTURE(type);
        // Within its region, one past the end included, a pointer that was not null is not zero.
        const EbpfDomain within = same_type_pointers(type, left, right, end, 0);
        CHECK_FALSE(is_feasible(within, imm_cond(Op::EQ, 1, 0)));
        CHECK(is_feasible(within, imm_cond(Op::NE, 1, 0)));

        // Outside it the address may be any, zero included: r1 = r2; r1 -= <the address r2 holds>.
        for (const Number& offset : {end + 1, Number{-1}, Number{0} - two_to_63}) {
            const EbpfDomain outside = same_type_pointers(type, left, right, offset, 0);
            CHECK(is_feasible(outside, imm_cond(Op::EQ, 1, 0)));
            CHECK(is_feasible(outside, imm_cond(Op::NE, 1, 0)));
        }
    }
}

// The transformer decides a comparison only for pointers within their region, and states the bounds of the
// regions itself (is_within_region). Wherever the checker lets an unprivileged program compare a pointer,
// those bounds must hold too, or the comparison would pass the checker and then teach the analysis nothing.
TEST_CASE("A comparison that the checker admits is decided", "[assume][pointer]") {
    using Op = Condition::Op;
    const struct {
        TypeEncoding type;
        Variable left;
        Variable right;
        Number floor;
        Number ceiling;
    } regions[] = {
        {T_STACK, reg_pack(1).stack_offset, reg_pack(2).stack_offset,
         Number{stack_size - RuntimeConfig{}.subprogram_stack_size}, Number{stack_size}},
        {T_CTX, reg_pack(1).ctx_offset, reg_pack(2).ctx_offset, Number{0},
         Number{default_info().type.ctx_descriptor->size}},
        {T_PACKET, reg_pack(1).packet_offset, reg_pack(2).packet_offset, Number{0}, Number{max_packet_size}},
        {T_SHARED, reg_pack(1).shared_offset, reg_pack(2).shared_offset, Number{0}, Number{shared_size}},
    };
    for (const auto& [type, left, right, floor, ceiling] : regions) {
        CAPTURE(type);
        const EbpfDomain ends = same_type_pointers(type, left, right, floor, ceiling);
        REQUIRE(checker_admits_comparison(ends, 1));
        REQUIRE(checker_admits_comparison(ends, 2));
        CHECK_FALSE(is_feasible(ends, imm_cond(Op::EQ, 1, 0)));
        CHECK_FALSE(is_feasible(ends, imm_cond(Op::EQ, 2, 0)));
        if (type != T_SHARED) {
            CHECK_FALSE(is_feasible(ends, reg_cond(Op::GE, 1, 2)));
        }

        // Past either end the checker refuses the comparison, so nothing is lost by not deciding it.
        CHECK_FALSE(checker_admits_comparison(same_type_pointers(type, left, right, floor - 1, ceiling), 1));
        CHECK_FALSE(checker_admits_comparison(same_type_pointers(type, left, right, ceiling + 1, floor), 1));
    }
}

TEST_CASE("Pointers into possibly different regions are not compared by offset", "[assume][pointer]") {
    using Op = Condition::Op;
    const struct {
        TypeEncoding type;
        Variable left;
        Variable right;
    } regions[] = {
        {T_SHARED, reg_pack(1).shared_offset, reg_pack(2).shared_offset},
        {T_ALLOC_MEM, reg_pack(1).alloc_mem_offset, reg_pack(2).alloc_mem_offset},
        {T_SOCKET, reg_pack(1).socket_offset, reg_pack(2).socket_offset},
        {T_BTF_ID, reg_pack(1).btf_id_offset, reg_pack(2).btf_id_offset},
    };
    for (const auto& [type, left, right] : regions) {
        CAPTURE(type);
        // Equal offsets in two objects are different addresses.
        const EbpfDomain equal_offsets = same_type_pointers(type, left, right, 0, 0);
        CHECK(is_feasible(equal_offsets, reg_cond(Op::NE, 1, 2)));
        CHECK(is_feasible(equal_offsets, reg_cond(Op::LT, 1, 2)));
        CHECK(is_feasible(equal_offsets, reg_cond(Op::EQ, 1, 2)));

        // Unequal offsets in two objects may be one address: the elements of an array map lie back to back,
        // so the end of one 8-byte element (offset 8) is the start of the next (offset 0).
        const EbpfDomain unequal_offsets = same_type_pointers(type, left, right, 8, 0);
        CHECK(is_feasible(unequal_offsets, reg_cond(Op::EQ, 1, 2)));
        CHECK(is_feasible(unequal_offsets, reg_cond(Op::NE, 1, 2)));
        CHECK(is_feasible(unequal_offsets, reg_cond(Op::GT, 1, 2)));
    }
}

TEST_CASE("Maps are not compared by descriptor", "[assume][pointer]") {
    using Op = Condition::Op;
    // The result of a lookup in a map of maps has the descriptor of the inner-map template, whichever map the
    // slot holds: equal descriptors may be different maps.
    const EbpfDomain equal_descriptors = same_type_pointers(T_MAP, reg_pack(1).map_fd, reg_pack(2).map_fd, 1, 1);
    CHECK(is_feasible(equal_descriptors, reg_cond(Op::NE, 1, 2)));
    CHECK(is_feasible(equal_descriptors, reg_cond(Op::EQ, 1, 2)));

    // Lookups in two outer maps with different templates may return the same map.
    const EbpfDomain different_descriptors = same_type_pointers(T_MAP, reg_pack(1).map_fd, reg_pack(2).map_fd, 1, 2);
    CHECK(is_feasible(different_descriptors, reg_cond(Op::EQ, 1, 2)));
    CHECK(is_feasible(different_descriptors, reg_cond(Op::NE, 1, 2)));

    const EbpfDomain program_maps =
        same_type_pointers(T_MAP_PROGRAMS, reg_pack(1).map_fd_programs, reg_pack(2).map_fd_programs, 1, 2);
    CHECK(is_feasible(program_maps, reg_cond(Op::EQ, 1, 2)));
    CHECK(is_feasible(program_maps, reg_cond(Op::NE, 1, 2)));
}

TEST_CASE("Pointers of different types keep both branches", "[assume][pointer]") {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    const RegPack r1 = reg_pack(1);
    const RegPack r2 = reg_pack(2);
    std::vector<LinearConstraint> csts = nonnull_address(r1);
    const auto r2_address = nonnull_address(r2);
    csts.insert(csts.end(), r2_address.begin(), r2_address.end());
    csts.push_back(r1.ctx_offset == 0);
    csts.push_back(r2.stack_offset == 0);
    const EbpfDomain pre =
        EbpfDomain::from_constraints({{reg_type(Reg{1}), TypeSet{T_CTX}}, {reg_type(Reg{2}), TypeSet{T_STACK}}}, csts);
    CHECK(is_feasible(pre, reg_cond(Op::EQ, 1, 2)));
    CHECK(is_feasible(pre, reg_cond(Op::NE, 1, 2)));
    CHECK(is_feasible(pre, reg_cond(Op::GT, 1, 2)));
}

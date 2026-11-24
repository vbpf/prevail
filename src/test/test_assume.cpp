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

using namespace prevail;

namespace {

constexpr int64_t ptr_max_default = 2147418112;

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

bool is_feasible(const EbpfDomain& pre, const Condition& cond) {
    VerifierOptions options{};
    const InstructionSeq sequence{{Label{0}, Exit{}, std::nullopt}};
    const AnalysisContext context{Program::from_sequence(sequence, default_info(), options), options};
    EbpfDomain post = pre;
    ebpf_domain_transform(post, Assume{.cond = cond, .is_implicit = true}, context);
    return !post.is_bottom();
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

EbpfDomain same_type_pointers(const TypeEncoding type, const Variable left_offset, const Variable right_offset,
                              const int64_t left, const int64_t right) {
    using namespace dsl_syntax;
    std::vector<LinearConstraint> csts = nonnull_address(reg_pack(1));
    const auto r2_address = nonnull_address(reg_pack(2));
    csts.insert(csts.end(), r2_address.begin(), r2_address.end());
    csts.push_back(left_offset == left);
    csts.push_back(right_offset == right);
    return EbpfDomain::from_constraints({{reg_type(Reg{1}), TypeSet{type}}, {reg_type(Reg{2}), TypeSet{type}}}, csts);
}

} // namespace

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

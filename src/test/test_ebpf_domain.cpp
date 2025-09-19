// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "arith/dsl_syntax.hpp"
#include "arith/num_extended.hpp"
#include "asm_syntax.hpp"
#include "config.hpp"
#include "crab/array_domain.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/interval.hpp"
#include "crab/type_domain.hpp"
#include "crab/var_registry.hpp"
#include "ebpf_base.h"
#include "ebpf_vm_isa.hpp"
#include "helpers.hpp"
#include "platform.hpp"
#include "spec_type_descriptors.hpp"
#include "string_constraints.hpp"

using namespace prevail;

namespace prevail {
class EbpfDomainTestAccess {
  public:
    static NumAbsDomain& numeric(EbpfDomain& dom) { return dom.m_inv; }
    static const NumAbsDomain& numeric(const EbpfDomain& dom) { return dom.m_inv; }
    static ArrayDomain& stack(EbpfDomain& dom) { return dom.stack; }
    static const ArrayDomain& stack(const EbpfDomain& dom) { return dom.stack; }
    static TypeDomain& types(EbpfDomain& dom) { return dom.type_inv; }
    static const TypeDomain& types(const EbpfDomain& dom) { return dom.type_inv; }

    static std::optional<Variable> type_offset_variable(const Reg& reg, int type) {
        return EbpfDomain::get_type_offset_variable(reg, type);
    }

    static std::optional<Variable> type_offset_variable(const EbpfDomain& dom, const Reg& reg) {
        return dom.get_type_offset_variable(reg);
    }

    static std::optional<Variable> type_offset_variable(const EbpfDomain& dom, const Reg& reg,
                                                        const NumAbsDomain& inv) {
        return dom.get_type_offset_variable(reg, inv);
    }

    static std::optional<uint32_t> map_type(const EbpfDomain& dom, const Reg& reg) { return dom.get_map_type(reg); }

    static std::optional<uint32_t> map_inner_map_fd(const EbpfDomain& dom, const Reg& reg) {
        return dom.get_map_inner_map_fd(reg);
    }

    static Interval map_key_size(const EbpfDomain& dom, const Reg& reg) { return dom.get_map_key_size(reg); }

    static Interval map_value_size(const EbpfDomain& dom, const Reg& reg) { return dom.get_map_value_size(reg); }

    static Interval map_max_entries(const EbpfDomain& dom, const Reg& reg) { return dom.get_map_max_entries(reg); }

    static bool map_fd_range(const EbpfDomain& dom, const Reg& reg, int32_t* start_fd, int32_t* end_fd) {
        return dom.get_map_fd_range(reg, start_fd, end_fd);
    }
};
} // namespace prevail

namespace {
thread_local std::unordered_map<uint32_t, EbpfMapType> g_test_map_types;

EbpfProgramType test_get_program_type(const std::string& section, const std::string& path) {
    return EbpfProgramType{
        .name = section + "/" + path,
        .context_descriptor = nullptr,
        .platform_specific_data = 0,
        .section_prefixes = {},
        .is_privileged = false,
    };
}

EbpfHelperPrototype test_get_helper_prototype(int32_t) {
    EbpfHelperPrototype proto{};
    proto.name = "helper";
    proto.return_type = EBPF_RETURN_TYPE_INTEGER;
    proto.argument_type[0] = EBPF_ARGUMENT_TYPE_DONTCARE;
    proto.argument_type[1] = EBPF_ARGUMENT_TYPE_DONTCARE;
    proto.argument_type[2] = EBPF_ARGUMENT_TYPE_DONTCARE;
    proto.argument_type[3] = EBPF_ARGUMENT_TYPE_DONTCARE;
    proto.argument_type[4] = EBPF_ARGUMENT_TYPE_DONTCARE;
    proto.reallocate_packet = false;
    proto.context_descriptor = nullptr;
    return proto;
}

bool test_is_helper_usable(int32_t) { return true; }

void test_parse_maps_section(std::vector<EbpfMapDescriptor>&, const char*, size_t, int, const ebpf_platform_t*,
                             ebpf_verifier_options_t) {}

void test_resolve_inner_map_references(std::vector<EbpfMapDescriptor>&) {}

EbpfMapDescriptor& test_get_map_descriptor(int map_fd) {
    auto& descriptors = thread_local_program_info->map_descriptors;
    const auto it = std::find_if(descriptors.begin(), descriptors.end(), [map_fd](const EbpfMapDescriptor& desc) {
        return static_cast<int>(desc.original_fd) == map_fd;
    });
    if (it == descriptors.end()) {
        throw std::out_of_range("map fd not found");
    }
    return *it;
}

EbpfMapType test_get_map_type(uint32_t platform_specific_type) {
    const auto it = g_test_map_types.find(platform_specific_type);
    if (it == g_test_map_types.end()) {
        return EbpfMapType{
            .platform_specific_type = platform_specific_type,
            .name = "unknown",
            .is_array = false,
            .value_type = EbpfMapValueType::ANY,
        };
    }
    return it->second;
}

const ebpf_platform_t kTestPlatform = {
    .get_program_type = test_get_program_type,
    .get_helper_prototype = test_get_helper_prototype,
    .is_helper_usable = test_is_helper_usable,
    .map_record_size = 0,
    .parse_maps_section = test_parse_maps_section,
    .get_map_descriptor = test_get_map_descriptor,
    .get_map_type = test_get_map_type,
    .resolve_inner_map_references = test_resolve_inner_map_references,
    .supported_conformance_groups = bpf_conformance_groups_t::default_groups,
};

const ebpf_context_descriptor_t kContextWithMeta{64, 0, 4, 8};
const ebpf_context_descriptor_t kContextWithoutMeta{64, 0, 4, -1};

class EbpfDomainTestEnvironment {
  public:
    EbpfDomainTestEnvironment(const ebpf_context_descriptor_t& context, std::vector<EbpfMapDescriptor> descriptors = {},
                              std::unordered_map<uint32_t, EbpfMapType> map_types = {}) {
        thread_local_options = {};
        variable_registry.clear();
        g_test_map_types = std::move(map_types);

        ProgramInfo info{};
        info.platform = &kTestPlatform;
        info.map_descriptors = std::move(descriptors);
        info.type = EbpfProgramType{
            .name = "test",
            .context_descriptor = &context,
            .platform_specific_data = 0,
            .section_prefixes = {},
            .is_privileged = false,
        };
        thread_local_program_info.set(info);
    }

    ~EbpfDomainTestEnvironment() {
        g_test_map_types.clear();
        thread_local_program_info.clear();
        variable_registry.clear();
        thread_local_options = {};
    }
};

EbpfDomain make_domain(const NumAbsDomain& inv) {
    ArrayDomain stack;
    stack.set_to_top();
    return EbpfDomain(inv, stack);
}

std::set<std::string> as_set(const StringInvariant& inv) {
    if (inv.is_bottom()) {
        return {};
    }
    return inv.value();
}

} // namespace

TEST_CASE("EbpfDomain identifies top and bottom states", "[ebpf_domain]") {
    EbpfDomainTestEnvironment env(kContextWithMeta);

    EbpfDomain dom;
    REQUIRE(dom.is_top());
    REQUIRE_FALSE(dom.is_bottom());

    dom.set_to_bottom();
    REQUIRE(dom.is_bottom());

    dom.set_to_top();
    REQUIRE(dom.is_top());

    EbpfDomain bottom = EbpfDomain::bottom();
    REQUIRE(bottom.is_bottom());
    bottom.set_to_top();
    REQUIRE(bottom.is_top());
}

TEST_CASE("EbpfDomain partial order compares precision", "[ebpf_domain]") {
    using namespace dsl_syntax;

    EbpfDomainTestEnvironment env(kContextWithMeta);

    const auto r0 = reg_pack(R0_RETURN_VALUE);

    NumAbsDomain precise = NumAbsDomain::top();
    precise.add_constraint(r0.svalue >= 0);
    precise.add_constraint(r0.svalue <= 5);
    EbpfDomain precise_dom = make_domain(precise);

    NumAbsDomain coarse = NumAbsDomain::top();
    coarse.add_constraint(r0.svalue >= -10);
    coarse.add_constraint(r0.svalue <= 10);
    EbpfDomain coarse_dom = make_domain(coarse);

    REQUIRE(precise_dom <= coarse_dom);
    REQUIRE_FALSE(coarse_dom <= precise_dom);

    NumAbsDomain same = precise;
    EbpfDomain same_dom = make_domain(same);
    REQUIRE(same_dom == precise_dom);
}

TEST_CASE("EbpfDomain joins merge both inputs", "[ebpf_domain]") {
    using namespace dsl_syntax;

    EbpfDomainTestEnvironment env(kContextWithMeta);

    const auto r0 = reg_pack(R0_RETURN_VALUE);

    NumAbsDomain left_inv = NumAbsDomain::top();
    left_inv.add_constraint(r0.svalue <= 5);
    EbpfDomain left = make_domain(left_inv);

    NumAbsDomain right_inv = NumAbsDomain::top();
    right_inv.add_constraint(r0.svalue >= 3);
    EbpfDomain right = make_domain(right_inv);

    EbpfDomain joined = left | right;
    REQUIRE(left <= joined);
    REQUIRE(right <= joined);

    EbpfDomain copy = make_domain(left_inv);
    copy |= EbpfDomain::bottom();
    REQUIRE(copy == make_domain(left_inv));

    EbpfDomain accumulator = EbpfDomain::bottom();
    accumulator |= make_domain(right_inv);
    REQUIRE(accumulator == make_domain(right_inv));

    EbpfDomain moved = make_domain(left_inv);
    EbpfDomain moved_join = std::move(moved) | right;
    REQUIRE(right <= moved_join);
}

TEST_CASE("EbpfDomain meet detects inconsistencies", "[ebpf_domain]") {
    using namespace dsl_syntax;

    EbpfDomainTestEnvironment env(kContextWithMeta);

    const auto r0 = reg_pack(R0_RETURN_VALUE);

    NumAbsDomain small = NumAbsDomain::top();
    small.add_constraint(r0.svalue <= 1);
    EbpfDomain dom_small = make_domain(small);

    NumAbsDomain large = NumAbsDomain::top();
    large.add_constraint(r0.svalue >= 5);
    EbpfDomain dom_large = make_domain(large);

    EbpfDomain meet = dom_small & dom_large;
    REQUIRE(meet.is_bottom());

    EbpfDomain self_meet = dom_small & dom_small;
    REQUIRE(self_meet == dom_small);
}

TEST_CASE("EbpfDomain join keeps type specific invariants", "[ebpf_domain]") {
    EbpfDomainTestEnvironment env(kContextWithMeta);

    const auto r1 = reg_pack(R1_ARG);

    NumAbsDomain packet_inv = NumAbsDomain::top();
    packet_inv.assign(r1.type, T_PACKET);
    packet_inv.assign(r1.packet_offset, 4);
    EbpfDomain packet = make_domain(packet_inv);

    NumAbsDomain stack_inv = NumAbsDomain::top();
    stack_inv.assign(r1.type, T_STACK);
    stack_inv.assign(r1.stack_offset, 32);
    stack_inv.assign(r1.stack_numeric_size, 16);
    EbpfDomain stack = make_domain(stack_inv);

    EbpfDomain joined = packet;
    joined |= stack;

    EbpfDomain commuted = stack;
    commuted |= packet;

    const Interval packet_offset = EbpfDomainTestAccess::numeric(joined).eval_interval(r1.packet_offset);
    REQUIRE(packet_offset == Interval(4, 4));

    const Interval stack_offset = EbpfDomainTestAccess::numeric(joined).eval_interval(r1.stack_offset);
    REQUIRE(stack_offset == Interval(32, 32));

    const Interval types = EbpfDomainTestAccess::numeric(joined).eval_interval(r1.type);
    REQUIRE(types == Interval(T_PACKET, T_STACK));

    REQUIRE(EbpfDomainTestAccess::numeric(commuted).eval_interval(r1.packet_offset) == Interval(4, 4));
    REQUIRE(EbpfDomainTestAccess::numeric(commuted).eval_interval(r1.stack_offset) == Interval(32, 32));
}

TEST_CASE("EbpfDomain widen optionally clamps to constant limits", "[ebpf_domain]") {
    using namespace dsl_syntax;

    EbpfDomainTestEnvironment env(kContextWithMeta);

    const auto r0 = reg_pack(R0_RETURN_VALUE);

    NumAbsDomain bounded = NumAbsDomain::top();
    bounded.add_constraint(r0.svalue >= -5);
    bounded.add_constraint(r0.svalue <= 5);
    EbpfDomain precise = make_domain(bounded);

    EbpfDomain unconstrained = make_domain(NumAbsDomain::top());

    EbpfDomain widened_no_limits = precise.widen(unconstrained, false);
    EbpfDomain widened_with_limits = precise.widen(unconstrained, true);

    const auto no_limits_interval = EbpfDomainTestAccess::numeric(widened_no_limits).eval_interval(r0.svalue);
    REQUIRE(no_limits_interval.ub().is_infinite());

    const auto limited_interval = EbpfDomainTestAccess::numeric(widened_with_limits).eval_interval(r0.svalue);
    REQUIRE(limited_interval.ub().is_finite());
    REQUIRE(limited_interval.ub().narrow<int32_t>() == std::numeric_limits<int32_t>::max());
}

TEST_CASE("EbpfDomain narrow refines previously widened state", "[ebpf_domain]") {
    using namespace dsl_syntax;

    EbpfDomainTestEnvironment env(kContextWithMeta);

    const auto r0 = reg_pack(R0_RETURN_VALUE);

    NumAbsDomain bounded = NumAbsDomain::top();
    bounded.add_constraint(r0.svalue >= -5);
    bounded.add_constraint(r0.svalue <= 5);
    EbpfDomain precise = make_domain(bounded);

    EbpfDomain unconstrained = make_domain(NumAbsDomain::top());
    EbpfDomain widened = precise.widen(unconstrained, false);
    EbpfDomain narrowed = widened.narrow(precise);

    REQUIRE(narrowed == precise);
}

TEST_CASE("EbpfDomain setup_entry initialises registers and packet", "[ebpf_domain]") {
    EbpfDomainTestEnvironment env(kContextWithMeta);

    SECTION("with r1 initialisation") {
        EbpfDomain dom = EbpfDomain::setup_entry(true);
        const auto& inv = EbpfDomainTestAccess::numeric(dom);
        const auto r10 = reg_pack(R10_STACK_POINTER);
        const auto r1 = reg_pack(R1_ARG);

        REQUIRE(inv.eval_interval(r10.svalue) == Interval(EBPF_TOTAL_STACK_SIZE, PTR_MAX));
        REQUIRE(inv.eval_interval(r10.stack_offset) == Interval(EBPF_TOTAL_STACK_SIZE, EBPF_TOTAL_STACK_SIZE));
        REQUIRE(inv.eval_interval(r10.type) == Interval(T_STACK, T_STACK));

        REQUIRE(inv.eval_interval(r1.svalue) == Interval(1, PTR_MAX));
        REQUIRE(inv.eval_interval(r1.ctx_offset) == Interval(0, 0));
        REQUIRE(inv.eval_interval(r1.type) == Interval(T_CTX, T_CTX));

        REQUIRE(inv.eval_interval(variable_registry->packet_size()) == Interval(0, MAX_PACKET_SIZE - 1));
        REQUIRE(inv.eval_interval(variable_registry->meta_offset()) == Interval(-4098, 0));
    }

    SECTION("without r1 initialisation") {
        EbpfDomain dom = EbpfDomain::setup_entry(false);
        const auto& inv = EbpfDomainTestAccess::numeric(dom);
        const auto r1 = reg_pack(R1_ARG);
        const Interval type = inv.eval_interval(r1.type);
        REQUIRE(type.is_top());
    }
}

TEST_CASE("EbpfDomain initialize_packet honours metadata presence", "[ebpf_domain]") {
    SECTION("context provides metadata pointer") {
        EbpfDomainTestEnvironment env(kContextWithMeta);
        EbpfDomain dom;
        dom.initialize_packet();
        const auto& inv = EbpfDomainTestAccess::numeric(dom);
        REQUIRE(inv.eval_interval(variable_registry->packet_size()) == Interval(0, MAX_PACKET_SIZE - 1));
        REQUIRE(inv.eval_interval(variable_registry->meta_offset()) == Interval(-4098, 0));
    }

    SECTION("context lacks metadata pointer") {
        EbpfDomainTestEnvironment env(kContextWithoutMeta);
        EbpfDomain dom;
        dom.initialize_packet();
        const auto& inv = EbpfDomainTestAccess::numeric(dom);
        REQUIRE(inv.eval_interval(variable_registry->packet_size()) == Interval(0, MAX_PACKET_SIZE - 1));
        REQUIRE(inv.eval_interval(variable_registry->meta_offset()) == Interval(0, 0));
    }
}

TEST_CASE("EbpfDomain from_constraints applies numeric and stack facts", "[ebpf_domain]") {
    EbpfDomainTestEnvironment env(kContextWithMeta);

    const std::set<std::string> constraints = {"r0.svalue=7", "s[0...3].type=number"};
    EbpfDomain dom = EbpfDomain::from_constraints(constraints, false);

    const auto& inv = EbpfDomainTestAccess::numeric(dom);
    REQUIRE(inv.eval_interval(reg_pack(R0_RETURN_VALUE).svalue) == Interval(7, 7));

    const auto stack_set = as_set(dom.to_set());
    REQUIRE(stack_set.contains("s[0...3].type=number"));
    REQUIRE(stack_set.contains("r0.svalue=7"));
}

TEST_CASE("EbpfDomain from_constraints honours setup entry when requested", "[ebpf_domain]") {
    EbpfDomainTestEnvironment env(kContextWithMeta);

    const std::set<std::string> constraints = {"r0.svalue=0"};
    EbpfDomain dom = EbpfDomain::from_constraints(constraints, true);

    const auto& inv = EbpfDomainTestAccess::numeric(dom);
    REQUIRE(inv.eval_interval(reg_pack(R10_STACK_POINTER).svalue) == Interval(EBPF_TOTAL_STACK_SIZE, PTR_MAX));
    REQUIRE(inv.eval_interval(reg_pack(R0_RETURN_VALUE).svalue) == Interval(0, 0));
}

TEST_CASE("EbpfDomain loop count upper bound tracks largest counter", "[ebpf_domain]") {
    EbpfDomainTestEnvironment env(kContextWithMeta);

    Variable counter_a = variable_registry->loop_counter("loop_a");
    Variable counter_b = variable_registry->loop_counter("loop_b");

    NumAbsDomain inv = NumAbsDomain::top();
    inv.assign(counter_a, 4);
    inv.assign(counter_b, 9);
    EbpfDomain dom = make_domain(inv);

    REQUIRE(dom.get_loop_count_upper_bound() == ExtendedNumber{9});
}

TEST_CASE("EbpfDomain get_r0 returns interval for return value", "[ebpf_domain]") {
    EbpfDomainTestEnvironment env(kContextWithMeta);

    NumAbsDomain inv = NumAbsDomain::top();
    inv.assign(reg_pack(R0_RETURN_VALUE).svalue, 42);
    EbpfDomain dom = make_domain(inv);

    REQUIRE(dom.get_r0() == Interval(42, 42));
}

TEST_CASE("EbpfDomain get_type_offset_variable resolves offsets", "[ebpf_domain]") {
    EbpfDomainTestEnvironment env(kContextWithMeta);

    const Reg reg{R1_ARG};
    const auto expected_ctx = reg_pack(reg).ctx_offset;
    const auto expected_packet = reg_pack(reg).packet_offset;

    REQUIRE(EbpfDomainTestAccess::type_offset_variable(reg, T_CTX) == std::optional<Variable>(expected_ctx));
    REQUIRE(EbpfDomainTestAccess::type_offset_variable(reg, T_PACKET) == std::optional<Variable>(expected_packet));

    NumAbsDomain inv_packet = NumAbsDomain::top();
    inv_packet.assign(reg_pack(reg).type, T_PACKET);
    EbpfDomain dom_packet = make_domain(inv_packet);
    REQUIRE(EbpfDomainTestAccess::type_offset_variable(dom_packet, reg) == std::optional<Variable>(expected_packet));

    NumAbsDomain inv_unknown = NumAbsDomain::top();
    inv_unknown.set(reg_pack(reg).type, Interval(T_CTX, T_STACK));
    EbpfDomain dom_unknown = make_domain(inv_unknown);
    REQUIRE_FALSE(EbpfDomainTestAccess::type_offset_variable(dom_unknown, reg).has_value());
}

TEST_CASE("EbpfDomain map queries combine descriptor ranges", "[ebpf_domain]") {
    std::vector<EbpfMapDescriptor> descriptors = {
        {.original_fd = 1, .type = 3, .key_size = 4, .value_size = 32, .max_entries = 64, .inner_map_fd = 3},
        {.original_fd = 2, .type = 3, .key_size = 4, .value_size = 64, .max_entries = 128, .inner_map_fd = 3},
    };
    EbpfDomainTestEnvironment env(kContextWithMeta, descriptors);

    NumAbsDomain inv = NumAbsDomain::top();
    const auto reg = reg_pack(R1_ARG);
    inv.set(reg.map_fd, Interval(1, 2));
    EbpfDomain dom = make_domain(inv);

    const auto map_type = EbpfDomainTestAccess::map_type(dom, Reg{R1_ARG});
    REQUIRE(map_type.has_value());
    REQUIRE(*map_type == 3);

    const auto inner_map_fd = EbpfDomainTestAccess::map_inner_map_fd(dom, Reg{R1_ARG});
    REQUIRE(inner_map_fd.has_value());
    REQUIRE(*inner_map_fd == 3);

    REQUIRE(EbpfDomainTestAccess::map_key_size(dom, Reg{R1_ARG}) == Interval(4, 4));
    REQUIRE(EbpfDomainTestAccess::map_value_size(dom, Reg{R1_ARG}) == Interval(32, 64));
    REQUIRE(EbpfDomainTestAccess::map_max_entries(dom, Reg{R1_ARG}) == Interval(64, 128));

    int32_t start_fd = 0;
    int32_t end_fd = 0;
    REQUIRE(EbpfDomainTestAccess::map_fd_range(dom, Reg{R1_ARG}, &start_fd, &end_fd));
    REQUIRE(start_fd == 1);
    REQUIRE(end_fd == 2);
}

TEST_CASE("EbpfDomain map queries detect inconsistencies", "[ebpf_domain]") {
    std::vector<EbpfMapDescriptor> descriptors = {
        {.original_fd = 1, .type = 7, .key_size = 4, .value_size = 16, .max_entries = 32, .inner_map_fd = 3},
        {.original_fd = 2, .type = 9, .key_size = 8, .value_size = 16, .max_entries = 32, .inner_map_fd = 4},
    };
    EbpfDomainTestEnvironment env(kContextWithMeta, descriptors);

    NumAbsDomain inv = NumAbsDomain::top();
    inv.set(reg_pack(R1_ARG).map_fd, Interval(1, 2));
    EbpfDomain dom = make_domain(inv);

    REQUIRE_FALSE(EbpfDomainTestAccess::map_type(dom, Reg{R1_ARG}).has_value());
    REQUIRE_FALSE(EbpfDomainTestAccess::map_inner_map_fd(dom, Reg{R1_ARG}).has_value());
    REQUIRE(EbpfDomainTestAccess::map_key_size(dom, Reg{R1_ARG}) == Interval(4, 8));
}

TEST_CASE("EbpfDomain map range limit prevents large queries", "[ebpf_domain]") {
    EbpfDomainTestEnvironment env(kContextWithMeta);

    NumAbsDomain inv = NumAbsDomain::top();
    inv.set(reg_pack(R1_ARG).map_fd, Interval(0, 40));
    EbpfDomain dom = make_domain(inv);

    REQUIRE_FALSE(EbpfDomainTestAccess::map_type(dom, Reg{R1_ARG}).has_value());
    REQUIRE(EbpfDomainTestAccess::map_key_size(dom, Reg{R1_ARG}).is_top());

    int32_t start_fd = 0;
    int32_t end_fd = 0;
    REQUIRE_FALSE(EbpfDomainTestAccess::map_fd_range(dom, Reg{R1_ARG}, &start_fd, &end_fd));
}

TEST_CASE("EbpfDomain constant limits bound registers and counters", "[ebpf_domain]") {
    EbpfDomainTestEnvironment env(kContextWithMeta);
    thread_local_options.cfg_opts.check_for_termination = true;
    variable_registry->loop_counter("loop");

    EbpfDomain limits = EbpfDomain::calculate_constant_limits();
    const auto& inv = EbpfDomainTestAccess::numeric(limits);

    const auto r0 = reg_pack(R0_RETURN_VALUE);
    const Interval r0_bounds = inv.eval_interval(r0.svalue);
    REQUIRE(r0_bounds == Interval(0, std::numeric_limits<int32_t>::max()));
    REQUIRE(inv.eval_interval(r0.uvalue) == Interval(uint32_t{0}, std::numeric_limits<uint32_t>::max()));
    REQUIRE(inv.eval_interval(r0.stack_offset) == Interval(0, EBPF_TOTAL_STACK_SIZE));

    const Variable counter = variable_registry->loop_counter("loop");
    REQUIRE(inv.eval_interval(counter) == Interval(0, std::numeric_limits<int32_t>::max()));
}

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "linux/kfunc.hpp"

#include <algorithm>
#include <array>
#include <string_view>

#include "ir/arg_kind.hpp"
#include "spec/function_prototypes.hpp"

namespace prevail {

namespace {

struct KfuncPrototypeEntry {
    int32_t btf_id{};
    EbpfHelperPrototype proto{};
    KfuncFlags flags = KfuncFlags::none;
    std::string_view required_program_type;
    bool requires_privileged = false;
};

constexpr std::array<KfuncPrototypeEntry, 12> kfunc_prototypes{{
    {.btf_id = 12, .proto = {.name = "kfunc_test_id_overlap_tail_call", .return_type = EBPF_RETURN_TYPE_INTEGER}},
    {.btf_id = 1000, .proto = {.name = "kfunc_test_ret_int", .return_type = EBPF_RETURN_TYPE_INTEGER}},
    {.btf_id = 1001,
     .proto = {.name = "kfunc_test_ctx_arg",
               .return_type = EBPF_RETURN_TYPE_INTEGER,
               .argument_type = {EBPF_ARGUMENT_TYPE_PTR_TO_CTX}}},
    {.btf_id = 1002,
     .proto = {.name = "kfunc_test_acquire_flag", .return_type = EBPF_RETURN_TYPE_INTEGER},
     .flags = KfuncFlags::acquire},
    {.btf_id = 1003,
     .proto = {.name = "kfunc_test_xdp_only", .return_type = EBPF_RETURN_TYPE_INTEGER},
     .required_program_type = "xdp"},
    {.btf_id = 1004,
     .proto = {.name = "kfunc_test_privileged_only", .return_type = EBPF_RETURN_TYPE_INTEGER},
     .requires_privileged = true},
    {.btf_id = 1005,
     .proto = {.name = "kfunc_test_ret_map_value_or_null", .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL}},
    {.btf_id = 1006,
     .proto = {.name = "kfunc_test_readable_mem_or_null_size",
               .return_type = EBPF_RETURN_TYPE_INTEGER,
               .argument_type = {EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
                                 EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO}}},
    {.btf_id = 1007,
     .proto = {.name = "kfunc_test_writable_mem_size",
               .return_type = EBPF_RETURN_TYPE_INTEGER,
               .argument_type = {EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM, EBPF_ARGUMENT_TYPE_CONST_SIZE}}},
    {.btf_id = 1008,
     .proto = {.name = "kfunc_test_release_flag", .return_type = EBPF_RETURN_TYPE_INTEGER},
     .flags = KfuncFlags::release},
    // bpf_cpumask_create/bpf_cpumask_release form an acquire/release pair.
    // Acquire without enforced release — verifier does not yet track release obligations (see ID 1010).
    {.btf_id = 1009,
     .proto = {.name = "bpf_cpumask_create", .return_type = EBPF_RETURN_TYPE_INTEGER},
     .flags = KfuncFlags::acquire},
    {.btf_id = 1010, .proto = {.name = "bpf_cpumask_release", .return_type = EBPF_RETURN_TYPE_INTEGER}},
}};

constexpr bool kfunc_prototypes_are_sorted_by_btf_id() {
    for (size_t i = 1; i < kfunc_prototypes.size(); ++i) {
        if (kfunc_prototypes[i - 1].btf_id >= kfunc_prototypes[i].btf_id) {
            return false;
        }
    }
    return true;
}

constexpr bool kfunc_prototypes_have_names() {
    for (const auto& entry : kfunc_prototypes) {
        if (entry.proto.name == nullptr) {
            return false;
        }
    }
    return true;
}

static_assert(kfunc_prototypes_are_sorted_by_btf_id(), "kfunc_prototypes must be strictly sorted by btf_id");
static_assert(kfunc_prototypes_have_names(), "kfunc_prototypes entries must define proto.name");

std::optional<KfuncPrototypeEntry> lookup_kfunc_prototype(const int32_t btf_id) {
    const auto it =
        std::lower_bound(kfunc_prototypes.begin(), kfunc_prototypes.end(), btf_id,
                         [](const KfuncPrototypeEntry& entry, const int32_t id) { return entry.btf_id < id; });
    if (it != kfunc_prototypes.end() && it->btf_id == btf_id) {
        return *it;
    }
    return std::nullopt;
}

void set_unsupported(std::string* why_not, const std::string& reason) {
    if (why_not) {
        *why_not = reason;
    }
}

} // namespace

std::optional<ResolvedCall> make_kfunc_call(const int32_t btf_id, const EbpfProgramType& program_type,
                                            std::string* why_not) {
    const auto entry = lookup_kfunc_prototype(btf_id);
    if (!entry) {
        set_unsupported(why_not, "kfunc prototype lookup failed for BTF id " + std::to_string(btf_id));
        return std::nullopt;
    }
    const auto& proto = entry->proto;

    ResolvedCall res;
    res.call = Call{.func = btf_id, .kind = CallKind::kfunc};
    res.name = proto.name;
    res.contract.reallocate_packet = proto.reallocate_packet;
    res.contract.is_map_lookup = proto.return_type == EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL;

    // Per-flag handling: accept flags whose safety properties are covered by existing type checking,
    // reject flags that require unimplemented reference lifecycle tracking.
    constexpr auto accepted_flags =
        KfuncFlags::acquire | KfuncFlags::destructive | KfuncFlags::trusted_args | KfuncFlags::sleepable;
    // KF_ACQUIRE: type propagation works; release obligation not enforced (same gap as ringbuf).
    // KF_DESTRUCTIVE: privilege-level gate; no verification machinery needed.
    // KF_TRUSTED_ARGS: arguments already type-checked via the normal assertion path.
    // KF_SLEEPABLE: context constraint; not a memory-safety property.
    // KF_RELEASE: rejected — requires acquire/release state machine (see docs/parity/lifetime.md).
    if ((entry->flags & ~accepted_flags) != KfuncFlags::none) {
        set_unsupported(why_not, std::string("kfunc has unsupported flags (release requires lifecycle tracking): ") +
                                     proto.name);
        return std::nullopt;
    }
    if (!entry->required_program_type.empty() && program_type.name != entry->required_program_type) {
        set_unsupported(why_not,
                        std::string("kfunc is unavailable for program type ") + program_type.name + ": " + proto.name);
        return std::nullopt;
    }
    if (entry->requires_privileged && !program_type.is_privileged) {
        set_unsupported(why_not, std::string("kfunc requires privileged program type: ") + proto.name);
        return std::nullopt;
    }

    if (proto.unsupported || proto.return_type == EBPF_RETURN_TYPE_UNSUPPORTED) {
        set_unsupported(why_not, std::string("kfunc prototype is unavailable on this platform: ") + proto.name);
        return std::nullopt;
    }
    const auto return_info = classify_call_return_type(proto.return_type);
    if (!return_info.has_value()) {
        set_unsupported(why_not, std::string("kfunc return type is unsupported on this platform: ") + proto.name);
        return std::nullopt;
    }
    res.contract.return_ptr_type = return_info->pointer_type;
    res.contract.return_nullable = return_info->pointer_nullable;

    const std::array<ebpf_argument_type_t, 7> args = {
        {EBPF_ARGUMENT_TYPE_DONTCARE, proto.argument_type[0], proto.argument_type[1], proto.argument_type[2],
         proto.argument_type[3], proto.argument_type[4], EBPF_ARGUMENT_TYPE_DONTCARE}};
    for (size_t i = 1; i < args.size() - 1;) {
        switch (process_arg(res.contract, args, i)) {
        case ArgOutcome::Single: i += 1; break;
        case ArgOutcome::Pair: i += 2; break;
        case ArgOutcome::Stop: return res;
        case ArgOutcome::Unavailable:
            set_unsupported(why_not, std::string("kfunc argument type is unsupported on this platform: ") + proto.name);
            return std::nullopt;
        case ArgOutcome::MismatchedSize:
            set_unsupported(why_not,
                            std::string("kfunc pointer argument not followed by EBPF_ARGUMENT_TYPE_CONST_SIZE or "
                                        "EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: ") +
                                proto.name);
            return std::nullopt;
        }
    }
    return res;
}

} // namespace prevail

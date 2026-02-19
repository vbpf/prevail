// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "ir/kfunc.hpp"

#include <array>
#include <string_view>

#include "spec/function_prototypes.hpp"

namespace prevail {

namespace {

struct KfuncPrototypeEntry {
    int32_t btf_id;
    EbpfHelperPrototype proto;
    KfuncFlags flags;
    std::string_view required_program_type;
    bool requires_privileged;
};

static constexpr std::array<KfuncPrototypeEntry, 7> kfunc_prototypes{{
    {
        1000,
        EbpfHelperPrototype{
            .name = "kfunc_test_ret_int",
            .return_type = EBPF_RETURN_TYPE_INTEGER,
            .argument_type = {EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE,
                              EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE},
            .reallocate_packet = false,
            .context_descriptor = nullptr,
            .unsupported = false,
        },
        KfuncFlags::none,
        "",
        false,
    },
    {
        1001,
        EbpfHelperPrototype{
            .name = "kfunc_test_ctx_arg",
            .return_type = EBPF_RETURN_TYPE_INTEGER,
            .argument_type = {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE,
                              EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE},
            .reallocate_packet = false,
            .context_descriptor = nullptr,
            .unsupported = false,
        },
        KfuncFlags::none,
        "",
        false,
    },
    {
        1002,
        EbpfHelperPrototype{
            .name = "kfunc_test_acquire_flag",
            .return_type = EBPF_RETURN_TYPE_INTEGER,
            .argument_type = {EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE,
                              EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE},
            .reallocate_packet = false,
            .context_descriptor = nullptr,
            .unsupported = false,
        },
        KfuncFlags::acquire,
        "",
        false,
    },
    {
        1003,
        EbpfHelperPrototype{
            .name = "kfunc_test_xdp_only",
            .return_type = EBPF_RETURN_TYPE_INTEGER,
            .argument_type = {EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE,
                              EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE},
            .reallocate_packet = false,
            .context_descriptor = nullptr,
            .unsupported = false,
        },
        KfuncFlags::none,
        "xdp",
        false,
    },
    {
        1004,
        EbpfHelperPrototype{
            .name = "kfunc_test_privileged_only",
            .return_type = EBPF_RETURN_TYPE_INTEGER,
            .argument_type = {EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE,
                              EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE},
            .reallocate_packet = false,
            .context_descriptor = nullptr,
            .unsupported = false,
        },
        KfuncFlags::none,
        "",
        true,
    },
    {
        1005,
        EbpfHelperPrototype{
            .name = "kfunc_test_ret_map_value_or_null",
            .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
            .argument_type = {EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE,
                              EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE},
            .reallocate_packet = false,
            .context_descriptor = nullptr,
            .unsupported = false,
        },
        KfuncFlags::none,
        "",
        false,
    },
    {
        1006,
        EbpfHelperPrototype{
            .name = "kfunc_test_readable_mem_or_null_size",
            .return_type = EBPF_RETURN_TYPE_INTEGER,
            .argument_type = {EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL, EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
                              EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE, EBPF_ARGUMENT_TYPE_DONTCARE},
            .reallocate_packet = false,
            .context_descriptor = nullptr,
            .unsupported = false,
        },
        KfuncFlags::none,
        "",
        false,
    },
}};

static std::optional<KfuncPrototypeEntry> lookup_kfunc_prototype(const int32_t btf_id) {
    for (const auto& entry : kfunc_prototypes) {
        const auto [id, proto, flags, required_program_type, requires_privileged] = entry;
        if (id == btf_id) {
            return KfuncPrototypeEntry{id, proto, flags, required_program_type, requires_privileged};
        }
    }
    return std::nullopt;
}

static ArgSingle::Kind to_arg_single_kind(const ebpf_argument_type_t t) {
    switch (t) {
    case EBPF_ARGUMENT_TYPE_ANYTHING: return ArgSingle::Kind::ANYTHING;
    case EBPF_ARGUMENT_TYPE_PTR_TO_STACK:
    case EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL: return ArgSingle::Kind::PTR_TO_STACK;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP: return ArgSingle::Kind::MAP_FD;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS: return ArgSingle::Kind::MAP_FD_PROGRAMS;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY: return ArgSingle::Kind::PTR_TO_MAP_KEY;
    case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE: return ArgSingle::Kind::PTR_TO_MAP_VALUE;
    case EBPF_ARGUMENT_TYPE_PTR_TO_CTX:
    case EBPF_ARGUMENT_TYPE_PTR_TO_CTX_OR_NULL: return ArgSingle::Kind::PTR_TO_CTX;
    default: break;
    }
    return {};
}

static ArgPair::Kind to_arg_pair_kind(const ebpf_argument_type_t t) {
    switch (t) {
    case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM: return ArgPair::Kind::PTR_TO_READABLE_MEM;
    case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL:
    case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM: return ArgPair::Kind::PTR_TO_WRITABLE_MEM;
    default: break;
    }
    return {};
}

static void set_unsupported(std::string* why_not, const std::string& reason) {
    if (why_not) {
        *why_not = reason;
    }
}

} // namespace

std::optional<Call> make_kfunc_call(const int32_t btf_id, const ProgramInfo* info, std::string* why_not) {
    const auto entry = lookup_kfunc_prototype(btf_id);
    if (!entry) {
        set_unsupported(why_not, "kfunc prototype lookup failed for BTF id " + std::to_string(btf_id));
        return std::nullopt;
    }
    const auto& proto = entry->proto;

    Call res;
    res.func = btf_id;
    res.name = proto.name;
    res.reallocate_packet = proto.reallocate_packet;
    res.is_map_lookup = proto.return_type == EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL;

    if (entry->flags != KfuncFlags::none) {
        set_unsupported(why_not, std::string("kfunc flags are unsupported on this platform: ") + proto.name);
        return std::nullopt;
    }
    if (info && !entry->required_program_type.empty() && info->type.name != entry->required_program_type) {
        set_unsupported(why_not,
                        std::string("kfunc is unavailable for program type ") + info->type.name + ": " + proto.name);
        return std::nullopt;
    }
    if (info && entry->requires_privileged && !info->type.is_privileged) {
        set_unsupported(why_not, std::string("kfunc requires privileged program type: ") + proto.name);
        return std::nullopt;
    }

    if (proto.unsupported || proto.return_type == EBPF_RETURN_TYPE_UNSUPPORTED) {
        set_unsupported(why_not, std::string("kfunc prototype is unavailable on this platform: ") + proto.name);
        return std::nullopt;
    }
    if (proto.return_type != EBPF_RETURN_TYPE_INTEGER &&
        proto.return_type != EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL) {
        set_unsupported(why_not, std::string("kfunc return type is unsupported on this platform: ") + proto.name);
        return std::nullopt;
    }

    const std::array<ebpf_argument_type_t, 7> args = {
        {EBPF_ARGUMENT_TYPE_DONTCARE, proto.argument_type[0], proto.argument_type[1], proto.argument_type[2],
         proto.argument_type[3], proto.argument_type[4], EBPF_ARGUMENT_TYPE_DONTCARE}};
    for (size_t i = 1; i < args.size() - 1; i++) {
        switch (args[i]) {
        case EBPF_ARGUMENT_TYPE_DONTCARE: return res;
        case EBPF_ARGUMENT_TYPE_UNSUPPORTED:
            set_unsupported(why_not, std::string("kfunc argument type is unavailable on this platform: ") + proto.name);
            return std::nullopt;
        case EBPF_ARGUMENT_TYPE_ANYTHING:
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP:
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS:
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY:
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE:
        case EBPF_ARGUMENT_TYPE_PTR_TO_STACK:
        case EBPF_ARGUMENT_TYPE_PTR_TO_CTX:
            res.singles.push_back({to_arg_single_kind(args[i]), false, Reg{gsl::narrow<uint8_t>(i)}});
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL:
        case EBPF_ARGUMENT_TYPE_PTR_TO_CTX_OR_NULL:
            res.singles.push_back({to_arg_single_kind(args[i]), true, Reg{gsl::narrow<uint8_t>(i)}});
            break;
        case EBPF_ARGUMENT_TYPE_CONST_SIZE:
            set_unsupported(
                why_not,
                std::string("mismatched kfunc EBPF_ARGUMENT_TYPE_PTR_TO* and EBPF_ARGUMENT_TYPE_CONST_SIZE: ") +
                    proto.name);
            return std::nullopt;
        case EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO:
            set_unsupported(why_not, std::string("mismatched kfunc EBPF_ARGUMENT_TYPE_PTR_TO* and "
                                                 "EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: ") +
                                         proto.name);
            return std::nullopt;
        case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
        case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM:
        case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL:
        case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM: {
            if (args.size() - i < 2 || (args[i + 1] != EBPF_ARGUMENT_TYPE_CONST_SIZE &&
                                        args[i + 1] != EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO)) {
                set_unsupported(why_not,
                                std::string("kfunc pointer argument not followed by EBPF_ARGUMENT_TYPE_CONST_SIZE or "
                                            "EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: ") +
                                    proto.name);
                return std::nullopt;
            }
            const bool can_be_zero = (args[i + 1] == EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO);
            const bool or_null = args[i] == EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL ||
                                 args[i] == EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL;
            res.pairs.push_back({to_arg_pair_kind(args[i]), or_null, Reg{gsl::narrow<uint8_t>(i)},
                                 Reg{gsl::narrow<uint8_t>(i + 1)}, can_be_zero});
            i++;
            break;
        }
        default:
            set_unsupported(why_not, std::string("kfunc argument type is unsupported on this platform: ") + proto.name);
            return std::nullopt;
        }
    }
    return res;
}

} // namespace prevail

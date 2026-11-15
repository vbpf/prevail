// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <elfio/elfio.hpp>
#include <libbtf/btf_c_type.h>

#include "crab_utils/num_safety.hpp"
#include "io/elf_reader.hpp"

namespace prevail {

// ---------------------------------------------------------------------------
// CO-RE types visible to the header (bpf_core_relo is forward-declared there)
// ---------------------------------------------------------------------------

enum bpf_core_relo_kind : uint32_t {
    BPF_CORE_FIELD_BYTE_OFFSET = 0,
    BPF_CORE_FIELD_BYTE_SIZE = 1,
    BPF_CORE_FIELD_EXISTS = 2,
    BPF_CORE_FIELD_SIGNED = 3,
    BPF_CORE_FIELD_LSHIFT_U64 = 4,
    BPF_CORE_FIELD_RSHIFT_U64 = 5,
    BPF_CORE_TYPE_ID_LOCAL = 6,
    BPF_CORE_TYPE_ID_TARGET = 7,
    BPF_CORE_TYPE_EXISTS = 8,
    BPF_CORE_TYPE_SIZE = 9,
    BPF_CORE_ENUMVAL_EXISTS = 10,
    BPF_CORE_ENUMVAL_VALUE = 11,
    BPF_CORE_TYPE_MATCHES = 12,
};

struct bpf_core_relo {
    uint32_t insn_off;
    uint32_t type_id;
    uint32_t access_str_off;
    bpf_core_relo_kind kind;
};
static_assert(sizeof(bpf_core_relo) == 16);

/// The local BTF that CO-RE relocations are resolved against.
struct CoreBtf {
    const libbtf::btf_type_data& types;
    /// The ids of the types whose kind_flag is set.
    std::set<uint32_t> types_with_kind_flag;

    [[nodiscard]]
    bool kind_flag(const uint32_t type_id) const {
        return types_with_kind_flag.contains(type_id);
    }
};

namespace {

// This type is used only for offsetof() lookups of core_relo fields in
// extended BTF.ext headers; it is never instantiated.
struct btf_ext_header_core_t {
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t hdr_len;
    uint32_t func_info_off;
    uint32_t func_info_len;
    uint32_t line_info_off;
    uint32_t line_info_len;
    uint32_t core_relo_off;
    uint32_t core_relo_len;
};

static_assert(sizeof(btf_ext_header_core_t) == 32);

struct btf_string_table_view_t {
    const char* base;
    size_t size;
};

struct core_field_resolution_t {
    uint32_t type_id;
    uint64_t offset_bits;
    /// The declared width of the field when the access ends at a bitfield member of a struct or union whose BTF
    /// kind_flag is set, and 0 otherwise.
    uint32_t bitfield_size;
};

/// Where a struct or union member lies, decoded from the offset field of its btf_member.
struct btf_member_location_t {
    uint32_t bit_offset;
    uint32_t bitfield_size;
};

/// With kind_flag clear, the offset field of a btf_member is the member's bit offset, all 32 bits of it. With
/// kind_flag set, it packs the bitfield size into its top 8 bits and the bit offset into its low 24.
btf_member_location_t decode_btf_member_offset(const uint32_t offset_field, const bool kind_flag) {
    if (!kind_flag) {
        return {offset_field, 0};
    }
    return {BTF_MEMBER_BIT_OFFSET(offset_field), BTF_MEMBER_BITFIELD_SIZE(offset_field)};
}

struct core_field_storage_t {
    uint64_t byte_offset;
    uint64_t byte_size;
};

template <typename T>
    requires std::is_trivially_copyable_v<T>
T read_struct_at(const char* data, const size_t data_size, const size_t offset, const std::string& context) {
    if (offset > data_size || data_size - offset < sizeof(T)) {
        throw UnmarshalError(context + " out of bounds");
    }
    T value;
    std::memcpy(&value, data + offset, sizeof(T));
    return value;
}

size_t checked_add(const size_t start, const size_t length, const size_t limit, const std::string& context) {
    if (start > limit || length > limit - start) {
        throw UnmarshalError(context + " out of bounds");
    }
    return start + length;
}

btf_string_table_view_t parse_btf_string_table(const ELFIO::section& btf_section) {
    if (!btf_section.get_data()) {
        throw UnmarshalError(".BTF section has no data");
    }
    const char* btf_data = btf_section.get_data();
    const size_t btf_size = btf_section.get_size();
    const auto hdr = read_struct_at<btf_header_t>(btf_data, btf_size, 0, "BTF header");
    if (hdr.magic != BTF_HEADER_MAGIC || hdr.version != BTF_HEADER_VERSION) {
        throw UnmarshalError("Invalid .BTF header");
    }
    if (hdr.hdr_len < sizeof(btf_header_t) || hdr.hdr_len > btf_size) {
        throw UnmarshalError("Invalid .BTF header length");
    }

    const size_t str_start = checked_add(hdr.hdr_len, hdr.str_off, btf_size, "BTF string table");
    const size_t str_end = checked_add(str_start, hdr.str_len, btf_size, "BTF string table");
    return {btf_data + str_start, str_end - str_start};
}

size_t btf_type_extra_size(const uint32_t kind, const uint32_t vlen) {
    switch (kind) {
    case libbtf::BTF_KIND_PTR:
    case libbtf::BTF_KIND_FWD:
    case libbtf::BTF_KIND_TYPEDEF:
    case libbtf::BTF_KIND_VOLATILE:
    case libbtf::BTF_KIND_CONST:
    case libbtf::BTF_KIND_RESTRICT:
    case libbtf::BTF_KIND_FUNCTION:
    case libbtf::BTF_KIND_FLOAT:
    case libbtf::BTF_KIND_TYPE_TAG: return 0;
    case libbtf::BTF_KIND_INT: return sizeof(uint32_t);
    case libbtf::BTF_KIND_VAR: return sizeof(btf_var_t);
    case libbtf::BTF_KIND_DECL_TAG: return sizeof(btf_decl_tag_t);
    case libbtf::BTF_KIND_ARRAY: return sizeof(btf_array_t);
    case libbtf::BTF_KIND_STRUCT:
    case libbtf::BTF_KIND_UNION: return size_t{vlen} * sizeof(btf_member_t);
    case libbtf::BTF_KIND_ENUM: return size_t{vlen} * sizeof(btf_enum_t);
    case libbtf::BTF_KIND_FUNCTION_PROTOTYPE: return size_t{vlen} * sizeof(btf_param_t);
    case libbtf::BTF_KIND_DATA_SECTION: return size_t{vlen} * sizeof(btf_var_secinfo_t);
    case libbtf::BTF_KIND_ENUM64: return size_t{vlen} * sizeof(btf_enum64_t);
    default: throw UnmarshalError("Invalid BTF kind " + std::to_string(kind));
    }
}

/// The ids of the types in a .BTF section whose kind_flag is set. libbtf's parsed types do not carry the flag of a
/// struct or union, which decides how its members' offset fields are encoded, so the type section is walked again
/// here, in the same order libbtf assigns ids (from 1; id 0 is void).
std::set<uint32_t> parse_btf_kind_flags(const ELFIO::section& btf_section) {
    if (!btf_section.get_data()) {
        throw UnmarshalError(".BTF section has no data");
    }
    const char* btf_data = btf_section.get_data();
    const size_t btf_size = btf_section.get_size();
    const auto hdr = read_struct_at<btf_header_t>(btf_data, btf_size, 0, "BTF header");
    if (hdr.magic != BTF_HEADER_MAGIC || hdr.version != BTF_HEADER_VERSION) {
        throw UnmarshalError("Invalid .BTF header");
    }
    if (hdr.hdr_len < sizeof(btf_header_t) || hdr.hdr_len > btf_size) {
        throw UnmarshalError("Invalid .BTF header length");
    }

    const size_t type_start = checked_add(hdr.hdr_len, hdr.type_off, btf_size, "BTF type section");
    const size_t type_end = checked_add(type_start, hdr.type_len, btf_size, "BTF type section");
    std::set<uint32_t> types_with_kind_flag;
    uint32_t type_id = 0;
    for (size_t offset = type_start; offset < type_end;) {
        const auto type = read_struct_at<btf_type_t>(btf_data, type_end, offset, "BTF type");
        ++type_id;
        if (BPF_TYPE_INFO_KIND_FLAG(type.info) != 0) {
            types_with_kind_flag.insert(type_id);
        }
        offset = checked_add(offset, sizeof(btf_type_t), type_end, "BTF type");
        offset = checked_add(offset, btf_type_extra_size(BPF_TYPE_INFO_KIND(type.info), BPF_TYPE_INFO_VLEN(type.info)),
                             type_end, "BTF type");
    }
    return types_with_kind_flag;
}

std::string_view btf_string_at(const btf_string_table_view_t& strings, const uint32_t string_offset,
                               const std::string& name) {
    if (string_offset >= strings.size) {
        throw UnmarshalError("Invalid BTF string offset for " + name);
    }
    const char* str = strings.base + string_offset;
    const size_t max_len = strings.size - string_offset;
    const void* nul = std::memchr(str, '\0', max_len);
    if (!nul) {
        throw UnmarshalError("Unterminated BTF string for " + name);
    }
    return {str, static_cast<size_t>(static_cast<const char*>(nul) - str)};
}

uint32_t strip_type_modifiers(const libbtf::btf_type_data& btf_data, uint32_t type_id) {
    int depth = 0;
    while (true) {
        if (++depth > 255) {
            throw UnmarshalError("CO-RE type resolution exceeded depth limit (possible corrupt BTF)");
        }

        switch (btf_data.get_kind_index(type_id)) {
        case libbtf::BTF_KIND_TYPEDEF: type_id = btf_data.get_kind_type<libbtf::btf_kind_typedef>(type_id).type; break;
        case libbtf::BTF_KIND_CONST: type_id = btf_data.get_kind_type<libbtf::btf_kind_const>(type_id).type; break;
        case libbtf::BTF_KIND_VOLATILE:
            type_id = btf_data.get_kind_type<libbtf::btf_kind_volatile>(type_id).type;
            break;
        case libbtf::BTF_KIND_RESTRICT:
            type_id = btf_data.get_kind_type<libbtf::btf_kind_restrict>(type_id).type;
            break;
        case libbtf::BTF_KIND_TYPE_TAG:
            type_id = btf_data.get_kind_type<libbtf::btf_kind_type_tag>(type_id).type;
            break;
        default: return type_id;
        }
    }
}

std::vector<uint32_t> parse_core_access_string(const std::string_view s) {
    std::vector<uint32_t> indices;
    std::stringstream ss(std::string{s});
    std::string item;
    while (std::getline(ss, item, ':')) {
        if (!item.empty()) {
            try {
                indices.push_back(gsl::narrow<uint32_t>(std::stoul(item)));
            } catch (const std::exception&) {
                throw UnmarshalError("Invalid CO-RE access string: " + std::string{s});
            }
        }
    }
    return indices;
}

core_field_resolution_t resolve_core_field(const CoreBtf& btf, const uint32_t type_id,
                                           const std::string_view access_string) {
    const libbtf::btf_type_data& btf_data = btf.types;
    auto indices = parse_core_access_string(access_string);
    core_field_resolution_t result{strip_type_modifiers(btf_data, type_id), 0, 0};

    // The first accessor is not a member index: it indexes the root type as an array element
    // (ptr[N], contributing N * sizeof(root) bytes), and Clang emits 0 unless the source
    // indexes the pointer. Member and array indices start with the second accessor.
    if (!indices.empty()) {
        if (const uint32_t root_index = indices.front(); root_index != 0) {
            const uint64_t root_size = btf_data.get_size(result.type_id);
            const uint64_t root_offset_bytes = static_cast<uint64_t>(root_index) * root_size;
            if (root_size == 0 || root_offset_bytes > std::numeric_limits<int32_t>::max()) {
                throw UnmarshalError("CO-RE: root index " + std::to_string(root_index) +
                                     " out of range for access path " + std::string(access_string));
            }
            result.offset_bits = root_offset_bytes * 8;
        }
        indices.erase(indices.begin());
    }
    // Like libbpf's is_flex_arr, only a zero-length array reached through a
    // named final struct/union member is flexible. This is a property of this
    // access step, not of the array type: array elements must not inherit it.
    bool final_member = false;
    const auto add_member_offset = [&](const uint32_t member_offset) {
        if (member_offset > std::numeric_limits<uint64_t>::max() - result.offset_bits) {
            throw UnmarshalError("CO-RE: member offset overflow for access path " + std::string(access_string));
        }
        result.offset_bits += member_offset;
    };

    // Steps into member `index` of the struct or union result.type_id, whose members are `members`.
    const auto enter_member = [&](const std::vector<libbtf::btf_kind_struct_member>& members,
                                  const std::string_view aggregate_kind, const uint32_t index) {
        if (index >= members.size()) {
            throw UnmarshalError("CO-RE: " + std::string(aggregate_kind) + " member index " + std::to_string(index) +
                                 " out of bounds (size " + std::to_string(members.size()) + ") for access path " +
                                 std::string(access_string));
        }
        const auto& member = members[index];
        final_member = index == members.size() - 1 && member.name && !member.name->empty();
        const auto location = decode_btf_member_offset(member.offset_from_start_in_bits, btf.kind_flag(result.type_id));
        add_member_offset(location.bit_offset);
        result.bitfield_size = location.bitfield_size;
        result.type_id = member.type;
    };

    for (const uint32_t index : indices) {
        result.type_id = strip_type_modifiers(btf_data, result.type_id);
        switch (btf_data.get_kind_index(result.type_id)) {
        case libbtf::BTF_KIND_STRUCT:
            enter_member(btf_data.get_kind_type<libbtf::btf_kind_struct>(result.type_id).members, "struct", index);
            break;
        case libbtf::BTF_KIND_UNION:
            enter_member(btf_data.get_kind_type<libbtf::btf_kind_union>(result.type_id).members, "union", index);
            break;
        case libbtf::BTF_KIND_ARRAY: {
            const auto a = btf_data.get_kind_type<libbtf::btf_kind_array>(result.type_id);
            if (index >= a.count_of_elements && !(final_member && a.count_of_elements == 0)) {
                throw UnmarshalError("CO-RE: array index " + std::to_string(index) + " out of bounds (size " +
                                     std::to_string(a.count_of_elements) + ") for access path " +
                                     std::string(access_string));
            }
            const uint64_t element_size = btf_data.get_size(a.element_type);
            if (element_size != 0 &&
                index > (std::numeric_limits<uint64_t>::max() - result.offset_bits) / 8 / element_size) {
                throw UnmarshalError("CO-RE: array offset overflow for access path " + std::string(access_string));
            }
            result.offset_bits += static_cast<uint64_t>(index) * element_size * 8;
            result.bitfield_size = 0;
            result.type_id = a.element_type;
            final_member = false;
            break;
        }
        default: throw UnmarshalError("CO-RE: indexing into non-aggregate type");
        }
    }

    result.type_id = strip_type_modifiers(btf_data, result.type_id);
    return result;
}

uint32_t core_field_bit_width(const libbtf::btf_type_data& btf_data, const core_field_resolution_t& field) {
    if (field.bitfield_size != 0) {
        return field.bitfield_size;
    }

    const auto kind = btf_data.get_kind_index(field.type_id);
    if (kind == libbtf::BTF_KIND_INT) {
        const auto int_kind = btf_data.get_kind_type<libbtf::btf_kind_int>(field.type_id);
        return int_kind.field_width_in_bits != 0 ? int_kind.field_width_in_bits : int_kind.size_in_bytes * 8;
    }

    return btf_data.get_size(field.type_id) * 8;
}

// The memory a field is loaded from. A bitfield is not addressed at the byte holding its first bit: as in
// libbpf's bpf_core_calc_field_relo(), it is read through the smallest naturally aligned unit, no smaller than
// its declared type, that covers all of its bits. FIELD_BYTE_OFFSET, FIELD_BYTE_SIZE and FIELD_LSHIFT_U64 must
// all describe that same unit, or the analyzed constants differ from the ones a CO-RE loader patches in.
core_field_storage_t core_field_storage(const libbtf::btf_type_data& btf_data, const core_field_resolution_t& field) {
    core_field_storage_t storage{field.offset_bits / 8, btf_data.get_size(field.type_id)};
    if (field.bitfield_size == 0) {
        return storage;
    }
    if (storage.byte_size == 0) {
        throw UnmarshalError("CO-RE bitfield has zero-sized type");
    }

    const uint64_t end_bits = field.offset_bits + field.bitfield_size;
    storage.byte_offset = field.offset_bits / 8 / storage.byte_size * storage.byte_size;
    while (end_bits - storage.byte_offset * 8 > storage.byte_size * 8) {
        if (storage.byte_size >= 8) {
            throw UnmarshalError("CO-RE bitfield cannot be read with a 64-bit load");
        }
        storage.byte_size *= 2;
        storage.byte_offset = field.offset_bits / 8 / storage.byte_size * storage.byte_size;
    }
    return storage;
}

bool core_field_offset_uses_offset_field(const EbpfInst& inst) {
    const uint8_t cls = inst.opcode & INST_CLS_MASK;
    if (cls != INST_CLS_LDX && cls != INST_CLS_ST && cls != INST_CLS_STX) {
        return false;
    }

    const uint8_t mode = inst.opcode & INST_MODE_MASK;
    return mode == INST_MODE_MEM || mode == INST_MODE_MEMSX || mode == INST_MODE_ATOMIC;
}

} // namespace

// ---------------------------------------------------------------------------
// ProgramReader CO-RE methods
// ---------------------------------------------------------------------------

void ProgramReader::apply_core_relocation(RawProgram& prog, const bpf_core_relo& relo,
                                          const std::string_view access_string, const CoreBtf& btf) {
    const libbtf::btf_type_data& btf_data = btf.types;
    if (relo.insn_off < prog.insn_off) {
        throw UnmarshalError("CO-RE relocation offset before program start");
    }
    const size_t byte_offset = relo.insn_off - prog.insn_off;
    if (byte_offset % sizeof(EbpfInst) != 0) {
        throw UnmarshalError("CO-RE relocation offset is not instruction-aligned");
    }

    const size_t inst_idx = byte_offset / sizeof(EbpfInst);
    if (inst_idx >= prog.prog.size()) {
        throw UnmarshalError("CO-RE relocation offset out of bounds");
    }
    EbpfInst& inst = prog.prog[inst_idx];

    // LDDW is a two-slot instruction: slot 0 (opcode 0x18) carries the lo32 immediate,
    // slot 1 (opcode 0x00) carries the hi32 immediate.  A CO-RE relocation that targets
    // the continuation slot would silently corrupt the hi32 bits instead of patching the
    // intended instruction field.
    if (inst.opcode == 0x00 && inst_idx > 0 && prog.prog[inst_idx - 1].opcode == INST_OP_LDDW_IMM) {
        throw UnmarshalError("CO-RE relocation at offset " + std::to_string(relo.insn_off) +
                             " targets LDDW continuation slot");
    }
    std::optional<core_field_resolution_t> resolved_field;
    const auto get_field = [&]() -> const core_field_resolution_t& {
        if (!resolved_field) {
            resolved_field = resolve_core_field(btf, relo.type_id, access_string);
        }
        return *resolved_field;
    };
    prog.core_relocation_count++;

    switch (relo.kind) {
    case BPF_CORE_FIELD_BYTE_OFFSET: {
        const auto core_field_byte_offset = gsl::narrow<int64_t>(core_field_storage(btf_data, get_field()).byte_offset);
        if (core_field_offset_uses_offset_field(inst)) {
            if (core_field_byte_offset < std::numeric_limits<int16_t>::min() ||
                core_field_byte_offset > std::numeric_limits<int16_t>::max()) {
                throw UnmarshalError("CO-RE field offset does not fit instruction offset field");
            }
            inst.offset = gsl::narrow<int16_t>(core_field_byte_offset);
        } else {
            inst.imm = gsl::narrow<int32_t>(core_field_byte_offset);
        }
        break;
    }
    case BPF_CORE_FIELD_BYTE_SIZE:
        inst.imm = gsl::narrow<int32_t>(core_field_storage(btf_data, get_field()).byte_size);
        break;
    case BPF_CORE_FIELD_EXISTS: inst.imm = 1; break;
    case BPF_CORE_FIELD_SIGNED: {
        switch (btf_data.get_kind_index(get_field().type_id)) {
        case libbtf::BTF_KIND_INT:
            inst.imm = btf_data.get_kind_type<libbtf::btf_kind_int>(get_field().type_id).is_signed;
            break;
        case libbtf::BTF_KIND_ENUM:
            inst.imm = btf_data.get_kind_type<libbtf::btf_kind_enum>(get_field().type_id).is_signed;
            break;
        case libbtf::BTF_KIND_ENUM64:
            inst.imm = btf_data.get_kind_type<libbtf::btf_kind_enum64>(get_field().type_id).is_signed;
            break;
        default: inst.imm = 0; break;
        }
        break;
    }
    case BPF_CORE_FIELD_LSHIFT_U64: {
        const auto& field = get_field();
        const auto field_bit_width = core_field_bit_width(btf_data, field);
        const uint64_t bit_offset_in_storage = field.offset_bits - core_field_storage(btf_data, field).byte_offset * 8;
        if (field_bit_width == 0 || field_bit_width > 64 || bit_offset_in_storage + field_bit_width > 64) {
            throw UnmarshalError("CO-RE field bit width exceeds 64 bits");
        }
        inst.imm = gsl::narrow<int32_t>(64 - (bit_offset_in_storage + field_bit_width));
        break;
    }
    case BPF_CORE_FIELD_RSHIFT_U64: {
        const auto field_bit_width = core_field_bit_width(btf_data, get_field());
        if (field_bit_width == 0 || field_bit_width > 64) {
            throw UnmarshalError("CO-RE field bit width exceeds 64 bits");
        }
        inst.imm = gsl::narrow<int32_t>(64 - field_bit_width);
        break;
    }
    // A type-id relocation asks for the id of the named type itself, modifiers included:
    // libbpf writes relo->type_id unchanged for TYPE_ID_LOCAL (and the id of the matching
    // target type for TYPE_ID_TARGET, which without target BTF is the local id as well).
    // Stripping typedef/const/... here would make a typedef compare equal to its
    // underlying type and decide branches differently from the loaded program.
    case BPF_CORE_TYPE_ID_LOCAL:
    case BPF_CORE_TYPE_ID_TARGET:
        // Reject ids that do not exist in the local BTF.
        (void)btf_data.get_kind_index(relo.type_id);
        inst.imm = gsl::narrow<int32_t>(relo.type_id);
        break;
    // Prevail is a static verifier without target-kernel BTF, so existence/match predicates
    // are resolved against local BTF only and therefore fold to true.
    case BPF_CORE_TYPE_EXISTS:
    case BPF_CORE_TYPE_MATCHES: inst.imm = 1; break;
    case BPF_CORE_TYPE_SIZE:
        inst.imm = gsl::narrow<int32_t>(btf_data.get_size(strip_type_modifiers(btf_data, relo.type_id)));
        break;
    case BPF_CORE_ENUMVAL_EXISTS:
    case BPF_CORE_ENUMVAL_VALUE: {
        const auto indices = parse_core_access_string(access_string);
        if (indices.empty()) {
            throw UnmarshalError("CO-RE enum relocation missing enum value index");
        }
        const auto enum_member_index = indices.back();
        const auto enum_type_id = strip_type_modifiers(btf_data, relo.type_id);

        switch (btf_data.get_kind_index(enum_type_id)) {
        case libbtf::BTF_KIND_ENUM: {
            const auto e = btf_data.get_kind_type<libbtf::btf_kind_enum>(enum_type_id);
            if (enum_member_index >= e.members.size()) {
                throw UnmarshalError("CO-RE enum member index out of bounds");
            }
            inst.imm =
                relo.kind == BPF_CORE_ENUMVAL_EXISTS ? 1 : gsl::narrow<int32_t>(e.members[enum_member_index].value);
            break;
        }
        case libbtf::BTF_KIND_ENUM64: {
            const auto e = btf_data.get_kind_type<libbtf::btf_kind_enum64>(enum_type_id);
            if (enum_member_index >= e.members.size()) {
                throw UnmarshalError("CO-RE enum64 member index out of bounds");
            }
            inst.imm =
                relo.kind == BPF_CORE_ENUMVAL_EXISTS ? 1 : gsl::narrow<int32_t>(e.members[enum_member_index].value);
            break;
        }
        default: throw UnmarshalError("CO-RE enum relocation target is not enum/enum64");
        }
        break;
    }
    default: throw UnmarshalError("Unsupported CO-RE relocation kind: " + std::to_string(relo.kind));
    }

    // libbpf's bpf_core_patch_insn() writes the new value over the whole 64-bit immediate of
    // an LDDW, so the continuation slot must not keep the hi32 bits the object shipped.
    if (inst.opcode == INST_OP_LDDW_IMM) {
        if (inst_idx + 1 >= prog.prog.size()) {
            throw UnmarshalError("CO-RE relocation at offset " + std::to_string(relo.insn_off) +
                                 " targets incomplete LDDW");
        }
        prog.prog[inst_idx + 1].imm = inst.imm < 0 ? -1 : 0;
    }
}

void ProgramReader::process_core_relocations(const libbtf::btf_type_data& btf_data) {
    const ELFIO::section* btf_ext_sec = reader.sections[".BTF.ext"];
    if (!btf_ext_sec || !btf_ext_sec->get_data()) {
        return;
    }
    const ELFIO::section* btf_sec = reader.sections[".BTF"];
    if (!btf_sec || !btf_sec->get_data()) {
        return;
    }

    const char* btf_ext_data = btf_ext_sec->get_data();
    const size_t btf_ext_size = btf_ext_sec->get_size();
    const auto btf_ext_header = read_struct_at<btf_ext_header_t>(btf_ext_data, btf_ext_size, 0, "BTF.ext header");
    if (btf_ext_header.magic != BTF_HEADER_MAGIC || btf_ext_header.version != BTF_HEADER_VERSION) {
        throw UnmarshalError("Invalid .BTF.ext header");
    }
    if (btf_ext_header.hdr_len < sizeof(btf_ext_header_t) || btf_ext_header.hdr_len > btf_ext_size) {
        throw UnmarshalError("Invalid .BTF.ext header length");
    }

    // Older BTF.ext headers might not include core_relo fields.
    if (btf_ext_header.hdr_len < offsetof(btf_ext_header_core_t, core_relo_len) + sizeof(uint32_t)) {
        return;
    }
    const auto core_relo_off = read_struct_at<uint32_t>(
        btf_ext_data, btf_ext_size, offsetof(btf_ext_header_core_t, core_relo_off), "BTF.ext core_relo_off");
    const auto core_relo_len = read_struct_at<uint32_t>(
        btf_ext_data, btf_ext_size, offsetof(btf_ext_header_core_t, core_relo_len), "BTF.ext core_relo_len");

    const size_t core_relo_start =
        checked_add(btf_ext_header.hdr_len, core_relo_off, btf_ext_size, "BTF.ext core_relo subsection");
    const size_t core_relo_end =
        checked_add(core_relo_start, core_relo_len, btf_ext_size, "BTF.ext core_relo subsection");
    if (core_relo_start == core_relo_end) {
        return;
    }

    size_t offset = core_relo_start;
    if (core_relo_end - offset < sizeof(uint32_t)) {
        throw UnmarshalError("BTF.ext core_relo subsection truncated");
    }
    const auto core_relo_rec_size =
        read_struct_at<uint32_t>(btf_ext_data, btf_ext_size, offset, "BTF.ext core_relo record size");
    offset += sizeof(uint32_t);
    if (core_relo_rec_size < sizeof(bpf_core_relo)) {
        throw UnmarshalError("Invalid CO-RE relocation record size");
    }

    const auto strings = parse_btf_string_table(*btf_sec);
    const CoreBtf btf{btf_data, parse_btf_kind_flags(*btf_sec)};
    std::map<std::string, std::vector<RawProgram*>> programs_by_section;
    for (auto& prog : raw_programs) {
        programs_by_section[prog.section_name].push_back(&prog);
    }

    while (offset < core_relo_end) {
        const auto section =
            read_struct_at<btf_ext_info_sec_t>(btf_ext_data, btf_ext_size, offset, "CO-RE section info");
        offset += sizeof(btf_ext_info_sec_t);
        if (offset > core_relo_end) {
            throw UnmarshalError("CO-RE section records out of bounds");
        }

        if (section.num_info != 0 && core_relo_rec_size > (core_relo_end - offset) / section.num_info) {
            throw UnmarshalError("CO-RE section records out of bounds");
        }
        const size_t records_size = static_cast<size_t>(section.num_info) * core_relo_rec_size;
        const size_t records_end = offset + records_size;
        const std::string section_name{btf_string_at(strings, section.sec_name_off, "CO-RE section name")};

        const auto prog_it = programs_by_section.find(section_name);
        if (prog_it == programs_by_section.end()) {
            offset = records_end;
            continue;
        }

        for (size_t i = 0; i < section.num_info; ++i) {
            const size_t record_offset = offset + i * core_relo_rec_size;
            const auto reloc =
                read_struct_at<bpf_core_relo>(btf_ext_data, btf_ext_size, record_offset, "CO-RE relocation");
            const auto access_string = btf_string_at(strings, reloc.access_str_off, "CO-RE access string");

            // This runs before linking, when the programs of a section do not overlap; linking then copies the
            // patched code into the callers. Every program that covers the instruction is patched nonetheless,
            // so that no copy would keep its placeholder if they did.
            bool applied = false;
            for (RawProgram* prog : prog_it->second) {
                const size_t prog_size = prog->prog.size() * sizeof(EbpfInst);
                if (reloc.insn_off >= prog->insn_off && reloc.insn_off < prog->insn_off + prog_size) {
                    apply_core_relocation(*prog, reloc, access_string, btf);
                    applied = true;
                }
            }

            if (!applied) {
                throw UnmarshalError("Failed to find program for CO-RE relocation at instruction offset " +
                                     std::to_string(reloc.insn_off) + " in section " + section_name);
            }
        }

        offset = records_end;
    }
}

} // namespace prevail

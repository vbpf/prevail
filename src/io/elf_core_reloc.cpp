// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cstring>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <elfio/elfio.hpp>
#include <libbtf/btf_c_type.h>
#include <libbtf/btf_parse.h>

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
    std::optional<uint32_t> member_offset_encoding;
};

template <typename T>
    requires std::is_trivially_copyable_v<T>
T read_struct_at(const char* data, size_t data_size, size_t offset, const std::string& context) {
    if (offset > data_size || data_size - offset < sizeof(T)) {
        throw UnmarshalError(context + " out of bounds");
    }
    T value;
    std::memcpy(&value, data + offset, sizeof(T));
    return value;
}

size_t checked_add(size_t start, size_t length, size_t limit, const std::string& context) {
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

std::string_view btf_string_at(const btf_string_table_view_t& strings, uint32_t string_offset,
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

core_field_resolution_t resolve_core_field(const libbtf::btf_type_data& btf_data, uint32_t type_id,
                                           std::string_view access_string) {
    auto indices = parse_core_access_string(access_string);
    // Clang/libbpf encode root type with a leading "0" accessor.
    if (!indices.empty() && indices.front() == 0) {
        indices.erase(indices.begin());
    }
    core_field_resolution_t result{type_id, 0, std::nullopt};

    for (const uint32_t index : indices) {
        result.type_id = strip_type_modifiers(btf_data, result.type_id);
        switch (btf_data.get_kind_index(result.type_id)) {
        case libbtf::BTF_KIND_STRUCT: {
            const auto s = btf_data.get_kind_type<libbtf::btf_kind_struct>(result.type_id);
            if (index >= s.members.size()) {
                throw UnmarshalError("CO-RE: struct member index " + std::to_string(index) + " out of bounds (size " +
                                     std::to_string(s.members.size()) + ") for access path " +
                                     std::string(access_string));
            }
            const auto& member = s.members[index];
            result.offset_bits += BTF_MEMBER_BIT_OFFSET(member.offset_from_start_in_bits);
            result.member_offset_encoding = member.offset_from_start_in_bits;
            result.type_id = member.type;
            break;
        }
        case libbtf::BTF_KIND_UNION: {
            const auto u = btf_data.get_kind_type<libbtf::btf_kind_union>(result.type_id);
            if (index >= u.members.size()) {
                throw UnmarshalError("CO-RE: union member index " + std::to_string(index) + " out of bounds (size " +
                                     std::to_string(u.members.size()) + ") for access path " +
                                     std::string(access_string));
            }
            const auto& member = u.members[index];
            result.offset_bits += BTF_MEMBER_BIT_OFFSET(member.offset_from_start_in_bits);
            result.member_offset_encoding = member.offset_from_start_in_bits;
            result.type_id = member.type;
            break;
        }
        case libbtf::BTF_KIND_ARRAY: {
            const auto a = btf_data.get_kind_type<libbtf::btf_kind_array>(result.type_id);
            if (index >= a.count_of_elements) {
                throw UnmarshalError("CO-RE: array index " + std::to_string(index) + " out of bounds (size " +
                                     std::to_string(a.count_of_elements) + ") for access path " +
                                     std::string(access_string));
            }
            result.offset_bits += static_cast<uint64_t>(index) * btf_data.get_size(a.element_type) * 8;
            result.member_offset_encoding.reset();
            result.type_id = a.element_type;
            break;
        }
        default: throw UnmarshalError("CO-RE: indexing into non-aggregate type");
        }
    }

    result.type_id = strip_type_modifiers(btf_data, result.type_id);
    return result;
}

uint32_t core_field_bit_width(const libbtf::btf_type_data& btf_data, const core_field_resolution_t& field) {
    if (field.member_offset_encoding && BTF_MEMBER_BITFIELD_SIZE(*field.member_offset_encoding) != 0) {
        return BTF_MEMBER_BITFIELD_SIZE(*field.member_offset_encoding);
    }

    const auto kind = btf_data.get_kind_index(field.type_id);
    if (kind == libbtf::BTF_KIND_INT) {
        const auto int_kind = btf_data.get_kind_type<libbtf::btf_kind_int>(field.type_id);
        return int_kind.field_width_in_bits != 0 ? int_kind.field_width_in_bits : int_kind.size_in_bytes * 8;
    }

    return btf_data.get_size(field.type_id) * 8;
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

void ProgramReader::apply_core_relocation(RawProgram& prog, const bpf_core_relo& relo, std::string_view access_string,
                                          const libbtf::btf_type_data& btf_data) {
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
            resolved_field = resolve_core_field(btf_data, relo.type_id, access_string);
        }
        return *resolved_field;
    };
    prog.core_relocation_count++;

    switch (relo.kind) {
    case BPF_CORE_FIELD_BYTE_OFFSET: {
        const auto core_field_byte_offset = gsl::narrow<int64_t>(get_field().offset_bits / 8);
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
    case BPF_CORE_FIELD_BYTE_SIZE: inst.imm = gsl::narrow<int32_t>(btf_data.get_size(get_field().type_id)); break;
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
        const uint32_t bit_offset_in_byte = static_cast<uint32_t>(field.offset_bits % 8);
        if (field_bit_width == 0 || field_bit_width > 64 || bit_offset_in_byte + field_bit_width > 64) {
            throw UnmarshalError("CO-RE field bit width exceeds 64 bits");
        }
        inst.imm = gsl::narrow<int32_t>(64 - (bit_offset_in_byte + field_bit_width));
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
    case BPF_CORE_TYPE_ID_LOCAL:
    case BPF_CORE_TYPE_ID_TARGET: inst.imm = gsl::narrow<int32_t>(strip_type_modifiers(btf_data, relo.type_id)); break;
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
    std::map<std::string, std::vector<RawProgram*>> programs_by_section;
    for (auto& prog : raw_programs) {
        programs_by_section[prog.section_name].push_back(&prog);
    }

    for (; offset < core_relo_end;) {
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

            bool applied = false;
            for (RawProgram* prog : prog_it->second) {
                const size_t prog_size = prog->prog.size() * sizeof(EbpfInst);
                if (reloc.insn_off >= prog->insn_off && reloc.insn_off < prog->insn_off + prog_size) {
                    apply_core_relocation(*prog, reloc, access_string, btf_data);
                    applied = true;
                    break;
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

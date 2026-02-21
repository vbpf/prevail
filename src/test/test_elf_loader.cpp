// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <catch2/catch_all.hpp>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <elfio/elfio.hpp>

#include "config.hpp"
#include "elf_loader.hpp"
#include "platform.hpp"

using namespace prevail;

namespace {

std::vector<uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open test input: " + path.string());
    }
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

void write_file_bytes(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        throw std::runtime_error("Failed to open test output: " + path.string());
    }
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file) {
        throw std::runtime_error("Failed to write mutated test input: " + path.string());
    }
}

uint32_t read_u32_le(const std::vector<uint8_t>& bytes, const size_t offset) {
    if (offset + sizeof(uint32_t) > bytes.size()) {
        throw std::runtime_error("u32 read out of bounds");
    }
    return static_cast<uint32_t>(bytes[offset] | (static_cast<uint32_t>(bytes[offset + 1]) << 8U) |
                                 (static_cast<uint32_t>(bytes[offset + 2]) << 16U) |
                                 (static_cast<uint32_t>(bytes[offset + 3]) << 24U));
}

uint64_t read_u64_le(const std::vector<uint8_t>& bytes, const size_t offset) {
    if (offset + sizeof(uint64_t) > bytes.size()) {
        throw std::runtime_error("u64 read out of bounds");
    }

    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        value |= static_cast<uint64_t>(bytes[offset + i]) << (8U * i);
    }
    return value;
}

void write_u16_le(std::vector<uint8_t>& bytes, const size_t offset, const uint16_t value) {
    if (offset + sizeof(uint16_t) > bytes.size()) {
        throw std::runtime_error("u16 write out of bounds");
    }
    bytes[offset] = static_cast<uint8_t>(value & 0xffU);
    bytes[offset + 1] = static_cast<uint8_t>((value >> 8U) & 0xffU);
}

void write_u32_le(std::vector<uint8_t>& bytes, const size_t offset, const uint32_t value) {
    if (offset + sizeof(uint32_t) > bytes.size()) {
        throw std::runtime_error("u32 write out of bounds");
    }
    bytes[offset] = static_cast<uint8_t>(value & 0xffU);
    bytes[offset + 1] = static_cast<uint8_t>((value >> 8U) & 0xffU);
    bytes[offset + 2] = static_cast<uint8_t>((value >> 16U) & 0xffU);
    bytes[offset + 3] = static_cast<uint8_t>((value >> 24U) & 0xffU);
}

void write_u64_le(std::vector<uint8_t>& bytes, const size_t offset, const uint64_t value) {
    if (offset + sizeof(uint64_t) > bytes.size()) {
        throw std::runtime_error("u64 write out of bounds");
    }
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        bytes[offset + i] = static_cast<uint8_t>((value >> (8U * i)) & 0xffU);
    }
}

class TempElfFile {
  public:
    TempElfFile(const std::filesystem::path& source, const std::string_view tag) {
        const auto temp_dir = std::filesystem::temp_directory_path();
        const auto seed = std::random_device{}();
        for (size_t attempt = 0; attempt < 4096; ++attempt) {
            path_ = temp_dir /
                    ("prevail-" + std::string(tag) + "-" + std::to_string(seed) + "-" + std::to_string(attempt) + ".o");
            if (std::filesystem::exists(path_)) {
                continue;
            }
            std::filesystem::copy_file(source, path_);
            return;
        }
        throw std::runtime_error("Failed to create temporary ELF copy");
    }

    ~TempElfFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    TempElfFile(const TempElfFile&) = delete;
    TempElfFile& operator=(const TempElfFile&) = delete;

    const std::filesystem::path& path() const { return path_; }

  private:
    std::filesystem::path path_;
};

struct SectionHeaderInfo {
    unsigned char elf_class;
    size_t section_header_offset;
};

SectionHeaderInfo get_section_header_info(const std::filesystem::path& path, const std::string& section_name) {
    ELFIO::elfio reader;
    if (!reader.load(path.string())) {
        throw std::runtime_error("Failed to parse test ELF copy: " + path.string());
    }

    const auto* section = reader.sections[section_name];
    if (!section) {
        throw std::runtime_error("Section not found in test ELF copy: " + section_name);
    }

    return {
        .elf_class = reader.get_class(),
        .section_header_offset =
            static_cast<size_t>(reader.get_sections_offset()) +
            static_cast<size_t>(section->get_index()) * static_cast<size_t>(reader.get_section_entry_size()),
    };
}

void patch_machine(const std::filesystem::path& path, const uint16_t machine) {
    auto bytes = read_file_bytes(path);
    if (bytes.size() < 20) {
        throw std::runtime_error("ELF header is truncated");
    }
    // e_machine field in ELF header (both 32-bit and 64-bit).
    write_u16_le(bytes, 18, machine);
    write_file_bytes(path, bytes);
}

void patch_section_offset(const std::filesystem::path& path, const std::string& section_name, const uint64_t offset) {
    const auto info = get_section_header_info(path, section_name);
    auto bytes = read_file_bytes(path);
    if (info.elf_class == ELFIO::ELFCLASS32) {
        write_u32_le(bytes, info.section_header_offset + 16, static_cast<uint32_t>(offset));
    } else if (info.elf_class == ELFIO::ELFCLASS64) {
        write_u64_le(bytes, info.section_header_offset + 24, offset);
    } else {
        throw std::runtime_error("Unexpected ELF class");
    }
    write_file_bytes(path, bytes);
}

void patch_section_size(const std::filesystem::path& path, const std::string& section_name, const uint64_t size) {
    const auto info = get_section_header_info(path, section_name);
    auto bytes = read_file_bytes(path);
    if (info.elf_class == ELFIO::ELFCLASS32) {
        write_u32_le(bytes, info.section_header_offset + 20, static_cast<uint32_t>(size));
    } else if (info.elf_class == ELFIO::ELFCLASS64) {
        write_u64_le(bytes, info.section_header_offset + 32, size);
    } else {
        throw std::runtime_error("Unexpected ELF class");
    }
    write_file_bytes(path, bytes);
}

struct RelocationSectionInfo {
    unsigned char elf_class;
    ELFIO::Elf_Word section_type;
    size_t section_offset;
    size_t section_size;
    size_t entry_size;
};

RelocationSectionInfo get_relocation_section_info(const std::filesystem::path& path, const std::string& section_name) {
    ELFIO::elfio reader;
    if (!reader.load(path.string())) {
        throw std::runtime_error("Failed to parse test ELF copy: " + path.string());
    }

    const auto* section = reader.sections[section_name];
    if (!section) {
        throw std::runtime_error("Relocation section not found in test ELF copy: " + section_name);
    }
    if (section->get_type() != ELFIO::SHT_REL && section->get_type() != ELFIO::SHT_RELA) {
        throw std::runtime_error("Section is not a relocation section: " + section_name);
    }
    if (section->get_entry_size() == 0 || section->get_size() < section->get_entry_size()) {
        throw std::runtime_error("Relocation section has no entries: " + section_name);
    }

    return {
        .elf_class = reader.get_class(),
        .section_type = section->get_type(),
        .section_offset = static_cast<size_t>(section->get_offset()),
        .section_size = static_cast<size_t>(section->get_size()),
        .entry_size = static_cast<size_t>(section->get_entry_size()),
    };
}

void patch_first_core_access_string_offset(const std::filesystem::path& path, const uint32_t new_offset) {
    ELFIO::elfio reader;
    if (!reader.load(path.string())) {
        throw std::runtime_error("Failed to parse test ELF copy: " + path.string());
    }
    const auto* btf_ext = reader.sections[".BTF.ext"];
    if (!btf_ext) {
        throw std::runtime_error("Section .BTF.ext not found in test ELF copy");
    }

    auto bytes = read_file_bytes(path);
    const size_t section_offset = static_cast<size_t>(btf_ext->get_offset());
    const size_t section_size = static_cast<size_t>(btf_ext->get_size());
    if (section_offset > bytes.size() || section_size > bytes.size() - section_offset) {
        throw std::runtime_error(".BTF.ext section out of file bounds in test ELF copy");
    }

    const size_t ext_base = section_offset;
    const uint32_t hdr_len = read_u32_le(bytes, ext_base + 4);
    const uint32_t core_relo_off = read_u32_le(bytes, ext_base + 24);
    const uint32_t core_relo_len = read_u32_le(bytes, ext_base + 28);
    const size_t core_start = ext_base + static_cast<size_t>(hdr_len) + static_cast<size_t>(core_relo_off);
    const size_t core_end = core_start + static_cast<size_t>(core_relo_len);

    if (core_start > ext_base + section_size || core_end > ext_base + section_size || core_end < core_start) {
        throw std::runtime_error("Invalid core_relo bounds in test ELF copy");
    }
    if (core_end - core_start < sizeof(uint32_t)) {
        throw std::runtime_error("core_relo subsection is truncated in test ELF copy");
    }

    const uint32_t record_size = read_u32_le(bytes, core_start);
    size_t cursor = core_start + sizeof(uint32_t);
    bool patched = false;
    while (cursor + 8 <= core_end) {
        const uint32_t num_info = read_u32_le(bytes, cursor + 4);
        cursor += 8;
        const size_t records_size = static_cast<size_t>(num_info) * static_cast<size_t>(record_size);
        if (records_size > core_end - cursor) {
            throw std::runtime_error("Invalid CO-RE records bounds in test ELF copy");
        }

        if (num_info > 0) {
            // bpf_core_relo.access_str_off is the third u32 field in a relocation record.
            write_u32_le(bytes, cursor + 8, new_offset);
            patched = true;
            break;
        }

        cursor += records_size;
    }

    if (!patched) {
        throw std::runtime_error("No CO-RE relocation records found in test ELF copy");
    }

    write_file_bytes(path, bytes);
}

void patch_first_relocation_symbol_index(const std::filesystem::path& path, const std::string& section_name,
                                         const uint32_t new_symbol_index) {
    const auto info = get_relocation_section_info(path, section_name);
    auto bytes = read_file_bytes(path);
    const size_t entry_offset = info.section_offset;
    if (entry_offset + info.entry_size > bytes.size()) {
        throw std::runtime_error("Relocation entry out of bounds in test ELF copy");
    }

    if (info.elf_class == ELFIO::ELFCLASS64) {
        constexpr size_t r_info_offset = 8;
        const auto old_info = read_u64_le(bytes, entry_offset + r_info_offset);
        const uint64_t new_info = (static_cast<uint64_t>(new_symbol_index) << 32U) | (old_info & 0xffffffffULL);
        write_u64_le(bytes, entry_offset + r_info_offset, new_info);
    } else if (info.elf_class == ELFIO::ELFCLASS32) {
        constexpr size_t r_info_offset = 4;
        const auto old_info = read_u32_le(bytes, entry_offset + r_info_offset);
        const uint32_t new_info = (new_symbol_index << 8U) | (old_info & 0xffU);
        write_u32_le(bytes, entry_offset + r_info_offset, new_info);
    } else {
        throw std::runtime_error("Unexpected ELF class");
    }

    write_file_bytes(path, bytes);
}

void patch_first_relocation_type(const std::filesystem::path& path, const std::string& section_name,
                                 const uint32_t new_relocation_type) {
    const auto info = get_relocation_section_info(path, section_name);
    auto bytes = read_file_bytes(path);
    const size_t entry_offset = info.section_offset;
    if (entry_offset + info.entry_size > bytes.size()) {
        throw std::runtime_error("Relocation entry out of bounds in test ELF copy");
    }

    if (info.elf_class == ELFIO::ELFCLASS64) {
        constexpr size_t r_info_offset = 8;
        const auto old_info = read_u64_le(bytes, entry_offset + r_info_offset);
        const uint64_t new_info = (old_info & 0xffffffff00000000ULL) | static_cast<uint64_t>(new_relocation_type);
        write_u64_le(bytes, entry_offset + r_info_offset, new_info);
    } else if (info.elf_class == ELFIO::ELFCLASS32) {
        constexpr size_t r_info_offset = 4;
        const auto old_info = read_u32_le(bytes, entry_offset + r_info_offset);
        const uint32_t new_info = (old_info & 0xffffff00U) | (new_relocation_type & 0xffU);
        write_u32_le(bytes, entry_offset + r_info_offset, new_info);
    } else {
        throw std::runtime_error("Unexpected ELF class");
    }

    write_file_bytes(path, bytes);
}

} // namespace

#define FAIL_LOAD_ELF_BASE(test_name, dirname, filename, sectionname)                                                  \
    TEST_CASE(test_name, "[elf]") {                                                                                    \
        thread_local_options = {};                                                                                     \
        REQUIRE_THROWS_AS(                                                                                             \
            ([&]() {                                                                                                   \
                ElfObject{"ebpf-samples/" dirname "/" filename, {}, &g_ebpf_platform_linux}.get_programs(sectionname); \
            }()),                                                                                                      \
            std::runtime_error);                                                                                       \
    }

#define FAIL_LOAD_ELF(dirname, filename, sectionname) \
    FAIL_LOAD_ELF_BASE("Try loading nonexisting program: " dirname "/" filename, dirname, filename, sectionname)

// Like FAIL_LOAD_ELF, but includes sectionname in the test name to avoid collisions
// when multiple sections of the same file fail to load.
#define FAIL_LOAD_ELF_SECTION(dirname, filename, sectionname) \
    FAIL_LOAD_ELF_BASE("Try loading bad section: " dirname "/" filename " " sectionname, dirname, filename, sectionname)

#define LOAD_ELF_SECTION(dirname, filename, sectionname)                                                           \
    TEST_CASE("Try loading section: " dirname "/" filename " " sectionname, "[elf]") {                             \
        thread_local_options = {};                                                                                 \
        const auto progs =                                                                                         \
            ElfObject{"ebpf-samples/" dirname "/" filename, {}, &g_ebpf_platform_linux}.get_programs(sectionname); \
        REQUIRE_FALSE(progs.empty());                                                                              \
    }

// Intentional loader failures.
FAIL_LOAD_ELF("cilium", "not-found.o", "2/1")
FAIL_LOAD_ELF("cilium", "bpf_lxc.o", "not-found")
FAIL_LOAD_ELF("invalid", "badsymsize.o", "xdp_redirect_map")

// Sections that used to be loader failures and now load successfully (verification may still reject later).
LOAD_ELF_SECTION("build", "badrelo.o", ".text")
LOAD_ELF_SECTION("linux-selftests", "bpf_cubic.o", "struct_ops")
LOAD_ELF_SECTION("linux-selftests", "bpf_dctcp.o", "struct_ops")
LOAD_ELF_SECTION("linux-selftests", "map_ptr_kern.o", "cgroup_skb/egress")
LOAD_ELF_SECTION("cilium-ebpf", "errors-el.elf", "socket")
LOAD_ELF_SECTION("cilium-ebpf", "fwd_decl-el.elf", "socket")
LOAD_ELF_SECTION("cilium-ebpf", "invalid-kfunc-el.elf", "tc")
LOAD_ELF_SECTION("cilium-ebpf", "kfunc-el.elf", "tc")
LOAD_ELF_SECTION("cilium-ebpf", "kfunc-el.elf", "fentry/bpf_fentry_test2")
LOAD_ELF_SECTION("cilium-ebpf", "kfunc-el.elf", "tp_btf/task_newtask")
LOAD_ELF_SECTION("cilium-ebpf", "kfunc-kmod-el.elf", "tc")
LOAD_ELF_SECTION("cilium-ebpf", "ksym-el.elf", "socket")
LOAD_ELF_SECTION("cilium-ebpf", "linked-el.elf", "socket")
LOAD_ELF_SECTION("cilium-ebpf", "linked1-el.elf", "socket")
LOAD_ELF_SECTION("cilium-ebpf", "linked2-el.elf", "socket")
LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "xdp")
LOAD_ELF_SECTION("cilium-ebpf", "loader-el.elf", "socket/2")
LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "xdp")
LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-14-el.elf", "socket/2")
LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "xdp")
LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-17-el.elf", "socket/2")
LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "xdp")
LOAD_ELF_SECTION("cilium-ebpf", "loader-clang-20-el.elf", "socket/2")
LOAD_ELF_SECTION("cilium-ebpf", "loader_nobtf-el.elf", "socket/2")

TEST_CASE("CO-RE relocations are parsed from .BTF.ext core_relo subsection", "[elf][core]") {
    thread_local_options = {};

    constexpr auto fentry_path = "ebpf-samples/cilium-examples/tcprtt_bpf_bpfel.o";
    constexpr auto fentry_section = "fentry/tcp_close";
    ElfObject fentry_elf{fentry_path, {}, &g_ebpf_platform_linux};
    const auto& fentry_progs = fentry_elf.get_programs(fentry_section);
    REQUIRE(fentry_progs.size() == 1);
    REQUIRE(fentry_progs[0].core_relocation_count > 0);

    constexpr auto sockops_path = "ebpf-samples/cilium-examples/tcprtt_sockops_bpf_bpfel.o";
    constexpr auto sockops_section = "sockops";
    ElfObject sockops_elf{sockops_path, {}, &g_ebpf_platform_linux};
    const auto& sockops_progs = sockops_elf.get_programs(sockops_section);
    REQUIRE(sockops_progs.size() == 1);
    REQUIRE(sockops_progs[0].core_relocation_count > 0);
}

TEST_CASE("ELF loader rejects non-BPF e_machine", "[elf][hardening]") {
    thread_local_options = {};

    TempElfFile elf{"ebpf-samples/build/twomaps.o", "bad-machine"};
    patch_machine(elf.path(), ELFIO::EM_X86_64);

    REQUIRE_THROWS_WITH((ElfObject{elf.path().string(), {}, &g_ebpf_platform_linux}.get_programs(".text")),
                        Catch::Matchers::ContainsSubstring("Unsupported ELF machine"));
}

TEST_CASE("ELF loader rejects relocation sections with out-of-bounds file offsets", "[elf][hardening]") {
    thread_local_options = {};

    TempElfFile elf{"ebpf-samples/build/twomaps.o", "bad-reloc-offset"};
    const auto file_size = std::filesystem::file_size(elf.path());
    patch_section_offset(elf.path(), ".rel.BTF", file_size + 4096);

    REQUIRE_THROWS_WITH((ElfObject{elf.path().string(), {}, &g_ebpf_platform_linux}.get_programs(".text")),
                        Catch::Matchers::ContainsSubstring("out-of-bounds file range"));
}

TEST_CASE("ELF loader rejects malformed legacy maps section record size", "[elf][hardening]") {
    thread_local_options = {};

    TempElfFile elf{"ebpf-samples/bpf_cilium_test/bpf_lb-DLB_L3.o", "bad-maps-size"};
    // Keep the section in-bounds but make each inferred map record too small.
    patch_section_size(elf.path(), "maps", 24);

    REQUIRE_THROWS_WITH((ElfObject{elf.path().string(), {}, &g_ebpf_platform_linux}.get_programs("2/1")),
                        Catch::Matchers::ContainsSubstring("Malformed legacy maps section"));
}

TEST_CASE("CO-RE access string offset out-of-bounds fails cleanly", "[elf][core][hardening]") {
    thread_local_options = {};

    TempElfFile elf{"ebpf-samples/cilium-examples/tcprtt_bpf_bpfel.o", "bad-core-access"};
    patch_first_core_access_string_offset(elf.path(), 0xfffffff0U);

    REQUIRE_THROWS_WITH((ElfObject{elf.path().string(), {}, &g_ebpf_platform_linux}.get_programs("fentry/tcp_close")),
                        Catch::Matchers::ContainsSubstring("Unsupported or invalid CO-RE/BTF relocation data"));
}

TEST_CASE("ELF loader rejects relocation entries with invalid symbol index", "[elf][hardening]") {
    thread_local_options = {};

    TempElfFile elf{"ebpf-samples/build/twomaps.o", "bad-reloc-symbol-index"};
    patch_first_relocation_symbol_index(elf.path(), ".rel.text", 0x00ffffffU);

    REQUIRE_THROWS_WITH((ElfObject{elf.path().string(), {}, &g_ebpf_platform_linux}.get_programs(".text")),
                        Catch::Matchers::ContainsSubstring("Invalid relocation symbol index"));
}

TEST_CASE("ELF loader rejects unsupported relocation types", "[elf][hardening]") {
    thread_local_options = {};

    TempElfFile elf{"ebpf-samples/build/twomaps.o", "bad-reloc-type"};
    patch_first_relocation_type(elf.path(), ".rel.text", 0xffU);

    REQUIRE_THROWS_WITH((ElfObject{elf.path().string(), {}, &g_ebpf_platform_linux}.get_programs(".text")),
                        Catch::Matchers::ContainsSubstring("Unsupported relocation type"));
}

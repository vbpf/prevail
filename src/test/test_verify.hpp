// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <catch2/catch_all.hpp>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <ranges>
#include <string>
#include <thread>
#include <unordered_map>
#include <string_view>

#include "ebpf_verifier.hpp"
#include "elf_loader.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"

using namespace prevail;

namespace verify_test {

enum class VerifyIssueKind {
    VerifierTypeTracking,
    VerifierBoundsTracking,
    VerifierStackInitialization,
    VerifierPointerArithmetic,
    VerifierMapTyping,
    VerifierNullability,
    VerifierContextModeling,
    VerifierRecursionModeling,
    UnmarshalControlFlow,
    ExternalSymbolResolution,
    PlatformHelperAvailability,
    ElfCoreRelocation,
    ElfSubprogramResolution,
    ElfLegacyMapLayout,
    VerificationTimeout,
    LegacyBccBehavior,
};

inline const char* to_string(VerifyIssueKind kind) noexcept {
    switch (kind) {
    case VerifyIssueKind::VerifierTypeTracking: return "VerifierTypeTracking";
    case VerifyIssueKind::VerifierBoundsTracking: return "VerifierBoundsTracking";
    case VerifyIssueKind::VerifierStackInitialization: return "VerifierStackInitialization";
    case VerifyIssueKind::VerifierPointerArithmetic: return "VerifierPointerArithmetic";
    case VerifyIssueKind::VerifierMapTyping: return "VerifierMapTyping";
    case VerifyIssueKind::VerifierNullability: return "VerifierNullability";
    case VerifyIssueKind::VerifierContextModeling: return "VerifierContextModeling";
    case VerifyIssueKind::VerifierRecursionModeling: return "VerifierRecursionModeling";
    case VerifyIssueKind::UnmarshalControlFlow: return "UnmarshalControlFlow";
    case VerifyIssueKind::ExternalSymbolResolution: return "ExternalSymbolResolution";
    case VerifyIssueKind::PlatformHelperAvailability: return "PlatformHelperAvailability";
    case VerifyIssueKind::ElfCoreRelocation: return "ElfCoreRelocation";
    case VerifyIssueKind::ElfSubprogramResolution: return "ElfSubprogramResolution";
    case VerifyIssueKind::ElfLegacyMapLayout: return "ElfLegacyMapLayout";
    case VerifyIssueKind::VerificationTimeout: return "VerificationTimeout";
    case VerifyIssueKind::LegacyBccBehavior: return "LegacyBccBehavior";
    }
    return "Unknown";
}

inline std::string format_issue(VerifyIssueKind kind, const char* reason) {
    return std::string(to_string(kind)) + ": " + reason;
}

inline std::string expected_exception_substring(const char* reason) {
    if (reason == nullptr) {
        return {};
    }
    const std::string text{reason};
    constexpr std::string_view marker = "Diagnostic: ";
    const auto marker_index = text.find(marker);
    if (marker_index == std::string::npos) {
        return text;
    }
    return text.substr(marker_index + marker.size());
}

template <typename T>
inline void hash_combine(size_t& seed, const T& value) noexcept {
    seed ^= std::hash<T>{}(value) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
}

struct ElfObjectCacheKey {
    std::string path;
    const ebpf_platform_t* platform;
    bool verbosity_print_line_info;
    bool verbosity_dump_btf_types_json;

    bool operator==(const ElfObjectCacheKey&) const = default;
};

struct ElfObjectCacheKeyHash {
    size_t operator()(const ElfObjectCacheKey& key) const noexcept {
        size_t seed = std::hash<std::string>{}(key.path);
        hash_combine(seed, key.platform);
        hash_combine(seed, key.verbosity_print_line_info);
        hash_combine(seed, key.verbosity_dump_btf_types_json);
        return seed;
    }
};

inline std::vector<RawProgram> read_elf_cached(const std::string& path, const std::string& desired_section,
                                               const std::string& desired_program,
                                               const ebpf_verifier_options_t& options,
                                               const ebpf_platform_t* platform) {
    static std::mutex cache_mutex;
    static std::unordered_map<ElfObjectCacheKey, ElfObject, ElfObjectCacheKeyHash> object_cache;

    ElfObjectCacheKey key{
        .path = path,
        .platform = platform,
        .verbosity_print_line_info = options.verbosity_opts.print_line_info,
        .verbosity_dump_btf_types_json = options.verbosity_opts.dump_btf_types_json,
    };
    ebpf_verifier_options_t loader_options{};
    loader_options.verbosity_opts.print_line_info = options.verbosity_opts.print_line_info;
    loader_options.verbosity_opts.dump_btf_types_json = options.verbosity_opts.dump_btf_types_json;

    std::lock_guard<std::mutex> lock(cache_mutex);
    auto [it, _] = object_cache.try_emplace(key, path, loader_options, platform);
    return it->second.get_programs(desired_section, desired_program);
}

} // namespace verify_test

// Verify a program in a section that may have multiple programs in it.
#define VERIFY_PROGRAM(dirname, filename, section_name, program_name, _options, platform, should_pass, count)        \
    do {                                                                                                             \
        thread_local_options = _options;                                                                             \
        const auto& raw_progs = verify_test::read_elf_cached("ebpf-samples/" dirname "/" filename, section_name, "", \
                                                             thread_local_options, platform);                        \
        REQUIRE(raw_progs.size() == count);                                                                          \
        for (const auto& raw_prog : raw_progs) {                                                                     \
            if (count == 1 || raw_prog.function_name == program_name) {                                              \
                const auto prog_or_error = unmarshal(raw_prog, thread_local_options);                                \
                const auto inst_seq = std::get_if<InstructionSeq>(&prog_or_error);                                   \
                REQUIRE(inst_seq);                                                                                   \
                const Program prog = Program::from_sequence(*inst_seq, raw_prog.info, thread_local_options);         \
                REQUIRE(verify(prog) == should_pass);                                                                \
            }                                                                                                        \
        }                                                                                                            \
    } while (0)

// Verify a section with only one program in it.
#define VERIFY_SECTION(dirname, filename, section_name, _options, platform, should_pass) \
    VERIFY_PROGRAM(dirname, filename, section_name, "", _options, platform, should_pass, 1)

#define TEST_SECTION(project, filename, section)                                      \
    TEST_CASE(project "/" filename " " section, "[verify][samples][" project "]") {   \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, true); \
    }

#define TEST_SECTION_SLOW(project, filename, section)                                     \
    TEST_CASE(project "/" filename " " section, "[verify][samples][slow][" project "]") { \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, true);     \
    }

#define TEST_PROGRAM(project, filename, section_name, program_name, count)                                      \
    TEST_CASE(project "/" filename " " program_name, "[verify][samples][" project "]") {                        \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &g_ebpf_platform_linux, true, count); \
    }

#define TEST_PROGRAM_FAIL(project, filename, section_name, program_name, count, kind, reason)                   \
    TEST_CASE(project "/" filename " " program_name, "[!shouldfail][verify][samples][" project "]") {           \
        INFO("issue_kind=" << verify_test::to_string(kind));                                                    \
        INFO("issue_reason=" << reason);                                                                        \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &g_ebpf_platform_linux, true, count); \
    }

#define TEST_PROGRAM_REJECT(project, filename, section_name, program_name, count)                                \
    TEST_CASE(project "/" filename " " program_name, "[verify][samples][" project "]") {                         \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &g_ebpf_platform_linux, false, count); \
    }

#define TEST_PROGRAM_REJECT_FAIL(project, filename, section_name, program_name, count)                           \
    TEST_CASE(project "/" filename " " program_name, "[!shouldfail][verify][samples][" project "]") {            \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &g_ebpf_platform_linux, false, count); \
    }

#define TEST_SECTION_REJECT(project, filename, section)                                \
    TEST_CASE(project "/" filename " " section, "[verify][samples][" project "]") {    \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, false); \
    }

#define TEST_SECTION_REJECT_IF_STRICT(project, filename, section)                           \
    TEST_CASE(project "/" filename " " section, "[verify][samples][" project "]") {         \
        ebpf_verifier_options_t options{};                                                  \
        VERIFY_SECTION(project, filename, section, options, &g_ebpf_platform_linux, true);  \
        options.strict = true;                                                              \
        VERIFY_SECTION(project, filename, section, options, &g_ebpf_platform_linux, false); \
    }

#define TEST_SECTION_FAIL(project, filename, section, kind, reason)                                                \
    TEST_CASE("expect failure " project "/" filename " " section, "[!shouldfail][verify][samples][" project "]") { \
        INFO("issue_kind=" << verify_test::to_string(kind));                                                       \
        INFO("issue_reason=" << reason);                                                                           \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, true);                              \
    }

#define TEST_SECTION_SKIP(project, filename, section, kind, reason)                 \
    TEST_CASE(project "/" filename " " section, "[verify][samples][" project "]") { \
        SKIP(verify_test::format_issue(kind, reason));                              \
    }

#define TEST_PROGRAM_SKIP(project, filename, section_name, program_name, kind, reason)   \
    TEST_CASE(project "/" filename " " program_name, "[verify][samples][" project "]") { \
        SKIP(verify_test::format_issue(kind, reason));                                   \
    }

#define TEST_SECTION_LOAD_FAIL(project, filename, section, kind, reason)                                              \
    TEST_CASE("expect load failure " project "/" filename " " section, "[verify][samples][" project "]") {            \
        INFO("issue_kind=" << verify_test::to_string(kind));                                                          \
        INFO("issue_reason=" << reason);                                                                              \
        REQUIRE_THROWS_WITH(([&]() {                                                                                  \
                                (void)verify_test::read_elf_cached("ebpf-samples/" project "/" filename, section, "", \
                                                                   {}, &g_ebpf_platform_linux);                       \
                            }()),                                                                                     \
                            Catch::Matchers::ContainsSubstring(verify_test::expected_exception_substring(reason)));   \
    }

#define TEST_SECTION_FAIL_SLOW(project, filename, section, kind, reason)              \
    TEST_CASE("expect failure " project "/" filename " " section,                     \
              "[!shouldfail][verify][samples][slow][" project "]") {                  \
        INFO("issue_kind=" << verify_test::to_string(kind));                          \
        INFO("issue_reason=" << reason);                                              \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, true); \
    }

#define TEST_SECTION_REJECT_FAIL(project, filename, section)                                                       \
    TEST_CASE("expect failure " project "/" filename " " section, "[!shouldfail][verify][samples][" project "]") { \
        VERIFY_SECTION(project, filename, section, {}, &g_ebpf_platform_linux, false);                             \
    }

#define TEST_SECTION_LEGACY(dirname, filename, sectionname) TEST_SECTION(dirname, filename, sectionname)
#define TEST_SECTION_LEGACY_SLOW(dirname, filename, sectionname) TEST_SECTION_SLOW(dirname, filename, sectionname)
#define TEST_SECTION_LEGACY_FAIL(dirname, filename, sectionname, kind, reason) \
    TEST_SECTION_FAIL(dirname, filename, sectionname, kind, reason)

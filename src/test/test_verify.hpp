// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <catch2/catch_all.hpp>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

#include "config.hpp"
#include "io/elf_loader.hpp"
#include "ir/program.hpp"
#include "ir/unmarshal.hpp"
#include "platform.hpp"
#include "verifier.hpp"

namespace verify_test {

// Why the verifier rejects a program that the kernel verifier would accept.
// Each value represents a category of imprecision in our abstract domain or modeling.
enum class VerifyIssueKind {
    // State refinement loses precise register type information across control-flow merges,
    // so a pointer or scalar register is later treated as an incompatible type.
    VerifierTypeTracking,
    // Numeric range reasoning is too coarse for dependent bounds, so safe accesses
    // fail range checks (packet size, stack window, map value window, context size).
    VerifierBoundsTracking,
    // Stack byte initialization tracking misses writes or invalidates facts too
    // aggressively, so reads are reported as non-numeric or uninitialized.
    VerifierStackInitialization,
    // Pointer arithmetic constraints are lost or over-approximated, causing safe
    // offset computations to be rejected.
    VerifierPointerArithmetic,
    // Map type or inner-map resolution is incomplete, so valid map operations
    // (e.g. map-in-map lookups) are rejected.
    VerifierMapTyping,
    // Nullability tracking is too conservative: a pointer that is guaranteed non-null
    // by program logic is still treated as potentially null.
    VerifierNullability,
    // Context struct modeling is incomplete or incorrect, causing valid context
    // field accesses to be rejected.
    VerifierContextModeling,
    // Recursive or re-entrant call patterns are not modeled, so the verifier
    // rejects programs that call themselves or cycle through tail calls.
    VerifierRecursionModeling,
    // Verification exceeds the iteration or time budget before reaching a fixed point.
    VerificationTimeout,
    // Legacy BCC-generated code uses patterns that our verifier does not recognize.
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
    case VerifyIssueKind::VerificationTimeout: return "VerificationTimeout";
    case VerifyIssueKind::LegacyBccBehavior: return "LegacyBccBehavior";
    }
    return "Unknown";
}

template <typename T>
void hash_combine(size_t& seed, const T& value) noexcept {
    seed ^= std::hash<T>{}(value) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
}

struct ElfObjectCacheKey {
    std::string path;
    const prevail::ebpf_platform_t* platform;
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

inline std::vector<prevail::RawProgram> read_elf_cached(const std::string& path, const std::string& desired_section,
                                                        const std::string& desired_program,
                                                        const prevail::ebpf_verifier_options_t& options,
                                                        const prevail::ebpf_platform_t* platform) {
    static std::mutex cache_mutex;
    static std::unordered_map<ElfObjectCacheKey, prevail::ElfObject, ElfObjectCacheKeyHash> object_cache;

    const ElfObjectCacheKey key{
        .path = path,
        .platform = platform,
        .verbosity_print_line_info = options.verbosity_opts.print_line_info,
        .verbosity_dump_btf_types_json = options.verbosity_opts.dump_btf_types_json,
    };
    prevail::ebpf_verifier_options_t loader_options{};
    loader_options.verbosity_opts.print_line_info = options.verbosity_opts.print_line_info;
    loader_options.verbosity_opts.dump_btf_types_json = options.verbosity_opts.dump_btf_types_json;

    std::lock_guard<std::mutex> lock(cache_mutex);
    auto [it, _] = object_cache.try_emplace(key, path, loader_options, platform);
    return it->second.get_programs(desired_section, desired_program);
}

// Compile-time test name truncation. Catch2's TEST_CASE accepts any const char*,
// so we can pass .data from a constexpr char array instead of a string literal.
// When the name exceeds MAX_LEN, we truncate and append a 4-digit hex hash of the
// full name to preserve uniqueness.
struct BoundedTestName {
    static constexpr size_t MAX_LEN = 75;
    char data[MAX_LEN + 1]{};

    template <size_t N>
    explicit constexpr BoundedTestName(const char (&str)[N]) {
        if constexpr (N - 1 <= MAX_LEN) {
            for (size_t i = 0; i < N; ++i) {
                data[i] = str[i];
            }
        } else {
            // FNV-1a hash of full name for a unique suffix.
            uint32_t hash = 2166136261u;
            for (size_t i = 0; i < N - 1; ++i) {
                hash ^= static_cast<unsigned char>(str[i]);
                hash *= 16777619u;
            }
            // Format: first (MAX_LEN - 6) chars + "..xxxx"
            constexpr size_t prefix_len = MAX_LEN - 6;
            for (size_t i = 0; i < prefix_len; ++i) {
                data[i] = str[i];
            }
            data[prefix_len] = '.';
            data[prefix_len + 1] = '.';
            constexpr char hex[] = "0123456789abcdef";
            data[prefix_len + 2] = hex[(hash >> 12) & 0xf];
            data[prefix_len + 3] = hex[(hash >> 8) & 0xf];
            data[prefix_len + 4] = hex[(hash >> 4) & 0xf];
            data[prefix_len + 5] = hex[hash & 0xf];
            data[MAX_LEN] = '\0';
        }
    }
};

} // namespace verify_test

// BOUNDED_TEST_CASE: like TEST_CASE, but truncates names exceeding MAX_LEN characters.
// Uses __LINE__ to generate a unique constexpr variable name; both expansions of
// PREVAIL_BOUNDED_NAME within one macro invocation share the same __LINE__.
#define PREVAIL_CONCAT_IMPL(a, b) a##b
#define PREVAIL_CONCAT(a, b) PREVAIL_CONCAT_IMPL(a, b)
#define PREVAIL_BOUNDED_NAME PREVAIL_CONCAT(_prevail_btn_, __LINE__)

#define BOUNDED_TEST_CASE(name_literal, tags)                                         \
    static constexpr verify_test::BoundedTestName PREVAIL_BOUNDED_NAME(name_literal); \
    TEST_CASE(PREVAIL_BOUNDED_NAME.data, tags)

// Verify a program in a section that may have multiple programs in it.
#define VERIFY_PROGRAM(dirname, filename, section_name, program_name, _options, platform, should_pass, count)        \
    do {                                                                                                             \
        prevail::thread_local_options = _options;                                                                    \
        const auto& raw_progs = verify_test::read_elf_cached("ebpf-samples/" dirname "/" filename, section_name, "", \
                                                             prevail::thread_local_options, platform);               \
        REQUIRE(raw_progs.size() == count);                                                                          \
        bool matched_program = false;                                                                                \
        for (const auto& raw_prog : raw_progs) {                                                                     \
            if (count == 1 || raw_prog.function_name == program_name) {                                              \
                matched_program = true;                                                                              \
                INFO("function_name=" << raw_prog.function_name);                                                    \
                if (should_pass) {                                                                                   \
                    const auto inst_seq = prevail::unmarshal(raw_prog, prevail::thread_local_options);               \
                    REQUIRE(inst_seq.has_value());                                                                   \
                    const prevail::Program prog =                                                                    \
                        prevail::Program::from_sequence(*inst_seq, raw_prog.info, prevail::thread_local_options);    \
                    REQUIRE(prevail::verify(prog) == true);                                                          \
                } else {                                                                                             \
                    bool rejected = false;                                                                           \
                    try {                                                                                            \
                        const auto inst_seq = prevail::unmarshal(raw_prog, prevail::thread_local_options);           \
                        if (!inst_seq.has_value()) {                                                                 \
                            rejected = true;                                                                         \
                        } else {                                                                                     \
                            const prevail::Program prog = prevail::Program::from_sequence(                           \
                                *inst_seq, raw_prog.info, prevail::thread_local_options);                            \
                            rejected = (prevail::verify(prog) == false);                                             \
                        }                                                                                            \
                    } catch (const std::runtime_error& ex) {                                                         \
                        INFO("rejected_by_exception=" << ex.what());                                                 \
                        rejected = true;                                                                             \
                    }                                                                                                \
                    REQUIRE(rejected);                                                                               \
                }                                                                                                    \
            }                                                                                                        \
        }                                                                                                            \
        REQUIRE(matched_program);                                                                                    \
    } while (0)

// Verify a section with only one program in it.
#define VERIFY_SECTION(dirname, filename, section_name, _options, platform, should_pass) \
    VERIFY_PROGRAM(dirname, filename, section_name, "", _options, platform, should_pass, 1)

#define TEST_SECTION(project, filename, section)                                               \
    BOUNDED_TEST_CASE(project "/" filename " " section, "[verify][samples][" project "]") {    \
        VERIFY_SECTION(project, filename, section, {}, &prevail::g_ebpf_platform_linux, true); \
    }

#define TEST_SECTION_SLOW(project, filename, section)                                             \
    BOUNDED_TEST_CASE(project "/" filename " " section, "[verify][samples][slow][" project "]") { \
        VERIFY_SECTION(project, filename, section, {}, &prevail::g_ebpf_platform_linux, true);    \
    }

#define TEST_PROGRAM(project, filename, section_name, program_name, count)                                       \
    BOUNDED_TEST_CASE(project "/" filename " " program_name, "[verify][samples][" project "]") {                 \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &prevail::g_ebpf_platform_linux, true, \
                       count);                                                                                   \
    }

#define TEST_PROGRAM_FAIL(project, filename, section_name, program_name, count, kind)                            \
    BOUNDED_TEST_CASE(project "/" filename " " program_name, "[!shouldfail][verify][samples][" project "]") {    \
        INFO("issue_kind=" << verify_test::to_string(kind));                                                     \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &prevail::g_ebpf_platform_linux, true, \
                       count);                                                                                   \
    }

#define TEST_PROGRAM_REJECT(project, filename, section_name, program_name, count)                                 \
    BOUNDED_TEST_CASE(project "/" filename " " program_name, "[verify][samples][" project "]") {                  \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &prevail::g_ebpf_platform_linux, false, \
                       count);                                                                                    \
    }

#define TEST_PROGRAM_REJECT_FAIL(project, filename, section_name, program_name, count)                            \
    BOUNDED_TEST_CASE(project "/" filename " " program_name, "[!shouldfail][verify][samples][" project "]") {     \
        VERIFY_PROGRAM(project, filename, section_name, program_name, {}, &prevail::g_ebpf_platform_linux, false, \
                       count);                                                                                    \
    }

#define TEST_SECTION_REJECT(project, filename, section)                                         \
    BOUNDED_TEST_CASE(project "/" filename " " section, "[verify][samples][" project "]") {     \
        VERIFY_SECTION(project, filename, section, {}, &prevail::g_ebpf_platform_linux, false); \
    }

#define TEST_SECTION_REJECT_IF_STRICT(project, filename, section)                                    \
    BOUNDED_TEST_CASE(project "/" filename " " section, "[verify][samples][" project "]") {          \
        prevail::ebpf_verifier_options_t options{};                                                  \
        VERIFY_SECTION(project, filename, section, options, &prevail::g_ebpf_platform_linux, true);  \
        options.strict = true;                                                                       \
        VERIFY_SECTION(project, filename, section, options, &prevail::g_ebpf_platform_linux, false); \
    }

#define TEST_SECTION_FAIL(project, filename, section, kind)                                    \
    BOUNDED_TEST_CASE("expect failure " project "/" filename " " section,                      \
                      "[!shouldfail][verify][samples][" project "]") {                         \
        INFO("issue_kind=" << verify_test::to_string(kind));                                   \
        VERIFY_SECTION(project, filename, section, {}, &prevail::g_ebpf_platform_linux, true); \
    }

#define TEST_SECTION_SKIP(project, filename, section, kind)                                 \
    BOUNDED_TEST_CASE(project "/" filename " " section, "[verify][samples][" project "]") { \
        SKIP(verify_test::to_string(kind));                                                 \
    }

#define TEST_PROGRAM_SKIP(project, filename, section_name, program_name, kind)                   \
    BOUNDED_TEST_CASE(project "/" filename " " program_name, "[verify][samples][" project "]") { \
        SKIP(verify_test::to_string(kind));                                                      \
    }

#define TEST_SECTION_REJECT_LOAD(project, filename, section)                                                         \
    BOUNDED_TEST_CASE("expect load rejection " project "/" filename " " section, "[verify][samples][" project "]") { \
        REQUIRE_THROWS_AS(([&]() {                                                                                   \
                              (void)verify_test::read_elf_cached("ebpf-samples/" project "/" filename, section, "",  \
                                                                 {}, &prevail::g_ebpf_platform_linux);               \
                          }()),                                                                                      \
                          std::runtime_error);                                                                       \
    }

#define TEST_SECTION_FAIL_SLOW(project, filename, section, kind)                               \
    BOUNDED_TEST_CASE("expect failure " project "/" filename " " section,                      \
                      "[!shouldfail][verify][samples][slow][" project "]") {                   \
        INFO("issue_kind=" << verify_test::to_string(kind));                                   \
        VERIFY_SECTION(project, filename, section, {}, &prevail::g_ebpf_platform_linux, true); \
    }

#define TEST_SECTION_REJECT_FAIL(project, filename, section)                                    \
    BOUNDED_TEST_CASE("expect failure " project "/" filename " " section,                       \
                      "[!shouldfail][verify][samples][" project "]") {                          \
        VERIFY_SECTION(project, filename, section, {}, &prevail::g_ebpf_platform_linux, false); \
    }

#define TEST_SECTION_LEGACY(dirname, filename, sectionname) TEST_SECTION(dirname, filename, sectionname)
#define TEST_SECTION_LEGACY_SLOW(dirname, filename, sectionname) TEST_SECTION_SLOW(dirname, filename, sectionname)
#define TEST_SECTION_LEGACY_FAIL(dirname, filename, sectionname, kind) \
    TEST_SECTION_FAIL(dirname, filename, sectionname, kind)

// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <catch2/catch_all.hpp>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "ebpf_verifier.hpp"
#include "io/elf_loader.hpp"

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

inline const char* to_string(const VerifyIssueKind kind) noexcept {
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

// Parse an ELF object once and reuse it across every program in the same file.
// Full-program verification tests iterate all programs in an object, so caching
// the parse keeps the corpus from re-reading the same .o hundreds of times.
inline std::vector<prevail::RawProgram> read_elf_cached(const std::string& path, const std::string& desired_section,
                                                        const std::string& desired_program,
                                                        const prevail::VerifierOptions& options,
                                                        const prevail::ebpf_platform_t* platform) {
    static std::mutex cache_mutex;
    static std::unordered_map<ElfObjectCacheKey, prevail::ElfObject, ElfObjectCacheKeyHash> object_cache;

    const ElfObjectCacheKey key{
        .path = path,
        .platform = platform,
        .verbosity_print_line_info = options.verbosity_opts.print_line_info,
        .verbosity_dump_btf_types_json = options.verbosity_opts.dump_btf_types_json,
    };
    prevail::VerifierOptions loader_options{};
    loader_options.verbosity_opts.print_line_info = options.verbosity_opts.print_line_info;
    loader_options.verbosity_opts.dump_btf_types_json = options.verbosity_opts.dump_btf_types_json;

    std::lock_guard<std::mutex> lock(cache_mutex);
    auto [it, _] = object_cache.try_emplace(key, path, loader_options, platform);
    return it->second.get_programs(desired_section, desired_program);
}

} // namespace verify_test

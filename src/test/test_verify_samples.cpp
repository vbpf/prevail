// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// Data-driven full-program verification tests.
//
// Every case is derived at runtime from test-data/elf_inventory.json, the single
// source of truth for the sample corpus. This replaces the per-project C++ files
// that scripts/generate_verify_project_tests.py used to emit: adding or retagging
// a sample is now a JSON edit, with no code generation and no recompile.
//
// Each (object, section[, program]) becomes one Catch2 DYNAMIC_SECTION. The
// inventory's test_overrides encode the expected outcome:
//   (default)          -> the program must verify (pass)
//   reject             -> the program must be rejected (unsafe; rejection is correct)
//   reject_load        -> the section must fail to load
//   expected_failure   -> a safe program the verifier is currently too imprecise to
//                         accept. Asserted as *still rejected*, an xfail/golden marker:
//                         if the verifier improves and accepts it, this case fails,
//                         prompting the inventory to be updated to a pass. The
//                         VerifyIssueKind and reason are surfaced via INFO.
//
// NOTE: Catch2's [!shouldfail] is a compile-time, per-TEST_CASE tag and cannot be
// applied per data-driven entry, so known imprecisions are encoded as assertions of
// the current (rejected) outcome rather than as [!shouldfail] cases. A regression on
// a passing program and a fix on an expected-failure program are both caught.

#include <catch2/catch_all.hpp>
#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "ebpf_verifier.hpp"
#include "test_verify.hpp"

using namespace prevail;
using verify_test::VerifyIssueKind;

namespace {

// One verification case derived from the inventory.
struct SampleEntry {
    std::string object;   // ELF file name within the project directory
    std::string section;  // ELF section name
    std::string function; // program (function) name; empty for a section-scoped single program
    int count{};          // number of programs expected in the section
    bool expected_pass{}; // true => the program must verify; false => it must be rejected
    bool reject_load{};   // true => the section must fail to load
    bool xfail{};         // expected_failure marker (a known imprecision)
    VerifyIssueKind kind{};
    std::string reason;
};

const YAML::Node& inventory() {
    // yaml-cpp parses JSON (JSON is a subset of YAML), so no extra dependency is needed.
    static const YAML::Node root = YAML::LoadFile("test-data/elf_inventory.json");
    return root;
}

VerifyIssueKind parse_kind(const std::string& name) {
    for (int i = 0; i <= static_cast<int>(VerifyIssueKind::LegacyBccBehavior); ++i) {
        const auto kind = static_cast<VerifyIssueKind>(i);
        if (name == verify_test::to_string(kind)) {
            return kind;
        }
    }
    throw std::runtime_error("unknown VerifyIssueKind '" + name + "'");
}

// Look up a test_overrides entry. Single-program sections carry overrides at section
// scope; multi-program sections carry them at program scope (mirroring how the
// inventory is written by scripts/update_verify_expectations.py).
YAML::Node override_node(const YAML::Node& obj, const std::string& section, const std::string& function,
                         const bool section_scope) {
    const YAML::Node overrides = obj["test_overrides"];
    if (!overrides || !overrides.IsMap()) {
        return {};
    }
    if (section_scope) {
        const YAML::Node sections = overrides["sections"];
        if (sections && sections.IsMap()) {
            return sections[section];
        }
    } else {
        const YAML::Node programs = overrides["programs"];
        if (programs && programs.IsMap()) {
            const YAML::Node section_programs = programs[section];
            if (section_programs && section_programs.IsMap()) {
                return section_programs[function];
            }
        }
    }
    return {};
}

std::string override_status(const YAML::Node& override) {
    if (override && override.IsMap() && override["status"]) {
        return override["status"].as<std::string>();
    }
    return "pass";
}

SampleEntry make_entry(const std::string& object, const std::string& section, const std::string& function,
                       const int count, const YAML::Node& override) {
    SampleEntry entry;
    entry.object = object;
    entry.section = section;
    entry.function = function;
    entry.count = count;

    const std::string status = override_status(override);
    if (status == "pass") {
        entry.expected_pass = true;
    } else if (status == "reject") {
        entry.expected_pass = false;
    } else if (status == "reject_load") {
        entry.expected_pass = false;
        entry.reject_load = true;
    } else if (status == "expected_failure") {
        entry.expected_pass = false;
        entry.xfail = true;
        entry.kind = parse_kind(override["kind"].as<std::string>());
        entry.reason = override["reason"] ? override["reason"].as<std::string>() : "";
    } else {
        throw std::runtime_error("unsupported status '" + status + "' for " + object + " " + section);
    }
    return entry;
}

std::vector<std::string> sorted_keys(const YAML::Node& map) {
    std::vector<std::string> keys;
    for (const auto& item : map) {
        keys.push_back(item.first.as<std::string>());
    }
    std::ranges::sort(keys);
    return keys;
}

std::vector<SampleEntry> build_entries(const std::string& project) {
    const YAML::Node projects = inventory()["projects"];
    const YAML::Node project_node = projects[project];
    if (!project_node || !project_node.IsMap()) {
        throw std::runtime_error("project '" + project + "' is not in the inventory");
    }
    const YAML::Node objects = project_node["objects"];

    std::vector<SampleEntry> entries;
    for (const std::string& object_name : sorted_keys(objects)) {
        const YAML::Node obj = objects[object_name];
        const YAML::Node sections = obj["sections"];
        for (const std::string& section : sorted_keys(sections)) {
            const YAML::Node programs = sections[section];
            const int count = static_cast<int>(programs.size());

            if (count == 1) {
                // Single-program section: overrides are read at section scope.
                entries.push_back(
                    make_entry(object_name, section, "", 1, override_node(obj, section, "", /*section_scope=*/true)));
                continue;
            }

            // Multi-program section: overrides are read at program scope. A section that
            // fails to load rejects every program in it, so a program-scope reject_load
            // collapses to one section-level load-rejection case.
            std::vector<std::string> functions;
            bool any_reject_load = false;
            for (const auto& program : programs) {
                const std::string function = program["function"].as<std::string>();
                functions.push_back(function);
                if (override_status(override_node(obj, section, function, /*section_scope=*/false)) == "reject_load") {
                    any_reject_load = true;
                }
            }
            if (any_reject_load) {
                SampleEntry entry;
                entry.object = object_name;
                entry.section = section;
                entry.count = count;
                entry.expected_pass = false;
                entry.reject_load = true;
                entries.push_back(entry);
                continue;
            }
            std::ranges::sort(functions);
            for (const std::string& function : functions) {
                entries.push_back(make_entry(object_name, section, function, count,
                                             override_node(obj, section, function, /*section_scope=*/false)));
            }
        }
    }
    return entries;
}

const std::vector<SampleEntry>& project_entries(const std::string& project) {
    static std::map<std::string, std::vector<SampleEntry>> cache;
    auto it = cache.find(project);
    if (it == cache.end()) {
        it = cache.emplace(project, build_entries(project)).first;
    }
    return it->second;
}

void run_entry(const std::string& project, const SampleEntry& entry) {
    const std::string path = "ebpf-samples/" + project + "/" + entry.object;
    const VerifierOptions options{};
    const auto* platform = &g_ebpf_platform_linux;

    if (entry.reject_load) {
        REQUIRE_THROWS_AS(verify_test::read_elf_cached(path, entry.section, "", options, platform), std::runtime_error);
        return;
    }

    auto raw_progs = verify_test::read_elf_cached(path, entry.section, "", options, platform);
    REQUIRE(static_cast<int>(raw_progs.size()) == entry.count);

    bool matched = false;
    for (auto& raw_prog : raw_progs) {
        if (entry.count != 1 && raw_prog.function_name != entry.function) {
            continue;
        }
        matched = true;
        INFO("function_name=" << raw_prog.function_name);
        if (entry.xfail) {
            INFO("issue_kind=" << verify_test::to_string(entry.kind));
            INFO("reason=" << entry.reason);
        }

        if (entry.expected_pass) {
            const auto prog_or_error = unmarshal(raw_prog, options);
            const auto* inst_seq = std::get_if<InstructionSeq>(&prog_or_error);
            REQUIRE(inst_seq);
            const Program prog = Program::from_sequence(*inst_seq, raw_prog.info, options);
            REQUIRE(verify(prog, options) == true);
        } else {
            bool rejected = false;
            try {
                const auto prog_or_error = unmarshal(raw_prog, options);
                const auto* inst_seq = std::get_if<InstructionSeq>(&prog_or_error);
                if (!inst_seq) {
                    rejected = true;
                } else {
                    const Program prog = Program::from_sequence(*inst_seq, raw_prog.info, options);
                    rejected = (verify(prog, options) == false);
                }
            } catch (const std::runtime_error& ex) {
                INFO("rejected_by_exception=" << ex.what());
                rejected = true;
            }
            REQUIRE(rejected);
        }
    }
    REQUIRE(matched);
}

// Projects registered below via VERIFY_PROJECT; checked against the inventory by the
// coverage guard so the two cannot drift apart.
std::set<std::string>& registered_projects() {
    static std::set<std::string> projects;
    return projects;
}

void run_project_samples(const std::string& project) {
    // Nest by object file (outer section) so ctest can shard a project by object via
    // `-c "<object>"`, letting a big project's objects verify in parallel. Entries are
    // grouped by object (project_entries is sorted by object, then section).
    const std::vector<SampleEntry>& entries = project_entries(project);
    for (size_t start = 0; start < entries.size();) {
        const std::string& object = entries[start].object;
        size_t end = start;
        while (end < entries.size() && entries[end].object == object) {
            ++end;
        }
        DYNAMIC_SECTION(object) {
            for (size_t k = start; k < end; ++k) {
                const SampleEntry& entry = entries[k];
                const std::string name = entry.section + (entry.function.empty() ? "" : " " + entry.function);
                DYNAMIC_SECTION(name) { run_entry(project, entry); }
            }
        }
        start = end;
    }
}

} // namespace

#define PREVAIL_CONCAT_IMPL(a, b) a##b
#define PREVAIL_CONCAT(a, b) PREVAIL_CONCAT_IMPL(a, b)

// One TEST_CASE per project, tagged so `ctest`/CI can shard the corpus by project.
// Registration is data-driven inside the case; only the project name is static
// (Catch2 test cases must be registered at load time).
#define VERIFY_PROJECT(project)                                                                                     \
    static const bool PREVAIL_CONCAT(prevail_registered_, __LINE__) = registered_projects().insert(project).second; \
    TEST_CASE("verify samples: " project, "[verify][samples][" project "]") { run_project_samples(project); }

VERIFY_PROJECT("bcc")
VERIFY_PROJECT("bpf_cilium_test")
VERIFY_PROJECT("build")
VERIFY_PROJECT("cilium")
VERIFY_PROJECT("cilium-core")
VERIFY_PROJECT("cilium-ebpf")
VERIFY_PROJECT("cilium-examples")
VERIFY_PROJECT("falco")
VERIFY_PROJECT("invalid")
VERIFY_PROJECT("katran")
VERIFY_PROJECT("libbpf-bootstrap")
VERIFY_PROJECT("linux")
VERIFY_PROJECT("linux-selftests")
VERIFY_PROJECT("new_linux")
VERIFY_PROJECT("ovs")
VERIFY_PROJECT("prototype-kernel")
VERIFY_PROJECT("suricata")

// Guard: every project in the inventory must have a registered TEST_CASE above (and
// vice versa), so a new project in the inventory cannot be silently left untested.
// Tagged outside [samples] so it runs in the default (non-shard) test bucket.
TEST_CASE("verify samples: inventory coverage", "[verify][meta]") {
    std::set<std::string> inventory_projects;
    for (const auto& project : inventory()["projects"]) {
        inventory_projects.insert(project.first.as<std::string>());
    }
    REQUIRE(registered_projects() == inventory_projects);
}

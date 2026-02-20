// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <catch2/catch_all.hpp>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "ebpf_verifier.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"

using namespace prevail;

enum class Expect { Pass, Reject, Xfail, XfailReject, Skip };

struct ProgramEntry {
    const char* section;
    const char* function = "";
    int count = 1;
    Expect expect = Expect::Pass;
    bool slow = false;
    bool legacy = false;
    bool strict_reject = false;
    const char* skip_reason = nullptr; // required when expect == Skip
};

struct FileEntry {
    const char* filename;
    std::vector<ProgramEntry> programs;
};

inline void verify_entry(const std::string& path, const ProgramEntry& entry, const std::vector<RawProgram>& all_progs) {
    if (entry.expect == Expect::Skip) {
        REQUIRE(entry.skip_reason != nullptr);
        SUCCEED(std::string("Skipped: ") + entry.skip_reason);
        return;
    }

    // Filter programs matching this section.
    std::vector<const RawProgram*> section_progs;
    for (const auto& rp : all_progs) {
        if (rp.section_name == entry.section) {
            section_progs.push_back(&rp);
        }
    }

    if (section_progs.empty()) {
        std::string avail;
        for (const auto& rp : all_progs) {
            if (!avail.empty()) {
                avail += ", ";
            }
            avail += rp.section_name;
        }
        FAIL("Section '" << entry.section << "' not found in ELF (available: " << avail << ")");
        return;
    }

    REQUIRE(static_cast<int>(section_progs.size()) == entry.count);

    const RawProgram* target = section_progs[0];
    if (entry.function[0] != '\0') {
        target = nullptr;
        for (const auto* rp : section_progs) {
            if (rp->function_name == entry.function) {
                target = rp;
                break;
            }
        }
        if (target == nullptr) {
            std::string avail;
            for (const auto* rp : section_progs) {
                if (!avail.empty()) {
                    avail += ", ";
                }
                avail += rp->function_name;
            }
            FAIL("Function '" << entry.function << "' not found in section '" << entry.section
                              << "' (available: " << avail << ")");
            return;
        }
    }

    auto do_verify = [&entry](const RawProgram& raw_prog) -> bool {
        thread_local_options = {};
        const auto prog_or_error = unmarshal(raw_prog, thread_local_options);
        const auto* inst_seq = std::get_if<InstructionSeq>(&prog_or_error);
        if (!inst_seq) {
            if (entry.expect == Expect::Xfail) {
                return false;
            }
            REQUIRE(inst_seq);
        }
        const Program prog = Program::from_sequence(*inst_seq, raw_prog.info, thread_local_options);
        return verify(prog);
    };

    if (entry.strict_reject) {
        REQUIRE(do_verify(*target));
        thread_local_options = {};
        thread_local_options.strict = true;
        const auto prog_or_error = unmarshal(*target, thread_local_options);
        const auto* inst_seq = std::get_if<InstructionSeq>(&prog_or_error);
        REQUIRE(inst_seq);
        const Program prog = Program::from_sequence(*inst_seq, target->info, thread_local_options);
        REQUIRE_FALSE(verify(prog));
        return;
    }

    if (entry.legacy) {
        bool result = do_verify(*target);
        if (entry.expect == Expect::Xfail) {
            if (result) {
                FAIL("Xfail now passes - update to Expect::Pass");
            } else {
                SUCCEED("Known failure");
            }
        } else {
            REQUIRE(result);
        }
        ebpf_platform_t platform = g_ebpf_platform_linux;
        platform.supported_conformance_groups &= ~bpf_conformance_groups_t::packet;
        auto raw_progs = read_elf(path, entry.section, "", {}, &platform);
        REQUIRE(raw_progs.size() == 1);
        RawProgram raw_prog = raw_progs.back();
        auto prog_or_error = unmarshal(raw_prog, {});
        REQUIRE(std::holds_alternative<InstructionSeq>(prog_or_error));
        REQUIRE_THROWS_WITH(Program::from_sequence(std::get<InstructionSeq>(prog_or_error), raw_prog.info, {}),
                            Catch::Matchers::ContainsSubstring("rejected: requires conformance group packet"));
        return;
    }

    bool result = do_verify(*target);
    switch (entry.expect) {
    case Expect::Pass: REQUIRE(result); break;
    case Expect::Reject: REQUIRE_FALSE(result); break;
    case Expect::Xfail:
        if (result) {
            FAIL("Xfail now passes - update to Expect::Pass");
        } else {
            SUCCEED("Known failure");
        }
        break;
    case Expect::XfailReject:
        if (!result) {
            FAIL("XfailReject now rejects - update to Expect::Reject");
        } else {
            SUCCEED("Known failure");
        }
        break;
    case Expect::Skip: break; // handled above
    }
}

inline void verify_file(const std::string& path, const FileEntry& file, const std::vector<RawProgram>& all_progs) {
    std::map<std::pair<std::string, std::string>, int> seen;
    for (size_t i = 0; i < file.programs.size(); i++) {
        const auto& e = file.programs[i];
        auto key = std::make_pair(std::string(e.section), std::string(e.function));
        auto [it, inserted] = seen.emplace(key, static_cast<int>(i));
        if (!inserted) {
            FAIL("Duplicate entry for section '" << e.section << "' function '" << e.function << "' at indices "
                                                 << it->second << " and " << i);
            return;
        }
    }

    for (const auto& entry : file.programs) {
        std::string label = std::string(file.filename) + " " + entry.section;
        if (entry.function[0] != '\0') {
            label += " " + std::string(entry.function);
        }
        if (entry.slow) {
            label += " [slow]";
        }
        DYNAMIC_SECTION(label) { verify_entry(path, entry, all_progs); }
    }
}

inline void check_coverage(const FileEntry& file, const std::vector<RawProgram>& all_progs) {
    std::set<std::pair<std::string, std::string>> mentioned;
    for (const auto& e : file.programs) {
        if (e.function[0] != '\0') {
            mentioned.emplace(e.section, e.function);
        } else {
            for (const auto& rp : all_progs) {
                if (rp.section_name == e.section) {
                    mentioned.emplace(rp.section_name, rp.function_name);
                }
            }
        }
    }
    std::string unmentioned;
    for (const auto& rp : all_progs) {
        auto key = std::make_pair(rp.section_name, rp.function_name);
        if (mentioned.find(key) == mentioned.end()) {
            if (!unmentioned.empty()) {
                unmentioned += ", ";
            }
            unmentioned += "'" + rp.section_name + "'/'" + rp.function_name + "'";
        }
    }
    if (!unmentioned.empty()) {
        FAIL("Unmentioned in " << file.filename << ": " << unmentioned);
    }
}

inline bool all_entries_skip(const FileEntry& file) {
    for (const auto& e : file.programs) {
        if (e.expect != Expect::Skip) {
            return false;
        }
    }
    return true;
}

inline void verify_file(const char* project, const FileEntry& file) {
    const std::string path = std::string("ebpf-samples/") + project + "/" + file.filename;
    try {
        const auto all_progs = read_elf(path, "", "", {}, &g_ebpf_platform_linux);
        verify_file(path, file, all_progs);
        DYNAMIC_SECTION(std::string(file.filename) + " [coverage]") { check_coverage(file, all_progs); }
    } catch (const std::runtime_error& e) {
        bool has_pass_entries = false;
        for (const auto& entry : file.programs) {
            std::string label = std::string(file.filename) + " " + entry.section;
            if (entry.function[0] != '\0') {
                label += " " + std::string(entry.function);
            }
            if (entry.expect == Expect::Skip) {
                DYNAMIC_SECTION(label) { SUCCEED(std::string("Skipped (load failed): ") + entry.skip_reason); }
            } else if (entry.expect == Expect::Xfail) {
                DYNAMIC_SECTION(label) { SUCCEED(std::string("Known failure (load failed): ") + e.what()); }
            } else {
                has_pass_entries = true;
            }
        }
        if (has_pass_entries) {
            FAIL("Failed to load " << path << ": " << e.what());
        }
    }
}

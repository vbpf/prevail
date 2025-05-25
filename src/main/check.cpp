// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <iostream>
#include <vector>

#include <boost/functional/hash.hpp>

#include "ebpf_verifier.hpp"
#ifdef _WIN32
#include "memsize_windows.hpp"
#else
#include "memsize_linux.hpp"
#endif
#include "linux_verifier.hpp"

// Avoid affecting other headers by macros.
#include "CLI11/CLI11.hpp"

using std::string;
using std::vector;

using namespace prevail;

static size_t hash(const RawProgram& raw_prog) {
    const char* start = reinterpret_cast<const char*>(raw_prog.prog.data());
    const char* end = start + raw_prog.prog.size() * sizeof(EbpfInst);
    return boost::hash_range(start, end);
}

template <void(on_exit)()>
struct AtScopeExit {
    AtScopeExit() = default;
    ~AtScopeExit() { on_exit(); }
};

static const std::map<std::string, bpf_conformance_groups_t> _conformance_groups = {
    {"atomic32", bpf_conformance_groups_t::atomic32}, {"atomic64", bpf_conformance_groups_t::atomic64},
    {"base32", bpf_conformance_groups_t::base32},     {"base64", bpf_conformance_groups_t::base64},
    {"callx", bpf_conformance_groups_t::callx},       {"divmul32", bpf_conformance_groups_t::divmul32},
    {"divmul64", bpf_conformance_groups_t::divmul64}, {"packet", bpf_conformance_groups_t::packet}};

static std::optional<bpf_conformance_groups_t> _get_conformance_group_by_name(const std::string& group) {
    if (!_conformance_groups.contains(group)) {
        return {};
    }
    return _conformance_groups.find(group)->second;
}

static std::set<std::string> _get_conformance_group_names() {
    std::set<std::string> result;
    for (const auto& name : _conformance_groups | std::views::keys) {
        result.insert(name);
    }
    return result;
}

static std::optional<RawProgram> find_program(vector<RawProgram>& raw_progs, const std::string& desired_program) {
    if (desired_program.empty() && raw_progs.size() == 1) {
        // Select the last program section.
        return raw_progs.back();
    }
    for (RawProgram current_program : raw_progs) {
        if (current_program.function_name == desired_program) {
            return current_program;
        }
    }
    return {};
}

int main(int argc, char** argv) {
    // Always call ebpf_verifier_clear_thread_local_state on scope exit.
    AtScopeExit<ebpf_verifier_clear_thread_local_state> clear_thread_local_state;

    ebpf_verifier_options_t ebpf_verifier_options;

    CrabEnableWarningMsg(false);

    // Parse command line arguments:

    CLI::App app{"PREVAIL is a new eBPF verifier based on abstract interpretation."};
    app.option_defaults()->delimiter(',');

    std::string filename;
    app.add_option("path", filename, "Elf file to analyze")->required()->check(CLI::ExistingFile);

    std::string desired_section;
    app.add_option("--section,section", desired_section, "Section to analyze")->type_name("SECTION");

    std::string desired_program;
    app.add_option("--function,function", desired_program, "Function to analyze")->type_name("FUNCTION");

    bool list = false;
    app.add_flag("-l", list, "List programs");

    std::string domain = "zoneCrab";
    app.add_option("--domain", domain, "Abstract domain")
        ->type_name("DOMAIN")
        ->capture_default_str()
        ->check(CLI::IsMember({"stats", "linux", "zoneCrab", "cfg"}));

    app.add_flag("--termination,!--no-verify-termination", ebpf_verifier_options.cfg_opts.check_for_termination,
                 "Verify termination. Default: ignore")
        ->group("Features");

    app.add_flag("--allow-division-by-zero,!--no-division-by-zero", ebpf_verifier_options.allow_division_by_zero,
                 "Handling potential division by zero. Default: allow")
        ->group("Features");

    app.add_flag("--strict,-s", ebpf_verifier_options.strict,
                 "Apply additional checks that would cause runtime failures")
        ->group("Features");

    std::set<std::string> include_groups = _get_conformance_group_names();
    app.add_option("--include_groups", include_groups, "Include conformance groups")
        ->group("Features")
        ->type_name("GROUPS")
        ->expected(0, _conformance_groups.size())
        ->check(CLI::IsMember(_get_conformance_group_names()));

    std::set<std::string> exclude_groups;
    app.add_option("--exclude_groups", exclude_groups, "Exclude conformance groups")
        ->group("Features")
        ->type_name("GROUPS")
        ->option_text("")
        ->expected(0, _conformance_groups.size())
        ->check(CLI::IsMember(_get_conformance_group_names()));

    app.add_flag("--simplify,!--no-simplify", ebpf_verifier_options.verbosity_opts.simplify,
                 "Simplify the CFG before analysis by merging chains of instructions into a single basic block. "
                 "Default: enabled")
        ->group("Verbosity");
    app.add_flag("--line-info", ebpf_verifier_options.verbosity_opts.print_line_info, "Print line information")
        ->group("Verbosity");
    app.add_flag("--print-btf-types", ebpf_verifier_options.verbosity_opts.dump_btf_types_json, "Print BTF types")
        ->group("Verbosity");

    app.add_flag("--assume-assert,!--no-assume-assert", ebpf_verifier_options.assume_assertions,
                 "Assume assertions (useful for debugging verification failures). Default: disabled")
        ->group("Verbosity");

    app.add_flag("-i", ebpf_verifier_options.verbosity_opts.print_invariants, "Print invariants")->group("Verbosity");
    app.add_flag("-f", ebpf_verifier_options.verbosity_opts.print_failures, "Print verifier's failure logs")
        ->group("Verbosity");
    bool verbose = false;
    app.add_flag("-v", verbose, "Print both invariants and failures")->group("Verbosity");

    std::string asmfile;
    app.add_option("--asm", asmfile, "Print disassembly to FILE")->group("CFG output")->type_name("FILE");
    std::string dotfile;
    app.add_option("--dot", dotfile, "Export control-flow graph to dot FILE")->group("CFG output")->type_name("FILE");

    CLI11_PARSE(app, argc, argv);

    if (verbose) {
        ebpf_verifier_options.verbosity_opts.print_invariants = ebpf_verifier_options.verbosity_opts.print_failures =
            true;
    }

    // Enable default conformance groups, which don't include callx or packet.
    ebpf_platform_t platform = g_ebpf_platform_linux;
    platform.supported_conformance_groups = bpf_conformance_groups_t::default_groups;
    for (const auto& group_name : include_groups) {
        platform.supported_conformance_groups |= _get_conformance_group_by_name(group_name).value();
    }
    for (const auto& group_name : exclude_groups) {
        platform.supported_conformance_groups &= _get_conformance_group_by_name(group_name).value();
    }

    // Main program

    if (filename == "@headers") {
        if (domain == "stats") {
            std::cout << "hash";
            std::cout << ",instructions";
            for (const string& h : stats_headers()) {
                std::cout << "," << h;
            }
        } else {
            std::cout << domain << "?,";
            std::cout << domain << "_sec,";
            std::cout << domain << "_kb";
        }
        std::cout << "\n";
        return 0;
    }

#if !__linux__
    if (domain == "linux") {
        std::cerr << "error: linux domain is unsupported on this machine\n";
        return 64;
    }
#endif

    if (domain == "linux") {
        ebpf_verifier_options.mock_map_fds = false;
    }

    // Read a set of raw program sections from an ELF file.
    vector<RawProgram> raw_progs;
    try {
        raw_progs = read_elf(filename, desired_section, ebpf_verifier_options, &platform);
    } catch (std::runtime_error& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }

    std::optional<RawProgram> found_prog = find_program(raw_progs, desired_program);
    if (list || !found_prog) {
        if (!list) {
            std::cout << "please specify a program\n";
            std::cout << "available programs:\n";
        }
        if (!desired_section.empty() && raw_progs.empty()) {
            // We could not find the desired program, so get the full list
            // of possibilities.
            raw_progs = read_elf(filename, string(), ebpf_verifier_options, &platform);
        }
        for (const RawProgram& raw_prog : raw_progs) {
            std::cout << "section=" << raw_prog.section_name << " function=" << raw_prog.function_name << std::endl;
        }
        std::cout << "\n";
        return list ? 0 : 64;
    }
    RawProgram raw_prog = *found_prog;

    // Convert the raw program section to a set of instructions.
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (auto prog = std::get_if<string>(&prog_or_error)) {
        std::cout << "unmarshaling error at " << *prog << "\n";
        return 1;
    }

    auto& inst_seq = std::get<InstructionSeq>(prog_or_error);
    if (!asmfile.empty()) {
        std::ofstream out{asmfile};
        print(inst_seq, out, {});
        print_map_descriptors(thread_local_program_info->map_descriptors, out);
    }

    if (domain == "zoneCrab" || domain == "cfg") {
        // Convert the instruction sequence to a control-flow graph.
        try {
            const auto verbosity = ebpf_verifier_options.verbosity_opts;
            const Program prog = Program::from_sequence(inst_seq, raw_prog.info, ebpf_verifier_options);
            if (domain == "cfg") {
                print_program(prog, std::cout, verbosity.simplify);
                return 0;
            }
            const auto begin = std::chrono::steady_clock::now();
            auto invariants = analyze(prog);
            const auto end = std::chrono::steady_clock::now();
            const auto seconds = std::chrono::duration<double>(end - begin).count();
            if (verbosity.print_invariants) {
                print_invariants(std::cout, prog, verbosity.simplify, invariants);
            }

            bool pass;
            if (verbosity.print_failures) {
                auto report = invariants.check_assertions(prog);
                print_warnings(std::cout, report);
                pass = report.verified();
            } else {
                pass = invariants.verified(prog);
            }
            if (pass && ebpf_verifier_options.cfg_opts.check_for_termination &&
                (verbosity.print_failures || verbosity.print_invariants)) {
                std::cout << "Program terminates within " << invariants.max_loop_count() << " loop iterations\n";
            }
            std::cout << pass << "," << seconds << "," << resident_set_size_kb() << "\n";
            return pass ? 0 : 1;
        } catch (UnmarshalError& e) {
            std::cerr << "error: " << e.what() << std::endl;
            return 1;
        }
    } else if (domain == "linux") {
        // Pass the instruction sequence to the Linux kernel verifier.
        const auto [res, seconds] = bpf_verify_program(raw_prog.info.type, raw_prog.prog, &ebpf_verifier_options);
        std::cout << res << "," << seconds << "," << resident_set_size_kb() << "\n";
        return !res;
    } else if (domain == "stats") {
        // Convert the instruction sequence to a control-flow graph.
        const Program prog = Program::from_sequence(inst_seq, raw_prog.info, ebpf_verifier_options);

        // Just print eBPF program stats.
        auto stats = collect_stats(prog);
        if (!dotfile.empty()) {
            print_dot(prog, dotfile);
        }
        std::cout << std::hex << hash(raw_prog) << std::dec << "," << inst_seq.size();
        for (const string& h : stats_headers()) {
            std::cout << "," << stats.at(h);
        }
        std::cout << "\n";
    } else {
        assert(false);
    }

    return 0;
}

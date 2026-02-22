// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <iostream>
#include <ranges>
#include <vector>

#include "ebpf_verifier.hpp"
#include "io/elf_loader.hpp"

// Avoid affecting other headers by macros.
#include <CLI11/CLI11.hpp>

using std::string;
using std::vector;

using namespace prevail;

static const std::map<std::string, bpf_conformance_groups_t> conformance_groups = {
    {"atomic32", bpf_conformance_groups_t::atomic32}, {"atomic64", bpf_conformance_groups_t::atomic64},
    {"base32", bpf_conformance_groups_t::base32},     {"base64", bpf_conformance_groups_t::base64},
    {"callx", bpf_conformance_groups_t::callx},       {"divmul32", bpf_conformance_groups_t::divmul32},
    {"divmul64", bpf_conformance_groups_t::divmul64}, {"packet", bpf_conformance_groups_t::packet}};

static std::optional<bpf_conformance_groups_t> et_conformance_group_by_name(const std::string& group) {
    if (!conformance_groups.contains(group)) {
        return {};
    }
    return conformance_groups.find(group)->second;
}

static std::set<std::string> get_conformance_group_names() {
    std::set<std::string> result;
    for (const auto& name : conformance_groups | std::views::keys) {
        result.insert(name);
    }
    return result;
}

/// Format the program label as "section/function" or just "section" if they match.
static std::string program_label(const RawProgram& raw_prog) {
    if (raw_prog.function_name.empty() || raw_prog.function_name == raw_prog.section_name) {
        return raw_prog.section_name;
    }
    return raw_prog.section_name + "/" + raw_prog.function_name;
}

int main(int argc, char** argv) {
    // Always call ebpf_verifier_clear_thread_local_state on scope exit.
    ThreadLocalGuard thread_local_state_guard;

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

    bool quiet = false;
    app.add_flag("-q,--quiet", quiet, "No stdout output, exit code only");

    bool print_cfg = false;
    app.add_flag("--cfg", print_cfg, "Print control-flow graph and exit");

    app.add_flag("--termination,!--no-verify-termination", ebpf_verifier_options.cfg_opts.check_for_termination,
                 "Verify termination. Default: ignore")
        ->group("Features");

    app.add_flag("--allow-division-by-zero,!--no-division-by-zero", ebpf_verifier_options.allow_division_by_zero,
                 "Handling potential division by zero. Default: allow")
        ->group("Features");

    app.add_flag("--strict,-s", ebpf_verifier_options.strict,
                 "Apply additional checks that would cause runtime failures")
        ->group("Features");

    std::set<std::string> include_groups = get_conformance_group_names();
    app.add_option("--include_groups", include_groups, "Include conformance groups")
        ->group("Features")
        ->type_name("GROUPS")
        ->expected(0, gsl::narrow<int>(conformance_groups.size()))
        ->check(CLI::IsMember(get_conformance_group_names()));

    std::set<std::string> exclude_groups;
    app.add_option("--exclude_groups", exclude_groups, "Exclude conformance groups")
        ->group("Features")
        ->type_name("GROUPS")
        ->option_text("")
        ->expected(0, gsl::narrow<int>(conformance_groups.size()))
        ->check(CLI::IsMember(get_conformance_group_names()));

    auto* simplify_opt = app.add_flag("--simplify,!--no-simplify", ebpf_verifier_options.verbosity_opts.simplify,
                                      "Simplify the display of the CFG by merging chains of instructions into a "
                                      "single basic block. Default: enabled (disabled with --failure-slice)")
                             ->group("Verbosity");
    app.add_flag("--line-info", ebpf_verifier_options.verbosity_opts.print_line_info, "Print line information")
        ->group("Verbosity");
    app.add_flag("--print-btf-types", ebpf_verifier_options.verbosity_opts.dump_btf_types_json, "Print BTF types")
        ->group("Verbosity");

    app.add_flag("-v", ebpf_verifier_options.verbosity_opts.print_invariants, "Print invariants and first failure")
        ->group("Verbosity");
    app.add_flag("-f", ebpf_verifier_options.verbosity_opts.print_failures, "Print first failure")->group("Verbosity");

    bool failure_slice = false;
    app.add_flag("--failure-slice", failure_slice,
                 "Print minimal failure slices showing only instructions that contributed to errors")
        ->group("Verbosity");

    size_t failure_slice_depth = 200;
    app.add_option("--failure-slice-depth", failure_slice_depth,
                   "Maximum backward steps for failure slicing (default: 200)")
        ->group("Verbosity");

    std::string asmfile;
    app.add_option("--asm", asmfile, "Print disassembly to FILE")->group("CFG output")->type_name("FILE");
    std::string dotfile;
    app.add_option("--dot", dotfile, "Export control-flow graph to dot FILE")->group("CFG output")->type_name("FILE");

    CLI11_PARSE(app, argc, argv);

    // Enable default conformance groups, which don't include callx or packet.
    ebpf_platform_t platform = g_ebpf_platform_linux;
    platform.supported_conformance_groups = bpf_conformance_groups_t::default_groups;
    for (const auto& group_name : include_groups) {
        platform.supported_conformance_groups |= et_conformance_group_by_name(group_name).value();
    }
    for (const auto& group_name : exclude_groups) {
        platform.supported_conformance_groups &= et_conformance_group_by_name(group_name).value();
    }

    // Main program

    ElfObject elf{filename, ebpf_verifier_options, &platform};
    vector<RawProgram> raw_progs;
    std::optional<std::string> load_error;
    if (!list) {
        try {
            raw_progs = elf.get_programs(desired_section, desired_program);
        } catch (const std::runtime_error& e) {
            load_error = e.what();
        }
    }

    if (list || load_error.has_value() || raw_progs.size() != 1) {
        if (load_error.has_value()) {
            std::cerr << "error: " << *load_error << std::endl;
        }
        if (!list && !load_error.has_value() && raw_progs.size() != 1) {
            std::cout << "please specify a program\n";
        }
        if (!list) {
            std::cout << "available programs:\n";
        }
        try {
            for (const ElfProgramInfo& prog : elf.list_programs()) {
                std::cout << "section=" << prog.section_name << " function=" << prog.function_name;
                if (prog.invalid) {
                    std::cout << " [invalid: " << prog.invalid_reason << "]";
                }
                std::cout << std::endl;
            }
        } catch (const std::runtime_error& e) {
            std::cerr << "error listing programs: " << e.what() << std::endl;
            return 1;
        }
        std::cout << "\n";
        if (list) {
            return 0;
        }
        return load_error.has_value() ? 1 : 64;
    }
    const RawProgram& raw_prog = raw_progs.back();

    // Convert the raw program section to a set of instructions.
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog, ebpf_verifier_options);
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

    // Convert the instruction sequence to a control-flow graph.
    try {
        // Enable dependency collection if failure slice is requested.
        // Also disable simplification by default so each instruction is shown individually,
        // unless the user explicitly specified --simplify.
        if (failure_slice) {
            ebpf_verifier_options.verbosity_opts.collect_instruction_deps = true;
            if (simplify_opt->count() == 0) {
                ebpf_verifier_options.verbosity_opts.simplify = false;
            }
        }
        const auto verbosity = ebpf_verifier_options.verbosity_opts;
        const Program prog = Program::from_sequence(inst_seq, raw_prog.info, ebpf_verifier_options);

        if (!dotfile.empty()) {
            print_dot(prog, dotfile);
        }

        if (print_cfg) {
            print_program(prog, std::cout, verbosity.simplify);
            return 0;
        }

        auto result = analyze(prog);
        if (!quiet) {
            if (verbosity.print_invariants) {
                print_invariants(std::cout, prog, verbosity.simplify, result);
            }
            if (verbosity.print_failures) {
                if (auto verification_error = result.find_first_error()) {
                    print_error(std::cout, *verification_error);
                }
            }
            if (failure_slice && result.failed) {
                // Compute only the first failure slice by default for concise output
                AnalysisResult::SliceParams slice_params;
                slice_params.max_steps = failure_slice_depth;
                slice_params.max_slices = 1;
                auto slices = result.compute_failure_slices(prog, slice_params);
                print_failure_slices(std::cout, prog, verbosity.simplify, result, slices);
            } else if (failure_slice && !result.failed) {
                std::cout << "Program passed verification; no failure slices to display.\n";
            }
        }

        const bool pass = !result.failed;
        const auto label = program_label(raw_prog);

        if (!quiet) {
            if (pass) {
                std::cout << "PASS: " << label;
                if (ebpf_verifier_options.cfg_opts.check_for_termination) {
                    std::cout << " (terminates within " << result.max_loop_count << " loop iterations)";
                }
                std::cout << "\n";
            } else {
                std::cout << "FAIL: " << label << "\n";
                // Print the first error if not already printed by -v or -f.
                if (!verbosity.print_invariants && !verbosity.print_failures && !failure_slice) {
                    if (auto verification_error = result.find_first_error()) {
                        print_error(std::cout, *verification_error);
                    }
                    std::cout << "Hint: run with --failure-slice for a causal trace, or -v for full invariants.\n";
                }
            }
        }
        return pass ? 0 : 1;
    } catch (const UnmarshalError& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
}

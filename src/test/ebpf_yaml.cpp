// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <bit>
#include <fstream>
#include <iostream>
#include <set>
#include <variant>

#include <yaml-cpp/yaml.h>

#include "crab_verifier.hpp"
#include "ebpf_verifier.hpp"
#include "ebpf_yaml.hpp"
#include "ir/parse.hpp"
#include "ir/syntax.hpp"
#include "string_constraints.hpp"

using std::string;
using std::vector;

namespace prevail {
// The YAML tests for Call depend on Linux prototypes.
// parse_instruction() in asm_parse.cpp explicitly uses
// g_ebpf_platform_linux when parsing Call instructions
// so we do the same here.

static EbpfProgramType ebpf_get_program_type(const string& section, const string& path) {
    return g_ebpf_platform_linux.get_program_type(section, path);
}

static EbpfMapType ebpf_get_map_type(const uint32_t platform_specific_type) {
    return g_ebpf_platform_linux.get_map_type(platform_specific_type);
}

static EbpfHelperPrototype ebpf_get_helper_prototype(const int32_t n) {
    return g_ebpf_platform_linux.get_helper_prototype(n);
}

static bool ebpf_is_helper_usable(const int32_t n) { return g_ebpf_platform_linux.is_helper_usable(n); }

static void ebpf_parse_maps_section(vector<EbpfMapDescriptor>&, const char*, size_t, int, const ebpf_platform_t*,
                                    ebpf_verifier_options_t) {}

static EbpfMapDescriptor test_map_descriptor = {.original_fd = 0,
                                                .type = 0,
                                                .key_size = sizeof(uint32_t),
                                                .value_size = sizeof(uint32_t),
                                                .max_entries = 4,
                                                .inner_map_fd = 0};

static EbpfMapDescriptor& ebpf_get_map_descriptor(int) { return test_map_descriptor; }

ebpf_platform_t g_platform_test = {.get_program_type = ebpf_get_program_type,
                                   .get_helper_prototype = ebpf_get_helper_prototype,
                                   .is_helper_usable = ebpf_is_helper_usable,
                                   .map_record_size = 0,
                                   .parse_maps_section = ebpf_parse_maps_section,
                                   .get_map_descriptor = ebpf_get_map_descriptor,
                                   .get_map_type = ebpf_get_map_type,
                                   .supported_conformance_groups = bpf_conformance_groups_t::default_groups |
                                                                   bpf_conformance_groups_t::packet |
                                                                   bpf_conformance_groups_t::callx};

static EbpfProgramType make_program_type(const string& name, const ebpf_context_descriptor_t* context_descriptor) {
    return EbpfProgramType{.name = name,
                           .context_descriptor = context_descriptor,
                           .platform_specific_data = 0,
                           .section_prefixes = {},
                           .is_privileged = false};
}

static std::set<string> vector_to_set(const vector<string>& s) {
    std::set<string> res;
    for (const auto& item : s) {
        res.insert(item);
    }
    return res;
}

std::set<string> operator-(const std::set<string>& a, const std::set<string>& b) {
    std::set<string> res;
    std::ranges::set_difference(a, b, std::inserter(res, res.begin()));
    return res;
}

static StringInvariant read_invariant(const vector<string>& raw_invariant) {
    const std::set<string> res = vector_to_set(raw_invariant);
    if (res == std::set<string>{"_|_"}) {
        return StringInvariant{};
    }
    return StringInvariant{res};
}

struct RawTestCase {
    string test_case;
    std::set<string> options;
    vector<string> pre;
    vector<std::tuple<string, vector<string>>> raw_blocks;
    vector<string> post;
    std::set<string> messages;
};

static vector<string> parse_block(const YAML::Node& block_node) {
    vector<string> block;
    std::istringstream is{block_node.as<string>()};
    string line;
    while (std::getline(is, line)) {
        block.emplace_back(line);
    }
    return block;
}

static auto parse_code(const YAML::Node& code_node) {
    vector<std::tuple<string, vector<string>>> res;
    for (const auto& item : code_node) {
        res.emplace_back(item.first.as<string>(), parse_block(item.second));
    }
    return res;
}

static std::set<string> as_set_empty_default(const YAML::Node& optional_node) {
    if (!optional_node.IsDefined() || optional_node.IsNull()) {
        return {};
    }
    return vector_to_set(optional_node.as<vector<string>>());
}

static RawTestCase parse_case(const YAML::Node& case_node) {
    return RawTestCase{
        .test_case = case_node["test-case"].as<string>(),
        .options = as_set_empty_default(case_node["options"]),
        .pre = case_node["pre"].as<vector<string>>(),
        .raw_blocks = parse_code(case_node["code"]),
        .post = case_node["post"].as<vector<string>>(),
        .messages = as_set_empty_default(case_node["messages"]),
    };
}

static InstructionSeq raw_cfg_to_instruction_seq(const vector<std::tuple<string, vector<string>>>& raw_blocks) {
    std::map<string, Label> label_name_to_label;

    int label_index = 0;
    for (const auto& [label_name, raw_block] : raw_blocks) {
        label_name_to_label.emplace(label_name, label_index);
        // don't count large instructions as 2
        label_index += gsl::narrow<int>(raw_block.size());
    }

    InstructionSeq res;
    label_index = 0;
    for (const auto& [label_name, raw_block] : raw_blocks) {
        for (const string& line : raw_block) {
            try {
                const Instruction& ins = parse_instruction(line, label_name_to_label);
                if (std::holds_alternative<Undefined>(ins)) {
                    std::cout << "text:" << line << "; ins: " << ins << "\n";
                }
                res.emplace_back(label_index, ins, std::optional<btf_line_info_t>());
            } catch (const std::exception& e) {
                std::cout << "text:" << line << "; error: " << e.what() << "\n";
                res.emplace_back(label_index, Undefined{0}, std::optional<btf_line_info_t>());
            }
            label_index++;
        }
    }
    return res;
}

static ebpf_verifier_options_t raw_options_to_options(const std::set<string>& raw_options) {
    ebpf_verifier_options_t options{};

    // Use ~simplify for YAML tests unless otherwise specified.
    options.verbosity_opts.simplify = false;

    // All YAML tests use !setup_constraints.
    options.setup_constraints = false;

    // Default to the machine's native endianness.
    options.big_endian = std::endian::native == std::endian::big;

    // Permit test cases to not have an exit instruction.
    options.cfg_opts.must_have_exit = false;

    for (const string& name : raw_options) {
        if (name == "!allow_division_by_zero") {
            options.allow_division_by_zero = false;
        } else if (name == "termination") {
            options.cfg_opts.check_for_termination = true;
        } else if (name == "strict") {
            options.strict = true;
        } else if (name == "simplify") {
            options.verbosity_opts.simplify = true;
        } else if (name == "big_endian") {
            options.big_endian = true;
        } else if (name == "!big_endian") {
            options.big_endian = false;
        } else {
            throw std::runtime_error("Unknown option: " + name);
        }
    }
    return options;
}

static TestCase read_case(const RawTestCase& raw_case) {
    return TestCase{.name = raw_case.test_case,
                    .options = raw_options_to_options(raw_case.options),
                    .assumed_pre_invariant = read_invariant(raw_case.pre),
                    .instruction_seq = raw_cfg_to_instruction_seq(raw_case.raw_blocks),
                    .expected_post_invariant = read_invariant(raw_case.post),
                    .expected_messages = raw_case.messages};
}

static vector<TestCase> read_suite(const string& path) {
    std::ifstream f{path};
    vector<TestCase> res;
    for (const YAML::Node& config : YAML::LoadAll(f)) {
        res.push_back(read_case(parse_case(config)));
    }
    return res;
}

template <typename T>
static Diff<T> make_diff(const T& actual, const T& expected) {
    return Diff<T>{
        .unexpected = actual - expected,
        .unseen = expected - actual,
    };
}

std::optional<Failure> run_yaml_test_case(TestCase test_case, bool debug) {
    thread_local_options = {};
    ThreadLocalGuard clear_thread_local_state;
    test_case.options.verbosity_opts.print_failures = true;
    if (debug) {
        test_case.options.verbosity_opts.print_invariants = true;
    }

    ebpf_context_descriptor_t context_descriptor{64, 0, 4, -1};
    EbpfProgramType program_type = make_program_type(test_case.name, &context_descriptor);

    ProgramInfo info{&g_platform_test, {}, program_type};
    thread_local_options = test_case.options;
    try {
        const Program prog = Program::from_sequence(test_case.instruction_seq, info, test_case.options);
        const Invariants invariants = analyze(prog, test_case.assumed_pre_invariant);
        const StringInvariant actual_last_invariant = invariants.invariant_at(Label::exit);
        const std::set<string> actual_messages = invariants.check_assertions(prog).all_messages();

        if (actual_last_invariant == test_case.expected_post_invariant &&
            actual_messages == test_case.expected_messages) {
            return {};
        }
        return Failure{
            .invariant = make_diff(actual_last_invariant, test_case.expected_post_invariant),
            .messages = make_diff(actual_messages, test_case.expected_messages),
        };
    } catch (InvalidControlFlow& ex) {
        const std::set<string> actual_messages{ex.what()};
        if (test_case.expected_post_invariant == StringInvariant::top() &&
            actual_messages == test_case.expected_messages) {
            return {};
        }
        return Failure{
            .invariant = make_diff(StringInvariant::top(), test_case.expected_post_invariant),
            .messages = make_diff(actual_messages, test_case.expected_messages),
        };
    }
}

template <typename T>
    requires std::is_trivially_copyable_v<T>
static vector<T> vector_of(const std::vector<std::byte>& bytes) {
    auto data = bytes.data();
    const auto size = bytes.size();
    if (size % sizeof(T) != 0 || size > std::numeric_limits<uint32_t>::max() || !data) {
        throw std::runtime_error("Invalid argument to vector_of");
    }
    return {reinterpret_cast<const T*>(data), reinterpret_cast<const T*>(data + size)};
}

template <std::signed_integral TS>
void add_stack_variable(std::set<std::string>& more, int& offset, const std::vector<std::byte>& memory_bytes) {
    using TU = std::make_unsigned_t<TS>;
    constexpr size_t size = sizeof(TS);
    static_assert(sizeof(TU) == size);
    const auto src = memory_bytes.data() + offset + memory_bytes.size() - EBPF_TOTAL_STACK_SIZE;
    TS svalue;
    std::memcpy(&svalue, src, size);
    TU uvalue;
    std::memcpy(&uvalue, src, size);
    const auto range = "s[" + std::to_string(offset) + "..." + std::to_string(offset + size - 1) + "]";
    more.insert(range + ".svalue=" + std::to_string(svalue));
    more.insert(range + ".uvalue=" + std::to_string(uvalue));
    offset += size;
}

StringInvariant stack_contents_invariant(const std::vector<std::byte>& memory_bytes) {
    std::set<std::string> more = {"r1.type=stack",
                                  "r1.stack_offset=" + std::to_string(EBPF_TOTAL_STACK_SIZE - memory_bytes.size()),
                                  "r1.stack_numeric_size=" + std::to_string(memory_bytes.size()),
                                  "r10.type=stack",
                                  "r10.stack_offset=" + std::to_string(EBPF_TOTAL_STACK_SIZE),
                                  "s[" + std::to_string(EBPF_TOTAL_STACK_SIZE - memory_bytes.size()) + "..." +
                                      std::to_string(EBPF_TOTAL_STACK_SIZE - 1) + "].type=number"};

    int offset = EBPF_TOTAL_STACK_SIZE - gsl::narrow<int>(memory_bytes.size());
    if (offset % 2 != 0) {
        add_stack_variable<int8_t>(more, offset, memory_bytes);
    }
    if (offset % 4 != 0) {
        add_stack_variable<int16_t>(more, offset, memory_bytes);
    }
    if (offset % 8 != 0) {
        add_stack_variable<int32_t>(more, offset, memory_bytes);
    }
    while (offset < EBPF_TOTAL_STACK_SIZE) {
        add_stack_variable<int64_t>(more, offset, memory_bytes);
    }

    return StringInvariant(more);
}

ConformanceTestResult run_conformance_test_case(const std::vector<std::byte>& memory_bytes,
                                                const std::vector<std::byte>& program_bytes, bool debug) {
    ebpf_context_descriptor_t context_descriptor{64, -1, -1, -1};
    EbpfProgramType program_type = make_program_type("conformance_check", &context_descriptor);

    ProgramInfo info{&g_platform_test, {}, program_type};

    auto insts = vector_of<EbpfInst>(program_bytes);
    StringInvariant pre_invariant = StringInvariant::top();

    if (!memory_bytes.empty()) {
        if (memory_bytes.size() > EBPF_TOTAL_STACK_SIZE) {
            std::cerr << "memory size overflow\n";
            return {};
        }
        pre_invariant = pre_invariant + stack_contents_invariant(memory_bytes);
    }
    RawProgram raw_prog{.prog = insts};
    ebpf_platform_t platform = g_ebpf_platform_linux;
    platform.supported_conformance_groups |= bpf_conformance_groups_t::callx;
    raw_prog.info.platform = &platform;

    // Convert the raw program section to a set of instructions.
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (auto prog = std::get_if<std::string>(&prog_or_error)) {
        std::cerr << "unmarshaling error at " << *prog << "\n";
        return {};
    }

    const InstructionSeq& inst_seq = std::get<InstructionSeq>(prog_or_error);

    ebpf_verifier_options_t options{};
    if (debug) {
        print(inst_seq, std::cout, {});
        options.verbosity_opts.print_failures = true;
        options.verbosity_opts.print_invariants = true;
        options.verbosity_opts.simplify = false;
    }

    try {
        const Program prog = Program::from_sequence(inst_seq, info, options);
        const Invariants invariants = analyze(prog, pre_invariant);
        return ConformanceTestResult{.success = invariants.verified(prog), .r0_value = invariants.exit_value()};
    } catch (const std::exception&) {
        // Catch exceptions thrown in ebpf_domain.cpp.
        return {};
    }
}

void print_failure(const Failure& failure, std::ostream& os) {
    constexpr auto INDENT = "  ";
    if (!failure.invariant.unexpected.empty()) {
        os << "Unexpected properties:\n" << INDENT << failure.invariant.unexpected << "\n";
    } else {
        os << "Unexpected properties: None\n";
    }
    if (!failure.invariant.unseen.empty()) {
        os << "Unseen properties:\n" << INDENT << failure.invariant.unseen << "\n";
    } else {
        os << "Unseen properties: None\n";
    }

    if (!failure.messages.unexpected.empty()) {
        os << "Unexpected messages:\n";
        for (const auto& item : failure.messages.unexpected) {
            os << INDENT << item << "\n";
        }
    } else {
        os << "Unexpected messages: None\n";
    }

    if (!failure.messages.unseen.empty()) {
        os << "Unseen messages:\n";
        for (const auto& item : failure.messages.unseen) {
            os << INDENT << item << "\n";
        }
    } else {
        os << "Unseen messages: None\n";
    }
}

bool all_suites(const string& path) {
    bool result = true;
    for (const TestCase& test_case : read_suite(path)) {
        result = result && static_cast<bool>(run_yaml_test_case(test_case));
    }
    return result;
}

void foreach_suite(const string& path, const std::function<void(const TestCase&)>& f) {
    for (const TestCase& test_case : read_suite(path)) {
        f(test_case);
    }
}
} // namespace prevail

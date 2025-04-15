// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#if __linux__

#include <cstring>
#include <iostream>
#include <linux/bpf.h>
#include <tuple>
#include <unistd.h>

#include "config.hpp"
#include "linux_verifier.hpp"
#include "spec_type_descriptors.hpp"

namespace prevail {
static int do_bpf(const bpf_cmd cmd, union bpf_attr& attr) { return syscall(321, cmd, &attr, sizeof(attr)); }

/** Run the built-in Linux verifier on a raw eBPF program.
 *
 *  \return A pair (passed, elapsed_secs)
 */

std::tuple<bool, double> bpf_verify_program(const EbpfProgramType& type, const std::vector<ebpf_inst>& raw_prog,
                                            ebpf_verifier_options_t* options) {
    std::vector<char> buf(options->verbosity_opts.print_failures ? 1000000 : 10);
    buf[0] = 0;
    std::memset(buf.data(), '\0', buf.size());

    union bpf_attr attr{};
    std::memset(&attr, '\0', sizeof(attr));
    attr.prog_type = gsl::narrow<__u32>(type.platform_specific_data);
    attr.insn_cnt = gsl::narrow<__u32>(raw_prog.size());
    attr.insns = reinterpret_cast<__u64>(raw_prog.data());
    attr.license = reinterpret_cast<__u64>("GPL");
    if (options->verbosity_opts.print_failures) {
        attr.log_buf = reinterpret_cast<__u64>(buf.data());
        attr.log_size = buf.size();
        attr.log_level = 3;
    }
    attr.kern_version = 0x041800;
    attr.prog_flags = 0;

    const auto begin = std::chrono::steady_clock::now();
    const int res = do_bpf(BPF_PROG_LOAD, attr);
    const auto end = std::chrono::steady_clock::now();
    const auto seconds = std::chrono::duration<double>(end - begin).count();

    if (res < 0) {
        if (options->verbosity_opts.print_failures) {
            std::cerr << "Failed to verify program: " << strerror(errno) << " (" << errno << ")\n";
            std::cerr << "LOG: " << reinterpret_cast<char*>(attr.log_buf);
        }
        return {false, seconds};
    }
    return {true, seconds};
}
} // namespace prevail
#endif

#include <iostream>
#include <fstream>
#include <vector>

#include <boost/lexical_cast.hpp>

#include <crab/common/debug.hpp>

#include "crab_verifier.hpp"
#include "asm.hpp"

using std::string;
using std::vector;

static int usage(const char *name)
{
    std::cerr << "usage: " << name << " [FLAGS] BINARY [TYPE] [DOMAIN]\n";
    std::cerr << "\n";
    std::cerr << "verifies the eBPF code in BINARY using DOMAIN assuming program type TYPE\n";
    std::cerr << "\n";
    std::cerr << "DOMAIN is defaulted to sdbm-arr\n";
    std::cerr << "TYPE may be extracted from BINARY suffix\n";
    std::cerr << "\n";
    std::cerr << "flags: "
                 "--log=CRABLOG --verbose=N "
                 "--stats --simplify --no-liveness --semantic-reachability\n";
    std::cerr << "available domains:\n";
    for (auto const [name, desc] : domain_descriptions())
        std::cerr << "\t" << name << " - " << desc << "\n";
    return 64;
}


int run(string domain_name, raw_program raw_prog, program_info info)
{
    auto prog = unmarshal(raw_prog);
    return std::visit(overloaded {
        [domain_name, info](auto prog) {
            print(prog);
            Cfg nondet_cfg = Cfg::make(prog).to_nondet(true);
            bool res = abs_validate(nondet_cfg, domain_name, info);
            print_stats(nondet_cfg);
            if (!res) {
                std::cout << "verification failed\n";
                return 1;
            }
            return 0;
        },
        [](string errmsg) { 
            std::cout << "trivial verification failure: " << errmsg << "\n";
            return 1;
        }
    }, prog);
}

int main(int argc, char **argv)
{
    vector<string> args{argv+1, argv + argc};
    vector<string> posargs;
    program_info info;
    bool is_raw = true;
    string path;
    string domain = "sdbm-arr";
    for (string arg : args) {
        if (arg.find("type=") == 0) {
            // type1 or type4
            info.program_type = std::stoi(arg.substr(5));
        } else if (arg.find("map") == 0) {
            // map64 map4096 [...]
            info.map_sizes.push_back(std::stoi(arg.substr(3)));
        } else if (arg.find("domain=") == 0) {
            domain = arg.substr(7);
        } else if (arg.find("elf=") == 0) {
            is_raw = false;
            path = arg.substr(4);
        } else if (arg.find("raw=") == 0) {
            is_raw = true;
            path = arg.substr(4);
            if (info.program_type == 0) {
                info.program_type = boost::lexical_cast<int>(path.substr(path.find_last_of('.') + 1));
            }
        } else if (arg.find("--log=") == 0) {
            crab::CrabEnableLog(arg.substr(6));
        } else if (arg == "--disable-warnings") {
            crab::CrabEnableWarningMsg(false);
        } else if (arg == "-q") {
            crab::CrabEnableWarningMsg(false);
            global_options.print_invariants = false;
        } else if (arg == "--sanity") {
            crab::CrabEnableSanityChecks(true);
        } else if (arg.find("--verbose=") == 0) {
            if (arg[0] == '"') arg=arg.substr(1, arg.size()-1);
            crab::CrabEnableVerbosity(std::stoi(arg.substr(10)));
        } else if (arg == "--help" || arg == "-h") {
            return usage(argv[0]);
        } else if (arg == "--stats" || arg == "--stat") {
            global_options.stats = true;
        } else if (arg == "--simplify") {
            global_options.simplify = true;
        } else if (arg == "--semantic-reachability") {
            global_options.check_semantic_reachability = true;
        } else if (arg == "--no-print-invariants") {
            global_options.print_invariants = false;
        } else if (arg == "--no-liveness") {
            global_options.liveness = false;
        } else {
            posargs.push_back(arg);
        }
    }
    if (posargs.size() >= 1 || path.empty())
        return usage(argv[0]);

    if (domain_descriptions().count(domain) == 0) {
        std::cerr << "argument " << domain << " is not a valid domain\n";
        return usage(argv[0]);
    }
    auto progs = is_raw ? read_raw(path, info) : read_elf(path);
    int res = 0;
    for (auto raw_prog : progs) {
        res += run(domain, raw_prog, info);
    }
    return res;
}

[![Coverage Status](https://coveralls.io/repos/github/vbpf/prevail/badge.svg?branch=main)](https://coveralls.io/github/vbpf/prevail?branch=main)[![CodeQL](https://github.com/vbpf/prevail/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/vbpf/prevail/actions/workflows/codeql-analysis.yml)

# PREVAIL - A new eBPF verifier
## a Polynomial-Runtime EBPF Verifier using an Abstract Interpretation Layer



The version discussed in the [PLDI paper](https://vbpf.github.io/assets/prevail-paper.pdf) is available [here](https://github.com/vbpf/prevail/tree/d29fd26345c3126bf166cf1c45233a9b2f9fb0a0).

DeepWiki: A comprehensive auto-generated documentation is avaliable at https://deepwiki.com/vbpf/prevail

## Getting Started

Clone:
```
git clone --recurse-submodules https://github.com/vbpf/prevail.git
cd prevail
```

### Building

<details open><summary>🐧 Linux</summary>

#### Dependencies (Ubuntu)
```bash
sudo apt install build-essential git cmake libboost-dev libyaml-cpp-dev
sudo apt install libboost-filesystem-dev libboost-program-options-dev
```

#### Make
```
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

</details>

<details><summary>🪟 Windows</summary>
  
#### Dependencies
* Install [git](https://git-scm.com/download/win)
* Install [Visual Studio Build Tools 2022](https://aka.ms/vs/17/release/vs_buildtools.exe) and:
  * Choose the "C++ build tools" workload (Visual Studio Build Tools 2022 has support for CMake Version 3.25)
  * Under Individual Components, select:
    * "C++ Clang Compiler"
    * "MSBuild support for LLVM"
* Install [nuget.exe](https://www.nuget.org/downloads)

#### Make on Windows (which uses a multi-configuration generator)
```
cmake -B build
cmake --build build --config Release
```

</details>


<details><summary>🍏 macOS</summary>

#### Dependencies:
```bash
brew install llvm cmake boost yaml-cpp
```
The system llvm currently comes with Clang 15, which isn't enough to compile prevail, as it depends on C++20. Brew's llvm comes with Clang 17.

#### Make:
```
export CPATH=$(brew --prefix)/include LIBRARY_PATH=$(brew --prefix)/lib CMAKE_PREFIX_PATH=$(brew --prefix)
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang -DCMAKE_CXX_COMPILER=$(brew --prefix llvm)/bin/clang++
cmake --build build
```
</details>

<details><summary>🐋 Docker</summary>
  
#### Build and run
```bash
docker build -t verifier .
docker run -it verifier ebpf-samples/cilium/bpf_lxc.o 2/1
1,0.009812,4132
# To run the Linux verifier you'll need a privileged container:
docker run --privileged -it verifier ebpf-samples/linux/cpustat_kern.o --domain=linux
```
</details>

### Example:
```
$ bin/check ebpf-samples/cilium/bpf_lxc.o 2/1
1,0.008288,4064
```
The output is three comma-separated values:
* 1 or 0, for "pass" and "fail" respectively
* The runtime of the fixpoint algorithm (in seconds)
* The peak memory consumption, in kb, as reflected by the resident-set size (rss)

<details><summary>Usage</summary>

```
PREVAIL is a new eBPF verifier based on abstract interpretation.
Usage: D:\workspace\prevail\bin\check.exe [OPTIONS] path [section] [function]

Positionals:
  path TEXT:FILE REQUIRED     Elf file to analyze
  section SECTION             Section to analyze
  function FUNCTION           Function to analyze

Options:
  -h,--help                   Print this help message and exit
  --section SECTION           Section to analyze
  --function FUNCTION         Function to analyze
  -l                          List programs
  --domain DOMAIN:{stats,linux,zoneCrab,cfg} [zoneCrab]
                              Abstract domain


Features:
  --termination,--no-verify-termination{false}
                              Verify termination. Default: ignore
  --allow-division-by-zero,--no-division-by-zero{false}
                              Handling potential division by zero. Default: allow
  -s,--strict                 Apply additional checks that would cause runtime failures
  --include_groups GROUPS:{atomic32,atomic64,base32,base64,callx,divmul32,divmul64,packet}
                              Include conformance groups
  --exclude_groups GROUPS:{atomic32,atomic64,base32,base64,callx,divmul32,divmul64,packet}
                              Exclude conformance groups


Verbosity:
  --simplify,--no-simplify{false}
                              Simplify the CFG before analysis by merging chains of instructions into a single basic block. Default: enabled
  --line-info                 Print line information
  --print-btf-types           Print BTF types
  --assume-assert,--no-assume-assert{false}
                              Assume assertions (useful for debugging verification failures). Default: disabled
  -i                          Print invariants
  -f                          Print verifier's failure logs
  -v                          Print both invariants and failures


CFG output:
  --asm FILE                  Print disassembly to FILE
  --dot FILE                  Export control-flow graph to dot FILE
```

A standard alternative to the --asm flag is `llvm-objdump -S FILE`.

The cfg can be viewed using `dot` and the standard PDF viewer:
```
sudo apt install graphviz
bin/check ebpf-samples/cilium/bpf_lxc.o 2/1 --dot cfg.dot --domain=stats
dot -Tpdf cfg.dot > cfg.pdf
```

</details>

## Testing the Linux verifier

To run the Linux verifier, you must use `sudo`:
```
sudo bin/check ebpf-samples/linux/cpustat_kern.o tracepoint/power/cpu_idle --domain=linux
```

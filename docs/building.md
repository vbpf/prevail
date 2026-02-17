# Building Prevail

This document covers building the Prevail eBPF verifier on all supported platforms.

## Prerequisites

### All Platforms

- CMake 3.14 or later
- C++20-compatible compiler
- Git (with submodule support)

### Linux

```bash
# Ubuntu/Debian
sudo apt-get install cmake g++ libboost-dev libyaml-cpp-dev

# Fedora
sudo dnf install cmake gcc-c++ boost-devel yaml-cpp-devel
```

### macOS

```bash
# Using Homebrew
brew install cmake boost yaml-cpp
```

### Windows

- Visual Studio 2022 (Build Tools or full IDE)
- Visual Studio must include:
  - "Desktop development with C++" workload
  - Windows SDK

## Getting the Source

```bash
git clone --recurse-submodules https://github.com/vbpf/ebpf-verifier.git
cd ebpf-verifier
```

If you already cloned without submodules:

```bash
git submodule update --init --recursive
```

## Building

### Quick Build (All Platforms)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Linux/macOS

```bash
# Configure
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build (parallel)
cmake --build build -j$(nproc)

# Binaries are in bin/
./bin/check --help
```

### Windows (Command Line)

```powershell
# Configure
cmake -S . -B build

# Build
cmake --build build --config Release

# Binaries are in bin/
.\bin\check.exe --help
```

### Windows (Visual Studio)

```powershell
# Generate Visual Studio solution
cmake -S . -B build -G "Visual Studio 17 2022"

# Open in Visual Studio
start build\ebpf-verifier.sln

# Or build from command line
cmake --build build --config Release
```

## Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `CMAKE_BUILD_TYPE` | Debug | Build type: Debug, Release, RelWithDebInfo |
| `BUILD_TESTING` | ON | Build test suite |
| `ENABLE_COVERAGE` | OFF | Enable code coverage instrumentation |

### Example with Options

```bash
cmake -B build \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_TESTING=ON \
    -DENABLE_COVERAGE=OFF
```

## Build Outputs

After building, you'll find these executables in `bin/`:

| Executable | Description |
|------------|-------------|
| `check` | Main verifier CLI tool |
| `tests` | Catch2 test runner |
| `run_yaml` | YAML test case runner |

## Running Tests

### All Tests

```bash
./bin/tests
```

### Specific Test Tags

```bash
# Only YAML-based tests
./bin/tests "[yaml]"

# Only conformance tests
./bin/tests "[conformance]"

# Only unit tests
./bin/tests "~[yaml]" "~[conformance]"
```

### Via CTest

```bash
cd build
ctest --output-on-failure
```

## Docker Build

For a reproducible build environment:

```bash
# Build the Docker image
docker build -t prevail .

# Run the verifier
docker run --rm prevail ./check --help

# Run tests
docker run --rm prevail ./tests

# Verify a program (mount your files)
docker run --rm -v $(pwd)/samples:/samples prevail ./check /samples/prog.o 2/1
```

## Development Build

For development with debug symbols and sanitizers:

```bash
# Debug build
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# With AddressSanitizer (Linux/macOS)
cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer"

cmake --build build
```

## IDE Support

### Visual Studio Code

Recommended extensions:
- C/C++ (Microsoft)
- CMake Tools

`.vscode/settings.json`:

```json
{
    "cmake.buildDirectory": "${workspaceFolder}/build",
    "cmake.configureArgs": ["-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
}
```

### CLion

Open the project directory; CLion will detect CMakeLists.txt automatically.

### Visual Studio

Use the generated `.sln` file from CMake.

## Troubleshooting

### Missing Boost

```text
Could not find Boost
```

**Linux**: `sudo apt-get install libboost-dev`
**macOS**: `brew install boost`
**Windows**: Boost is fetched via NuGet automatically

### yaml-cpp Not Found

```text
Could not find yaml-cpp
```

On Windows, yaml-cpp is built automatically via `ExternalProject_Add`.

On Linux/macOS:
```bash
sudo apt-get install libyaml-cpp-dev  # Ubuntu
brew install yaml-cpp                  # macOS
```

### Submodule Issues

```text
external/bpf_conformance is empty
```

```bash
git submodule update --init --recursive
```

### Compiler Too Old

```text
error: 'span' is not a member of 'std'
```

You need a C++20 compatible compiler:
- GCC 10+
- Clang 10+
- MSVC 19.29+ (VS 2019 16.10+)

## Cross-Compilation

### For ARM64 on x86_64 Linux

```bash
cmake -B build \
    -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
    -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++
```

## Performance Tips

### Release Build

Always use Release or RelWithDebInfo for performance:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
```

### Link-Time Optimization

```bash
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON
```

### Parallel Build

```bash
cmake --build build -j$(nproc)   # Linux/macOS
cmake --build build -j %NUMBER_OF_PROCESSORS%  # Windows
```

# Using Installed Prevail Package

This example demonstrates how to use prevail as an installed CMake package in your own project.

## Prerequisites

Install prevail first:

```bash
# From prevail root directory
cmake -B build -DCMAKE_BUILD_TYPE=Release -Dprevail_ENABLE_TESTS=OFF
cmake --build build --config Release
cmake --install build --prefix /usr/local  # or your preferred location
```

On Windows:

```cmd
cmake -B build -DCMAKE_BUILD_TYPE=Release -Dprevail_ENABLE_TESTS=OFF
cmake --build build --config Release
cmake --install build --prefix C:\Program Files\prevail
```

## Building This Example

```bash
cd examples/using_installed_package
cmake -B build -DCMAKE_PREFIX_PATH=/usr/local  # match install prefix
cmake --build build
./build/install_test
```

On Windows:

```cmd
cd examples\using_installed_package
cmake -B build -DCMAKE_PREFIX_PATH="C:\Program Files\prevail"
cmake --build build --config Release
build\Release\install_test.exe
```

## Key Points

### CMakeLists.txt

```cmake
find_package(prevail 0.1.0 REQUIRED)

add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE prevail::prevail)
```

### Using in Your Code

**Simple approach** - Include the convenience header:

```cpp
#include <prevail.hpp>

// Use core prevail API
auto platform = prevail::create_ebpf_platform(...);
```

**Advanced usage** - Include specific headers as needed:

```cpp
#include <prevail.hpp>
#include <prevail/arith/linear_constraint.hpp>
#include <prevail/crab/split_dbm.hpp>

// Use advanced features
prevail::LinearConstraint constraint(...);
```

## What This Tests

- ✅ `find_package(prevail)` works
- ✅ Headers are accessible
- ✅ Library links correctly
- ✅ Dependencies (GSL, Boost) are found automatically

## Automated Testing

Run the installation test from the project root:

**Linux/macOS:**

```bash
./scripts/test_install.sh
```

**Windows:**

```powershell
.\scripts\test_install.ps1
```

These scripts build prevail, install it to a temporary location, build this example, and verify it runs correctly.

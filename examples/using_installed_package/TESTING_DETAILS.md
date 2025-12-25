# Testing Prevail Installation

## Testing Strategy

This test suite validates that prevail can be installed and consumed as a CMake package without breaking changes to the
installation mechanism (not API stability).

### What We Test

1. **Installation Mechanics**
    - `cmake --install` completes without errors
    - Files are placed in correct locations
    - Proper permissions are set

2. **CMake Package Discovery**
    - `find_package(prevail 0.1.0 REQUIRED)` succeeds
    - Version checking works correctly
    - Package config files are valid

3. **Header Accessibility**
    - All public headers are installed
    - Include paths are correctly configured
    - Headers can be compiled

4. **Dependency Resolution**
    - Transitive dependencies are found (GSL, Boost)
    - `prevailConfig.cmake.in` correctly declares dependencies
    - Linked libraries are accessible

5. **Basic Functionality**
    - Library links successfully
    - Simple API calls work
    - No missing symbols at link time

### What We Don't Test

- API stability (expected to be fragile)
- Full functional verification (covered by main test suite)
- Performance
- Edge cases in the verifier logic

## Running Tests

### Quick Test (Local)

**Linux/macOS:**

```bash
./scripts/test_install.sh
```

**Windows:**

```powershell
.\scripts\test_install.ps1
```

### Manual Step-by-Step

See [README.md](README.md) for detailed manual testing steps.

### CI Integration

From the project root, copy `.github/workflows/test-installation.yml.example` to `test-installation.yml` to enable
automated testing on:

- Ubuntu (Linux)
- macOS
- Windows

## Failure Diagnosis

### Test Fails at: "cmake --install"

**Problem:** Installation itself broken

**Check:**

- CMakeLists.txt install() commands are valid
- Install destinations are defined (CMAKE_INSTALL_BINDIR, etc.)
- Targets being installed actually exist

### Test Fails at: "find_package(prevail)"

**Problem:** Package config not found or invalid

**Check:**

- `prevailConfig.cmake.in` exists and is valid
- `write_basic_package_version_file()` completed
- `configure_package_config_file()` completed
- Install location is in CMAKE_PREFIX_PATH

### Test Fails at: Compilation (missing headers)

**Problem:** Headers not installed or paths wrong

**Check:**

- `install(DIRECTORY ...)` for headers executed
- `target_include_directories()` has INSTALL_INTERFACE
- Installed include paths match what's in prevailConfig.cmake

### Test Fails at: Compilation (missing dependencies)

**Problem:** Transitive dependency not found

**Check:**

- `prevailConfig.cmake.in` has `find_dependency()` for all PUBLIC dependencies
- GSL: `find_dependency(Microsoft.GSL REQUIRED)`
- Boost: `find_dependency(Boost REQUIRED)`

**Common Issue:** Missing GSL dependency declaration causes:

```
fatal error: gsl/narrow: No such file or directory
```

### Test Fails at: Linking

**Problem:** Library symbols not found

**Check:**

- Library visibility (PRIVATE vs PUBLIC vs INTERFACE)
- `install(TARGETS ...)` includes all necessary targets
- `EXPORT prevailTargets` is correct
- prevailTargets.cmake was generated and installed

### Test Fails at: Runtime

**Problem:** Dynamic libraries not found (rare on this project)

**Check:**

- LD_LIBRARY_PATH / PATH includes install location
- Libraries are actually built as shared if expected

## Maintenance

### When to Update Tests

Update the test when you change:

- Installation destinations
- Exported targets
- Public dependencies
- Header installation rules
- Package config template

### Don't Update Tests For

- API changes (add/remove/modify functions)
- Internal implementation changes
- Bug fixes that don't affect installation
- Documentation changes

### Adding Test Coverage

To test a new feature:

1. Add a simple usage example to `test_consumer.cpp`
2. Ensure it exercises the new installed component
3. Keep it minimal - just smoke test

Example:

```cpp
// Test new feature: custom platform types
#include <prevail/new_feature.hpp>
auto obj = prevail::NewFeature();
std::cout << "  V NewFeature works" << std::endl;
```

## Interpreting Results

### ✅ Success Means

- Installation process is not broken
- Package config is valid
- Headers and dependencies are accessible
- Basic linking and runtime work

### ✅ Success Does NOT Mean

- API is stable or backward compatible
- All features work correctly
- Performance is acceptable
- Code is bug-free

This is a **smoke test** for the installation mechanism, not comprehensive validation.

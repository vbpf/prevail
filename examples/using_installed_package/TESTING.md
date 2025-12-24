# Prevail Installation Test

This directory contains a minimal test to verify that prevail can be installed and consumed as a CMake package.

## Manual Testing

### Step 1: Build and Install Prevail

```bash
# From prevail root directory
cmake -B build -DCMAKE_BUILD_TYPE=Release -Dprevail_ENABLE_TESTS=OFF
cmake --build build --config Release
cmake --install build --prefix /tmp/prevail-install
```

On Windows:

```cmd
cmake -B build -DCMAKE_BUILD_TYPE=Release -Dprevail_ENABLE_TESTS=OFF
cmake --build build --config Release
cmake --install build --prefix C:\temp\prevail-install
```

### Step 2: Build and Run the Test Consumer

```bash
cd examples/using_installed_package
cmake -B build -DCMAKE_PREFIX_PATH=/tmp/prevail-install
cmake --build build
./build/install_test
```

On Windows:

```cmd
cd examples\using_installed_package
cmake -B build -DCMAKE_PREFIX_PATH=C:\temp\prevail-install
cmake --build build --config Release
build\Release\install_test.exe
```

## What This Tests

- ✅ `cmake --install` works without errors
- ✅ `find_package(prevail)` succeeds
- ✅ Installed headers are accessible
- ✅ Library links correctly
- ✅ Transitive dependencies (GSL, Boost) are found
- ✅ Basic API functionality works

## Expected Output

```
Testing prevail installation...
  V Platform creation works
  V GSL dependency available
  V All headers accessible

V Prevail installation test PASSED!
```

## Common Failures

### "Could not find package prevail"

- Check CMAKE_PREFIX_PATH points to install location
- Verify `cmake --install` completed successfully

### "gsl/narrow: No such file or directory"

- GSL dependency missing from prevailConfig.cmake.in
- Add: `find_dependency(Microsoft.GSL REQUIRED)`

### Linking errors

- Check that libbtf and GSL are PUBLIC dependencies
- Verify prevailTargets.cmake was installed correctly

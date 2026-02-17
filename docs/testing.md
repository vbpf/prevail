# Testing

This document describes the testing infrastructure in Prevail.

## Test Framework

Prevail uses [Catch2](https://github.com/catchorg/Catch2) v3 for unit and integration testing.

**Location**: `src/test/`

## Test Categories

### 1. YAML-Based Tests

**Tag**: `[yaml]`

YAML tests define expected verification outcomes:

```yaml
# test-data/assign.yaml
test-case: simple assignment
options:
  domain: zoneCrab
  
code:
  - mov r0, 1
  - exit

post:
  - r0.svalue=1
  - r0.uvalue=1
```

**Schema**: `test-schema.yaml`

**Fields**:

| Field | Description |
|-------|-------------|
| `test-case` | Test name |
| `options` | Verifier options |
| `code` | eBPF assembly or hex |
| `pre` | Expected preconditions |
| `post` | Expected postconditions |
| `messages` | Expected error messages |

### 2. Conformance Tests

**Tag**: `[conformance]`

Tests against the BPF conformance suite:

```cpp
// src/test/test_conformance.cpp
TEST_CONFORMANCE("add.data")
TEST_CONFORMANCE("div32-by-zero-reg.data")
```

These verify that Prevail correctly models eBPF instruction semantics.

### 3. Unit Tests

**Tag**: Various (e.g., `[domain]`, `[cfg]`)

```cpp
// Example: testing interval arithmetic
TEST_CASE("interval addition", "[domain]") {
    Interval a(1, 5);
    Interval b(2, 3);
    REQUIRE((a + b) == Interval(3, 8));
}
```

## Running Tests

### All Tests

```bash
./bin/tests
```

### By Tag

```bash
# YAML tests only
./bin/tests "[yaml]"

# Conformance tests only
./bin/tests "[conformance]"

# Exclude slow tests
./bin/tests "~[slow]"

# Combine tags
./bin/tests "[yaml][domain]"
```

### By Name

```bash
# Run tests matching pattern
./bin/tests "simple assignment"

# Run specific test file
./bin/tests -# "assign.yaml"
```

### Verbose Output

```bash
./bin/tests -s  # Show successful assertions
./bin/tests -d  # Show test duration
```

## YAML Test Format

### Basic Test

```yaml
test-case: add two numbers
code:
  - mov r1, 5
  - mov r2, 3
  - add r1, r2
  - mov r0, r1
  - exit

post:
  - r0.svalue=8
```

### Testing Errors

```yaml
test-case: null pointer dereference
code:
  - mov r0, 0
  - ldxw r1, [r0+0]
  - exit

messages:
  - "0: Invalid mem access 'r0'"
```

### Testing Loops

```yaml
test-case: bounded loop
options:
  check_for_termination: true

code:
  - mov r0, 0
  - mov r1, 10
loop:
  - jge r0, r1, exit
  - add r0, 1
  - ja loop
exit:
  - exit

post:
  - r0.svalue=10
```

### Assembly vs Hex

Assembly format:
```yaml
code:
  - mov r0, 1
  - exit
```

Hex format:

```yaml
code:
  - b7 00 00 00 01 00 00 00  # mov r0, 1
  - 95 00 00 00 00 00 00 00  # exit
```

## Conformance Tests

### Test Data Format

```text
# tests/add.data
-- asm
mov %r0, 1
mov %r1, 2  
add %r0, %r1
exit
-- result
0x3
```

### Running Conformance

Conformance tests use test files from `external/bpf_conformance/tests/` and verify
that the expected return value is within the verifier's computed range (soundness check).

```bash
# Run all conformance tests
./bin/tests "[conformance]"

# Run a specific conformance test
./bin/tests "conformance_check add.data"
```

### Expected Failures

Some tests are expected to fail verification (the program is rejected by the verifier):

```cpp
// In test_conformance.cpp
TEST_CONFORMANCE_VERIFICATION_FAILED("mem-len.data")
```

## Writing Tests

### Add a YAML Test

1. Create file in `test-data/`:

   ```yaml
   # test-data/my_test.yaml
   test-case: my new test
   code:
     - mov r0, 42
     - exit
   post:
     - r0.svalue=42
   ```

2. Test is automatically discovered.

### Add a Unit Test

1. Add to existing test file or create new one in `src/test/`:

   ```cpp
   // src/test/test_myfeature.cpp
   #include <catch2/catch_all.hpp>
   
   TEST_CASE("my feature works", "[myfeature]") {
       // Test code
       REQUIRE(result == expected);
   }
   ```

2. Add to CMakeLists.txt if new file:
   ```cmake
   add_executable(tests
       src/test/test_myfeature.cpp
       # ... other files
   )
   ```

### Add a Conformance Test

1. Add test file to `external/bpf_conformance/tests/`:
   ```
   -- asm
   ; Your test code
   -- result
   0x1
   ```

2. Register in `test_conformance.cpp`:
   ```cpp
   TEST_CONFORMANCE("my_test.data")
   ```

## Test Fixtures

### Predefined Domains

```yaml
options:
  domain: zoneCrab      # Default numeric domain
  domain: intervalDomain  # Simpler interval domain
```

### Entry State

Default entry state:
- R1 = context pointer
- R10 = stack pointer
- R0, R2-R9 = uninitialized

Custom entry:
```yaml
pre:
  - r1.type=ctx
  - r1.ctx_offset=0
  - r2.svalue=[0, 100]
```

## Test Assertions

### Post-Conditions

```yaml
post:
  # Exact value
  - r0.svalue=42
  
  # Range
  - r0.svalue=[0, 100]
  
  # Type
  - r1.type=stack
  
  # Multiple conditions
  - r0.svalue>=0
  - r0.svalue<=10
```

### Expected Messages

```yaml
messages:
  - "1: Upper bound must be"  # Partial match
  - "Code is unreachable"
```

## Coverage

### Enable Coverage

```bash
cmake -B build -DENABLE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build
./bin/tests
# Generate report
gcovr --html-details coverage.html
```

### Coverage Goals

- Core verifier logic: >90%
- Instruction handlers: >95%
- Error paths: >80%

## Debugging Tests

### Run Single Test with Verbose

```bash
./bin/tests "test name" -s -d
```

### Debug in GDB

```bash
gdb --args ./bin/tests "test name"
(gdb) run
(gdb) bt  # on failure
```

### Print Invariants

In YAML test:
```yaml
options:
  print_invariants: true
```

## CI Integration

Tests run automatically on:
- Pull requests
- Main branch pushes

CI matrix:
- Linux (GCC, Clang)
- Windows (MSVC)
- macOS (Clang)

### Running CI Locally

```bash
# Simulate CI build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./bin/tests
```

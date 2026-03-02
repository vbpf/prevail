# prevail_mcp — PREVAIL Verifier MCP Server

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that exposes
PREVAIL's eBPF verification analysis as structured, queryable tools for LLM agents.

Instead of parsing verbose text output from `check`, LLM agents can query invariants,
errors, control flow, source mappings, and constraint hypotheses through structured JSON
tool calls.

## Building

The MCP server is built alongside the `check` executable:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target prevail_mcp
```

Output: `bin/prevail_mcp`

To disable the MCP server build:

```bash
cmake -B build -Dprevail_ENABLE_MCP=OFF
```

## Usage

The server communicates via JSON-RPC 2.0 over stdio (newline-delimited JSON).
It is designed to be launched by an MCP client such as GitHub Copilot CLI or VS Code.

### GitHub Copilot CLI

```
/mcp add
```

Set **Command** to the path to `prevail_mcp` (e.g. `bin/prevail_mcp`).

### VS Code

Add to `.vscode/mcp.json`:

```json
{
    "servers": {
        "prevail-verifier": {
            "type": "stdio",
            "command": "bin/prevail_mcp"
        }
    }
}
```

### Manual testing

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"verify_program","arguments":{"elf_path":"ebpf-samples/build/badhelpercall.o"}}}' | bin/prevail_mcp
```

## Tools

| Tool | Description |
|------|-------------|
| `list_programs` | List all programs (sections/functions) in an ELF file |
| `verify_program` | Run verification, get pass/fail with error summary and stats |
| `get_invariant` | Get pre/post abstract state at one or more instructions |
| `get_instruction` | Full detail: disassembly, assertions, invariants, source, CFG neighbors |
| `get_errors` | All verification errors with pre-invariants and source lines |
| `get_cfg` | Control-flow graph as JSON basic blocks or Graphviz DOT |
| `get_source_mapping` | Bidirectional C source ↔ BPF instruction mapping (requires `-g`) |
| `check_constraint` | Test if constraints are consistent with / proven by verifier state |
| `get_slice` | Backward slice from an error or arbitrary PC with register relevance |
| `get_disassembly` | Instruction listing with source lines for a PC range |

### Diagnostic Workflow

These tools support the diagnostic protocol described in
[docs/llm-context.md](../docs/llm-context.md):

1. **`get_slice`** — Start here. Returns the error, pre-invariant, assertions,
   source line, and a backward slice showing only the instructions that causally
   contributed to the failure, with per-instruction register relevance tracking.
2. **`check_constraint`** — Test hypotheses: "is `r1.type=packet` possible at PC 5?"
   (`consistent` mode) or "does the verifier guarantee `packet_size >= 42`?"
   (`proven` mode).
3. **`get_instruction`** / **`get_invariant`** — Deep dive on specific instructions.
4. **`get_source_mapping`** — Find the C source line for a BPF instruction or vice versa.

### check_constraint Modes

| Mode | Question it answers | Semantics |
|------|-------------------|-----------|
| `consistent` | "Is this possible?" | Constraints don't contradict the invariant (A ∩ C ≠ ⊥) |
| `proven` | "Does the verifier guarantee this?" | Invariant implies the constraints (A ⊑ C) |
| `entailed` | "Is this a sub-state?" | Observation is contained in invariant (C ⊑ A); requires near-complete constraint set |

### Failure Slicing

`get_slice` uses PREVAIL's backward dataflow slicing (same algorithm as
`check --failure-slice`) to identify only the instructions that causally contributed
to a verification failure. Each instruction in the slice includes:

- The instruction text and PC
- Which registers are relevant at that point
- The post-invariant (constraints after the instruction)
- Source line mapping (if BTF info is available)

The `trace_depth` parameter (default: 200) controls the maximum backward traversal
steps, matching `check --failure-slice-depth`.

## Relationship to check

| Feature | `check` | `prevail_mcp` |
|---------|---------|---------------|
| Interface | CLI (text output) | MCP (JSON-RPC over stdio) |
| Invariant access | All-or-nothing (`-v` flag) | Per-instruction query |
| Error diagnosis | `--failure-slice` | Built into `get_slice` |
| Constraint testing | Not available | `check_constraint` with 3 modes |
| Source mapping | `--line-info` flag | `get_source_mapping` tool |
| CFG output | `--dot` to file | `get_cfg` returns JSON or DOT |
| Platform | Linux | Cross-platform (Linux, Windows) |
| Caching | None (single run) | LRU cache + live session reuse |

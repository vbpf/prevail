#!/usr/bin/env python3
"""
Class Name Renaming Script

This script automatically renames class names in a codebase according to a predefined mapping.
It handles both class definitions and usages throughout the code.
"""

import os
import re
import sys
from typing import Dict, List, Tuple
import argparse

# Define the mapping of old class names to new class names
CLASS_MAPPING = {
    # Arithmetic and Number Theory
    "number_t": "Number",
    "extended_number": "ExtendedNumber",
    "safe_i64": "SafeI64",
    "wideint_t": "WideInt",
    "arith_binop_t": "ArithBinOp",
    "bitwise_binop_t": "BitwiseBinOp",
    "binop_t": "BinOp",
    "bound_t": "Bound",
    "index_t": "Index",  # Used for array indexing, related to numbers/offsets
    "key_t": "Key",  # Used in maps, often numeric
    "mut_val_ref_t": "MutValRef",  # Related to graph weights/values
    "val_t": "Val",  # Generic value type

    # Control Flow Graph (CFG) and Analysis
    "adjacent_t": "Adjacent",  # CFG structure
    "basic_block_t": "BasicBlock",
    "cfg_t": "Cfg",
    "cfg_builder_t": "CfgBuilder",
    "label_t": "Label",
    "label_vec_t": "LabelVec",  # Vector of labels
    "stmt_list_t": "StmtList",  # List of statements (labels)
    "pc_t": "Pc",  # Program Counter
    "wto_t": "Wto",  # Weak Topological Ordering
    "wto_builder_t": "WtoBuilder",
    "wto_cycle_t": "WtoCycle",
    "wto_nesting_t": "WtoNesting",
    "wto_thresholds_t": "WtoThresholds",
    "wto_vertex_data_t": "WtoVertexData",
    "wto_partition_t": "WtoPartition",
    "cycle_or_label": "CycleOrLabel",  # Variant used in WTO structure
    "interleaved_fwd_fixpoint_iterator_t": "InterleavedFwdFixpointIterator",
    "invariant_map_pair": "InvariantMapPair",  # Used in analysis results
    "invariant_table_t": "InvariantTable",  # Table of invariants
    "visit_args_t": "VisitArgs",  # Used in analysis traversal
    "print_visitor": "PrintVisitor",  # Used for printing CFG/WTO

    # Domains and Constraints
    "array_domain_t": "ArrayDomain",
    "bitset_domain_t": "BitsetDomain",
    "ebpf_domain_t": "EbpfDomain",
    "interval_t": "Interval",
    "linear_constraint_t": "LinearConstraint",
    "linear_expression_t": "LinearExpression",
    "variable_t": "Variable",
    "reg_pack_t": "RegPack",  # Structure for register components
    "cell_t": "Cell",  # Used in array domain
    "thresholds_t": "Thresholds",  # Used in widening
    "string_invariant": "StringInvariant",  # Represents string-based invariants
    "variable_terms_t": "VariableTerms",  # Part of linear expression
    "variable_vector_t": "VariableVector",  # Vector of variables
    "constraint_kind_t": "ConstraintKind",  # Enum for linear constraints
    "data_kind_t": "DataKind",  # Enum for variable data kind
    "type_domain_t": "TypeDomain",
    "type_group_t": "TypeGroup",  # Enum for type groups
    "type_encoding_t": "TypeEncoding",  # Enum for type encoding
    "num_abs_domain_t": "NumAbsDomain",  # Numerical Abstract Domain

    # Low-Level / Instruction Representation
    "program_info": "ProgramInfo",
    "raw_program": "RawProgram",
    "function_relocation": "FunctionRelocation",  # Used in ELF parsing
    "ebpf_inst": "EbpfInst",  # eBPF instruction struct
    "ebpf_instruction_template_t": "EbpfInstructionTemplate",  # Used in testing
    "bpf_load_map_def": "BpfLoadMapDef",  # ELF map definition struct
    "map_offsets_t": "MapOffsets",  # Used in ELF parsing
    "visit_task_type_t": "VisitTaskType",  # Used in unmarshalling/processing
    "add_bottom": "AddBottom",  # Domain helper/wrapper

    # Graph and Data Structures
    "graph_t": "Graph",  # Generic graph type
    "vert_id": "VertId",  # Vertex ID
    "vert_map_t": "VertMap",  # Mapping variable to vertex ID
    "vert_set_t": "VertSet",  # Set of vertex IDs
    "edge_ref": "EdgeRef",  # Reference to a graph edge
    "edge_vector": "EdgeVector",  # Vector of edges
    "vert_const_iterator": "VertConstIterator",  # Iterator for vertices
    "adj_const_range_t": "AdjConstRange",  # Range of adjacent vertices
    "adj_range_t": "AdjRange",
    "e_neighbour_const_range": "ENeighbourConstRange",  # Range of adjacent edges
    "g_e_neighbour_const_range": "GENeighbourConstRange",
    "g_neighbour_const_range": "GNeighbourConstRange",
    "neighbour_const_range": "NeighbourConstRange",
    "neighbour_range": "NeighbourRange",
    "fwd_edge_const_iter": "FwdEdgeConstIter",  # Iterator for forward edges
    "fwd_edge_range": "FwdEdgeRange",
    "rev_edge_const_iter": "RevEdgeConstIter",  # Iterator for reverse edges
    "rev_edge_range": "RevEdgeRange",
    "rev_map_t": "RevMap",  # Mapping vertex ID to variable
    "elt_iter_t": "EltIter",  # Iterator for elements in sparse map
    "elt_range_t": "EltRange",
    "patricia_tree_t": "PatriciaTree",  # Underlying structure for OffsetMap
    "adj_const_iterator": "AdjConstIterator",
    "adj_iterator": "AdjIterator",
    "adj_list": "AdjList",
    "const_adj_list": "ConstAdjList",
    "e_adj_const_iterator": "EAdjConstIterator",
    "e_adj_iterator": "EAdjIterator",
    "elt_const_range_t": "EltConstRange",
    "key_const_range_t": "KeyConstRange",
    "key_iter_t": "KeyIter",
    "vert_const_range": "VertConstRange",
    "vert_set_wrap_t": "VertSetWrap",  # Wrapper for VertSet

    # Utilities and Others
    "ebpf_checker": "EbpfChecker",  # Verification checker
    "ebpf_transformer": "EbpfTransformer",  # Applies instruction effects
    "overloaded": "Overloaded",  # C++ utility for variant visitors
    "at_scope_exit": "AtScopeExit",  # C++ utility for scope-based cleanup
    "lazy_allocator": "LazyAllocator",  # Utility for lazy initialization
    "expand_variadic_pack": "ExpandVariadicPack",  # C++ template utility
    "swap_signedness": "SwapSignedness",  # C++ type trait
    "compare_binding_t": "CompareBinding",  # Used in OffsetMap
    "program_reader_t": "ProgramReader",  # Used in ELF parsing
}


def build_regex_patterns() -> Dict[str, re.Pattern]:
    """
    Build regex patterns for each class name to match different contexts where they might appear.
    Avoids matching in file paths by excluding patterns followed by a period.
    """
    patterns = {}
    for old_name in CLASS_MAPPING:
        # This pattern will match class definitions and usages but not when followed by a period,
        # which would indicate a file extension or namespace access
        patterns[old_name] = re.compile(r'\b' + re.escape(old_name) + r'\b(?!\.)')
    return patterns


def should_skip_file(file_path: str, extensions: List[str]) -> bool:
    """
    Check if a file should be skipped based on its extension or path.
    """
    _, ext = os.path.splitext(file_path)
    if ext and ext[1:] not in extensions:  # Remove the dot from extension
        return True
    return False


def process_file(file_path: str, patterns: Dict[str, re.Pattern], dry_run: bool = False) -> Tuple[int, List[str]]:
    """
    Process a single file, applying the renaming patterns.
    Returns the number of replacements made and a list of changes.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content
    change_count = 0
    changes = []

    # Apply each pattern
    for old_name, pattern in patterns.items():
        new_name = CLASS_MAPPING[old_name]

        # Count occurrences before replacement
        occurrences = len(pattern.findall(content))
        if occurrences > 0:
            # Replace all occurrences
            content = pattern.sub(new_name, content)
            change_count += occurrences
            changes.append(f"  {old_name} → {new_name} ({occurrences} occurrences)")

    # Write changes back to the file if not a dry run and changes were made
    if not dry_run and content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

    return change_count, changes


def process_directory(directory: str, patterns: Dict[str, re.Pattern],
                      extensions: List[str], dry_run: bool = False) -> int:
    """
    Recursively process files in a directory.
    Returns the total number of replacements made.
    """
    total_changes = 0
    file_count = 0
    modified_file_count = 0

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)

            if should_skip_file(file_path, extensions):
                continue

            file_count += 1
            changes, change_list = process_file(file_path, patterns, dry_run)

            if changes > 0:
                modified_file_count += 1
                total_changes += changes
                relative_path = os.path.relpath(file_path, directory)
                print(f"Modified {relative_path} ({changes} changes):")
                for change in change_list:
                    print(change)
                print()

    print(f"Summary: {total_changes} changes across {modified_file_count} files (scanned {file_count} files)")
    if dry_run:
        print("Note: This was a dry run. No files were actually modified.")

    return total_changes


def main():
    parser = argparse.ArgumentParser(description="Rename class names in codebase according to a predefined mapping")
    parser.add_argument("--dry-run", "-d", action="store_true",
                        help="Perform a dry run without actually modifying files")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    directory = os.path.normpath(os.path.join(script_dir, "../src"))
    extensions = ["cpp", "hpp"]

    patterns = build_regex_patterns()

    print(f"Starting class name renaming in {directory}")
    print(f"Processing files with extensions: {', '.join(extensions)}")
    print(
        f"{'Dry run mode - ' if args.dry_run else ''}Changes will be applied based on {len(CLASS_MAPPING)} class mappings\n")

    try:
        changes = process_directory(directory, patterns, extensions, args.dry_run)
        print(f"Completed with {changes} total changes")
        return 0
    except Exception as e:
        print(f"Error occurred: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

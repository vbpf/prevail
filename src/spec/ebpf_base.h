// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file contains type definitions that can be used in C or C++
// that would typically be shared between the verifier and other
// eBPF components.

typedef enum _ebpf_return_type {
    EBPF_RETURN_TYPE_INTEGER = 0,
    EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED,
    EBPF_RETURN_TYPE_UNSUPPORTED,
    EBPF_RETURN_TYPE_PTR_TO_SOCK_COMMON_OR_NULL,
    EBPF_RETURN_TYPE_PTR_TO_SOCKET_OR_NULL,
    EBPF_RETURN_TYPE_PTR_TO_TCP_SOCKET_OR_NULL,
    EBPF_RETURN_TYPE_PTR_TO_ALLOC_MEM_OR_NULL,
    EBPF_RETURN_TYPE_PTR_TO_BTF_ID_OR_NULL,
    EBPF_RETURN_TYPE_PTR_TO_MEM_OR_BTF_ID_OR_NULL,
    EBPF_RETURN_TYPE_PTR_TO_BTF_ID,
    EBPF_RETURN_TYPE_PTR_TO_MEM_OR_BTF_ID,
} ebpf_return_type_t;

// Describes the type of an eBPF program argument.
// This information is used by the verifier to ensure that
// the program uses its arguments correctly.
// Note: Some dependent products may rely on the specific integer values
// assigned to these enum members. If possible only add new members
// at the end of the list.
typedef enum _ebpf_argument_type {
    EBPF_ARGUMENT_TYPE_DONTCARE = 0,
    EBPF_ARGUMENT_TYPE_ANYTHING = 1, // All values are valid, e.g., 64-bit flags.
    EBPF_ARGUMENT_TYPE_CONST_SIZE = 2,
    EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO = 3,
    EBPF_ARGUMENT_TYPE_PTR_TO_CTX = 4,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP = 5,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS = 6,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY = 7,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE = 8,
    EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM = 9, // Memory must have been initialized.
    EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL = 10,
    EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM = 11,
    EBPF_ARGUMENT_TYPE_PTR_TO_STACK = 12,
    EBPF_ARGUMENT_TYPE_PTR_TO_STACK_OR_NULL = 13,
    EBPF_ARGUMENT_TYPE_PTR_TO_CTX_OR_NULL = 14,
    EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM_OR_NULL = 15,
    EBPF_ARGUMENT_TYPE_UNSUPPORTED = 16,
    EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON = 17,
    EBPF_ARGUMENT_TYPE_PTR_TO_SPIN_LOCK = 18,
    EBPF_ARGUMENT_TYPE_PTR_TO_SOCK_COMMON = 19,
    EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID = 20,
    EBPF_ARGUMENT_TYPE_PTR_TO_LONG = 21,
    EBPF_ARGUMENT_TYPE_PTR_TO_INT = 22,
    EBPF_ARGUMENT_TYPE_PTR_TO_CONST_STR = 23,
    EBPF_ARGUMENT_TYPE_PTR_TO_FUNC = 24,
    EBPF_ARGUMENT_TYPE_CONST_ALLOC_SIZE_OR_ZERO = 25,
    EBPF_ARGUMENT_TYPE_PTR_TO_ALLOC_MEM = 26,
    EBPF_ARGUMENT_TYPE_PTR_TO_TIMER = 27,
    EBPF_ARGUMENT_TYPE_PTR_TO_PERCPU_BTF_ID = 28,
    EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM = 29,
    EBPF_ARGUMENT_TYPE_PTR_TO_READONLY_MEM_OR_NULL = 30,
    EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MAP_VALUE = 31,
    EBPF_ARGUMENT_TYPE_CONST_PTR_TO_MAP = 32,
} ebpf_argument_type_t;

// The following struct describes how to access the layout in
// memory of the data (e.g., the actual packet).
typedef struct _ebpf_context_descriptor {
    int size; // Size of ctx struct.
    int data; // Offset into ctx struct of pointer to data.
    int end;  // Offset into ctx struct of pointer to end of data.
    int meta; // Offset into ctx struct of pointer to metadata.
} ebpf_context_descriptor_t;

// Maximum number of nested function calls allowed in eBPF programs.
// This limit helps prevent stack overflow and ensures predictable behavior.
#define MAX_CALL_STACK_FRAMES 8

// Stack space allocated for each subprogram (in bytes).
// This ensures each function call has its own dedicated stack space.
#define EBPF_SUBPROGRAM_STACK_SIZE 512

// Total stack space usable with nested subprogram calls.
#define EBPF_TOTAL_STACK_SIZE (MAX_CALL_STACK_FRAMES * EBPF_SUBPROGRAM_STACK_SIZE)

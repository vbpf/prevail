// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

/// @file Aggregate include for PREVAIL verifier headers used by the MCP server.
/// On MSVC, suppresses warnings from PREVAIL headers that are treated as errors
/// by projects with /W4 /WX (e.g. ebpf-for-windows). On GCC/Clang these are no-ops.

// Pre-define the include guard for bpf_conformance's ebpf_inst.h to prevent it
// from being included (its EbpfInst struct conflicts with prevail::EbpfInst).
#ifndef BPF_CONFORMANCE_CORE_EBPF_INST_H
#define BPF_CONFORMANCE_CORE_EBPF_INST_H
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4100) // Unreferenced formal parameter.
#pragma warning(disable : 4244) // Conversion, possible loss of data.
#pragma warning(disable : 4267) // Conversion from 'size_t' to 'int'.
#pragma warning(disable : 4458) // Declaration hides class member.
#pragma warning(disable : 26439) // Function may not throw.
#pragma warning(disable : 26450) // Arithmetic overflow.
#pragma warning(disable : 26451) // Arithmetic overflow.
#pragma warning(disable : 26495) // Always initialize a member variable.
#endif

// Undef macros that conflict with PREVAIL headers on Windows.
#undef FALSE
#undef TRUE
#undef min
#undef max

#include "cfg/cfg.hpp"
#include "config.hpp"
#include "ebpf_verifier.hpp"
#include "ir/program.hpp"
#include "ir/unmarshal.hpp"
#include "platform.hpp"
#include "result.hpp"
#include "spec/type_descriptors.hpp"
#include "string_constraints.hpp"
#include "verifier.hpp"

#ifdef _WIN32
#define FALSE 0
#define TRUE 1
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

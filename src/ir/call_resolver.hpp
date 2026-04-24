// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "ir/syntax.hpp"
#include "platform.hpp"

namespace prevail {

/// Resolves a Call's (func, kind) key against a program's platform and type
/// to produce the full ABI/diagnostic info:
///   * CallKind::helper  -> platform.get_helper_prototype(func, type)
///   * CallKind::kfunc   -> platform.resolve_kfunc_call(func, type)
///   * CallKind::builtin -> platform.get_builtin_call(func)
///
/// When resolution fails the returned ResolvedCall has is_supported == false
/// and a populated unsupported_reason; the contract is empty.
///
/// Implemented in terms of the existing make_call / kfunc lookup /
/// get_builtin_call plumbing.
[[nodiscard]]
ResolvedCall resolve(const Call& call, const ProgramInfo& info);

} // namespace prevail

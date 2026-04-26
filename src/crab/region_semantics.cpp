// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "crab/region_semantics.hpp"
#include "crab/type_to_num.hpp"

namespace prevail {

std::optional<Variable> primary_kind_variable_for_type(const Reg& reg, const TypeEncoding type) {
    RegPack r = reg_pack(reg);
    switch (type) {
    case T_CTX: return r.ctx_offset;
    case T_MAP: return r.map_fd;
    case T_MAP_PROGRAMS: return r.map_fd_programs;
    case T_PACKET: return r.packet_offset;
    case T_SHARED: return r.shared_offset;
    case T_STACK: return r.stack_offset;
    case T_SOCKET: return r.socket_offset;
    case T_BTF_ID: return r.btf_id_offset;
    case T_ALLOC_MEM: return r.alloc_mem_offset;
    default: return {};
    }
}

} // namespace prevail

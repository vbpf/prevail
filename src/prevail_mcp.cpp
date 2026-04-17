// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

/// @file Entry point for the PREVAIL MCP server (portable/Linux build).

#include "analysis_engine.hpp"
#include "mcp/mcp_server.hpp"
#include "mcp/mcp_transport.hpp"
#include "platform_ops_prevail.hpp"
#include "mcp/tools.hpp"

#include "linux/gpl/spec_type_descriptors.hpp"

#include <cstdio>
#include <iostream>

#ifndef _WIN32
#include <unistd.h>
#endif

int
main()
{
    try {
        // Set up the MCP output stream: duplicate stdout for exclusive MCP use,
        // then redirect std::cout to std::cerr so that library diagnostics
        // (e.g., verbose verifier output) don't corrupt the JSON-RPC framing.
        // Note: fd-level stdout is left intact so that parent processes can pipe
        // it normally (e.g., subprocess.Popen in Python, Start-Process in PowerShell).
        FILE* mcp_out = stdout;
#ifndef _WIN32
        int mcp_fd = dup(fileno(stdout));
        if (mcp_fd >= 0) {
            mcp_out = fdopen(mcp_fd, "wb");
            if (!mcp_out) {
                close(mcp_fd);
                mcp_out = stdout; // Fallback: use stdout directly.
            }
        }
#endif
        setvbuf(mcp_out, nullptr, _IONBF, 0);

        // Redirect C++ std::cout to stderr so library diagnostics don't reach the client.
        std::cout.rdbuf(std::cerr.rdbuf());

        // Use the Linux eBPF platform from PREVAIL.
        prevail::PrevailPlatformOps ops(&prevail::g_ebpf_platform_linux);

        prevail::AnalysisEngine engine(&ops);
        prevail::McpServer server;
        prevail::register_all_tools(server, engine);

        std::cerr << "prevail: server started" << std::endl;

        prevail::McpTransport transport(mcp_out);
        transport.run([&server](const std::string& method, const nlohmann::json& params) {
            return server.dispatch(method, params);
        });

        std::cerr << "prevail: server stopped" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "prevail: fatal error: " << e.what() << std::endl;
        return 1;
    }
}

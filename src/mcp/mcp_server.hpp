// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

/// @file MCP server: tool registry, capability negotiation, and request dispatch.

#include <functional>
#include <map>
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 26495) // Uninitialized member variable (nlohmann::basic_json::m_data).
#pragma warning(disable : 26819) // Unannotated fallthrough (nlohmann serializer).
#endif
#include <nlohmann/json.hpp>
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#include <string>

namespace prevail {

/// Metadata and handler for a single MCP tool.
struct ToolInfo
{
    std::string name;
    std::string description;
    nlohmann::json input_schema; // JSON Schema object for the tool's parameters.
    std::function<nlohmann::json(const nlohmann::json& arguments)> handler;
};

/// MCP server that registers tools and dispatches incoming requests.
class McpServer
{
  public:
    explicit McpServer(
        const std::string& name = "prevail-verifier", const std::string& version = "0.1.0")
        : server_name_(name), server_version_(version)
    {
    }

    void
    register_tool(ToolInfo tool);

    /// Dispatch a JSON-RPC request.  Suitable as the handler for McpTransport::run().
    nlohmann::json
    dispatch(const std::string& method, const nlohmann::json& params);

  private:
    nlohmann::json
    handle_initialize(const nlohmann::json& params);
    nlohmann::json
    handle_tools_list(const nlohmann::json& params);
    nlohmann::json
    handle_tools_call(const nlohmann::json& params);

    std::map<std::string, ToolInfo> tools_;
    std::string server_name_;
    std::string server_version_;
};

} // namespace prevail

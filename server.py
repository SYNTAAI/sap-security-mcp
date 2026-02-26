#!/usr/bin/env python3
"""
SyntaAI SAP Security MCP Server (OData Edition)
================================================
A Model Context Protocol (MCP) server that enables AI assistants like Claude
to analyze SAP security configurations in real-time via OData services.

No JCo, no RFC SDK, no native libraries - pure HTTP/OData.

Built by SyntaAI (https://syntaai.com)
"""

import asyncio
import logging
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

# Load .env file from the same directory as server.py
load_dotenv(Path(__file__).parent / ".env")

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from config.settings import Settings
from sap.odata_client import SAPODataClient
from auth.mcp_auth import MCPAuthManager
from tools.security_tools import SecurityTools
from tools.basis_tools import BasisTools
from tools.report_tools import ReportTools

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("syntaai-mcp")

# Initialize
settings = Settings()
sap_client = SAPODataClient(settings)
auth_manager = MCPAuthManager()
security_tools = SecurityTools(sap_client)
basis_tools = BasisTools(sap_client)
report_tools = ReportTools(sap_client)

# Create MCP Server
app = Server("syntaai-sap-security")


# ─── Tool Registry ───────────────────────────────────────────────────────────

TOOL_DEFINITIONS = [
    # Authentication
    Tool(
        name="mcp_login",
        description="Authenticate to the MCP server. Required before using other tools.",
        inputSchema={
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "MCP username"},
                "password": {"type": "string", "description": "MCP password"}
            },
            "required": ["username", "password"]
        }
    ),

    # Security Tools (1-10)
    Tool(
        name="get_user_roles",
        description="Get all roles assigned to a specific SAP user. Shows role names, descriptions, and validity dates.",
        inputSchema={
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "SAP username (e.g., SMITHJ)"}
            },
            "required": ["username"]
        }
    ),
    Tool(
        name="check_sap_all_users",
        description="Find all users with SAP_ALL or SAP_NEW profiles assigned. These are critical security risks.",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="get_dormant_users",
        description="Find users inactive for specified number of days. Default is 90 days.",
        inputSchema={
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Days of inactivity (default: 90)", "default": 90}
            }
        }
    ),
    Tool(
        name="get_locked_users",
        description="Get all locked users with lock type and reason.",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="check_sod_violations",
        description="Check for Segregation of Duties (SoD) violations across users. Identifies conflicting transaction code access.",
        inputSchema={
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Optional: check specific user. Leave empty for all users."}
            }
        }
    ),
    Tool(
        name="check_critical_tcodes",
        description="Find users with access to critical transaction codes (SU01, SE16, SM49, SE38, etc.)",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="get_users_created_recently",
        description="Get users created in the last N days.",
        inputSchema={
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Lookback period in days (default: 30)", "default": 30}
            }
        }
    ),
    Tool(
        name="check_default_users",
        description="Check status of default SAP users (SAP*, DDIC, TMSADM, EARLYWATCH, etc.)",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="check_password_policy",
        description="Analyze SAP password policy configuration and compliance.",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="check_users_no_roles",
        description="Find active users that have no role assignments.",
        inputSchema={"type": "object", "properties": {}}
    ),

    # Basis Tools (11-15)
    Tool(
        name="get_system_info",
        description="Get SAP system information including version, kernel, database, and instance details.",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="get_failed_jobs",
        description="Get failed background jobs from the last N days.",
        inputSchema={
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Lookback period (default: 7)", "default": 7}
            }
        }
    ),
    Tool(
        name="check_rfc_destinations",
        description="Check RFC destination configurations for security risks (stored passwords, HTTP connections, etc.)",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="get_system_parameters",
        description="Get security-relevant system parameters (login/*, rfc/*, auth/*).",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="check_transport_requests",
        description="Check recent transport requests and their status.",
        inputSchema={
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Lookback period (default: 30)", "default": 30}
            }
        }
    ),

    # Report Tools (16-17)
    Tool(
        name="generate_security_excel",
        description="Generate a comprehensive Excel security report.",
        inputSchema={
            "type": "object",
            "properties": {
                "report_type": {
                    "type": "string",
                    "enum": ["full_report", "user_report", "role_report", "compliance_report"],
                    "description": "Type of report to generate",
                    "default": "full_report"
                }
            }
        }
    ),
    Tool(
        name="generate_risk_summary",
        description="Get a comprehensive risk assessment summary with findings categorized by severity.",
        inputSchema={"type": "object", "properties": {}}
    ),
]


@app.list_tools()
async def list_tools():
    return TOOL_DEFINITIONS


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    """Route tool calls to appropriate handlers."""
    try:
        # Authentication tool - no auth required
        if name == "mcp_login":
            result = auth_manager.login(
                arguments.get("username", ""),
                arguments.get("password", "")
            )
            return [TextContent(type="text", text=result)]

        # All other tools require authentication
        if not auth_manager.is_authenticated():
            return [TextContent(
                type="text",
                text="❌ Not authenticated. Please call mcp_login first."
            )]

        # Check RBAC permissions
        if not auth_manager.has_permission(name):
            return [TextContent(
                type="text",
                text=f"❌ User '{auth_manager.current_user}' is not authorized to use '{name}'."
            )]

        # Route to appropriate tool handler
        handler_map = {
            # Security tools
            "get_user_roles": lambda: security_tools.get_user_roles(arguments.get("username", "")),
            "check_sap_all_users": lambda: security_tools.check_sap_all_users(),
            "get_dormant_users": lambda: security_tools.get_dormant_users(arguments.get("days", 90)),
            "get_locked_users": lambda: security_tools.get_locked_users(),
            "check_sod_violations": lambda: security_tools.check_sod_violations(arguments.get("username")),
            "check_critical_tcodes": lambda: security_tools.check_critical_tcodes(),
            "get_users_created_recently": lambda: security_tools.get_users_created_recently(arguments.get("days", 30)),
            "check_default_users": lambda: security_tools.check_default_users(),
            "check_password_policy": lambda: security_tools.check_password_policy(),
            "check_users_no_roles": lambda: security_tools.check_users_no_roles(),
            # Basis tools
            "get_system_info": lambda: basis_tools.get_system_info(),
            "get_failed_jobs": lambda: basis_tools.get_failed_jobs(arguments.get("days", 7)),
            "check_rfc_destinations": lambda: basis_tools.check_rfc_destinations(),
            "get_system_parameters": lambda: basis_tools.get_system_parameters(),
            "check_transport_requests": lambda: basis_tools.check_transport_requests(arguments.get("days", 30)),
            # Report tools
            "generate_security_excel": lambda: report_tools.generate_security_excel(arguments.get("report_type", "full_report")),
            "generate_risk_summary": lambda: report_tools.generate_risk_summary(),
        }

        handler = handler_map.get(name)
        if not handler:
            return [TextContent(type="text", text=f"❌ Unknown tool: {name}")]

        result = await handler()
        return [TextContent(type="text", text=result)]

    except Exception as e:
        logger.error(f"Tool {name} failed: {e}", exc_info=True)
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def main():
    logger.info("Starting SyntaAI SAP Security MCP Server (OData Edition)...")
    logger.info(f"SAP Host: {settings.sap_base_url}")
    logger.info(f"OData Mode: {settings.odata_mode}")
    logger.info(f"Tools available: {len(TOOL_DEFINITIONS)}")

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())

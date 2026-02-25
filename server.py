#!/usr/bin/env python3
"""
SyntaAI SAP Security MCP Server (Fixed SSE Transport)
Connects Claude/any AI to SAP Security data via JCo REST connector.

Usage:
    python server.py                          # STDIO mode (default)
    python server.py --transport stdio        # STDIO mode (explicit)
    python server.py --transport sse          # SSE/HTTP mode on port 8001
    python server.py --transport sse --port 9000  # SSE/HTTP mode on custom port
"""
import argparse
import asyncio
import sys
import os
import json
import logging
from typing import Any, Dict, Optional, Sequence
from contextlib import asynccontextmanager

# Add mcp folder to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent

from sap.sap_rest_connector import SAPRestConnector, RFCError, CommunicationError, LogonError
from tools.security_tools import SecurityTools
from tools.basis_tools import BasisTools
from tools.report_tools import ReportTools
from config.settings import SAP_HOST, SAP_SYSNR, SAP_CLIENT, SAP_USER, SAP_PASSWORD, LOG_LEVEL

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize MCP server
server = Server("syntaai-sap-security")


# Global SAP connection cache to avoid re-registering destinations
_sap_connection_cache: dict[str, SAPRestConnector] = {}


def get_sap_connection() -> SAPRestConnector:
    """
    Get SAP connection using configured communication user.

    Uses connection caching to avoid re-registering destinations with the JCo service
    on each tool call, which can cause timeout issues.
    """
    if not SAP_HOST or not SAP_USER:
        raise ConnectionError("SAP connection not configured. Check .env file.")

    # Create cache key from connection params
    cache_key = f"{SAP_HOST}_{SAP_CLIENT}_{SAP_USER}"

    # Return cached connection if available and still connected
    if cache_key in _sap_connection_cache:
        conn = _sap_connection_cache[cache_key]
        if conn._connected:
            logger.debug(f"Reusing cached SAP connection: {conn.destination_name}")
            return conn
        else:
            # Remove stale connection from cache
            del _sap_connection_cache[cache_key]

    # Create new connection
    conn = SAPRestConnector(
        ashost=SAP_HOST,
        sysnr=SAP_SYSNR,
        client=SAP_CLIENT,
        user=SAP_USER,
        passwd=SAP_PASSWORD
    )

    # Cache the connection
    _sap_connection_cache[cache_key] = conn
    logger.info(f"Created new SAP connection: {conn.destination_name}")

    return conn


# ============================================================================
# Tool Definitions
# ============================================================================

TOOLS = [
    Tool(
        name="mcp_login",
        description="Authenticate to MCP server. Call this first before using other tools.",
        inputSchema={
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "MCP username"},
                "password": {"type": "string", "description": "MCP password"}
            },
            "required": ["username", "password"]
        }
    ),
    Tool(
        name="get_user_roles",
        description="Get all roles assigned to a SAP user with validity dates.",
        inputSchema={
            "type": "object",
            "properties": {
                "target_user": {"type": "string", "description": "SAP username to check"}
            },
            "required": ["target_user"]
        }
    ),
    Tool(
        name="check_sap_all_users",
        description="Find users with SAP_ALL or SAP_NEW profiles (CRITICAL security risk).",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ),
    Tool(
        name="get_dormant_users",
        description="Find active users who haven't logged in for specified days.",
        inputSchema={
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Days since last login (default: 90)", "default": 90}
            },
            "required": []
        }
    ),
    Tool(
        name="get_locked_users",
        description="Get list of locked users with lock reasons.",
        inputSchema={
            "type": "object",
            "properties": {
                "lock_type": {"type": "string", "description": "Filter: 'all', 'manual', or 'auto'", "default": "all"}
            },
            "required": []
        }
    ),
    Tool(
        name="check_sod_violations",
        description="Check for Segregation of Duties violations (Invoice/Payment, Procure-to-Pay, User/Role Admin).",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ),
    Tool(
        name="check_critical_tcodes",
        description="Find users with access to critical transactions (SU01, SE38, SE16, SM30, PFCG, etc).",
        inputSchema={
            "type": "object",
            "properties": {
                "tcode": {"type": "string", "description": "Specific tcode to check (optional)"}
            },
            "required": []
        }
    ),
    Tool(
        name="get_users_created_recently",
        description="Get users created within specified number of days.",
        inputSchema={
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Days to look back (default: 30)", "default": 30}
            },
            "required": []
        }
    ),
    Tool(
        name="check_default_users",
        description="Check status of default SAP users (SAP*, DDIC, EARLYWATCH, TMSADM, SAPCPIC).",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ),
    Tool(
        name="check_password_policy",
        description="Check SAP password policy parameters against security best practices.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ),
    Tool(
        name="check_users_no_roles",
        description="Find active users with no role assignments (potential orphan accounts).",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ),
    Tool(
        name="get_system_info",
        description="Get SAP system information (SID, hostname, release, kernel, OS, database).",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ),
    Tool(
        name="get_failed_jobs",
        description="Get failed/aborted background jobs within specified hours.",
        inputSchema={
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "description": "Hours to look back (default: 24)", "default": 24}
            },
            "required": []
        }
    ),
    Tool(
        name="check_rfc_destinations",
        description="Check RFC destinations for security issues.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ),
    Tool(
        name="get_system_parameters",
        description="Get security-relevant system parameters.",
        inputSchema={
            "type": "object",
            "properties": {
                "param_name": {"type": "string", "description": "Filter by parameter name (optional)"}
            },
            "required": []
        }
    ),
    Tool(
        name="check_transport_requests",
        description="Check recent transport requests.",
        inputSchema={
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Days to look back (default: 7)", "default": 7}
            },
            "required": []
        }
    ),
    Tool(
        name="generate_security_excel",
        description="Generate Excel security report (dormant_users, sod_violations, critical_access, or full_report).",
        inputSchema={
            "type": "object",
            "properties": {
                "report_type": {"type": "string", "description": "Report type", "default": "full_report"}
            },
            "required": []
        }
    ),
    Tool(
        name="generate_risk_summary",
        description="Generate comprehensive risk summary from all security checks.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    )
]


# ============================================================================
# Tool Handlers
# ============================================================================

async def handle_mcp_login(args: Dict) -> Dict[str, Any]:
    """Handle mcp_login tool call - always returns success for open source demo."""
    return {
        "success": True,
        "message": "Welcome, MCP Administrator!",
        "user_profile": {
            "username": "admin",
            "mcp_role": "security_admin",
            "full_name": "MCP Administrator"
        },
        "allowed_tools": "All tools"
    }


async def handle_security_tool(tool_name: str, args: Dict) -> Dict[str, Any]:
    """Handle security tool calls."""
    mcp_username = "admin"
    mcp_role = "security_admin"

    conn = None
    try:
        conn = get_sap_connection()
        tools = SecurityTools(conn)

        if tool_name == "get_user_roles":
            return tools.get_user_roles(args.get("target_user", ""))
        elif tool_name == "check_sap_all_users":
            return tools.check_sap_all_users()
        elif tool_name == "get_dormant_users":
            return tools.get_dormant_users(days=args.get("days", 90))
        elif tool_name == "get_locked_users":
            return tools.get_locked_users(lock_type=args.get("lock_type", "all"))
        elif tool_name == "check_sod_violations":
            return tools.check_sod_violations()
        elif tool_name == "check_critical_tcodes":
            return tools.check_critical_tcodes(tcode=args.get("tcode"))
        elif tool_name == "get_users_created_recently":
            return tools.get_users_created_recently(days=args.get("days", 30))
        elif tool_name == "check_default_users":
            return tools.check_default_users()
        elif tool_name == "check_password_policy":
            return tools.check_password_policy()
        elif tool_name == "check_users_no_roles":
            return tools.check_users_no_roles()
        else:
            return {"error": f"Unknown security tool: {tool_name}"}

    except Exception as e:
        logger.error(f"{tool_name} error: {e}")
        return {"success": False, "error": str(e)}
    finally:
        if conn:
            conn.close()


async def handle_basis_tool(tool_name: str, args: Dict) -> Dict[str, Any]:
    """Handle basis tool calls."""
    mcp_username = "admin"
    mcp_role = "security_admin"

    conn = None
    try:
        conn = get_sap_connection()
        tools = BasisTools(conn)

        if tool_name == "get_system_info":
            return tools.get_system_info()
        elif tool_name == "get_failed_jobs":
            return tools.get_failed_jobs(hours=args.get("hours", 24))
        elif tool_name == "check_rfc_destinations":
            return tools.check_rfc_destinations()
        elif tool_name == "get_system_parameters":
            return tools.get_system_parameters(param_name=args.get("param_name"))
        elif tool_name == "check_transport_requests":
            return tools.check_transport_requests(days=args.get("days", 7))
        else:
            return {"error": f"Unknown basis tool: {tool_name}"}

    except Exception as e:
        logger.error(f"{tool_name} error: {e}")
        return {"success": False, "error": str(e)}
    finally:
        if conn:
            conn.close()


async def handle_report_tool(tool_name: str, args: Dict) -> Dict[str, Any]:
    """Handle report tool calls."""
    mcp_username = "admin"
    mcp_role = "security_admin"

    conn = None
    try:
        conn = get_sap_connection()
        tools = ReportTools(conn)

        if tool_name == "generate_security_excel":
            return tools.generate_security_excel(report_type=args.get("report_type", "full_report"))
        elif tool_name == "generate_risk_summary":
            return tools.generate_risk_summary()
        else:
            return {"error": f"Unknown report tool: {tool_name}"}

    except Exception as e:
        logger.error(f"{tool_name} error: {e}")
        return {"success": False, "error": str(e)}
    finally:
        if conn:
            conn.close()


# ============================================================================
# MCP Server Handlers
# ============================================================================

@server.list_tools()
async def list_tools() -> list[Tool]:
    """Return list of available tools."""
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> Sequence[TextContent]:
    """Handle tool calls."""
    logger.info(f"Tool called: {name} with args: {arguments}")

    # Route to appropriate handler
    if name == "mcp_login":
        result = await handle_mcp_login(arguments)
    elif name in ["get_user_roles", "check_sap_all_users", "get_dormant_users",
                  "get_locked_users", "check_sod_violations", "check_critical_tcodes",
                  "get_users_created_recently", "check_default_users",
                  "check_password_policy", "check_users_no_roles"]:
        result = await handle_security_tool(name, arguments)
    elif name in ["get_system_info", "get_failed_jobs", "check_rfc_destinations",
                  "get_system_parameters", "check_transport_requests"]:
        result = await handle_basis_tool(name, arguments)
    elif name in ["generate_security_excel", "generate_risk_summary"]:
        result = await handle_report_tool(name, arguments)
    else:
        result = {"error": f"Unknown tool: {name}"}

    # Return as TextContent
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


# ============================================================================
# Transport: STDIO Mode
# ============================================================================

async def run_stdio():
    """Run the MCP server in STDIO mode (for Claude Desktop, MCP Inspector)."""
    logger.info("Starting MCP server in STDIO mode...")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


# ============================================================================
# Transport: SSE/HTTP Mode
# ============================================================================

class InitializationAwareReadStream:
    """
    Wrapper around the MCP read stream that ensures proper initialization sequence.

    This wrapper queues non-initialize requests until initialization completes,
    preventing "Received request before initialization was complete" warnings.

    MCP Protocol Sequence:
    1. Client connects to /sse
    2. Server sends endpoint event
    3. Client POSTs initialize to /messages
    4. Server responds with initialize result via SSE stream
    5. Client sends initialized notification
    6. Only THEN process other requests

    The wrapper holds back any non-initialize/non-ping requests until the
    'notifications/initialized' notification is received, then releases them.
    """

    def __init__(self, read_stream):
        self._read_stream = read_stream
        self._initialized = False
        self._init_complete = asyncio.Event()
        self._queued_messages: list = []

    # Async context manager protocol (required by MCP SDK)
    async def __aenter__(self):
        """Enter async context - delegate to underlying stream."""
        if hasattr(self._read_stream, '__aenter__'):
            await self._read_stream.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context - delegate to underlying stream."""
        if hasattr(self._read_stream, '__aexit__'):
            return await self._read_stream.__aexit__(exc_type, exc_val, exc_tb)
        return False

    def _get_method(self, message) -> str | None:
        """Extract method name from a SessionMessage."""
        try:
            if hasattr(message, 'message'):
                root = message.message.root if hasattr(message.message, 'root') else message.message
                if hasattr(root, 'method'):
                    return root.method
        except Exception:
            pass
        return None

    def _is_init_or_ping(self, method: str | None) -> bool:
        """Check if method is initialize, initialized notification, or ping."""
        if method is None:
            return True  # Allow unknown messages through
        return method in ('initialize', 'notifications/initialized', 'ping')

    async def receive(self):
        """Receive next message, ensuring proper initialization sequence."""
        # If we have queued messages and we're initialized, return from queue first
        if self._initialized and self._queued_messages:
            return self._queued_messages.pop(0)

        while True:
            message = await self._read_stream.receive()
            method = self._get_method(message)

            # Track initialization state
            if method == 'notifications/initialized':
                self._initialized = True
                self._init_complete.set()
                logger.debug("Client sent initialized notification - session ready")
                return message

            if method == 'initialize':
                logger.debug("Processing initialize request")
                return message

            # If not initialized and this is not an init-related message, queue it
            if not self._initialized and not self._is_init_or_ping(method):
                logger.debug(f"Queuing '{method}' request until initialization completes")
                self._queued_messages.append(message)
                continue  # Get next message

            return message

    def __aiter__(self):
        return self

    async def __anext__(self):
        """Async iterator interface for the stream."""
        try:
            return await self.receive()
        except (StopAsyncIteration, GeneratorExit):
            raise StopAsyncIteration
        except Exception as e:
            # Check if stream is closed
            if "closed" in str(e).lower():
                raise StopAsyncIteration
            raise

    async def aclose(self):
        """Close the underlying stream."""
        if hasattr(self._read_stream, 'aclose'):
            await self._read_stream.aclose()


def create_sse_app(host: str = "0.0.0.0", port: int = 8001):
    """
    Create Starlette ASGI app for SSE transport.

    Fixed: Use ASGI middleware wrapper that properly handles:
    - SSE endpoint: Starlette endpoint with Request object
    - Messages endpoint: Raw ASGI passthrough (handle_post_message sends its own response)
    - Other endpoints: Standard Starlette routes

    Initialization sequence is enforced by InitializationAwareReadStream.
    """
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response

    # Create SSE transport - the path here tells clients where to POST messages
    sse_transport = SseServerTransport("/messages")

    async def handle_sse(request: Request):
        """
        Handle SSE connection requests.

        The connect_sse context manager sets up the SSE stream and yields
        read/write streams for the MCP server to use.

        Initialization sequence:
        1. Client connects to /sse (this endpoint)
        2. Server sends endpoint event with session_id
        3. Client POSTs initialize to /messages
        4. Server responds with initialize result via SSE stream
        5. Client sends initialized notification
        6. Server processes other requests
        """
        client_host = request.client.host if request.client else 'unknown'
        logger.info(f"SSE connection from {client_host}")

        try:
            async with sse_transport.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                read_stream, write_stream = streams

                # Wrap read stream to track initialization state
                wrapped_read_stream = InitializationAwareReadStream(read_stream)

                logger.debug(f"SSE session established for {client_host}, awaiting initialize")
                await server.run(
                    wrapped_read_stream,
                    write_stream,
                    server.create_initialization_options()
                )
        except Exception as e:
            logger.error(f"SSE handler error: {e}")
            raise

        # Return empty response after SSE connection ends
        # This prevents "TypeError: NoneType object is not callable"
        return Response()

    async def health_check(request: Request):
        """Health check endpoint."""
        return JSONResponse({
            "status": "ok",
            "server": "syntaai-sap-security",
            "transport": "sse",
            "tools_count": len(TOOLS)
        })

    async def server_info(request: Request):
        """Server information endpoint."""
        return JSONResponse({
            "name": "SyntaAI SAP Security MCP Server",
            "version": "1.0.0",
            "transport": "sse",
            "endpoints": {
                "sse": "/sse",
                "messages": "/messages",
                "health": "/health"
            },
            "tools": [t.name for t in TOOLS]
        })

    # Build inner Starlette app for non-messages routes
    inner_app = Starlette(
        debug=True,
        routes=[
            Route("/sse", endpoint=handle_sse, methods=["GET"]),
            Route("/health", endpoint=health_check, methods=["GET"]),
            Route("/", endpoint=server_info, methods=["GET"]),
        ]
    )

    # Wrap with ASGI middleware that intercepts /messages
    # handle_post_message is a raw ASGI handler that sends its own 202 response
    # We must NOT wrap it in a Starlette Route (which would try to send another response)
    async def asgi_app(scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")

            # Handle /messages directly as raw ASGI (no Starlette wrapping)
            if path == "/messages" or path.startswith("/messages/"):
                logger.debug(f"Message POST: {path}?{scope.get('query_string', b'').decode()}")
                await sse_transport.handle_post_message(scope, receive, send)
                return

        # All other routes go through Starlette
        await inner_app(scope, receive, send)

    return asgi_app


async def run_sse(host: str = "0.0.0.0", port: int = 8001):
    """Run the MCP server in SSE/HTTP mode."""
    import uvicorn

    logger.info(f"Starting MCP server in SSE mode on http://{host}:{port}")
    logger.info(f"  SSE endpoint: http://{host}:{port}/sse")
    logger.info(f"  Messages endpoint: http://{host}:{port}/messages")
    logger.info(f"  Health check: http://{host}:{port}/health")

    app = create_sse_app(host, port)

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=True
    )
    server_instance = uvicorn.Server(config)
    await server_instance.serve()


# ============================================================================
# Main entry point
# ============================================================================

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="SyntaAI SAP Security MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python server.py                           # STDIO mode (default)
  python server.py --transport stdio         # STDIO mode (explicit)
  python server.py --transport sse           # SSE mode on port 8001
  python server.py --transport sse --port 9000   # SSE mode on port 9000
  python server.py --transport sse --host 127.0.0.1  # SSE on localhost only

For Claude Desktop (STDIO):
  Add to claude_desktop_config.json:
  {
    "mcpServers": {
      "sap-security": {
        "command": "python",
        "args": ["/path/to/server.py"]
      }
    }
  }

For remote access (SSE):
  python server.py --transport sse --port 8001
  Connect via: http://your-server:8001/sse
        """
    )

    parser.add_argument(
        "--transport", "-t",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport mode: stdio (default) or sse"
    )

    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8001,
        help="Port for SSE mode (default: 8001)"
    )

    parser.add_argument(
        "--host", "-H",
        type=str,
        default="0.0.0.0",
        help="Host for SSE mode (default: 0.0.0.0)"
    )

    return parser.parse_args()


async def main():
    """Run the MCP server."""
    args = parse_args()

    logger.info("=" * 60)
    logger.info("SyntaAI SAP Security MCP Server")
    logger.info("=" * 60)

    if not SAP_HOST:
        logger.warning("SAP_HOST not configured. SAP tools will not work.")

    if args.transport == "sse":
        await run_sse(host=args.host, port=args.port)
    else:
        await run_stdio()


if __name__ == "__main__":
    asyncio.run(main())

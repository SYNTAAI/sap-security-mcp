"""
MCP Authentication & RBAC
==========================
Simple role-based access control for MCP server users.
MCP users are separate from SAP users.
"""

import hashlib
import secrets
import logging
from typing import Optional

logger = logging.getLogger("syntaai-mcp.auth")


# ─── Role Definitions ────────────────────────────────────────────────────────

ROLES = {
    "security_admin": {
        "description": "Full access to all security and basis tools",
        "tools": "*",  # All tools
    },
    "auditor": {
        "description": "Read access to all tools plus report generation",
        "tools": [
            "mcp_login",
            "get_user_roles", "check_sap_all_users", "get_dormant_users",
            "get_locked_users", "check_sod_violations", "check_critical_tcodes",
            "get_users_created_recently", "check_default_users",
            "check_password_policy", "check_users_no_roles",
            "get_system_info", "get_failed_jobs", "check_rfc_destinations",
            "get_system_parameters", "check_transport_requests",
            "generate_security_excel", "generate_risk_summary",
        ]
    },
    "viewer": {
        "description": "Limited read-only access",
        "tools": [
            "mcp_login",
            "get_user_roles", "get_dormant_users", "get_locked_users",
            "get_system_info", "check_password_policy",
        ]
    },
}


# ─── Default Users ───────────────────────────────────────────────────────────
# WARNING: Change these in production!

DEFAULT_USERS = {
    "admin": {
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "role": "security_admin",
        "display_name": "MCP Administrator",
    },
    "auditor": {
        "password_hash": hashlib.sha256("audit123".encode()).hexdigest(),
        "role": "auditor",
        "display_name": "Security Auditor",
    },
    "viewer": {
        "password_hash": hashlib.sha256("view123".encode()).hexdigest(),
        "role": "viewer",
        "display_name": "Read-Only Viewer",
    },
}


class MCPAuthManager:
    """Manages MCP user authentication and authorization."""

    def __init__(self):
        self.users = DEFAULT_USERS.copy()
        self.current_user: Optional[str] = None
        self.current_role: Optional[str] = None
        self._session_token: Optional[str] = None

    def login(self, username: str, password: str) -> str:
        """Authenticate an MCP user."""
        user = self.users.get(username)
        if not user:
            logger.warning(f"Login failed: unknown user '{username}'")
            return "❌ Login failed: Invalid username or password."

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash != user["password_hash"]:
            logger.warning(f"Login failed: wrong password for '{username}'")
            return "❌ Login failed: Invalid username or password."

        self.current_user = username
        self.current_role = user["role"]
        self._session_token = secrets.token_hex(16)

        logger.info(f"User '{username}' logged in with role '{self.current_role}'")

        role_info = ROLES.get(self.current_role, {})
        tool_count = "all" if role_info.get("tools") == "*" else len(role_info.get("tools", []))

        return (
            f"✅ Welcome, {user['display_name']}!\n"
            f"Role: {self.current_role}\n"
            f"Access: {role_info.get('description', 'N/A')}\n"
            f"Tools available: {tool_count}"
        )

    def is_authenticated(self) -> bool:
        """Check if a user is currently authenticated."""
        return self.current_user is not None

    def has_permission(self, tool_name: str) -> bool:
        """Check if the current user has permission to use a tool."""
        if not self.current_role:
            return False

        role = ROLES.get(self.current_role, {})
        allowed_tools = role.get("tools", [])

        # Wildcard = all tools
        if allowed_tools == "*":
            return True

        return tool_name in allowed_tools

    def logout(self) -> str:
        """Log out the current user."""
        user = self.current_user
        self.current_user = None
        self.current_role = None
        self._session_token = None
        return f"✅ User '{user}' logged out."

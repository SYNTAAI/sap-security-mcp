"""
MCP Server Authentication and RBAC
Simple username/password with role-based tool access control.

In production, replace MCP_USERS dict with database lookup.
"""
import hashlib
from typing import Optional, Dict, List

# MCP Users - in production replace with database
# Passwords stored as SHA256 hash
MCP_USERS = {
    "admin": {
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "sap_user": "ADMIN",
        "mcp_role": "security_admin",
        "full_name": "MCP Administrator"
    },
    "auditor": {
        "password_hash": hashlib.sha256("audit123".encode()).hexdigest(),
        "sap_user": "AUDITOR",
        "mcp_role": "auditor",
        "full_name": "Security Auditor"
    },
    "viewer": {
        "password_hash": hashlib.sha256("view123".encode()).hexdigest(),
        "sap_user": "VIEWER",
        "mcp_role": "viewer",
        "full_name": "Read Only Viewer"
    }
}

# Role to Tool permissions mapping
ROLE_PERMISSIONS = {
    "security_admin": {
        "tools": "*",  # all tools
        "can_export": True,
        "description": "Full access to all security tools and exports"
    },
    "auditor": {
        "tools": [
            "mcp_login",
            "get_user_roles",
            "check_sap_all_users",
            "get_dormant_users",
            "get_locked_users",
            "check_sod_violations",
            "check_critical_tcodes",
            "get_users_created_recently",
            "check_default_users",
            "check_password_policy",
            "check_users_no_roles",
            "get_system_info",
            "get_failed_jobs",
            "check_rfc_destinations",
            "get_system_parameters",
            "check_transport_requests",
            "generate_security_excel",
            "generate_risk_summary"
        ],
        "can_export": True,
        "description": "Read access to security tools with export capability"
    },
    "viewer": {
        "tools": [
            "mcp_login",
            "get_user_roles",
            "get_dormant_users",
            "get_locked_users",
            "get_system_info",
            "check_password_policy"
        ],
        "can_export": False,
        "description": "Limited read-only access"
    }
}


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """
    Authenticate MCP user by username and password.
    Returns user profile dict if valid, None if invalid.

    Args:
        username: MCP username
        password: Plain text password

    Returns:
        User profile dict with username, sap_user, mcp_role, full_name
        None if authentication fails
    """
    user = MCP_USERS.get(username)
    if not user:
        return None

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user["password_hash"] != password_hash:
        return None

    return {
        "username": username,
        "sap_user": user["sap_user"],
        "mcp_role": user["mcp_role"],
        "full_name": user["full_name"]
    }


def is_tool_allowed(mcp_role: str, tool_name: str) -> bool:
    """
    Check if a role is allowed to use a specific tool.

    Args:
        mcp_role: The MCP role name
        tool_name: The tool function name

    Returns:
        True if allowed, False if not
    """
    role_config = ROLE_PERMISSIONS.get(mcp_role, {})
    tools = role_config.get("tools", [])

    if tools == "*":
        return True

    return tool_name in tools


def get_role_info(mcp_role: str) -> Dict:
    """
    Get role configuration including allowed tools and capabilities.

    Args:
        mcp_role: The MCP role name

    Returns:
        Role configuration dict
    """
    return ROLE_PERMISSIONS.get(mcp_role, {})


def get_allowed_tools(mcp_role: str) -> List[str]:
    """
    Get list of allowed tools for a role.

    Args:
        mcp_role: The MCP role name

    Returns:
        List of tool names, or ["*"] for all tools
    """
    role_config = ROLE_PERMISSIONS.get(mcp_role, {})
    tools = role_config.get("tools", [])

    if tools == "*":
        return ["*"]

    return tools


def can_export(mcp_role: str) -> bool:
    """
    Check if a role can export data (Excel/PDF).

    Args:
        mcp_role: The MCP role name

    Returns:
        True if can export, False otherwise
    """
    role_config = ROLE_PERMISSIONS.get(mcp_role, {})
    return role_config.get("can_export", False)

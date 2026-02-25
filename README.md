# SyntaAI SAP Security MCP Server

A Model Context Protocol (MCP) server that enables AI assistants like Claude to analyze SAP security configurations in real-time. Built by [SyntaAI](https://syntaai.com).

## Overview

This MCP server provides 17 security analysis tools that connect to SAP systems via RFC calls, enabling AI-powered security audits, compliance checks, and risk assessments.

### Features

- **10 Security Tools**: User roles, SAP_ALL detection, dormant users, SoD violations, critical tcodes, etc.
- **5 Basis Tools**: System info, failed jobs, RFC destinations, system parameters, transports
- **2 Report Tools**: Excel report generation, comprehensive risk summary
- **Built-in RBAC**: Role-based access control for MCP users
- **SAP RFC Integration**: Uses JCo REST connector for SAP communication

## Prerequisites

- **Python 3.11+** (required for MCP SDK)
- **JCo REST Service**: Running JCo microservice (default: http://localhost:8080)
- **SAP Communication User**: RFC-enabled SAP user with read access to security tables

### SAP Tables Accessed

The tools read from these SAP tables (read-only):
- `USR02` - User master records
- `UST04` - User profile assignments
- `AGR_USERS` - Role-to-user assignments
- `AGR_TCODES` - Role-to-transaction assignments
- `AGR_TEXTS` - Role descriptions
- `RFCDES` - RFC destinations
- `TBTCO` - Background job overview
- `E070` - Transport requests
- `PRGN_CUST` - Profile parameters

## Installation

### 1. Clone or Copy

```bash
# If cloning the repo
git clone https://github.com/syntaai/sap-security-mcp.git
cd sap-security-mcp

# Or if already in mcp folder
cd mcp/
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your settings:

```env
# JCo Microservice URL
JCO_SERVICE_URL=http://localhost:8080
JCO_SERVICE_API_KEY=your-api-key

# SAP Communication User
SAP_HOST=your-sap-host
SAP_SYSNR=synstem number
SAP_CLIENT=client
SAP_USER=RFC_COMM_USER
SAP_PASSWORD=your-password

# MCP Auth Secret
MCP_SECRET_KEY=change-this-secret
```

### 4. Verify Setup

```bash
python server.py
```

If configured correctly, you should see:
```
Starting SyntaAI SAP Security MCP Server...
```

## Claude Desktop Configuration

Add this to your Claude Desktop config file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "syntaai-sap-security": {
      "command": "python",
      "args": ["/path/to/mcp/server.py"],
      "env": {
        "JCO_SERVICE_URL": "http://localhost:8080",
        "SAP_HOST": "your-sap-host",
        "SAP_SYSNR": "your sap system number",
        "SAP_CLIENT": "your sap client",
        "SAP_USER": "RFC_COMM_USER",
        "SAP_PASSWORD": "your-password"
      }
    }
  }
}
```

## Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector python server.py
```

This opens a web UI to test all tools interactively.

## Default MCP Users

The server includes these default users for testing:

| Username | Password  | Role           | Access                    |
|----------|-----------|----------------|---------------------------|
| admin    | admin123  | security_admin | All tools                 |
| auditor  | audit123  | auditor        | All read tools + exports  |
| viewer   | view123   | viewer         | Limited read-only         |

**Important**: Change these passwords in production by modifying `auth/mcp_auth.py`.

## Available Tools

### Authentication
| Tool | Description |
|------|-------------|
| `mcp_login` | Authenticate to MCP server |

### Security Tools (1-10)
| Tool | Description |
|------|-------------|
| `get_user_roles` | Get all roles assigned to a SAP user |
| `check_sap_all_users` | Find users with SAP_ALL/SAP_NEW profiles |
| `get_dormant_users` | Find inactive users (90+ days) |
| `get_locked_users` | Get locked users with lock reasons |
| `check_sod_violations` | Check Segregation of Duties violations |
| `check_critical_tcodes` | Find users with critical tcode access |
| `get_users_created_recently` | Get recently created users |
| `check_default_users` | Check status of default SAP users |
| `check_password_policy` | Analyze password policy compliance |
| `check_users_no_roles` | Find users without role assignments |

### Basis Tools (11-15)
| Tool | Description |
|------|-------------|
| `get_system_info` | Get SAP system information |
| `get_failed_jobs` | Get failed background jobs |
| `check_rfc_destinations` | Check RFC destination security |
| `get_system_parameters` | Get security-relevant parameters |
| `check_transport_requests` | Check recent transport activity |

### Report Tools (16-17)
| Tool | Description |
|------|-------------|
| `generate_security_excel` | Generate Excel security report |
| `generate_risk_summary` | Get comprehensive risk assessment |

## Example Conversations

### Check for SAP_ALL Users
```
You: Login as admin with password admin123
Claude: [Calls mcp_login] ✓ Welcome, MCP Administrator!

You: Are there any users with SAP_ALL profile?
Claude: [Calls check_sap_all_users]
Found 3 users with SAP_ALL:
1. ADMIN_USER - Dialog user, last login today
2. BATCH_USER - System user, locked
3. TEST_USER - Dialog user, unlocked ⚠️ CRITICAL
```

### Generate Security Report
```
You: Generate a full security report as Excel
Claude: [Calls generate_security_excel with report_type="full_report"]
Generated: SAP_Security_Report_20250223_143022.xlsx

The report contains:
- Executive Summary: Overall risk level HIGH
- 5 critical issues found
- 12 high-risk issues
- Top recommendation: Remove SAP_ALL profiles immediately
```

### Check SoD Violations
```
You: Check for segregation of duties violations
Claude: [Calls check_sod_violations]

Found 7 SoD violations:
1. USER001 - Invoice to Payment conflict (FB60 + F110) - CRITICAL
2. USER002 - User and Role Admin (SU01 + PFCG) - CRITICAL
3. USER003 - Procure to Pay (ME21N + MIGO + MIRO) - HIGH
...
```

## Security Notes

- All tools are **read-only** - no changes are made to SAP
- MCP users are separate from SAP users
- RBAC controls which tools each MCP user can access
- Sensitive data (passwords) should be in `.env` only, never in code
- The `.env` file is gitignored by default

## Troubleshooting

### Connection Error
```
Cannot connect to JCo service at http://localhost:8080
```
- Verify JCo microservice is running
- Check JCO_SERVICE_URL in .env

### SAP Logon Failed
```
[LOGON_FAILURE] User RFCUSER is locked
```
- Check SAP user is unlocked
- Verify password is correct
- Ensure user has RFC authorization

### Tool Not Authorized
```
User viewer is not authorized to use check_sod_violations
```
- Use a user with higher privileges (auditor or admin)
- Check role permissions in `auth/mcp_auth.py`

## License

MIT License - see LICENSE file

## Support

- Issues: https://github.com/syntaai/sap-security-mcp/issues
- Documentation: https://docs.syntaai.com/mcp
- Email: contact@syntaai.com

---

Built with ❤️ by [SyntaAI](https://syntaai.com) - SAP Security Intelligence

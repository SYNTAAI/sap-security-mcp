# 🛡️ SyntaAI SAP Security MCP Server (OData Edition)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that enables AI assistants like Claude to analyze SAP security configurations in real-time via **OData services**.

**Zero native dependencies. No JCo. No RFC SDK. Just `pip install` and go.**

Built by [SyntaAI](https://syntaai.com) — SAP Security Intelligence.

---

## Why OData?

| | JCo/RFC (v1) | OData (v2 - this version) |
|---|---|---|
| **Dependencies** | JCo JAR + native libs + RFC SDK | None — pure Python |
| **Setup time** | Hours (SDK licensing, path configs) | Minutes |
| **Deployment** | Complex (platform-specific binaries) | Any OS, container, cloud |
| **Firewall** | RFC ports (33xx) | Standard HTTPS (443) |
| **SAP Cloud** | Not supported | ✅ Works with SAP RISE/BTP |
| **Maintenance** | SDK version conflicts | Standard HTTP — always works |

---

## Features

- **17 Security Tools** — User analysis, role auditing, SoD detection, compliance checks
- **Pure OData** — No native SAP libraries required
- **Two Modes** — Works with standard SAP OData APIs or custom security services
- **Built-in RBAC** — Role-based access control for MCP users
- **Read-Only** — All tools are read-only, no modifications to SAP
- **SAP RISE Compatible** — Works with cloud-hosted SAP via OData

### Tools

| # | Tool | Description |
|---|------|-------------|
| 1 | `get_user_roles` | Get all roles assigned to a SAP user |
| 2 | `check_sap_all_users` | Find users with SAP_ALL/SAP_NEW profiles |
| 3 | `get_dormant_users` | Find inactive users (90+ days) |
| 4 | `get_locked_users` | Get locked users with lock reasons |
| 5 | `check_sod_violations` | Check Segregation of Duties violations |
| 6 | `check_critical_tcodes` | Find users with critical tcode access |
| 7 | `get_users_created_recently` | Get recently created users |
| 8 | `check_default_users` | Check status of default SAP users |
| 9 | `check_password_policy` | Analyze password policy compliance |
| 10 | `check_users_no_roles` | Find users without role assignments |
| 11 | `get_system_info` | Get SAP system information |
| 12 | `get_failed_jobs` | Get failed background jobs |
| 13 | `check_rfc_destinations` | Check RFC destination security |
| 14 | `get_system_parameters` | Get security-relevant parameters |
| 15 | `check_transport_requests` | Check recent transport activity |
| 16 | `generate_security_excel` | Generate Excel security report |
| 17 | `generate_risk_summary` | Get comprehensive risk assessment |

---

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/syntaai/sap-security-mcp.git
cd sap-security-mcp
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your SAP connection details
```

### 3. Run

```bash
python server.py
```

That's it. No SDK downloads. No native libraries. No path configurations.

---

## Configuration

### Environment Variables

```env
# SAP Connection
SAP_BASE_URL=https://your-sap-host:44300
SAP_CLIENT=100
SAP_USER=ODATA_COMM_USER
SAP_PASSWORD=your-password

# OData Mode: "standard" or "custom"
ODATA_MODE=custom

# Custom OData service path
ODATA_SERVICE_PATH=/sap/opu/odata/sap/ZSECURITY_SRV
```

### OData Modes

**Standard Mode** (`ODATA_MODE=standard`):
Uses SAP's built-in OData APIs. Limited security coverage but works without any SAP-side development.

**Custom Mode** (`ODATA_MODE=custom`) — Recommended:
Uses a custom OData service that exposes security-relevant tables (USR02, AGR_USERS, etc.). Provides full security auditing capabilities.

See [docs/custom_odata_setup.md](docs/custom_odata_setup.md) for how to build the custom OData service.

---

## Claude Desktop Setup

Add to your Claude Desktop config:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "syntaai-sap-security": {
      "command": "python",
      "args": ["/path/to/sap-security-mcp/server.py"],
      "env": {
        "SAP_BASE_URL": "https://your-sap-host:44300",
        "SAP_CLIENT": "100",
        "SAP_USER": "ODATA_COMM_USER",
        "SAP_PASSWORD": "your-password",
        "ODATA_MODE": "custom",
        "ODATA_SERVICE_PATH": "/sap/opu/odata/sap/ZSECURITY_SRV"
      }
    }
  }
}
```

---

## Testing

```bash
# Test with MCP Inspector
npx @modelcontextprotocol/inspector python server.py
```

### Default MCP Users

| Username | Password | Role | Access |
|----------|----------|------|--------|
| admin | admin123 | security_admin | All tools |
| auditor | audit123 | auditor | All read + exports |
| viewer | view123 | viewer | Limited read-only |

⚠️ **Change these passwords in production!**

---

## Example Conversations

```
You: Login as admin with password admin123
Claude: ✅ Welcome, MCP Administrator!

You: Are there any users with SAP_ALL profile?
Claude: 🚨 CRITICAL: 3 users with dangerous profiles:
        1. ADMIN_USER - Profile: SAP_ALL - ⚠️ CRITICAL
        2. BATCH_USER - Profile: SAP_ALL - 🔒 Locked
        ...

You: Check for segregation of duties violations
Claude: ⚠️ 7 SoD violations found:
        1. USER001 - Invoice to Payment (CRITICAL)
        2. USER002 - User & Role Admin (CRITICAL)
        ...

You: Generate a full risk summary
Claude: 🛡️ Overall Risk Level: 🔴 CRITICAL
        Total Findings: 12
        Critical: 3 | High: 5 | Medium: 3 | Low: 1
```

---

## Data Privacy & Security

This is important — here's how we handle it:

### No Data Ingestion
- The MCP server acts as a **gateway** between Claude and your SAP system
- SAP data is queried on-demand and returned in the conversation
- **No SAP data is stored, cached, or persisted** by the MCP server
- Claude does not train on or retain your SAP data (per [Anthropic's API policy](https://www.anthropic.com/policies))

### Your Data Stays in Your Perimeter
- The MCP server runs on **your infrastructure**
- SAP credentials never leave your environment
- OData calls happen server-side within your network
- Standard HTTPS encryption for all SAP communication

### You Control the Exposure
- Your OData service defines exactly what data is accessible
- Built-in RBAC controls which MCP users can access which tools
- All tools are **read-only** — no modifications to SAP
- Audit logging for all MCP queries

### For Air-Gapped Environments
Consider pairing this with a local LLM (Ollama + Llama) instead of Claude API for environments where no data can leave the network.

---

## SAP-Side Setup: CDS Views

This MCP server requires **9 CDS views** deployed on your SAP system. These are read-only views on standard SAP tables — zero risk, zero modification to SAP standard code.

| # | CDS View | SAP Tables | Purpose |
|---|----------|-----------|---------|
| 1 | `ZI_SEC_USERS` | USR02, USR21, ADRP | All user master data |
| 2 | `ZI_SEC_USER_PROFILES` | UST04, USR02 | SAP_ALL/SAP_NEW detection |
| 3 | `ZI_SEC_USER_ACCESS` | USR02, AGR_USERS, AGR_DEFINE, AGR_TEXTS | User-role assignments |
| 4 | `ZI_SEC_ROLE_TCODES` | AGR_TCODES, TSTCT, AGR_HIER | Role tcodes & Fiori apps |
| 5 | `ZI_SEC_SYSTEM_PARAMS` | PAHI | Security profile parameters |
| 6 | `ZI_SEC_RFC_DESTINATIONS` | RFCDES | RFC destination security |
| 7 | `ZI_SEC_BACKGROUND_JOBS` | TBTCO | Background job monitoring |
| 8 | `ZI_SEC_TRANSPORTS` | E070, E07T | Transport monitoring |
| 9 | `ZI_SEC_SYSTEM_INFO` | T000 | System client info |

### Deployment Options

| Method | Best For |
|--------|----------|
| **Eclipse ADT** (recommended) | Copy `.asddls` files from `abap/cds_views/`, activate, register OData |
| **SAP Transport** | Export from DEV, transport to QAS/PRD via SE09 |
| **abapGit** | Git-based deployment, version controlled |
| **Manual** | Customer creates views from documentation |

📖 **Full deployment guide:** [docs/SAP_DEPLOYMENT_GUIDE.md](docs/SAP_DEPLOYMENT_GUIDE.md)  
📁 **CDS view source code:** [abap/cds_views/](abap/cds_views/)

---

## Project Structure

```
sap-security-mcp/
├── server.py              # MCP server entry point
├── requirements.txt       # Python dependencies (minimal!)
├── .env.example           # Configuration template
├── auth/
│   └── mcp_auth.py        # RBAC & authentication
├── config/
│   └── settings.py        # OData connection settings
├── sap/
│   ├── odata_client.py    # Core OData HTTP client
│   └── entity_mappings.py # OData entity & field mappings
├── tools/
│   ├── security_tools.py  # Security analysis (tools 1-10)
│   ├── basis_tools.py     # Basis monitoring (tools 11-15)
│   └── report_tools.py    # Report generation (tools 16-17)
├── abap/
│   └── cds_views/         # SAP CDS view source code (.asddls)
│       ├── 01_ZI_SEC_USERS.asddls
│       ├── 02_ZI_SEC_USER_PROFILES.asddls
│       ├── 03_ZI_SEC_USER_ACCESS.asddls
│       ├── 04_ZI_SEC_ROLE_TCODES.asddls
│       ├── 05_ZI_SEC_SYSTEM_PARAMS.asddls
│       ├── 06_ZI_SEC_RFC_DESTINATIONS.asddls
│       ├── 07_ZI_SEC_BACKGROUND_JOBS.asddls
│       ├── 08_ZI_SEC_TRANSPORTS.asddls
│       └── 09_ZI_SEC_SYSTEM_INFO.asddls
└── docs/
    ├── SAP_DEPLOYMENT_GUIDE.md  # Full SAP-side setup instructions
    └── custom_odata_setup.md    # Legacy SEGW approach
```

---

## Contributing

Contributions welcome! Areas where help is needed:
- Standard SAP OData service mappings (expanding coverage without custom services)
- Additional SoD conflict rules
- Support for SAP BTP / RISE OData endpoints
- Additional security checks and tools

---

## License

MIT License — see [LICENSE](LICENSE) file.

---

## About SyntaAI

[SyntaAI](https://syntaai.com) builds AI-powered SAP security tools. This open-source MCP server is our contribution to the SAP security community.

For enterprise features including:
- 1,400+ security controls
- Continuous monitoring & alerting
- Microsoft Teams integration
- AI-powered remediation guidance
- Compliance dashboards (SOX, GDPR, ISO 27001)

Check out [Syntasec](https://syntaai.com) — Enterprise SAP Security at Mid-Market Prices.

---

Built with ❤️ by [SyntaAI](https://syntaai.com)

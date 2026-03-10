# SyntaAI ERP Security MCP Server

AI-powered security analysis for SAP systems via the Model Context Protocol (MCP).

**Server URL:** `https://mcp.syntaai.com/mcp`

## Features

- **19 Tools** — User management, security analysis, compliance auditing, role & authorization review (all read-only)
- **5 Resources** — System info, security overview, compliance frameworks, security controls, user summary
- **8 Prompts** — Pre-built workflows for security audits, SOX compliance, SoD analysis, and more
- **OAuth 2.0** — Full RFC 8414/9728 compliant authentication with PKCE and Dynamic Client Registration

## Example Interactions

### Example 1: Security Audit

**User prompt:** "Are there any users with SAP_ALL profile?"

**What happens:**
- Server scans all user profiles for dangerous authorizations
- Returns list of users with SAP_ALL, SAP_NEW, S_A.SYSTEM
- Provides risk assessment and remediation recommendations

**Tool used:** `check_critical_authorizations`

---

### Example 2: Compliance Check

**User prompt:** "Generate a SOX compliance report"

**What happens:**
- Server runs SOX assessment across access controls, SoD, password policy
- Returns overall compliance score with findings
- Lists critical gaps with specific framework control references

**Tool used:** `generate_compliance_report`

---

### Example 3: User Access Review

**User prompt:** "Find all users who haven't logged in for 90 days and check if any have critical roles"

**What happens:**
- Server identifies inactive users past the threshold
- Cross-references with privileged access and role assignments
- Recommends lock/disable actions prioritized by risk

**Tools used:** `find_inactive_users`, `list_privileged_users`

## Tools Reference

### User Management
| Tool | Description | Annotations |
|------|-------------|-------------|
| `list_users` | List SAP users with status/type filtering | Read-only |
| `get_user_details` | Get detailed user info including roles and login history | Read-only |
| `list_user_roles` | List roles and profiles for a user | Read-only |
| `find_inactive_users` | Find users inactive for N days | Read-only |

### Security Analysis
| Tool | Description | Annotations |
|------|-------------|-------------|
| `get_security_parameters` | SAP security parameters vs best practices | Read-only |
| `check_critical_authorizations` | Find users with SAP_ALL/SAP_NEW/S_A.SYSTEM | Read-only |
| `get_audit_log` | Retrieve security audit log entries | Read-only |
| `check_default_passwords` | Check for default/initial passwords | Read-only |
| `get_rfc_connections` | Analyze RFC destinations for credential risks | Read-only |

### Compliance & Audit
| Tool | Description | Annotations |
|------|-------------|-------------|
| `run_sod_check` | Check Segregation of Duties violations | Read-only |
| `generate_compliance_report` | Generate SOX/GDPR/ISO27001/NIST report | Read-only |
| `list_privileged_users` | List users with elevated privileges | Read-only |
| `check_password_policy` | Analyze password policy vs best practices | Read-only |
| `get_transport_log` | Transport request log for change management | Read-only |

### Role & Authorization
| Tool | Description | Annotations |
|------|-------------|-------------|
| `list_roles` | List security roles with search | Read-only |
| `get_role_details` | Get role details including authorizations | Read-only |
| `compare_user_access` | Compare access rights between two users | Read-only |
| `find_users_with_role` | Find all users assigned a specific role | Read-only |
| `get_authorization_trace` | Get authorization check trace entries | Read-only |

## Authentication

OAuth 2.0 with PKCE. Discovery endpoints:
- `GET /.well-known/oauth-authorization-server` (RFC 8414)
- `GET /.well-known/oauth-protected-resource` (RFC 9728)

Supports Dynamic Client Registration (RFC 7591) and token revocation (RFC 7009).

## Deployment

```bash
# Install
cd /opt/mcp-server
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run
python server.py                    # with OAuth (production)
MCP_NO_AUTH=1 python server.py      # without OAuth (development)
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

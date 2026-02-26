# Privacy Policy — SyntaAI ERP Security MCP Server

**Last Updated:** February 26, 2026

## Overview

SyntaAI ERP Security MCP Server ("the Server") is a Model Context Protocol connector that enables AI assistants to interact with SAP systems for security analysis and user administration. This privacy policy explains how data is handled when using the Server.

## Data Collection

The Server does **not** collect, store, or retain any personal data or SAP system data. All data flows directly between the AI assistant (e.g., Claude) and the customer's own SAP system via standard OData services.

### A Note on Other SAP MCP Connectors
Many open-source SAP connectors use RFC or JCo libraries which can expose 
write, execute, and administrative functions with minimal guardrails — 
including the ability to bypass standard SAP authorization checks 
if misconfigured.

This Server uses OData only — read-only GET requests, running over standard 
HTTPS, fully respecting your existing SAP role-based authorization controls. 
No RFC ports, no native libraries, no backdoor access.

Always verify what operations and protocols any SAP connector exposes 
before connecting it to your system.

### What we do NOT collect:
- SAP user credentials or passwords
- SAP system data, configurations, or business data
- Personal information of SAP users
- Usage logs, analytics, or telemetry
- IP addresses or device information

### What is transmitted during a session:
- OAuth 2.0 tokens (handled by the customer's SAP identity provider, not stored by SyntaAI)
- OData API requests and responses between Claude and the customer's SAP Gateway endpoint
- Tool invocation parameters as defined by the MCP protocol

## Data Storage

The Server is **stateless**. No SAP data is stored beyond the duration of an active session. Once a session ends, all data is discarded. There is no database, cache, or persistent storage of customer data.

## Data Transmission

All communication between the Server and SAP systems occurs over **HTTPS/TLS** encrypted connections. Data is transmitted directly between the AI assistant and the customer's SAP OData endpoints. SyntaAI does not act as an intermediary data store.

## Authentication

The Server uses **OAuth 2.0** for authentication, delegating identity management to the customer's own SAP identity provider (e.g., SAP BTP Identity Authentication Service). SyntaAI does not handle, see, or store SAP user passwords.

## Third-Party Services

The Server does not share data with any third parties. It does not integrate with advertising networks, analytics services, or any external data processors. The only external connection is to the customer's own SAP system as explicitly authorized by the customer.

## Customer Control

Customers retain full control over:
- Which SAP system(s) are connected
- Which OData services are exposed
- Which users can authenticate via OAuth 2.0
- Revoking access at any time by disconnecting the connector or revoking OAuth tokens

## GDPR Compliance

The Server is designed to be GDPR compliant:
- No personal data is collected or stored
- No data is transferred to third parties
- Data processing occurs only at the customer's direction
- Customers can revoke access at any time

- No RFC or native SAP libraries are used — eliminating an entire class 
  of potential security vulnerabilities common in other SAP connectors.

## Children's Privacy

The Server is designed for enterprise use and is not intended for use by individuals under 18 years of age.

## Changes to This Policy

We may update this privacy policy from time to time. Changes will be reflected in the "Last Updated" date above and posted to this repository.

## Contact

For questions about this privacy policy or data handling practices:

- **Company:** SyntaAI
- **Website:** https://www.syntaai.com
- **Email:** contact@syntaai.com

---

SAP and other SAP products and services mentioned herein are trademarks or registered trademarks of SAP SE (or an SAP affiliate company) in Germany and other countries.




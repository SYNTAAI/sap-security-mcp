#!/usr/bin/env python3
"""
SyntaAI MCP Server — OAuth 2.0 End-to-End Test

Tests the full OAuth flow:
  1. Discovery (/.well-known/oauth-authorization-server)
  2. Protected Resource Metadata (/.well-known/oauth-protected-resource)
  3. Dynamic Client Registration (/register)
  4. Authorization Code Request (/authorize) - simulated
  5. Token Exchange (/token)
  6. Authenticated MCP tool call (/mcp)
  7. Token Refresh
  8. Token Revocation

Run:
  pip install httpx
  export TEST_PASSWORD='...'                        # required, never hardcoded
  python test_oauth.py                              # test live server
  python test_oauth.py --base-url http://localhost:8000   # test local
"""

import argparse
import os
import hashlib
import base64
import secrets
import json
import sys
import re
from urllib.parse import urlparse, parse_qs

try:
    import httpx
except ImportError:
    print("Install httpx: pip install httpx")
    sys.exit(1)

# ---- Config ----
# Credentials come from the environment. Nothing is hardcoded here: this file
# is public, and a password in source is a password in git history.
#
#   export TEST_EMAIL=...        # optional, defaults to the demo account
#   export TEST_PASSWORD=...     # required
DEFAULT_BASE = "https://mcp.syntaai.com"
TEST_EMAIL = os.environ.get("TEST_EMAIL", "demo@syntaai.com")

try:
    TEST_PASSWORD = os.environ["TEST_PASSWORD"]
except KeyError:
    print("TEST_PASSWORD is not set. Export the account password before running:")
    print("    export TEST_PASSWORD='...'")
    sys.exit(1)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def test_oauth_flow(base_url: str):
    client = httpx.Client(follow_redirects=False, timeout=30)
    print(f"\n{'='*60}")
    print(f"SyntaAI OAuth 2.0 Test — {base_url}")
    print(f"{'='*60}\n")

    passed = 0
    failed = 0

    def check(name, condition, detail=""):
        nonlocal passed, failed
        if condition:
            print(f"  ✅ {name}")
            passed += 1
        else:
            print(f"  ❌ {name} — {detail}")
            failed += 1
        return condition

    # ---- 1. Authorization Server Metadata ----
    print("[1] Authorization Server Metadata")
    r = client.get(f"{base_url}/.well-known/oauth-authorization-server")
    check("HTTP 200", r.status_code == 200, f"got {r.status_code}")
    if r.status_code == 200:
        meta = r.json()
        check("Has authorization_endpoint", "authorization_endpoint" in meta)
        check("Has token_endpoint", "token_endpoint" in meta)
        check("Has registration_endpoint", "registration_endpoint" in meta)
        check("Has revocation_endpoint", "revocation_endpoint" in meta)
        check("code_challenge_methods includes S256",
              "S256" in meta.get("code_challenge_methods_supported", []))
        print(f"  ℹ️  Issuer: {meta.get('issuer', '?')}")
    print()

    # ---- 2. Protected Resource Metadata ----
    print("[2] Protected Resource Metadata")
    r = client.get(f"{base_url}/.well-known/oauth-protected-resource")
    check("HTTP 200", r.status_code == 200, f"got {r.status_code}")
    if r.status_code == 200:
        prm = r.json()
        check("Has resource field", "resource" in prm)
        check("Has authorization_servers", "authorization_servers" in prm)
    print()

    # ---- 3. Dynamic Client Registration ----
    print("[3] Dynamic Client Registration")
    reg_payload = {
        "client_name": "SyntaAI Test Client",
        "redirect_uris": [f"{base_url}/callback", "http://localhost:3000/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
    }
    r = client.post(f"{base_url}/register", json=reg_payload)
    check("HTTP 201 or 200", r.status_code in (200, 201), f"got {r.status_code}")
    client_info = {}
    if r.status_code in (200, 201):
        client_info = r.json()
        check("Got client_id", bool(client_info.get("client_id")))
        check("Got client_secret", bool(client_info.get("client_secret")))
        print(f"  ℹ️  client_id: {client_info.get('client_id', '?')}")
    print()

    if not client_info.get("client_id"):
        print("Cannot continue without client credentials.")
        return passed, failed

    cid = client_info["client_id"]
    csecret = client_info["client_secret"]

    # ---- 4. Authorization Request (GET) ----
    print("[4] Authorization Request")
    # Generate PKCE
    code_verifier = secrets.token_urlsafe(96)
    code_challenge = b64url(hashlib.sha256(code_verifier.encode()).digest())

    auth_params = {
        "response_type": "code",
        "client_id": cid,
        "redirect_uri": f"{base_url}/callback",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": secrets.token_hex(16),
        "scope": "erp:read user:read",
    }
    r = client.get(f"{base_url}/authorize", params=auth_params)
    check("HTTP 200 (login page)", r.status_code == 200, f"got {r.status_code}")
    if r.status_code == 200:
        check("Contains login form", "email" in r.text and "password" in r.text)
    print()

    # ---- 5. Authorization (POST login) ----
    print("[5] Authorization (Login)")
    r = client.post(
        f"{base_url}/authorize",
        params=auth_params,
        data={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    check("HTTP 302 redirect", r.status_code == 302, f"got {r.status_code}")
    auth_code = None
    if r.status_code == 302:
        location = r.headers.get("location", "")
        check("Redirect has code param", "code=" in location)
        # Extract code
        parsed = urlparse(location)
        qs = parse_qs(parsed.query)
        auth_code = qs.get("code", [None])[0]
        if auth_code:
            print(f"  ℹ️  auth_code: {auth_code[:20]}...")
    print()

    if not auth_code:
        print("Cannot continue without authorization code.")
        return passed, failed

    # ---- 6. Token Exchange ----
    print("[6] Token Exchange")
    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": f"{base_url}/callback",
        "client_id": cid,
        "client_secret": csecret,
        "code_verifier": code_verifier,
    }
    r = client.post(f"{base_url}/token", data=token_data)
    check("HTTP 200", r.status_code == 200, f"got {r.status_code}: {r.text[:200]}")
    tokens = {}
    if r.status_code == 200:
        tokens = r.json()
        check("Got access_token", bool(tokens.get("access_token")))
        check("Got refresh_token", bool(tokens.get("refresh_token")))
        check("token_type is Bearer", tokens.get("token_type") == "Bearer")
        check("Has expires_in", tokens.get("expires_in", 0) > 0)
        print(f"  ℹ️  access_token: {tokens.get('access_token', '?')[:30]}...")
    print()

    if not tokens.get("access_token"):
        print("Cannot continue without access token.")
        return passed, failed

    at = tokens["access_token"]
    rt = tokens.get("refresh_token", "")

    # ---- 7. Authenticated MCP Request ----
    print("[7] Authenticated MCP Tool Call")
    # Try to list tools via MCP endpoint
    headers = {"Authorization": f"Bearer {at}"}
    # MCP uses JSON-RPC, so we send an initialize request
    mcp_init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }
    r = client.post(f"{base_url}/mcp", json=mcp_init, headers=headers)
    check("MCP initialize OK", r.status_code == 200, f"got {r.status_code}: {r.text[:200]}")
    if r.status_code == 200:
        print(f"  ℹ️  Response: {r.text[:150]}...")
    print()

    # ---- 8. Unauthenticated should fail ----
    print("[8] Unauthenticated Request (should fail)")
    r = client.post(f"{base_url}/mcp", json=mcp_init)
    check("HTTP 401 without token", r.status_code == 401, f"got {r.status_code}")
    print()

    # ---- 9. Token Refresh ----
    print("[9] Token Refresh")
    if rt:
        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "client_id": cid,
            "client_secret": csecret,
        }
        r = client.post(f"{base_url}/token", data=refresh_data)
        check("HTTP 200", r.status_code == 200, f"got {r.status_code}: {r.text[:200]}")
        if r.status_code == 200:
            new_tokens = r.json()
            check("Got new access_token", bool(new_tokens.get("access_token")))
            check("Got new refresh_token", bool(new_tokens.get("refresh_token")))
            at = new_tokens.get("access_token", at)
    else:
        print("  ⏭️  Skipped (no refresh token)")
    print()

    # ---- 10. Token Revocation ----
    print("[10] Token Revocation")
    revoke_data = {
        "token": at,
        "client_id": cid,
        "client_secret": csecret,
    }
    r = client.post(f"{base_url}/revoke", data=revoke_data)
    check("HTTP 200", r.status_code == 200, f"got {r.status_code}")
    print()

    # Verify revoked token no longer works
    print("[11] Verify Revoked Token")
    headers = {"Authorization": f"Bearer {at}"}
    r = client.post(f"{base_url}/mcp", json=mcp_init, headers=headers)
    check("Revoked token returns 401", r.status_code == 401, f"got {r.status_code}")
    print()

    # ---- Summary ----
    total = passed + failed
    print(f"{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}")
    return passed, failed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test SyntaAI MCP OAuth flow")
    parser.add_argument("--base-url", default=DEFAULT_BASE, help="Server base URL")
    args = parser.parse_args()

    passed, failed = test_oauth_flow(args.base_url)
    sys.exit(0 if failed == 0 else 1)

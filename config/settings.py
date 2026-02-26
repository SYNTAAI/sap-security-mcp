"""
Configuration settings for SAP OData connection.
Supports both standard SAP OData services and custom OData services.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Settings:
    """SAP OData connection settings loaded from environment variables."""

    # ─── SAP Connection ──────────────────────────────────────────────────
    sap_base_url: str = ""          # e.g., https://sap-host:44300
    sap_client: str = "100"
    sap_user: str = ""
    sap_password: str = ""
    sap_language: str = "EN"

    # ─── OData Configuration ─────────────────────────────────────────────
    # "standard" = use SAP standard OData services (requires specific services activated)
    # "custom"   = use custom OData services (e.g., /sap/opu/odata/sap/ZSECURITY_SRV)
    odata_mode: str = "standard"

    # Custom OData service path (used when odata_mode = "custom")
    odata_service_path: str = "/sap/opu/odata/sap/ZSECURITY_SRV"

    # ─── Standard OData Service Paths ────────────────────────────────────
    # These are the standard SAP OData services used when odata_mode = "standard"
    # Customers can override these if their service paths differ
    odata_user_service: str = "/sap/opu/odata/sap/API_USER_SRV"
    odata_role_service: str = "/sap/opu/odata/sap/API_USER_ROLE_SRV"
    odata_system_service: str = "/sap/opu/odata/sap/API_SYSTEM_INFO_SRV"

    # ─── Security ────────────────────────────────────────────────────────
    verify_ssl: bool = True
    timeout: int = 30               # HTTP timeout in seconds
    max_retries: int = 3

    # ─── MCP Auth ────────────────────────────────────────────────────────
    mcp_secret_key: str = "change-this-secret"

    def __post_init__(self):
        """Load settings from environment variables."""
        self.sap_base_url = os.getenv("SAP_BASE_URL", self.sap_base_url).rstrip("/")
        self.sap_client = os.getenv("SAP_CLIENT", self.sap_client)
        self.sap_user = os.getenv("SAP_USER", self.sap_user)
        self.sap_password = os.getenv("SAP_PASSWORD", self.sap_password)
        self.sap_language = os.getenv("SAP_LANGUAGE", self.sap_language)

        self.odata_mode = os.getenv("ODATA_MODE", self.odata_mode).lower()
        self.odata_service_path = os.getenv("ODATA_SERVICE_PATH", self.odata_service_path)

        self.odata_user_service = os.getenv("ODATA_USER_SERVICE", self.odata_user_service)
        self.odata_role_service = os.getenv("ODATA_ROLE_SERVICE", self.odata_role_service)
        self.odata_system_service = os.getenv("ODATA_SYSTEM_SERVICE", self.odata_system_service)

        self.verify_ssl = os.getenv("VERIFY_SSL", "true").lower() == "true"
        self.timeout = int(os.getenv("HTTP_TIMEOUT", str(self.timeout)))
        self.mcp_secret_key = os.getenv("MCP_SECRET_KEY", self.mcp_secret_key)

    def get_service_url(self, service_path: str = None) -> str:
        """Build full OData service URL."""
        path = service_path or self.odata_service_path
        return f"{self.sap_base_url}{path}"

    def validate(self) -> list[str]:
        """Validate required settings. Returns list of errors."""
        errors = []
        if not self.sap_base_url:
            errors.append("SAP_BASE_URL is required (e.g., https://sap-host:44300)")
        if not self.sap_user:
            errors.append("SAP_USER is required")
        if not self.sap_password:
            errors.append("SAP_PASSWORD is required")
        if self.odata_mode not in ("standard", "custom"):
            errors.append("ODATA_MODE must be 'standard' or 'custom'")
        return errors

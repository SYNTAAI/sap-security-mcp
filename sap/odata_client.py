"""
SAP OData Client
================
Pure HTTP/OData client for SAP system communication.
Replaces JCo/RFC with standard REST calls - no native dependencies.

Supports:
- Standard SAP OData services (API_USER_SRV, etc.)
- Custom OData services (ZSECURITY_SRV, etc.)
- Basic Auth and CSRF token handling
- Automatic pagination for large result sets
"""

import logging
from typing import Any, Optional
from urllib.parse import urlencode

import httpx

from config.settings import Settings

logger = logging.getLogger("syntaai-mcp.odata")


class SAPODataClient:
    """SAP OData client for security data retrieval."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._csrf_token: Optional[str] = None
        self._cookies: dict = {}
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with SAP authentication."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                auth=(self.settings.sap_user, self.settings.sap_password),
                verify=self.settings.verify_ssl,
                timeout=self.settings.timeout,
                headers={
                    "Accept": "application/json",
                    "sap-client": self.settings.sap_client,
                    "sap-language": self.settings.sap_language,
                },
                follow_redirects=True,
            )
        return self._client

    async def _fetch_csrf_token(self):
        """Fetch CSRF token for write operations (if ever needed)."""
        client = await self._get_client()
        url = f"{self.settings.sap_base_url}/sap/opu/odata/sap/"
        response = await client.head(url, headers={"X-CSRF-Token": "Fetch"})
        self._csrf_token = response.headers.get("x-csrf-token")

    # ─── Core OData Operations ───────────────────────────────────────────

    async def get_entity_set(
        self,
        entity_set: str,
        service_path: Optional[str] = None,
        filters: Optional[str] = None,
        select: Optional[list[str]] = None,
        top: Optional[int] = None,
        skip: Optional[int] = None,
        orderby: Optional[str] = None,
        expand: Optional[str] = None,
    ) -> list[dict]:
        """
        Read an OData entity set with optional query parameters.

        Args:
            entity_set: OData entity set name (e.g., "SapAllUsers", "UserRoles")
            service_path: Override service path (defaults to settings)
            filters: OData $filter expression
            select: List of fields to select
            top: Maximum number of records
            skip: Number of records to skip
            orderby: OData $orderby expression
            expand: OData $expand expression

        Returns:
            List of entity dictionaries
        """
        client = await self._get_client()

        # Build URL
        if self.settings.odata_mode == "custom":
            base = self.settings.get_service_url(service_path)
        else:
            base = self.settings.get_service_url(service_path)

        url = f"{base}/{entity_set}"

        # Build query parameters
        params = {}
        if filters:
            params["$filter"] = filters
        if select:
            params["$select"] = ",".join(select)
        if top:
            params["$top"] = str(top)
        if skip:
            params["$skip"] = str(skip)
        if orderby:
            params["$orderby"] = orderby
        if expand:
            params["$expand"] = expand
        params["$format"] = "json"

        logger.info(f"OData GET: {url} | params: {params}")

        response = await client.get(url, params=params)
        response.raise_for_status()

        data = response.json()

        # Handle OData v2 response format (SAP standard)
        if "d" in data:
            results = data["d"].get("results", [])
            if not results and isinstance(data["d"], dict):
                # Single entity response
                return [data["d"]]
            return results

        # Handle OData v4 response format
        if "value" in data:
            return data["value"]

        return [data] if data else []

    async def get_entity_set_all(
        self,
        entity_set: str,
        service_path: Optional[str] = None,
        filters: Optional[str] = None,
        select: Optional[list[str]] = None,
        page_size: int = 500,
    ) -> list[dict]:
        """
        Read ALL records from an entity set with automatic pagination.
        Use for large datasets where $top alone isn't enough.
        """
        all_results = []
        skip = 0

        while True:
            batch = await self.get_entity_set(
                entity_set=entity_set,
                service_path=service_path,
                filters=filters,
                select=select,
                top=page_size,
                skip=skip,
            )
            if not batch:
                break
            all_results.extend(batch)
            if len(batch) < page_size:
                break
            skip += page_size

        return all_results

    async def get_entity(
        self,
        entity_set: str,
        key: str,
        service_path: Optional[str] = None,
        select: Optional[list[str]] = None,
        expand: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Read a single entity by key.

        Args:
            entity_set: OData entity set name
            key: Entity key (e.g., "'SMITHJ'" or "UserName='SMITHJ'")
            service_path: Override service path
        """
        client = await self._get_client()
        base = self.settings.get_service_url(service_path)
        url = f"{base}/{entity_set}({key})"

        params = {"$format": "json"}
        if select:
            params["$select"] = ",".join(select)
        if expand:
            params["$expand"] = expand

        logger.info(f"OData GET entity: {url}")

        response = await client.get(url, params=params)
        if response.status_code == 404:
            return None
        response.raise_for_status()

        data = response.json()
        return data.get("d", data)

    async def call_function_import(
        self,
        function_name: str,
        service_path: Optional[str] = None,
        params: Optional[dict] = None,
        method: str = "GET",
    ) -> Any:
        """
        Call an OData function import.
        Useful for custom operations exposed by the SAP service.
        """
        client = await self._get_client()
        base = self.settings.get_service_url(service_path)
        url = f"{base}/{function_name}"

        query_params = {"$format": "json"}
        if params:
            query_params.update(params)

        if method == "GET":
            response = await client.get(url, params=query_params)
        else:
            if not self._csrf_token:
                await self._fetch_csrf_token()
            response = await client.post(
                url,
                params=query_params,
                headers={"X-CSRF-Token": self._csrf_token}
            )

        response.raise_for_status()
        data = response.json()
        return data.get("d", data)

    # ─── Convenience Methods for Security Data ───────────────────────────

    async def read_table(
        self,
        entity_set: str,
        filters: Optional[str] = None,
        fields: Optional[list[str]] = None,
    ) -> list[dict]:
        """
        High-level method to read SAP table data via OData.
        Maps to the same pattern as the old RFC READ_TABLE calls.
        """
        return await self.get_entity_set(
            entity_set=entity_set,
            filters=filters,
            select=fields,
        )

    async def test_connection(self) -> dict:
        """Test the SAP OData connection."""
        try:
            client = await self._get_client()
            # Try to reach the OData service metadata
            url = f"{self.settings.get_service_url()}/$metadata"
            response = await client.get(url)
            return {
                "status": "connected" if response.status_code == 200 else "error",
                "http_status": response.status_code,
                "url": url,
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

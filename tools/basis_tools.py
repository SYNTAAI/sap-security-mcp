"""
Basis Tools (11-15)
===================
SAP Basis administration and monitoring tools via OData.
All tools are READ-ONLY.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from sap.odata_client import SAPODataClient
from sap.entity_mappings import CUSTOM_ENTITIES, SECURITY_PARAMETERS

logger = logging.getLogger("syntaai-mcp.basis")


class BasisTools:
    """SAP Basis monitoring tools via OData."""

    def __init__(self, client: SAPODataClient):
        self.client = client

    # ─── Tool 11: System Info ────────────────────────────────────────────

    async def get_system_info(self) -> str:
        """Get SAP system information."""
        entity = CUSTOM_ENTITIES["system_info"]
        fields = entity["fields"]

        results = await self.client.get_entity_set(
            entity_set=entity["entity_set"],
        )

        if not results:
            return "❌ Could not retrieve system information."

        info = results[0]
        output = "🖥️ SAP System Information:\n\n"
        output += f"  System ID:      {info.get(fields.get('sid', ''), 'N/A')}\n"
        output += f"  Client:         {info.get(fields.get('client', ''), 'N/A')}\n"
        output += f"  Host:           {info.get(fields.get('host', ''), 'N/A')}\n"
        output += f"  Instance:       {info.get(fields.get('instance', ''), 'N/A')}\n"
        output += f"  SAP Release:    {info.get(fields.get('sap_release', ''), 'N/A')}\n"
        output += f"  Kernel:         {info.get(fields.get('kernel_release', ''), 'N/A')}\n"
        output += f"  Database:       {info.get(fields.get('db_system', ''), 'N/A')}\n"

        return output

    # ─── Tool 12: Failed Jobs ────────────────────────────────────────────

    async def get_failed_jobs(self, days: int = 7) -> str:
        """Get failed background jobs."""
        entity = CUSTOM_ENTITIES["background_jobs"]
        fields = entity["fields"]

        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y%m%d")

        results = await self.client.get_entity_set(
            entity_set=entity["entity_set"],
            filters=f"{fields['status']} eq 'A' and {fields['start_date']} ge '{cutoff}'",
            orderby=f"{fields['start_date']} desc",
        )

        if not results:
            return f"✅ No failed background jobs in the last {days} days."

        output = f"❌ {len(results)} failed jobs in the last {days} days:\n\n"
        for i, job in enumerate(results[:20], 1):
            job_name = job.get(fields["job_name"], "N/A")
            creator = job.get(fields.get("job_creator", ""), "N/A")
            start_date = job.get(fields.get("start_date", ""), "N/A")

            output += f"{i}. {job_name}\n"
            output += f"   Creator: {creator} | Date: {start_date}\n"

        if len(results) > 20:
            output += f"\n... and {len(results) - 20} more."

        return output

    # ─── Tool 13: RFC Destinations ───────────────────────────────────────

    async def check_rfc_destinations(self) -> str:
        """Check RFC destination configurations for security risks."""
        entity = CUSTOM_ENTITIES["rfc_destinations"]
        fields = entity["fields"]

        results = await self.client.get_entity_set(
            entity_set=entity["entity_set"],
        )

        if not results:
            return "ℹ️ No RFC destinations found."

        output = f"🔌 {len(results)} RFC destinations found:\n\n"
        risks = 0

        for i, dest in enumerate(results, 1):
            dest_name = dest.get(fields["destination"], "N/A")
            dest_type = dest.get(fields.get("type", ""), "N/A")
            host = dest.get(fields.get("host", ""), "N/A")
            desc = dest.get(fields.get("description", ""), "")

            # Flag risky types
            risk_marker = ""
            if dest_type in ("H", "G"):  # HTTP connections
                risk_marker = " ⚠️ HTTP"
                risks += 1
            elif dest_type == "T":  # TCP/IP
                risk_marker = " ⚠️ TCP/IP"

            output += f"{i}. {dest_name} (Type: {dest_type}){risk_marker}\n"
            output += f"   Host: {host}\n"
            if desc:
                output += f"   Desc: {desc}\n"

        if risks > 0:
            output += f"\n⚠️ {risks} HTTP-based RFC destinations found. Review for security."

        return output

    # ─── Tool 14: System Parameters ──────────────────────────────────────

    async def get_system_parameters(self) -> str:
        """Get security-relevant system parameters."""
        entity = CUSTOM_ENTITIES["system_parameters"]
        fields = entity["fields"]

        output = "⚙️ Security-Relevant System Parameters:\n\n"
        found = 0

        for param in SECURITY_PARAMETERS:
            results = await self.client.get_entity_set(
                entity_set=entity["entity_set"],
                filters=f"{fields['name']} eq '{param}'",
            )

            if results:
                p = results[0]
                value = p.get(fields["value"], "N/A")
                default = p.get(fields.get("default", ""), "")
                is_default = value == default

                marker = "" if not is_default else " (default)"
                output += f"  {param} = {value}{marker}\n"
                found += 1

        if found == 0:
            return "❌ Could not retrieve system parameters. Check OData service configuration."

        output += f"\n📊 Retrieved {found}/{len(SECURITY_PARAMETERS)} parameters."
        return output

    # ─── Tool 15: Transport Requests ─────────────────────────────────────

    async def check_transport_requests(self, days: int = 30) -> str:
        """Check recent transport requests."""
        entity = CUSTOM_ENTITIES["transport_requests"]
        fields = entity["fields"]

        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y%m%d")

        results = await self.client.get_entity_set(
            entity_set=entity["entity_set"],
            filters=f"{fields['date']} ge '{cutoff}'",
            orderby=f"{fields['date']} desc",
        )

        if not results:
            return f"ℹ️ No transport requests in the last {days} days."

        # Count by status
        status_map = {
            "D": "Modifiable",
            "L": "Modifiable (protected)",
            "O": "Released",
            "R": "Released",
            "N": "Released (imported)",
        }

        status_counts = {}
        for t in results:
            status = t.get(fields.get("status", ""), "?")
            label = status_map.get(status, f"Status: {status}")
            status_counts[label] = status_counts.get(label, 0) + 1

        output = f"📦 {len(results)} transport requests in the last {days} days:\n\n"

        output += "Status Summary:\n"
        for status, count in sorted(status_counts.items()):
            output += f"  {status}: {count}\n"

        output += "\nRecent Transports:\n"
        for i, t in enumerate(results[:15], 1):
            request = t.get(fields["request"], "N/A")
            owner = t.get(fields.get("owner", ""), "N/A")
            desc = t.get(fields.get("description", ""), "")
            date = t.get(fields.get("date", ""), "N/A")

            output += f"  {i}. {request} | {owner} | {date}\n"
            if desc:
                output += f"     {desc}\n"

        if len(results) > 15:
            output += f"\n... and {len(results) - 15} more."

        return output

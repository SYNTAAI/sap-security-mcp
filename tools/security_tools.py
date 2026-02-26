"""
Security Tools (1-10)
=====================
SAP security analysis tools powered by OData.
All tools are READ-ONLY - no modifications to SAP systems.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from sap.odata_client import SAPODataClient
from sap.entity_mappings import (
    CUSTOM_ENTITIES, CRITICAL_TCODES, DEFAULT_SAP_USERS,
    SOD_CONFLICT_MATRIX,
)

logger = logging.getLogger("syntaai-mcp.security")


class SecurityTools:
    """SAP security analysis tools via OData."""

    def __init__(self, client: SAPODataClient):
        self.client = client

    # ─── Tool 1: Get User Roles ──────────────────────────────────────────

    async def get_user_roles(self, username: str) -> str:
        """Get all roles assigned to a specific SAP user."""
        if not username:
            return "❌ Please provide a username."

        entity = CUSTOM_ENTITIES["user_roles"]
        fields = entity["fields"]

        results = await self.client.get_entity_set(
            entity_set=entity["entity_set"],
            filters=f"{fields['username']} eq '{username.upper()}'",
        )

        if not results:
            return f"ℹ️ No roles found for user '{username.upper()}'."

        output = f"🔍 Roles for user '{username.upper()}' ({len(results)} found):\n\n"
        for i, role in enumerate(results, 1):
            role_name = role.get(fields["role_name"], "N/A")
            from_date = role.get(fields.get("from_date", ""), "N/A")
            to_date = role.get(fields.get("to_date", ""), "N/A")
            output += f"{i}. {role_name}\n"
            output += f"   Valid: {from_date} → {to_date}\n"

        return output

    # ─── Tool 2: Check SAP_ALL Users ─────────────────────────────────────

    async def check_sap_all_users(self) -> str:
        """Find users with SAP_ALL or SAP_NEW profiles."""
        entity = CUSTOM_ENTITIES["user_profiles"]
        fields = entity["fields"]

        # Query for SAP_ALL
        sap_all_users = await self.client.get_entity_set(
            entity_set=entity["entity_set"],
            filters=f"{fields['profile']} eq 'SAP_ALL'",
        )

        # Query for SAP_NEW
        sap_new_users = await self.client.get_entity_set(
            entity_set=entity["entity_set"],
            filters=f"{fields['profile']} eq 'SAP_NEW'",
        )

        all_critical = sap_all_users + sap_new_users

        if not all_critical:
            return "✅ No users found with SAP_ALL or SAP_NEW profiles. Good!"

        output = f"🚨 CRITICAL: {len(all_critical)} users with dangerous profiles:\n\n"

        # Get user details for context
        user_entity = CUSTOM_ENTITIES["all_users"]
        user_fields = user_entity["fields"]

        for i, entry in enumerate(all_critical, 1):
            username = entry.get(fields["username"], "UNKNOWN")
            profile = entry.get(fields["profile"], "UNKNOWN")

            # Try to get user details
            user_details = await self.client.get_entity_set(
                entity_set=user_entity["entity_set"],
                filters=f"{user_fields['username']} eq '{username}'",
            )

            user_type = "Unknown"
            lock_status = "Unknown"
            last_logon = "Unknown"

            if user_details:
                u = user_details[0]
                user_type = u.get(user_fields.get("user_type", ""), "N/A")
                lock_status = u.get(user_fields.get("lock_status", ""), "N/A")
                last_logon = u.get(user_fields.get("last_logon", ""), "N/A")

            risk = "⚠️ CRITICAL" if lock_status in ("0", 0, None) else "🔒 Locked"

            output += f"{i}. {username} - Profile: {profile}\n"
            output += f"   Type: {user_type} | Lock: {lock_status} | Last Login: {last_logon}\n"
            output += f"   Risk: {risk}\n\n"

        output += "\n💡 Recommendation: Remove SAP_ALL/SAP_NEW profiles immediately."
        return output

    # ─── Tool 3: Dormant Users ───────────────────────────────────────────

    async def get_dormant_users(self, days: int = 90) -> str:
        """Find users inactive for specified number of days."""
        entity = CUSTOM_ENTITIES["all_users"]
        fields = entity["fields"]

        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y%m%d")

        results = await self.client.get_entity_set(
            entity_set=entity["entity_set"],
            filters=f"{fields['last_logon']} lt '{cutoff}' and {fields['lock_status']} eq '0'",
        )

        if not results:
            return f"✅ No dormant users found (inactive > {days} days)."

        output = f"💤 {len(results)} dormant users (inactive > {days} days):\n\n"
        for i, user in enumerate(results[:50], 1):  # Limit to 50
            username = user.get(fields["username"], "N/A")
            last_logon = user.get(fields["last_logon"], "Never")
            user_type = user.get(fields.get("user_type", ""), "N/A")
            output += f"{i}. {username} | Type: {user_type} | Last Login: {last_logon}\n"

        if len(results) > 50:
            output += f"\n... and {len(results) - 50} more."

        output += f"\n\n💡 Recommendation: Lock or delete dormant users to reduce attack surface."
        return output

    # ─── Tool 4: Locked Users ────────────────────────────────────────────

    async def get_locked_users(self) -> str:
        """Get all locked users with lock type information."""
        entity = CUSTOM_ENTITIES["all_users"]
        fields = entity["fields"]

        results = await self.client.get_entity_set(
            entity_set=entity["entity_set"],
            filters=f"{fields['lock_status']} ne '0'",
        )

        if not results:
            return "ℹ️ No locked users found."

        output = f"🔒 {len(results)} locked users:\n\n"
        for i, user in enumerate(results[:50], 1):
            username = user.get(fields["username"], "N/A")
            lock_flag = user.get(fields["lock_status"], "N/A")
            last_logon = user.get(fields.get("last_logon", ""), "N/A")

            # Interpret lock flag
            lock_reasons = {
                "32": "Locked by admin",
                "64": "Locked due to failed logins",
                "128": "Locked by admin (global)",
                "192": "Admin + failed logins",
            }
            reason = lock_reasons.get(str(lock_flag), f"Lock flag: {lock_flag}")

            output += f"{i}. {username} | {reason} | Last Login: {last_logon}\n"

        return output

    # ─── Tool 5: SoD Violations ──────────────────────────────────────────

    async def check_sod_violations(self, username: Optional[str] = None) -> str:
        """Check for Segregation of Duties violations."""

        # First, try custom SoD entity if available
        if "sod_violations" in CUSTOM_ENTITIES:
            entity = CUSTOM_ENTITIES["sod_violations"]
            fields = entity["fields"]

            filters = None
            if username:
                filters = f"{fields['username']} eq '{username.upper()}'"

            try:
                results = await self.client.get_entity_set(
                    entity_set=entity["entity_set"],
                    filters=filters,
                )

                if results:
                    output = f"⚠️ {len(results)} SoD violations found:\n\n"
                    for i, v in enumerate(results, 1):
                        output += (
                            f"{i}. {v.get(fields['username'], 'N/A')} - "
                            f"{v.get(fields['conflict_type'], 'N/A')}\n"
                            f"   TCodes: {v.get(fields['tcode1'], '')} vs {v.get(fields['tcode2'], '')}\n"
                            f"   Risk: {v.get(fields['risk_level'], 'N/A')}\n"
                            f"   {v.get(fields['description'], '')}\n\n"
                        )
                    return output
            except Exception:
                logger.info("Custom SoD entity not available, falling back to local analysis")

        # Fallback: Local SoD analysis using role-tcode mappings
        return await self._local_sod_analysis(username)

    async def _local_sod_analysis(self, username: Optional[str] = None) -> str:
        """Perform local SoD analysis using role and tcode data."""
        role_entity = CUSTOM_ENTITIES["user_roles"]
        tcode_entity = CUSTOM_ENTITIES["role_tcodes"]
        role_fields = role_entity["fields"]
        tcode_fields = tcode_entity["fields"]

        # Get user-role assignments
        filters = None
        if username:
            filters = f"{role_fields['username']} eq '{username.upper()}'"

        user_roles = await self.client.get_entity_set(
            entity_set=role_entity["entity_set"],
            filters=filters,
        )

        if not user_roles:
            msg = f" for user '{username.upper()}'" if username else ""
            return f"ℹ️ No role assignments found{msg}."

        # Build user -> tcodes mapping
        user_tcodes: dict[str, set] = {}
        for ur in user_roles:
            uname = ur.get(role_fields["username"], "")
            role = ur.get(role_fields["role_name"], "")

            # Get tcodes for this role
            role_tcodes = await self.client.get_entity_set(
                entity_set=tcode_entity["entity_set"],
                filters=f"{tcode_fields['role_name']} eq '{role}'",
            )

            if uname not in user_tcodes:
                user_tcodes[uname] = set()

            for rt in role_tcodes:
                tcode = rt.get(tcode_fields["tcode"], "")
                if tcode:
                    user_tcodes[uname].add(tcode)

        # Check against SoD matrix
        violations = []
        for uname, tcodes in user_tcodes.items():
            for conflict in SOD_CONFLICT_MATRIX:
                side1_match = any(t in tcodes for group in [conflict["tcodes"][0]] for t in group)
                side2_match = any(t in tcodes for group in [conflict["tcodes"][1]] for t in group)

                if side1_match and side2_match:
                    matched_t1 = [t for group in [conflict["tcodes"][0]] for t in group if t in tcodes]
                    matched_t2 = [t for group in [conflict["tcodes"][1]] for t in group if t in tcodes]
                    violations.append({
                        "user": uname,
                        "conflict": conflict["name"],
                        "risk": conflict["risk"],
                        "tcode1": ", ".join(matched_t1),
                        "tcode2": ", ".join(matched_t2),
                        "description": conflict["description"],
                    })

        if not violations:
            return "✅ No SoD violations detected."

        output = f"⚠️ {len(violations)} SoD violations found:\n\n"
        for i, v in enumerate(violations, 1):
            output += (
                f"{i}. {v['user']} - {v['conflict']} ({v['risk']})\n"
                f"   Side 1: {v['tcode1']}\n"
                f"   Side 2: {v['tcode2']}\n"
                f"   Risk: {v['description']}\n\n"
            )

        return output

    # ─── Tool 6: Critical Tcodes ─────────────────────────────────────────

    async def check_critical_tcodes(self) -> str:
        """Find users with access to critical transaction codes."""
        tcode_entity = CUSTOM_ENTITIES["role_tcodes"]
        role_entity = CUSTOM_ENTITIES["user_roles"]
        tcode_fields = tcode_entity["fields"]
        role_fields = role_entity["fields"]

        findings = []

        for tcode, info in CRITICAL_TCODES.items():
            if info["risk"] not in ("CRITICAL", "HIGH"):
                continue

            # Find roles with this tcode
            roles_with_tcode = await self.client.get_entity_set(
                entity_set=tcode_entity["entity_set"],
                filters=f"{tcode_fields['tcode']} eq '{tcode}'",
            )

            for role_entry in roles_with_tcode:
                role_name = role_entry.get(tcode_fields["role_name"], "")

                # Find users with this role
                users_with_role = await self.client.get_entity_set(
                    entity_set=role_entity["entity_set"],
                    filters=f"{role_fields['role_name']} eq '{role_name}'",
                )

                for user_entry in users_with_role:
                    username = user_entry.get(role_fields["username"], "")
                    findings.append({
                        "user": username,
                        "tcode": tcode,
                        "role": role_name,
                        "risk": info["risk"],
                        "description": info["description"],
                    })

        if not findings:
            return "✅ No users found with critical transaction code access."

        # Deduplicate and sort
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["user"], f["tcode"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        unique_findings.sort(key=lambda x: (0 if x["risk"] == "CRITICAL" else 1, x["user"]))

        output = f"🚨 {len(unique_findings)} critical tcode assignments found:\n\n"
        for i, f in enumerate(unique_findings[:30], 1):
            output += (
                f"{i}. {f['user']} → {f['tcode']} ({f['risk']})\n"
                f"   Role: {f['role']}\n"
                f"   {f['description']}\n\n"
            )

        if len(unique_findings) > 30:
            output += f"... and {len(unique_findings) - 30} more findings."

        return output

    # ─── Tool 7: Recently Created Users ──────────────────────────────────

    async def get_users_created_recently(self, days: int = 30) -> str:
        """Get users created in the last N days."""
        entity = CUSTOM_ENTITIES["all_users"]
        fields = entity["fields"]

        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y%m%d")

        results = await self.client.get_entity_set(
            entity_set=entity["entity_set"],
            filters=f"{fields['created_date']} ge '{cutoff}'",
            orderby=f"{fields['created_date']} desc",
        )

        if not results:
            return f"ℹ️ No users created in the last {days} days."

        output = f"👤 {len(results)} users created in the last {days} days:\n\n"
        for i, user in enumerate(results, 1):
            username = user.get(fields["username"], "N/A")
            created = user.get(fields["created_date"], "N/A")
            created_by = user.get(fields.get("created_by", ""), "N/A")
            user_type = user.get(fields.get("user_type", ""), "N/A")

            output += f"{i}. {username} | Created: {created} | By: {created_by} | Type: {user_type}\n"

        return output

    # ─── Tool 8: Default Users ───────────────────────────────────────────

    async def check_default_users(self) -> str:
        """Check status of default SAP users."""
        entity = CUSTOM_ENTITIES["all_users"]
        fields = entity["fields"]

        output = "🔐 Default SAP User Status:\n\n"
        issues = 0

        for default_user in DEFAULT_SAP_USERS:
            results = await self.client.get_entity_set(
                entity_set=entity["entity_set"],
                filters=f"{fields['username']} eq '{default_user}'",
            )

            if not results:
                output += f"  ✅ {default_user} - Not found (good)\n"
                continue

            u = results[0]
            lock_status = u.get(fields.get("lock_status", ""), "0")
            last_logon = u.get(fields.get("last_logon", ""), "Never")

            is_locked = str(lock_status) != "0"

            if is_locked:
                output += f"  ✅ {default_user} - Locked | Last Login: {last_logon}\n"
            else:
                output += f"  ⚠️ {default_user} - UNLOCKED | Last Login: {last_logon}\n"
                issues += 1

        if issues > 0:
            output += f"\n🚨 {issues} default users are unlocked! Lock them immediately."
        else:
            output += "\n✅ All default users are properly secured."

        return output

    # ─── Tool 9: Password Policy ─────────────────────────────────────────

    async def check_password_policy(self) -> str:
        """Analyze SAP password policy configuration."""
        entity = CUSTOM_ENTITIES["system_parameters"]
        fields = entity["fields"]

        # Recommended values for password parameters
        recommendations = {
            "login/min_password_lng": {"min": 8, "desc": "Minimum password length"},
            "login/min_password_digits": {"min": 1, "desc": "Minimum digits in password"},
            "login/min_password_letters": {"min": 1, "desc": "Minimum letters in password"},
            "login/min_password_specials": {"min": 1, "desc": "Minimum special characters"},
            "login/password_expiration_time": {"max": 90, "desc": "Password expiration (days)"},
            "login/fails_to_user_lock": {"max": 5, "desc": "Failed attempts before lock"},
            "login/failed_user_auto_unlock": {"exact": 0, "desc": "Auto-unlock after failed logins (0=disabled)"},
            "login/no_automatic_user_sapstar": {"exact": 1, "desc": "Disable automatic SAP* user"},
        }

        output = "🔑 Password Policy Analysis:\n\n"
        compliant = 0
        non_compliant = 0

        for param_name, rec in recommendations.items():
            results = await self.client.get_entity_set(
                entity_set=entity["entity_set"],
                filters=f"{fields['name']} eq '{param_name}'",
            )

            if not results:
                output += f"  ❓ {param_name} - Not set (using default)\n"
                non_compliant += 1
                continue

            value = results[0].get(fields["value"], "N/A")

            try:
                num_value = int(value)
                is_ok = True

                if "min" in rec and num_value < rec["min"]:
                    is_ok = False
                if "max" in rec and num_value > rec["max"]:
                    is_ok = False
                if "exact" in rec and num_value != rec["exact"]:
                    is_ok = False

                status = "✅" if is_ok else "⚠️"
                if is_ok:
                    compliant += 1
                else:
                    non_compliant += 1

                output += f"  {status} {param_name} = {value} ({rec['desc']})\n"

            except ValueError:
                output += f"  ❓ {param_name} = {value} ({rec['desc']})\n"

        total = compliant + non_compliant
        score = (compliant / total * 100) if total > 0 else 0
        output += f"\n📊 Compliance Score: {score:.0f}% ({compliant}/{total} parameters compliant)"

        return output

    # ─── Tool 10: Users Without Roles ────────────────────────────────────

    async def check_users_no_roles(self) -> str:
        """Find active users that have no role assignments."""
        user_entity = CUSTOM_ENTITIES["all_users"]
        role_entity = CUSTOM_ENTITIES["user_roles"]
        user_fields = user_entity["fields"]
        role_fields = role_entity["fields"]

        # Get all active (unlocked) users
        active_users = await self.client.get_entity_set(
            entity_set=user_entity["entity_set"],
            filters=f"{user_fields['lock_status']} eq '0'",
        )

        # Get all role assignments
        all_roles = await self.client.get_entity_set_all(
            entity_set=role_entity["entity_set"],
        )

        # Build set of users with roles
        users_with_roles = {r.get(role_fields["username"], "") for r in all_roles}

        # Find active users without roles
        no_role_users = []
        for user in active_users:
            username = user.get(user_fields["username"], "")
            if username and username not in users_with_roles:
                no_role_users.append(user)

        if not no_role_users:
            return "✅ All active users have role assignments."

        output = f"👻 {len(no_role_users)} active users without role assignments:\n\n"
        for i, user in enumerate(no_role_users[:30], 1):
            username = user.get(user_fields["username"], "N/A")
            user_type = user.get(user_fields.get("user_type", ""), "N/A")
            last_logon = user.get(user_fields.get("last_logon", ""), "N/A")
            output += f"{i}. {username} | Type: {user_type} | Last Login: {last_logon}\n"

        if len(no_role_users) > 30:
            output += f"\n... and {len(no_role_users) - 30} more."

        output += "\n\n💡 Recommendation: Review these users - they may be orphaned accounts."
        return output

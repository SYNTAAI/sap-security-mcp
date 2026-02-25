"""
SAP Security Tools for MCP Server
Implements security analysis scenarios using RFC_READ_TABLE via JCo connector.

All tools accept an SAP connection and return structured results.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class SecurityTools:
    """SAP Security analysis tools using RFC calls."""

    def __init__(self, sap_connection):
        """
        Initialize with SAP connection.

        Args:
            sap_connection: SAPRestConnector instance (already connected)
        """
        self.conn = sap_connection

    def _read_table(self, table: str, fields: List[str], options: List[str] = None,
                    rowcount: int = 500, delimiter: str = "|") -> List[Dict]:
        """
        Helper to read SAP table via RFC_READ_TABLE.

        Args:
            table: SAP table name
            fields: List of field names to retrieve
            options: List of WHERE clause conditions
            rowcount: Max rows to return
            delimiter: Field delimiter

        Returns:
            List of dicts with field values
        """
        try:
            result = self.conn.call(
                "RFC_READ_TABLE",
                QUERY_TABLE=table,
                DELIMITER=delimiter,
                FIELDS=[{"FIELDNAME": f} for f in fields],
                OPTIONS=[{"TEXT": opt} for opt in (options or [])],
                ROWCOUNT=rowcount
            )

            # Parse the result
            data = result.get("DATA", [])
            parsed = []

            for row in data:
                wa = row.get("WA", "")
                values = wa.split(delimiter)
                record = {}
                for i, field in enumerate(fields):
                    record[field] = values[i].strip() if i < len(values) else ""
                parsed.append(record)

            return parsed

        except Exception as e:
            logger.error(f"Error reading table {table}: {e}")
            raise

    def get_user_roles(self, target_user: str) -> Dict[str, Any]:
        """
        Tool 1: Get all roles assigned to a SAP user.

        Args:
            target_user: SAP username to check

        Returns:
            Dict with user roles and validity dates
        """
        try:
            # Get role assignments from AGR_USERS
            roles = self._read_table(
                table="AGR_USERS",
                fields=["AGR_NAME", "UNAME", "FROM_DAT", "TO_DAT"],
                options=[f"UNAME = '{target_user.upper()}'"]
            )

            if not roles:
                return {
                    "success": True,
                    "user": target_user,
                    "roles": [],
                    "message": f"No roles found for user {target_user}"
                }

            # Get role descriptions from AGR_TEXTS
            role_names = [r["AGR_NAME"] for r in roles]
            descriptions = {}

            try:
                for role_name in role_names[:50]:  # Limit to avoid too many calls
                    desc_result = self._read_table(
                        table="AGR_TEXTS",
                        fields=["AGR_NAME", "TEXT"],
                        options=[f"AGR_NAME = '{role_name}'", "AND SPRAS = 'E'"],
                        rowcount=1
                    )
                    if desc_result:
                        descriptions[role_name] = desc_result[0].get("TEXT", "")
            except Exception as e:
                logger.warning(f"Could not fetch role descriptions: {e}")

            # Format response
            role_list = []
            today = datetime.now().strftime("%Y%m%d")

            for role in roles:
                from_dat = role.get("FROM_DAT", "")
                to_dat = role.get("TO_DAT", "99991231")
                is_active = from_dat <= today <= to_dat

                role_list.append({
                    "role_name": role["AGR_NAME"],
                    "description": descriptions.get(role["AGR_NAME"], ""),
                    "valid_from": from_dat,
                    "valid_to": to_dat,
                    "is_active": is_active
                })

            return {
                "success": True,
                "user": target_user,
                "total_roles": len(role_list),
                "active_roles": sum(1 for r in role_list if r["is_active"]),
                "roles": role_list
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_sap_all_users(self) -> Dict[str, Any]:
        """
        Tool 2: Find users with SAP_ALL or SAP_NEW profiles (critical risk).

        Returns:
            Dict with list of users having SAP_ALL/SAP_NEW
        """
        try:
            # Query UST04 for SAP_ALL and SAP_NEW profile assignments
            profiles = self._read_table(
                table="UST04",
                fields=["BNAME", "PROFILE"],
                options=["PROFILE = 'SAP_ALL' OR PROFILE = 'SAP_NEW'"],
                rowcount=1000
            )

            if not profiles:
                return {
                    "success": True,
                    "risk_level": "LOW",
                    "users": [],
                    "message": "No users found with SAP_ALL or SAP_NEW profiles"
                }

            # Get user details from USR02
            users_with_sap_all = []
            user_names = list(set(p["BNAME"] for p in profiles))

            for username in user_names[:100]:  # Limit
                try:
                    user_info = self._read_table(
                        table="USR02",
                        fields=["BNAME", "UFLAG", "TRDAT", "USTYP"],
                        options=[f"BNAME = '{username}'"],
                        rowcount=1
                    )

                    if user_info:
                        user = user_info[0]
                        user_profiles = [p["PROFILE"] for p in profiles if p["BNAME"] == username]

                        users_with_sap_all.append({
                            "username": username,
                            "profiles": user_profiles,
                            "user_type": user.get("USTYP", ""),
                            "lock_status": self._get_lock_status(user.get("UFLAG", "0")),
                            "last_login": user.get("TRDAT", "")
                        })
                except Exception:
                    continue

            return {
                "success": True,
                "risk_level": "CRITICAL" if users_with_sap_all else "LOW",
                "total_users": len(users_with_sap_all),
                "users": users_with_sap_all,
                "recommendation": "SAP_ALL and SAP_NEW profiles grant unrestricted access. "
                                  "Remove these profiles immediately and assign specific roles."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_dormant_users(self, days: int = 90) -> Dict[str, Any]:
        """
        Tool 3: Find active users who haven't logged in for specified days.

        Args:
            days: Number of days since last login (default 90)

        Returns:
            Dict with list of dormant users
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).strftime("%Y%m%d")

            # Get users who haven't logged in and are not locked
            users = self._read_table(
                table="USR02",
                fields=["BNAME", "TRDAT", "UFLAG", "USTYP", "ERDAT"],
                options=[f"TRDAT < '{cutoff_date}'", "AND UFLAG = '0'"],
                rowcount=1000
            )

            dormant_users = []
            for user in users:
                last_login = user.get("TRDAT", "")
                if last_login and last_login != "00000000":
                    try:
                        login_date = datetime.strptime(last_login, "%Y%m%d")
                        days_inactive = (datetime.now() - login_date).days
                    except ValueError:
                        days_inactive = None
                else:
                    days_inactive = "Never logged in"

                dormant_users.append({
                    "username": user["BNAME"],
                    "last_login": last_login,
                    "days_inactive": days_inactive,
                    "user_type": self._get_user_type(user.get("USTYP", "")),
                    "created_on": user.get("ERDAT", "")
                })

            # Sort by days inactive
            dormant_users.sort(
                key=lambda x: x["days_inactive"] if isinstance(x["days_inactive"], int) else 9999,
                reverse=True
            )

            return {
                "success": True,
                "risk_level": "HIGH" if len(dormant_users) > 50 else "MEDIUM" if dormant_users else "LOW",
                "threshold_days": days,
                "total_dormant_users": len(dormant_users),
                "users": dormant_users,
                "recommendation": f"Review and lock/delete users inactive for more than {days} days "
                                  "to reduce attack surface."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_locked_users(self, lock_type: str = "all") -> Dict[str, Any]:
        """
        Tool 4: Get list of locked users with lock reason.

        Args:
            lock_type: 'all', 'manual', or 'auto' (default: all)

        Returns:
            Dict with locked users and lock reasons
        """
        try:
            # UFLAG values:
            # 0 = not locked
            # 32 = locked by admin (global)
            # 64 = locked by admin
            # 128 = too many wrong passwords
            # 192 = both admin and wrong passwords

            if lock_type == "manual":
                options = ["UFLAG = '64' OR UFLAG = '32'"]
            elif lock_type == "auto":
                options = ["UFLAG = '128'"]
            else:
                options = ["UFLAG <> '0'"]

            users = self._read_table(
                table="USR02",
                fields=["BNAME", "UFLAG", "TRDAT", "GLTGB", "USTYP"],
                options=options,
                rowcount=1000
            )

            locked_users = []
            for user in users:
                uflag = user.get("UFLAG", "0")

                locked_users.append({
                    "username": user["BNAME"],
                    "lock_status": self._get_lock_status(uflag),
                    "lock_reason": self._get_lock_reason(uflag),
                    "last_login": user.get("TRDAT", ""),
                    "validity_end": user.get("GLTGB", ""),
                    "user_type": self._get_user_type(user.get("USTYP", ""))
                })

            return {
                "success": True,
                "filter": lock_type,
                "total_locked": len(locked_users),
                "locked_users": locked_users
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_sod_violations(self) -> Dict[str, Any]:
        """
        Tool 5: Check for Segregation of Duties violations.

        Checks critical SoD combinations:
        - FB60 (vendor invoice) + F110 (payment run)
        - ME21N (create PO) + MIGO (goods receipt) + MIRO (invoice verify)
        - SU01 (user admin) + PFCG (role admin)
        - FK01 (create vendor) + F110 (payment)

        Returns:
            Dict with SoD violations found
        """
        try:
            sod_rules = [
                {
                    "name": "Invoice to Payment",
                    "description": "User can create vendor invoice and run payment",
                    "tcodes": ["FB60", "F110"],
                    "risk": "CRITICAL"
                },
                {
                    "name": "Procure to Pay",
                    "description": "User can create PO, receive goods, and verify invoice",
                    "tcodes": ["ME21N", "MIGO", "MIRO"],
                    "risk": "HIGH"
                },
                {
                    "name": "User and Role Admin",
                    "description": "User can manage both users and roles",
                    "tcodes": ["SU01", "PFCG"],
                    "risk": "CRITICAL"
                },
                {
                    "name": "Vendor to Payment",
                    "description": "User can create vendor master and run payments",
                    "tcodes": ["FK01", "F110"],
                    "risk": "CRITICAL"
                }
            ]

            violations = []

            for rule in sod_rules:
                # Find roles that have these tcodes
                tcode_roles = {}

                for tcode in rule["tcodes"]:
                    roles = self._read_table(
                        table="AGR_TCODES",
                        fields=["AGR_NAME", "TCODE"],
                        options=[f"TCODE = '{tcode}'"],
                        rowcount=500
                    )
                    tcode_roles[tcode] = set(r["AGR_NAME"] for r in roles)

                # Find users with roles that contain ALL conflicting tcodes
                all_conflict_roles = set()
                for roles_set in tcode_roles.values():
                    if not all_conflict_roles:
                        all_conflict_roles = roles_set
                    else:
                        all_conflict_roles = all_conflict_roles.union(roles_set)

                # Check users with these roles
                violating_users = {}

                for role in list(all_conflict_roles)[:50]:  # Limit
                    try:
                        users = self._read_table(
                            table="AGR_USERS",
                            fields=["UNAME", "AGR_NAME"],
                            options=[f"AGR_NAME = '{role}'"],
                            rowcount=200
                        )

                        for user in users:
                            username = user["UNAME"]
                            if username not in violating_users:
                                violating_users[username] = {"tcodes": set(), "roles": set()}

                            # Check which tcodes this role provides
                            for tcode, roles_with_tcode in tcode_roles.items():
                                if role in roles_with_tcode:
                                    violating_users[username]["tcodes"].add(tcode)
                                    violating_users[username]["roles"].add(role)

                    except Exception:
                        continue

                # Filter to only users who have ALL conflicting tcodes
                for username, data in violating_users.items():
                    if all(tcode in data["tcodes"] for tcode in rule["tcodes"]):
                        violations.append({
                            "user": username,
                            "rule_name": rule["name"],
                            "description": rule["description"],
                            "risk": rule["risk"],
                            "conflicting_tcodes": list(data["tcodes"]),
                            "via_roles": list(data["roles"])[:5]  # Limit roles shown
                        })

            return {
                "success": True,
                "risk_level": "CRITICAL" if any(v["risk"] == "CRITICAL" for v in violations)
                             else "HIGH" if violations else "LOW",
                "total_violations": len(violations),
                "violations": violations,
                "rules_checked": [r["name"] for r in sod_rules],
                "recommendation": "Implement proper segregation of duties. "
                                  "Users should not have access to conflicting transactions."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_critical_tcodes(self, tcode: str = None) -> Dict[str, Any]:
        """
        Tool 6: Find users with access to critical transactions.

        Args:
            tcode: Specific tcode to check (optional, checks all critical if empty)

        Returns:
            Dict with users having critical tcode access
        """
        try:
            critical_tcodes = ["SU01", "SE38", "SE16", "SM30", "PFCG",
                               "SCC5", "RZ10", "SM59", "SE80", "SA38"]

            if tcode:
                check_tcodes = [tcode.upper()]
            else:
                check_tcodes = critical_tcodes

            results = []

            for tc in check_tcodes:
                # Get roles with this tcode
                roles = self._read_table(
                    table="AGR_TCODES",
                    fields=["AGR_NAME", "TCODE"],
                    options=[f"TCODE = '{tc}'"],
                    rowcount=200
                )

                if not roles:
                    continue

                # Get users with these roles
                users_with_tcode = []

                for role in roles[:30]:  # Limit
                    try:
                        users = self._read_table(
                            table="AGR_USERS",
                            fields=["UNAME", "AGR_NAME"],
                            options=[f"AGR_NAME = '{role['AGR_NAME']}'"],
                            rowcount=100
                        )

                        for user in users:
                            existing = next((u for u in users_with_tcode
                                             if u["username"] == user["UNAME"]), None)
                            if existing:
                                existing["via_roles"].append(role["AGR_NAME"])
                            else:
                                users_with_tcode.append({
                                    "username": user["UNAME"],
                                    "via_roles": [role["AGR_NAME"]]
                                })
                    except Exception:
                        continue

                results.append({
                    "tcode": tc,
                    "description": self._get_tcode_description(tc),
                    "risk": self._get_tcode_risk(tc),
                    "user_count": len(users_with_tcode),
                    "users": users_with_tcode[:20]  # Limit users shown
                })

            return {
                "success": True,
                "tcodes_checked": len(check_tcodes),
                "results": results,
                "recommendation": "Restrict access to critical transactions. "
                                  "Use authorization objects for fine-grained control."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_users_created_recently(self, days: int = 30) -> Dict[str, Any]:
        """
        Tool 7: Get users created within specified number of days.

        Args:
            days: Number of days to look back (default 30)

        Returns:
            Dict with recently created users
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).strftime("%Y%m%d")

            users = self._read_table(
                table="USR02",
                fields=["BNAME", "ERDAT", "ERNAM", "USTYP", "GLTGB", "UFLAG"],
                options=[f"ERDAT >= '{cutoff_date}'"],
                rowcount=500
            )

            recent_users = []
            for user in users:
                recent_users.append({
                    "username": user["BNAME"],
                    "created_date": user.get("ERDAT", ""),
                    "created_by": user.get("ERNAM", ""),
                    "user_type": self._get_user_type(user.get("USTYP", "")),
                    "validity_end": user.get("GLTGB", ""),
                    "lock_status": self._get_lock_status(user.get("UFLAG", "0"))
                })

            # Sort by creation date, newest first
            recent_users.sort(key=lambda x: x["created_date"], reverse=True)

            return {
                "success": True,
                "period_days": days,
                "total_new_users": len(recent_users),
                "users": recent_users,
                "recommendation": "Review new user accounts to ensure they are authorized "
                                  "and have appropriate access levels."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_default_users(self) -> Dict[str, Any]:
        """
        Tool 8: Check status of default SAP users.

        Checks: SAP*, DDIC, EARLYWATCH, TMSADM, SAPCPIC

        Returns:
            Dict with default user status and risk assessment
        """
        try:
            default_users = ["SAP*", "DDIC", "EARLYWATCH", "TMSADM", "SAPCPIC"]
            results = []

            for username in default_users:
                try:
                    users = self._read_table(
                        table="USR02",
                        fields=["BNAME", "UFLAG", "TRDAT", "PWDCHGDATE", "USTYP"],
                        options=[f"BNAME = '{username}'"],
                        rowcount=1
                    )

                    if users:
                        user = users[0]
                        is_locked = user.get("UFLAG", "0") != "0"
                        last_login = user.get("TRDAT", "")
                        pwd_changed = user.get("PWDCHGDATE", "")

                        # Determine risk
                        risk = "LOW"
                        issues = []

                        if not is_locked:
                            risk = "HIGH"
                            issues.append("User is not locked")

                        if last_login and last_login != "00000000":
                            risk = "CRITICAL" if not is_locked else "MEDIUM"
                            issues.append(f"User has logged in (last: {last_login})")

                        if not pwd_changed or pwd_changed == "00000000":
                            issues.append("Password may not have been changed from default")
                            if not is_locked:
                                risk = "CRITICAL"

                        results.append({
                            "username": username,
                            "exists": True,
                            "is_locked": is_locked,
                            "lock_status": self._get_lock_status(user.get("UFLAG", "0")),
                            "last_login": last_login,
                            "password_changed": pwd_changed,
                            "user_type": self._get_user_type(user.get("USTYP", "")),
                            "risk": risk,
                            "issues": issues
                        })
                    else:
                        results.append({
                            "username": username,
                            "exists": False,
                            "risk": "LOW",
                            "issues": []
                        })

                except Exception as e:
                    results.append({
                        "username": username,
                        "exists": "unknown",
                        "error": str(e),
                        "risk": "UNKNOWN"
                    })

            overall_risk = "CRITICAL" if any(r.get("risk") == "CRITICAL" for r in results) \
                          else "HIGH" if any(r.get("risk") == "HIGH" for r in results) \
                          else "MEDIUM" if any(r.get("risk") == "MEDIUM" for r in results) \
                          else "LOW"

            return {
                "success": True,
                "overall_risk": overall_risk,
                "users_checked": len(default_users),
                "results": results,
                "recommendation": "Lock all default SAP users and change their passwords. "
                                  "These accounts are well-known and targeted by attackers."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_password_policy(self) -> Dict[str, Any]:
        """
        Tool 9: Check SAP password policy parameters.

        Returns:
            Dict with password policy settings and recommendations
        """
        try:
            # Read profile parameters from PRGN_CUST
            params_to_check = [
                ("login/min_password_lng", "8", "Minimum password length"),
                ("login/password_expiration_time", "90", "Password expiration days"),
                ("login/min_password_letters", "1", "Minimum letters in password"),
                ("login/min_password_digits", "1", "Minimum digits in password"),
                ("login/min_password_specials", "1", "Minimum special characters"),
                ("login/password_history_size", "5", "Password history size"),
                ("login/fails_to_session_end", "3", "Failed logins before session end"),
                ("login/fails_to_user_lock", "5", "Failed logins before user lock"),
            ]

            results = []

            for param_name, recommended, description in params_to_check:
                try:
                    # Try to get from profile parameter (if function available)
                    param_data = self._read_table(
                        table="PRGN_CUST",
                        fields=["NAME", "VALUE"],
                        options=[f"NAME = '{param_name}'"],
                        rowcount=1
                    )

                    if param_data:
                        current_value = param_data[0].get("VALUE", "Not set")
                    else:
                        current_value = "Not set"

                    # Check compliance
                    compliant = self._check_param_compliance(param_name, current_value, recommended)

                    results.append({
                        "parameter": param_name,
                        "description": description,
                        "current_value": current_value,
                        "recommended_value": recommended,
                        "compliant": compliant,
                        "risk": "LOW" if compliant else "MEDIUM"
                    })

                except Exception:
                    results.append({
                        "parameter": param_name,
                        "description": description,
                        "current_value": "Unable to read",
                        "recommended_value": recommended,
                        "compliant": False,
                        "risk": "UNKNOWN"
                    })

            compliant_count = sum(1 for r in results if r.get("compliant", False))

            return {
                "success": True,
                "overall_compliance": f"{compliant_count}/{len(results)}",
                "risk_level": "LOW" if compliant_count == len(results)
                             else "MEDIUM" if compliant_count >= len(results) / 2
                             else "HIGH",
                "parameters": results,
                "recommendation": "Review and update password policy parameters to meet security standards. "
                                  "Consider SAP Note 1458262 for best practices."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_users_no_roles(self) -> Dict[str, Any]:
        """
        Tool 10: Find active users with no role assignments.

        Returns:
            Dict with orphan user accounts
        """
        try:
            # Get all active users
            all_users = self._read_table(
                table="USR02",
                fields=["BNAME", "USTYP", "ERDAT", "TRDAT"],
                options=["UFLAG = '0'"],  # Not locked
                rowcount=2000
            )

            # Get all users with role assignments
            users_with_roles = self._read_table(
                table="AGR_USERS",
                fields=["UNAME"],
                options=[],
                rowcount=5000
            )

            users_with_roles_set = set(u["UNAME"] for u in users_with_roles)

            # Find users without roles
            orphan_users = []
            for user in all_users:
                username = user["BNAME"]
                if username not in users_with_roles_set:
                    orphan_users.append({
                        "username": username,
                        "user_type": self._get_user_type(user.get("USTYP", "")),
                        "created_date": user.get("ERDAT", ""),
                        "last_login": user.get("TRDAT", "")
                    })

            return {
                "success": True,
                "risk_level": "MEDIUM" if orphan_users else "LOW",
                "total_active_users": len(all_users),
                "users_without_roles": len(orphan_users),
                "users": orphan_users,
                "recommendation": "Users without roles may indicate orphaned accounts or setup issues. "
                                  "Review and either assign roles or lock these accounts."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    # Helper methods

    def _get_lock_status(self, uflag: str) -> str:
        """Convert UFLAG value to human-readable status."""
        try:
            flag = int(uflag)
        except (ValueError, TypeError):
            return "Unknown"

        if flag == 0:
            return "Not locked"
        elif flag == 32:
            return "Globally locked by admin"
        elif flag == 64:
            return "Locked by admin"
        elif flag == 128:
            return "Locked (wrong passwords)"
        elif flag == 192:
            return "Locked (admin + wrong passwords)"
        else:
            return f"Locked (flag: {flag})"

    def _get_lock_reason(self, uflag: str) -> str:
        """Get lock reason from UFLAG."""
        try:
            flag = int(uflag)
        except (ValueError, TypeError):
            return "Unknown"

        if flag == 0:
            return "Not locked"
        elif flag in [32, 64]:
            return "Administrator lock"
        elif flag == 128:
            return "Too many wrong password attempts"
        elif flag == 192:
            return "Administrator lock + wrong password attempts"
        else:
            return f"System lock (code: {flag})"

    def _get_user_type(self, ustyp: str) -> str:
        """Convert USTYP to human-readable type."""
        types = {
            "A": "Dialog",
            "B": "System",
            "C": "Communication",
            "L": "Reference",
            "S": "Service"
        }
        return types.get(ustyp, f"Unknown ({ustyp})")

    def _get_tcode_description(self, tcode: str) -> str:
        """Get description for critical tcode."""
        descriptions = {
            "SU01": "User Maintenance",
            "SE38": "ABAP Editor",
            "SE16": "Data Browser",
            "SM30": "Table Maintenance",
            "PFCG": "Role Maintenance",
            "SCC5": "Client Delete",
            "RZ10": "Profile Maintenance",
            "SM59": "RFC Destinations",
            "SE80": "Object Navigator",
            "SA38": "Program Execution"
        }
        return descriptions.get(tcode, "Unknown")

    def _get_tcode_risk(self, tcode: str) -> str:
        """Get risk level for critical tcode."""
        critical = ["SU01", "PFCG", "SCC5", "RZ10", "SM59"]
        high = ["SE38", "SE80", "SA38"]

        if tcode in critical:
            return "CRITICAL"
        elif tcode in high:
            return "HIGH"
        else:
            return "MEDIUM"

    def _check_param_compliance(self, param: str, current: str, recommended: str) -> bool:
        """Check if a parameter meets recommended value."""
        if current in ["Not set", "Unable to read", ""]:
            return False

        try:
            current_int = int(current)
            recommended_int = int(recommended)

            # For min values, current should be >= recommended
            if "min" in param:
                return current_int >= recommended_int
            # For max/limit values, current should be <= recommended
            elif "fails" in param or "lock" in param:
                return current_int <= recommended_int
            # For expiration, should be > 0 and <= recommended
            elif "expiration" in param:
                return 0 < current_int <= recommended_int
            # For history, should be >= recommended
            elif "history" in param:
                return current_int >= recommended_int
            else:
                return current_int >= recommended_int

        except (ValueError, TypeError):
            return current == recommended

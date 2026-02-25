"""
SAP Basis Tools for MCP Server
Implements system administration scenarios using RFC calls via JCo connector.

Tools for system health, jobs, RFC destinations, and transport management.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class BasisTools:
    """SAP Basis administration tools using RFC calls."""

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

    def get_system_info(self) -> Dict[str, Any]:
        """
        Tool 11: Get SAP system information.

        Returns:
            Dict with system details (SID, hostname, release, kernel, OS, DB)
        """
        try:
            # Call RFC_SYSTEM_INFO
            result = self.conn.get_system_info()

            # Extract relevant info from the result
            rfcsi_export = result.get("RFCSI_EXPORT", {})

            system_info = {
                "system_id": rfcsi_export.get("RFCSYSID", ""),
                "database_host": rfcsi_export.get("RFCDBHOST", ""),
                "database_system": rfcsi_export.get("RFCDBSYS", ""),
                "sap_release": rfcsi_export.get("RFCSAPRL", ""),
                "machine_type": rfcsi_export.get("RFCMACH", ""),
                "operating_system": rfcsi_export.get("RFCOPSYS", ""),
                "timezone": rfcsi_export.get("RFCTZONE", ""),
                "kernel_release": rfcsi_export.get("RFCKERNRL", ""),
                "host": rfcsi_export.get("RFCHOST", ""),
                "ip_address": rfcsi_export.get("RFCIPADDR", ""),
                "codepage": rfcsi_export.get("RFCCHARTYP", ""),
                "installation_number": rfcsi_export.get("RFCINSTNR", "")
            }

            return {
                "success": True,
                "system_info": system_info,
                "summary": f"SAP {system_info['system_id']} - "
                           f"Release {system_info['sap_release']} on {system_info['operating_system']}"
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_failed_jobs(self, hours: int = 24) -> Dict[str, Any]:
        """
        Tool 12: Get failed/aborted background jobs.

        Args:
            hours: Number of hours to look back (default 24)

        Returns:
            Dict with list of failed jobs
        """
        try:
            # Calculate cutoff date and time
            cutoff = datetime.now() - timedelta(hours=hours)
            cutoff_date = cutoff.strftime("%Y%m%d")
            cutoff_time = cutoff.strftime("%H%M%S")

            # Query TBTCO for aborted jobs (STATUS = 'A')
            jobs = self._read_table(
                table="TBTCO",
                fields=["JOBNAME", "JOBCOUNT", "STATUS", "SDLSTRTDT", "SDLSTRTTM",
                        "ENDDATE", "ENDTIME", "AUTHCKNAM"],
                options=[
                    f"STATUS = 'A'",
                    f"AND SDLSTRTDT >= '{cutoff_date}'"
                ],
                rowcount=500
            )

            failed_jobs = []
            for job in jobs:
                start_date = job.get("SDLSTRTDT", "")
                start_time = job.get("SDLSTRTTM", "")
                end_date = job.get("ENDDATE", "")
                end_time = job.get("ENDTIME", "")

                # Calculate duration if possible
                duration = "Unknown"
                if start_date and end_date and start_time and end_time:
                    try:
                        start_dt = datetime.strptime(f"{start_date}{start_time}", "%Y%m%d%H%M%S")
                        end_dt = datetime.strptime(f"{end_date}{end_time}", "%Y%m%d%H%M%S")
                        duration_sec = (end_dt - start_dt).total_seconds()
                        if duration_sec >= 3600:
                            duration = f"{duration_sec / 3600:.1f} hours"
                        elif duration_sec >= 60:
                            duration = f"{duration_sec / 60:.1f} minutes"
                        else:
                            duration = f"{duration_sec:.0f} seconds"
                    except ValueError:
                        pass

                failed_jobs.append({
                    "job_name": job.get("JOBNAME", ""),
                    "job_count": job.get("JOBCOUNT", ""),
                    "status": self._get_job_status(job.get("STATUS", "")),
                    "start_date": start_date,
                    "start_time": start_time,
                    "end_date": end_date,
                    "end_time": end_time,
                    "duration": duration,
                    "scheduled_by": job.get("AUTHCKNAM", "")
                })

            # Sort by start date/time, newest first
            failed_jobs.sort(
                key=lambda x: f"{x['start_date']}{x['start_time']}",
                reverse=True
            )

            return {
                "success": True,
                "period_hours": hours,
                "total_failed_jobs": len(failed_jobs),
                "risk_level": "HIGH" if len(failed_jobs) > 10 else "MEDIUM" if failed_jobs else "LOW",
                "jobs": failed_jobs,
                "recommendation": "Investigate aborted jobs and fix root causes. "
                                  "Critical batch jobs may need immediate attention."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_rfc_destinations(self) -> Dict[str, Any]:
        """
        Tool 13: Check RFC destinations for security issues.

        Returns:
            Dict with RFC destination list and security assessment
        """
        try:
            # Query RFCDES for RFC destinations
            destinations = self._read_table(
                table="RFCDES",
                fields=["RFCDEST", "RFCTYPE", "RFCOPTIONS"],
                options=["RFCTYPE IN ('3', 'T', 'H')"],  # R/3, TCP/IP, HTTP
                rowcount=500
            )

            # Parse destinations and check for security issues
            dest_list = []
            security_issues = []

            for dest in destinations:
                rfcdest = dest.get("RFCDEST", "")
                rfctype = dest.get("RFCTYPE", "")
                options = dest.get("RFCOPTIONS", "")

                # Parse type
                dest_type = self._get_rfc_type(rfctype)

                # Check for security issues
                issues = []

                # Check if using default user SAP*
                if "SAP*" in options.upper():
                    issues.append("Uses SAP* user")
                    security_issues.append({
                        "destination": rfcdest,
                        "issue": "Using SAP* default user",
                        "risk": "CRITICAL"
                    })

                # Check for stored password indicator
                if "P=" in options and rfctype == "3":
                    # Password stored in destination
                    pass  # This is normal but should be audited

                dest_info = {
                    "destination": rfcdest,
                    "type": dest_type,
                    "raw_type": rfctype,
                    "issues": issues,
                    "risk": "CRITICAL" if issues else "LOW"
                }
                dest_list.append(dest_info)

            # Get destination counts by type
            type_counts = {}
            for d in dest_list:
                t = d["type"]
                type_counts[t] = type_counts.get(t, 0) + 1

            return {
                "success": True,
                "total_destinations": len(dest_list),
                "destinations_by_type": type_counts,
                "risk_level": "CRITICAL" if security_issues else "LOW",
                "security_issues": security_issues,
                "destinations": dest_list[:50],  # Limit output
                "recommendation": "Review RFC destinations using default users. "
                                  "Use dedicated technical users with minimal privileges."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_system_parameters(self, param_name: str = None) -> Dict[str, Any]:
        """
        Tool 14: Get security-relevant system parameters.

        Args:
            param_name: Optional filter for parameter name

        Returns:
            Dict with parameter values and recommendations
        """
        try:
            # Security-relevant parameters to check
            security_params = [
                ("login/min_password_lng", "8", "Password minimum length"),
                ("login/password_expiration_time", "90", "Password expiration (days)"),
                ("login/fails_to_session_end", "3", "Failed logins to end session"),
                ("login/fails_to_user_lock", "5", "Failed logins to lock user"),
                ("login/no_automatic_user_sapstar", "1", "Disable auto SAP* user"),
                ("auth/no_check_in_some_cases", "N", "Skip auth checks (should be N)"),
                ("rdisp/gui_auto_logout", "3600", "GUI auto logout (seconds)"),
                ("icm/HTTP/logging_0", "PREFIX=/,LOGFILE=...", "ICM HTTP logging"),
                ("login/password_compliance_to_current_policy", "1", "Enforce password policy"),
                ("login/disable_cpic", "0", "CPIC user type disabled"),
            ]

            results = []

            for param, recommended, description in security_params:
                if param_name and param_name.lower() not in param.lower():
                    continue

                try:
                    param_data = self._read_table(
                        table="PRGN_CUST",
                        fields=["NAME", "VALUE"],
                        options=[f"NAME = '{param}'"],
                        rowcount=1
                    )

                    current_value = param_data[0].get("VALUE", "Not set") if param_data else "Not set"

                    # Check compliance
                    compliant = self._check_param_security(param, current_value, recommended)

                    results.append({
                        "parameter": param,
                        "description": description,
                        "current_value": current_value,
                        "recommended_value": recommended,
                        "compliant": compliant,
                        "risk": "LOW" if compliant else "MEDIUM"
                    })

                except Exception:
                    results.append({
                        "parameter": param,
                        "description": description,
                        "current_value": "Error reading",
                        "recommended_value": recommended,
                        "compliant": False,
                        "risk": "UNKNOWN"
                    })

            compliant_count = sum(1 for r in results if r.get("compliant", False))

            return {
                "success": True,
                "parameters_checked": len(results),
                "compliant_count": compliant_count,
                "risk_level": "LOW" if compliant_count == len(results)
                             else "MEDIUM" if compliant_count >= len(results) / 2
                             else "HIGH",
                "parameters": results,
                "recommendation": "Review and update system parameters according to SAP security guidelines. "
                                  "See SAP Notes 1539556 and 1458262."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_transport_requests(self, days: int = 7) -> Dict[str, Any]:
        """
        Tool 15: Check recent transport requests.

        Args:
            days: Number of days to look back (default 7)

        Returns:
            Dict with recent transport requests
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).strftime("%Y%m%d")

            # Query E070 for transport header
            transports = self._read_table(
                table="E070",
                fields=["TRKORR", "TRSTATUS", "AS4USER", "AS4DATE", "AS4TIME", "STRKORR"],
                options=[
                    f"AS4DATE >= '{cutoff_date}'",
                    "AND TRSTATUS IN ('D', 'L', 'R')"  # Modifiable, Local, Released
                ],
                rowcount=200
            )

            transport_list = []

            for tr in transports:
                status = tr.get("TRSTATUS", "")

                transport_list.append({
                    "transport": tr.get("TRKORR", ""),
                    "status": self._get_transport_status(status),
                    "owner": tr.get("AS4USER", ""),
                    "date": tr.get("AS4DATE", ""),
                    "time": tr.get("AS4TIME", ""),
                    "parent": tr.get("STRKORR", "")
                })

            # Sort by date, newest first
            transport_list.sort(
                key=lambda x: f"{x['date']}{x['time']}",
                reverse=True
            )

            # Count by status
            status_counts = {}
            for t in transport_list:
                s = t["status"]
                status_counts[s] = status_counts.get(s, 0) + 1

            return {
                "success": True,
                "period_days": days,
                "total_transports": len(transport_list),
                "by_status": status_counts,
                "transports": transport_list,
                "recommendation": "Review recent transports for unauthorized changes. "
                                  "Monitor transport activity in production systems."
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    # Helper methods

    def _get_job_status(self, status: str) -> str:
        """Convert job status code to description."""
        statuses = {
            "S": "Scheduled",
            "R": "Running",
            "F": "Finished",
            "A": "Aborted",
            "P": "Planned",
            "Y": "Ready",
            "Z": "Canceled"
        }
        return statuses.get(status, f"Unknown ({status})")

    def _get_rfc_type(self, rfctype: str) -> str:
        """Convert RFC type code to description."""
        types = {
            "3": "ABAP Connection (R/3)",
            "T": "TCP/IP Connection",
            "H": "HTTP Connection",
            "I": "Internal",
            "L": "Logical Destination",
            "2": "R/2 Connection",
            "X": "Special",
            "G": "HTTP Connection to Group"
        }
        return types.get(rfctype, f"Unknown ({rfctype})")

    def _get_transport_status(self, status: str) -> str:
        """Convert transport status code to description."""
        statuses = {
            "D": "Modifiable",
            "L": "Local",
            "R": "Released",
            "N": "Released (import started)",
            "O": "Release started"
        }
        return statuses.get(status, f"Unknown ({status})")

    def _check_param_security(self, param: str, current: str, recommended: str) -> bool:
        """Check if a parameter meets security recommendation."""
        if current in ["Not set", "Error reading", ""]:
            return False

        try:
            # Numeric comparisons
            current_int = int(current)
            recommended_int = int(recommended)

            if "min" in param:
                return current_int >= recommended_int
            elif "fails" in param or "logout" in param:
                return current_int <= recommended_int
            elif "expiration" in param:
                return 0 < current_int <= recommended_int
            else:
                return current_int >= recommended_int

        except (ValueError, TypeError):
            # String comparison
            return current.upper() == recommended.upper()

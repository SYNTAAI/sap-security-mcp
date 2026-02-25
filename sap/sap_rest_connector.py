"""
SAP REST Connector - Drop-in replacement for PyRFC Connection.
Communicates with JCo microservice via REST API.

Usage:
    # Instead of: from pyrfc import Connection
    # Use:        from sap_rest_connector import SAPRestConnector as Connection

    conn = SAPRestConnector()
    conn.connect(
        destination_name="SAP_DEV",
        ashost="sap-host",
        sysnr="00",
        client="100",
        user="RFC_USER",
        passwd="password"
    )

    result = conn.call("RFC_READ_TABLE",
        QUERY_TABLE="USR02",
        DELIMITER="|",
        FIELDS=[{"FIELDNAME": "BNAME"}]
    )

    conn.close()
"""

import os
import logging
import requests
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class RFCError(Exception):
    """RFC Error compatible with PyRFC exceptions."""
    def __init__(self, code: str = "RFC_ERROR", message: str = "Unknown error"):
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


class CommunicationError(RFCError):
    """Communication error with SAP system."""
    pass


class ABAPApplicationError(RFCError):
    """ABAP application error."""
    pass


class ABAPRuntimeError(RFCError):
    """ABAP runtime error."""
    pass


class LogonError(RFCError):
    """Logon failure."""
    pass


class SAPRestConnector:
    """
    SAP Connector using REST API to JCo microservice.
    Drop-in replacement for PyRFC Connection.

    Supports two usage patterns:

    1. PyRFC-compatible (connect in constructor):
       conn = SAPRestConnector(ashost="host", sysnr="00", client="100", user="usr", passwd="pwd")
       result = conn.call("RFC_FUNCTION")
       conn.close()

    2. Two-step connect:
       conn = SAPRestConnector()
       conn.connect(ashost="host", ...)
       result = conn.call("RFC_FUNCTION")
       conn.close()
    """

    def __init__(self,
                 ashost: str = None,
                 sysnr: str = None,
                 client: str = None,
                 user: str = None,
                 passwd: str = None,
                 lang: str = "EN",
                 service_url: str = None,
                 api_key: str = None,
                 timeout: int = 120,
                 **kwargs):
        """
        Initialize REST connector. If SAP connection params provided, connects immediately.

        Args:
            ashost: SAP application server host
            sysnr: SAP system number
            client: SAP client number
            user: SAP username
            passwd: SAP password
            lang: Language (default: EN)
            service_url: JCo service URL (default: from env JCO_SERVICE_URL or http://localhost:8080)
            api_key: API key for authentication (default: from env JCO_SERVICE_API_KEY)
            timeout: Request timeout in seconds (default: 120 for large table reads)
            **kwargs: Additional parameters (codepage, etc.) - ignored for compatibility
        """
        self.service_url = (service_url or
                           os.environ.get('JCO_SERVICE_URL', 'http://localhost:8080')).rstrip('/')
        self.api_key = api_key or os.environ.get('JCO_SERVICE_API_KEY')
        self.timeout = timeout
        self.destination_name: Optional[str] = None
        self._connected = False
        self._connection_params = {}

        # If connection params provided, connect immediately (PyRFC-compatible behavior)
        if ashost and user and passwd:
            self.connect(
                ashost=ashost,
                sysnr=sysnr or "00",
                client=client or "100",
                user=user,
                passwd=passwd,
                lang=lang,
                **kwargs
            )

    @property
    def _headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def connect(self,
                destination_name: str = None,
                ashost: str = None,
                sysnr: str = "00",
                client: str = "100",
                user: str = None,
                passwd: str = None,
                lang: str = "EN",
                **kwargs) -> bool:
        """
        Register destination and establish connection.
        Compatible with PyRFC Connection interface.
        """
        # Generate destination name if not provided
        if not destination_name:
            destination_name = f"DEST_{ashost}_{client}".replace(".", "_").replace("-", "_")

        self.destination_name = destination_name
        self._connection_params = {
            "ashost": ashost,
            "sysnr": str(sysnr),
            "client": str(client),
            "user": user,
            "passwd": passwd,
            "lang": lang
        }

        logger.info(f"Connecting to SAP via JCo: {destination_name} ({ashost}:{sysnr} client {client})")

        # Register destination with JCo service
        try:
            response = requests.post(
                f"{self.service_url}/api/v1/destinations",
                headers=self._headers,
                json={
                    "name": destination_name,
                    "config": {
                        "ashost": ashost,
                        "sysnr": str(sysnr),
                        "client": str(client),
                        "user": user,
                        "passwd": passwd,
                        "lang": lang,
                        "pool_capacity": kwargs.get("pool_capacity", 5),
                        "peak_limit": kwargs.get("peak_limit", 10)
                    }
                },
                timeout=30
            )

            if response.status_code != 200:
                raise ConnectionError(f"Failed to register destination: {response.text}")

            result = response.json()
            if not result.get("success", True):
                raise ConnectionError(f"Registration failed: {result.get('error', 'Unknown')}")

        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to JCo service at {self.service_url}: {e}")
        except requests.exceptions.Timeout:
            raise ConnectionError(f"Timeout connecting to JCo service at {self.service_url}")

        # Test connection with ping
        try:
            ping_response = requests.post(
                f"{self.service_url}/api/v1/destinations/{destination_name}/ping",
                headers=self._headers,
                timeout=30
            )

            if ping_response.status_code == 200:
                result = ping_response.json()
                if result.get("success"):
                    self._connected = True
                    response_time = result.get('responseTimeMs', '?')
                    logger.info(f"Connected to SAP: {destination_name} ({response_time}ms)")
                    return True
                else:
                    error_msg = result.get('error', 'Unknown error')
                    if 'logon' in error_msg.lower() or 'password' in error_msg.lower():
                        raise LogonError("LOGON_FAILURE", error_msg)
                    raise ConnectionError(f"SAP ping failed: {error_msg}")
            else:
                raise ConnectionError(f"Ping request failed: {ping_response.text}")

        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Ping failed - JCo service unreachable: {e}")
        except requests.exceptions.Timeout:
            raise ConnectionError("Ping timeout - SAP system may be unreachable")

    def call(self, function_name: str, **params) -> Dict[str, Any]:
        """
        Execute RFC function call.
        Compatible with PyRFC Connection.call() interface.

        Args:
            function_name: Name of RFC function to call
            **params: Function parameters

        Returns:
            Dictionary with function results (same format as PyRFC)

        Raises:
            RFCError: If RFC call fails
            ConnectionError: If not connected
        """
        if not self._connected:
            raise ConnectionError("Not connected to SAP system. Call connect() first.")

        logger.debug(f"RFC Call: {function_name} on {self.destination_name}")

        try:
            response = requests.post(
                f"{self.service_url}/api/v1/rfc/execute",
                headers=self._headers,
                json={
                    "destination": self.destination_name,
                    "function": function_name,
                    "parameters": params
                },
                timeout=self.timeout
            )

            if response.status_code != 200:
                raise RFCError("HTTP_ERROR", f"HTTP {response.status_code}: {response.text}")

            result = response.json()

            if not result.get("success"):
                error = result.get("error", "Unknown error")
                error_code = result.get("errorCode", "RFC_ERROR")

                # Map to specific exception types (compatible with PyRFC)
                if "COMMUNICATION" in error_code:
                    raise CommunicationError(error_code, error)
                elif "LOGON" in error_code:
                    raise LogonError(error_code, error)
                elif "APPLICATION" in error_code:
                    raise ABAPApplicationError(error_code, error)
                elif "SYSTEM" in error_code or "RUNTIME" in error_code:
                    raise ABAPRuntimeError(error_code, error)
                else:
                    raise RFCError(error_code, error)

            execution_time = result.get("executionTimeMs", 0)
            logger.debug(f"RFC {function_name} completed in {execution_time}ms")

            # Return data in same format as PyRFC
            return result.get("data", {})

        except requests.exceptions.Timeout:
            raise CommunicationError("TIMEOUT", f"Request timed out after {self.timeout}s")
        except requests.exceptions.ConnectionError as e:
            raise CommunicationError("CONNECTION_ERROR", f"JCo service connection failed: {e}")

    def ping(self) -> bool:
        """Test if connection is alive."""
        if not self.destination_name:
            return False

        try:
            response = requests.post(
                f"{self.service_url}/api/v1/destinations/{self.destination_name}/ping",
                headers=self._headers,
                timeout=10
            )
            return response.status_code == 200 and response.json().get("success", False)
        except:
            return False

    def get_system_info(self) -> Dict[str, Any]:
        """Get SAP system information via RFC_SYSTEM_INFO."""
        return self.call("RFC_SYSTEM_INFO")

    def close(self):
        """Close connection (release from pool)."""
        self._connected = False
        logger.debug(f"Connection closed: {self.destination_name}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def __repr__(self):
        status = "connected" if self._connected else "disconnected"
        return f"<SAPRestConnector({self.destination_name}) {status}>"


# Convenience alias for drop-in replacement
Connection = SAPRestConnector

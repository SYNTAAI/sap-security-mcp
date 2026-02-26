"""
OData Entity Mappings
=====================
Maps SAP security concepts to OData entity sets and fields.

Two configurations:
- STANDARD: Uses SAP standard OData services (API_USER_SRV, etc.)
- CUSTOM:   Uses custom OData service (ZSECURITY_SRV or similar)

To add your own custom OData service, modify the CUSTOM_ENTITIES mapping
to match your service's entity sets and field names.
"""


# ─── Standard SAP OData Entities ─────────────────────────────────────────────
# These map to SAP's standard OData APIs
# Note: Not all security data is available via standard APIs.
# For comprehensive security auditing, custom OData services are recommended.

STANDARD_ENTITIES = {
    "users": {
        "service": "/sap/opu/odata/sap/API_BUSINESS_PARTNER",
        "entity_set": "A_BusinessPartner",
        "fields": {
            "username": "BusinessPartner",
            "name": "BusinessPartnerFullName",
            "user_type": "BusinessPartnerCategory",
        }
    },
    # Standard APIs are limited for security auditing.
    # Most security tables (USR02, AGR_USERS, etc.) require custom OData services.
}


# ─── Custom OData Entities ───────────────────────────────────────────────────
# These map to a custom OData service built for SAP security auditing.
# Modify these to match YOUR custom OData service entity sets and fields.
#
# Expected custom service: /sap/opu/odata/sap/ZSECURITY_SRV
# (or whatever your service is named)

CUSTOM_ENTITIES = {

    # ── User Security ────────────────────────────────────────────────────
    "all_users": {
        "entity_set": "SapAllUsers",
        "fields": {
            "username": "Bname",
            "user_type": "Ustyp",
            "last_logon": "Trdat",
            "created_date": "Erdat",
            "created_by": "Creator",
            "lock_status": "Uflag",
            "valid_from": "Gltgv",
            "valid_to": "Gltgb",
            "password_changed": "Pwdchgdate",
        }
    },
    "user_profiles": {
        "entity_set": "UserProfiles",
        "fields": {
            "username": "Bname",
            "profile": "Profile",
        }
    },
    "user_roles": {
        "entity_set": "UserRoles",
        "fields": {
            "username": "Uname",
            "role_name": "AgrName",
            "from_date": "FromDat",
            "to_date": "ToDat",
        }
    },

    # ── Role Security ────────────────────────────────────────────────────
    "role_tcodes": {
        "entity_set": "RoleTcodes",
        "fields": {
            "role_name": "AgrName",
            "tcode": "Tcode",
        }
    },
    "role_descriptions": {
        "entity_set": "RoleTexts",
        "fields": {
            "role_name": "AgrName",
            "description": "Text",
            "language": "Spras",
        }
    },

    # ── System Security ──────────────────────────────────────────────────
    "rfc_destinations": {
        "entity_set": "RfcDestinations",
        "fields": {
            "destination": "Rfcdest",
            "type": "Rfctype",
            "host": "Rfchost",
            "service": "Rfcservice",
            "description": "Rfcdoc1",
        }
    },
    "system_parameters": {
        "entity_set": "SystemParameters",
        "fields": {
            "name": "Name",
            "value": "Value",
            "default": "DefaultValue",
            "description": "Description",
        }
    },
    "background_jobs": {
        "entity_set": "BackgroundJobs",
        "fields": {
            "job_name": "Jobname",
            "job_creator": "Sdluname",
            "status": "Status",
            "start_date": "Strtdate",
            "end_date": "Enddate",
        }
    },
    "transport_requests": {
        "entity_set": "TransportRequests",
        "fields": {
            "request": "Trkorr",
            "owner": "AsUser",
            "status": "Trstatus",
            "description": "As4text",
            "date": "As4date",
        }
    },

    # ── Audit & Compliance ───────────────────────────────────────────────
    "security_audit_log": {
        "entity_set": "SecurityAuditLog",
        "fields": {
            "date": "Aldate",
            "time": "Altime",
            "user": "Aluser",
            "event": "Aleession",
            "terminal": "Alterminal",
            "message": "Almessage",
        }
    },
    "sod_violations": {
        "entity_set": "SodViolations",
        "fields": {
            "username": "Bname",
            "conflict_type": "ConflictType",
            "tcode1": "Tcode1",
            "tcode2": "Tcode2",
            "risk_level": "RiskLevel",
            "description": "Description",
        }
    },

    # ── System Info ──────────────────────────────────────────────────────
    "system_info": {
        "entity_set": "SystemInfo",
        "fields": {
            "sid": "Sysid",
            "client": "Mandt",
            "host": "Host",
            "instance": "Instance",
            "db_system": "DbSystem",
            "kernel_release": "KernelRelease",
            "sap_release": "SapRelease",
        }
    },
}


# ─── SoD Conflict Matrix ────────────────────────────────────────────────────
# Used for local SoD analysis when no dedicated SoD entity exists.
# Maps conflict descriptions to pairs of critical transaction codes.

SOD_CONFLICT_MATRIX = [
    {
        "name": "User & Role Administration",
        "risk": "CRITICAL",
        "tcodes": [["SU01", "SU01D"], ["PFCG", "SU02"]],
        "description": "User can create users AND assign roles - complete access control bypass"
    },
    {
        "name": "Invoice to Payment",
        "risk": "CRITICAL",
        "tcodes": [["FB60", "FB65", "FV60"], ["F110", "F-53"]],
        "description": "User can create invoices AND execute payments - fraud risk"
    },
    {
        "name": "Procure to Pay",
        "risk": "HIGH",
        "tcodes": [["ME21N", "ME22N"], ["MIGO", "MIRO"]],
        "description": "User can create POs AND perform goods receipt/invoice verification"
    },
    {
        "name": "Vendor Master & Payments",
        "risk": "CRITICAL",
        "tcodes": [["XK01", "XK02", "MK01"], ["F110", "F-53"]],
        "description": "User can create/modify vendors AND execute payments"
    },
    {
        "name": "HR Master Data & Payroll",
        "risk": "CRITICAL",
        "tcodes": [["PA20", "PA30"], ["PC00_M99_PAY"]],
        "description": "User can modify HR master data AND run payroll"
    },
    {
        "name": "Transport & Debug",
        "risk": "HIGH",
        "tcodes": [["SE01", "SE09", "SE10"], ["SE38", "SE80", "SA38"]],
        "description": "User can manage transports AND execute programs in production"
    },
    {
        "name": "Basis Administration",
        "risk": "HIGH",
        "tcodes": [["SM49", "SM69"], ["SE16", "SE16N"]],
        "description": "User can execute OS commands AND browse tables directly"
    },
    {
        "name": "Financial Period & Posting",
        "risk": "HIGH",
        "tcodes": [["OB52"], ["FB01", "FB50", "F-02"]],
        "description": "User can open/close periods AND post financial documents"
    },
]


# ─── Critical Transaction Codes ─────────────────────────────────────────────

CRITICAL_TCODES = {
    "SU01": {"risk": "CRITICAL", "category": "User Admin", "description": "User Maintenance"},
    "SU01D": {"risk": "HIGH", "category": "User Admin", "description": "User Display (can see password hashes)"},
    "PFCG": {"risk": "CRITICAL", "category": "Role Admin", "description": "Role Maintenance"},
    "SU02": {"risk": "CRITICAL", "category": "Role Admin", "description": "Profile Maintenance"},
    "SE16": {"risk": "CRITICAL", "category": "Data Access", "description": "Data Browser - direct table access"},
    "SE16N": {"risk": "CRITICAL", "category": "Data Access", "description": "General Table Display"},
    "SM49": {"risk": "CRITICAL", "category": "System", "description": "Execute External OS Commands"},
    "SM69": {"risk": "CRITICAL", "category": "System", "description": "Maintain External OS Commands"},
    "SE38": {"risk": "HIGH", "category": "Development", "description": "ABAP Editor"},
    "SE80": {"risk": "HIGH", "category": "Development", "description": "Object Navigator"},
    "SA38": {"risk": "HIGH", "category": "Development", "description": "ABAP Reporting"},
    "SM30": {"risk": "HIGH", "category": "Config", "description": "Table Maintenance"},
    "SM31": {"risk": "HIGH", "category": "Config", "description": "Table Maintenance"},
    "STMS": {"risk": "HIGH", "category": "Transport", "description": "Transport Management System"},
    "SE01": {"risk": "HIGH", "category": "Transport", "description": "Transport Organizer"},
    "SE09": {"risk": "HIGH", "category": "Transport", "description": "Workbench Organizer"},
    "SE10": {"risk": "HIGH", "category": "Transport", "description": "Customizing Organizer"},
    "SM59": {"risk": "HIGH", "category": "Connectivity", "description": "RFC Destinations"},
    "SICF": {"risk": "HIGH", "category": "Connectivity", "description": "HTTP Service Maintenance"},
    "SM21": {"risk": "MEDIUM", "category": "Monitoring", "description": "System Log"},
    "SM37": {"risk": "MEDIUM", "category": "Jobs", "description": "Background Job Overview"},
    "ST01": {"risk": "HIGH", "category": "Trace", "description": "System Trace"},
    "ST05": {"risk": "HIGH", "category": "Trace", "description": "Performance Trace / SQL Trace"},
    "RZ10": {"risk": "HIGH", "category": "System", "description": "Profile Parameter Maintenance"},
    "RZ11": {"risk": "MEDIUM", "category": "System", "description": "Profile Parameter Display"},
}


# ─── Default SAP Users ──────────────────────────────────────────────────────

DEFAULT_SAP_USERS = [
    "SAP*", "DDIC", "TMSADM", "EARLYWATCH", "SAPCPIC",
    "BTC_DATA_LOAD", "SAPSUPPORT", "ADMIN",
]


# ─── Security-Relevant Profile Parameters ───────────────────────────────────

SECURITY_PARAMETERS = [
    # Login parameters
    "login/min_password_lng",
    "login/min_password_digits",
    "login/min_password_letters",
    "login/min_password_specials",
    "login/min_password_uppercase",
    "login/min_password_lowercase",
    "login/password_max_idle_initial",
    "login/password_max_idle_productive",
    "login/fails_to_session_end",
    "login/fails_to_user_lock",
    "login/failed_user_auto_unlock",
    "login/no_automatic_user_sapstar",
    "login/disable_multi_gui_login",
    "login/password_expiration_time",
    "login/password_change_for_sso",
    # RFC parameters
    "rfc/reject_expired_passwd",
    "rfc/selfd_disable",
    # Auth parameters
    "auth/rfc_authority_check",
    "auth/no_check_in_some_cases",
    # ICM/Security parameters
    "icm/HTTPS/verify_client",
    "ssl/ciphersuites",
    # Audit
    "rsau/enable",
    "rsau/selection_slots",
]

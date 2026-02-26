# Building a Custom OData Service for SAP Security Auditing

This guide explains how to create a custom OData service in SAP that exposes security-relevant data for use with the SyntaAI MCP Server.

## Overview

While SAP provides some standard OData APIs, they don't cover the security tables needed for comprehensive auditing. You'll need to create a custom OData service (recommended name: `ZSECURITY_SRV`) that exposes the relevant tables as read-only entity sets.

## Prerequisites

- SAP NetWeaver 7.40+ (for CDS views) or 7.31+ (for SEGW)
- Authorization to create OData services (transaction SEGW or ADT)
- ICF service node activation rights (transaction SICF)

## Approach 1: CDS Views + OData (Recommended for S/4HANA)

### Step 1: Create CDS Views

```abap
@AbapCatalog.sqlViewName: 'ZSEC_USERS'
@AbapCatalog.compiler.compareFilter: true
@OData.publish: true
@AccessControl.authorizationCheck: #CHECK
define view ZI_SecurityUsers as select from usr02 {
  key bname    as Bname,
      ustyp    as Ustyp,
      trdat    as Trdat,
      erdat    as Erdat,
      creator  as Creator,
      uflag    as Uflag,
      gltgv    as Gltgv,
      gltgb    as Gltgb,
      pwdchgdate as Pwdchgdate
}
```

Create similar CDS views for:
- `UST04` → UserProfiles
- `AGR_USERS` → UserRoles
- `AGR_TCODES` → RoleTcodes
- `AGR_TEXTS` → RoleTexts
- `RFCDES` → RfcDestinations
- `TBTCO` → BackgroundJobs
- `E070` → TransportRequests

### Step 2: Expose as OData

With `@OData.publish: true`, the CDS view is automatically available as an OData service. Register it in transaction `/IWFND/MAINT_SERVICE`.

## Approach 2: SEGW (Classic Gateway - all SAP versions)

### Step 1: Create OData Project

1. Transaction `SEGW`
2. Create new project: `ZSECURITY`
3. Add Entity Types for each table
4. Generate Runtime Objects

### Step 2: Implement Data Provider

In the DPC_EXT class, implement the `GET_ENTITYSET` methods to read from the security tables.

Example for Users entity:

```abap
METHOD userset_get_entityset.
  SELECT bname ustyp trdat erdat creator uflag gltgv gltgb pwdchgdate
    FROM usr02
    INTO CORRESPONDING FIELDS OF TABLE et_entityset.
ENDMETHOD.
```

### Step 3: Register Service

1. Transaction `/IWFND/MAINT_SERVICE`
2. Add service `ZSECURITY_SRV`
3. Assign system alias

## Entity Set Reference

Your custom service should expose these entity sets:

| Entity Set | Source Table | Key Field | Purpose |
|-----------|-------------|-----------|---------|
| SapAllUsers | USR02 | Bname | User master records |
| UserProfiles | UST04 | Bname, Profile | Profile assignments |
| UserRoles | AGR_USERS | Uname, AgrName | Role assignments |
| RoleTcodes | AGR_TCODES | AgrName, Tcode | Transaction codes in roles |
| RoleTexts | AGR_TEXTS | AgrName, Spras | Role descriptions |
| RfcDestinations | RFCDES | Rfcdest | RFC connections |
| SystemParameters | RSPARAM | Name | Profile parameters |
| BackgroundJobs | TBTCO | Jobname, Jobcount | Job overview |
| TransportRequests | E070 | Trkorr | Transport requests |
| SystemInfo | Custom | Sysid | System information |

## Security Considerations

1. **Read-Only**: Only implement `GET_ENTITY` and `GET_ENTITYSET`. Do NOT implement create/update/delete.
2. **Authorization**: Use SAP standard authorization checks (S_TCODE, S_USER_GRP, etc.)
3. **Communication User**: Create a dedicated service user with:
   - Type: System/Communication
   - Only the authorizations needed for reading the above tables
   - No dialog login capability
4. **HTTPS Only**: Ensure the ICF service node only accepts HTTPS connections
5. **Rate Limiting**: Consider implementing throttling in the DPC class

## Testing

Test your OData service in browser:

```
https://your-sap-host:44300/sap/opu/odata/sap/ZSECURITY_SRV/SapAllUsers?$format=json&sap-client=100
```

You should see JSON output with user records.

## Mapping to MCP Server

Once your service is created, update the `.env` file:

```env
ODATA_MODE=custom
ODATA_SERVICE_PATH=/sap/opu/odata/sap/ZSECURITY_SRV
```

If your entity set names or field names differ, update `sap/entity_mappings.py` → `CUSTOM_ENTITIES` to match your service.

---

Need help building the OData service? Contact [support@syntaai.com](mailto:support@syntaai.com) or check our [enterprise offering](https://syntaai.com) which includes pre-built OData services.

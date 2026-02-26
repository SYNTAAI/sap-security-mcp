# SAP-Side Deployment Guide: SyntaAI MCP Security Service

## Overview

The SyntaAI SAP Security MCP Server requires a **single OData service** (`ZSB_SYNTASEC`) deployed on your SAP S/4HANA system. This service exposes 9 read-only entity sets for security auditing via RAP.

**Effort:** ~1 hour | **Risk:** Zero — read-only views on standard tables | **SAP Version:** S/4HANA 1909+

**ECC Customers:** See separate ECC deployment guide (uses individual CDS `@OData.publish`)

---

## Architecture

```
9 CDS Views → 1 Service Definition (ZSD_SYNTASEC) → 1 Service Binding (ZSB_SYNTASEC)
Result: /sap/opu/odata/sap/ZSB_SYNTASEC/ with 9 entity sets
```

| Entity Set | CDS View | Source Tables | Purpose |
|-----------|----------|---------------|---------|
| Users | ZI_SEC_USERS | USR02, USR21, ADRP | All user master data |
| UserProfiles | ZI_SEC_USER_PROFILES | UST04, USR02 | SAP_ALL/SAP_NEW detection |
| UserRoleAccess | ZI_SEC_USER_ACCESS | USR02, AGR_USERS, AGR_DEFINE, AGR_TEXTS | User-role assignments |
| RoleTcodes | ZI_SEC_ROLE_TCODES | AGR_TCODES, TSTCT, AGR_HIER | Role tcodes and Fiori apps |
| SystemParameters | ZI_SEC_SYSTEM_PARAMS | PAHI | Security profile parameters |
| RfcDestinations | ZI_SEC_RFC_DESTINATIONS | RFCDES | RFC destination security |
| BackgroundJobs | ZI_SEC_BACKGROUND_JOBS | TBTCO | Background job monitoring |
| Transports | ZI_SEC_TRANSPORTS | E070, E07T | Transport monitoring |
| SystemInfo | ZI_SEC_SYSTEM_INFO | T000 | System client info |

---

## Step-by-Step Deployment

### Step 1: Create Package

Eclipse ADT → New → ABAP Package → Name: `Z_SYNTASEC` → Assign transport request

### Step 2: Create 9 CDS Views

For each `.asddls` file in `abap/cds_views/`:
1. Right-click `Z_SYNTASEC` → New → Data Definition
2. Paste source code → Activate (Ctrl+F3)

**Important:** These views do NOT have `@OData.publish: true`. They are exposed through the unified RAP service.

### Step 3: Create Service Definition

1. Right-click `Z_SYNTASEC` → New → Service Definition
2. Name: `ZSD_SYNTASEC`
3. Paste from `abap/service/ZSD_SYNTASEC.srvd`
4. Activate

### Step 4: Create Service Binding

1. Right-click `Z_SYNTASEC` → New → Service Binding
2. Name: `ZSB_SYNTASEC`
3. Binding Type: **OData V2 - Web API**
4. Service Definition: `ZSD_SYNTASEC`
5. Activate
6. **Click Publish** (required!)

### Step 5: Test

```
https://<host>:<port>/sap/opu/odata/sap/ZSB_SYNTASEC/Users?$format=json&$top=5&sap-client=100
```

### Step 6: Create Communication User

SU01 → Create `ZMCP_ODATA` → Type: Communication (C) → Assign S_SERVICE for ZSB_SYNTASEC

### Step 7: Configure MCP Server

```env
SAP_BASE_URL=https://your-sap-host:44300
SAP_CLIENT=100
SAP_USER=ZMCP_ODATA
SAP_PASSWORD=your-password
ODATA_MODE=custom
ODATA_SERVICE_PATH=/sap/opu/odata/sap/ZSB_SYNTASEC
```

---

## Transport to QAS/PRD

**Standard Transport:** SE09 → Release → Import via landscape route. After import, open Service Binding in ADT → click Publish.

**abapGit:** Push package Z_SYNTASEC to GitHub → Pull on target → Activate → Publish binding.

**Manual:** Customer follows this guide and creates objects in ADT.

---

## Useful OData Queries

```
/Users?$filter=DaysSinceLogon gt 90 and IsActive eq 'X'           # Dormant users
/UserProfiles?$filter=ProfileRisk eq 'Critical'                     # SAP_ALL users
/BackgroundJobs?$filter=Status eq 'A'                               # Failed jobs
/RfcDestinations?$filter=SecurityRisk eq 'High'                     # Risky RFC
/SystemParameters?$filter=Category eq 'Login'                       # Password params
```

---

## Uninstallation

Unpublish binding → Delete all objects in Z_SYNTASEC → Delete package. Zero SAP standard impact.

---

Built by [SyntaAI](https://syntaai.com)

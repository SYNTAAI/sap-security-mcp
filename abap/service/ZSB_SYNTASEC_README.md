# Service Binding: ZSB_SYNTASEC

## Create in Eclipse ADT

1. Right-click package `Z_SYNTASEC`
2. New → Other ABAP Repository Object
3. Business Services → Service Binding
4. Enter:
   - Name: `ZSB_SYNTASEC`
   - Description: `SyntaAI Security OData Service`
   - Binding Type: `OData V2 - Web API`
   - Service Definition: `ZSD_SYNTASEC`
5. Activate (Ctrl+F3)
6. Click **Publish** button in the editor

## After Publishing

The service will be available at:
```
/sap/opu/odata/sap/ZSB_SYNTASEC/
```

### Entity Sets (all under one service):
```
/sap/opu/odata/sap/ZSB_SYNTASEC/Users
/sap/opu/odata/sap/ZSB_SYNTASEC/UserProfiles
/sap/opu/odata/sap/ZSB_SYNTASEC/UserRoleAccess
/sap/opu/odata/sap/ZSB_SYNTASEC/RoleTcodes
/sap/opu/odata/sap/ZSB_SYNTASEC/SystemParameters
/sap/opu/odata/sap/ZSB_SYNTASEC/RfcDestinations
/sap/opu/odata/sap/ZSB_SYNTASEC/BackgroundJobs
/sap/opu/odata/sap/ZSB_SYNTASEC/Transports
/sap/opu/odata/sap/ZSB_SYNTASEC/SystemInfo
```

### Test URL:
```
https://<sap-host>:<port>/sap/opu/odata/sap/ZSB_SYNTASEC/Users?$format=json&$top=5&sap-client=100
```

## Notes
- Binding Type should be OData V2 for maximum compatibility
- OData V4 is also available if preferred (change Binding Type)
- No need to register in /IWFND/MAINT_SERVICE — RAP handles it automatically
- Service is automatically available after Publish

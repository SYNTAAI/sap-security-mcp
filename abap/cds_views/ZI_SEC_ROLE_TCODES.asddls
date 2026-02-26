@AbapCatalog.sqlViewName: 'ZSECROLETC'
@AbapCatalog.compiler.compareFilter: true
@AccessControl.authorizationCheck: #NOT_REQUIRED
@EndUserText.label: 'UAR - Role TCodes and Fiori'
define view ZI_SEC_ROLE_TCODES as select from agr_tcodes as AT
  left outer join tstct as TT on AT.tcode = TT.tcode and TT.sprsl = 'E'
{
  key AT.agr_name as Role,
  key AT.tcode as ObjectId,
  TT.ttext as ObjectDescription,
  'TCode' as ObjectType
}
union all select from agr_hier as AH
  left outer join agr_hiert as AHT on AH.agr_name = AHT.agr_name and AH.object_id = AHT.object_id and AHT.spras = 'E'
{
  key AH.agr_name as Role,
  key AH.object_id as ObjectId,
  AHT.text as ObjectDescription,
  'Fiori App' as ObjectType
}
where AH.report = 'CAT_PROVIDER' or AH.report = 'GROUP_PROVIDER'

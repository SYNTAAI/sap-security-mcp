@AbapCatalog.sqlViewName: 'ZSECPARAMS'
@AbapCatalog.compiler.compareFilter: true
@AccessControl.authorizationCheck: #NOT_REQUIRED
@EndUserText.label: 'SEC - Security Profile Parameters'
@Metadata.ignorePropagatedAnnotations: true
define view ZI_SEC_SYSTEM_PARAMS
  as select from pahi
{
  key pahi.parname        as ParameterName,
  key pahi.paession       as Instance,
  key pahi.pardate        as ChangeDate,

  pahi.parvalue           as ParameterValue,
  pahi.paruser            as ChangedBy,

  case
    when pahi.parname like 'login/%' then 'Login'
    when pahi.parname like 'rfc/%' then 'RFC'
    when pahi.parname like 'auth/%' then 'Authorization'
    when pahi.parname like 'gw/%' then 'Gateway'
    when pahi.parname like 'snc/%' then 'SNC'
    when pahi.parname like 'icm/%' then 'ICM'
    when pahi.parname like 'rsau/%' then 'Audit'
    when pahi.parname like 'ssl/%' then 'SSL'
    else 'Other'
  end                     as Category
}
where pahi.parname like 'login/%'
   or pahi.parname like 'rfc/%'
   or pahi.parname like 'auth/%'
   or pahi.parname like 'gw/%'
   or pahi.parname like 'snc/%'
   or pahi.parname like 'icm/%'
   or pahi.parname like 'rsau/%'
   or pahi.parname like 'ssl/%'

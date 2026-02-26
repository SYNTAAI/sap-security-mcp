@AbapCatalog.sqlViewName: 'ZSECSYSINFO'
@AbapCatalog.compiler.compareFilter: true
@AccessControl.authorizationCheck: #NOT_REQUIRED
@EndUserText.label: 'SEC - System Client Info'
@Metadata.ignorePropagatedAnnotations: true
define view ZI_SEC_SYSTEM_INFO
  as select from t000 as C
{
  key C.mandt              as Client,

  C.mtext                  as ClientDescription,
  C.cccategory             as ClientCategory,
  C.cccoractiv             as ChangeOption,
  C.ccnocliind             as CrossClientChanges,
  C.logsys                 as LogicalSystem,

  case C.cccategory
    when 'P' then 'Production'
    when 'T' then 'Test'
    when 'C' then 'Customizing'
    when 'D' then 'Demo'
    when 'E' then 'Training'
    when 'S' then 'SAP Reference'
    else 'Other'
  end                     as ClientCategoryDesc,

  case C.cccoractiv
    when '0' then 'Changes allowed'
    when '1' then 'No changes allowed'
    when '2' then 'No changes - auto transport'
    else 'Other'
  end                     as ChangeOptionDesc
}

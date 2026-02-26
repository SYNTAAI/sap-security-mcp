@AbapCatalog.sqlViewName: 'ZSECTRANSP'
@AbapCatalog.compiler.compareFilter: true
@AccessControl.authorizationCheck: #NOT_REQUIRED
@EndUserText.label: 'SEC - Transport Requests'
@Metadata.ignorePropagatedAnnotations: true
define view ZI_SEC_TRANSPORTS
  as select from e070 as T
    left outer join e07t as TT
      on T.trkorr = TT.trkorr and TT.langu = 'E'
{
  key T.trkorr             as TransportId,

  T.trfunction             as Function,
  T.trstatus               as Status,
  T.as4user                as Owner,
  T.as4date                as Date,
  T.as4time                as Time,
  TT.as4text               as Description,

  case T.trstatus
    when 'D' then 'Modifiable'
    when 'L' then 'Modifiable (Protected)'
    when 'O' then 'Released'
    when 'R' then 'Released'
    when 'N' then 'Released (Imported)'
    else 'Other'
  end                     as StatusDesc,

  case T.trfunction
    when 'K' then 'Workbench'
    when 'W' then 'Customizing'
    when 'T' then 'Transport of Copies'
    when 'C' then 'Relocation'
    else 'Other'
  end                     as FunctionDesc
}

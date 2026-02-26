@AbapCatalog.sqlViewName: 'ZSECRFCDEST'
@AbapCatalog.compiler.compareFilter: true
@AccessControl.authorizationCheck: #NOT_REQUIRED
@EndUserText.label: 'SEC - RFC Destinations'
@Metadata.ignorePropagatedAnnotations: true
define view ZI_SEC_RFC_DESTINATIONS
  as select from rfcdes
{
  key rfcdes.rfcdest       as Destination,

  rfcdes.rfctype           as RfcType,
  rfcdes.rfcoptions        as Options,
  rfcdes.rfchost           as Host,
  rfcdes.rfcservice        as Service,
  rfcdes.rfcsysid          as TargetSystem,
  rfcdes.rfcsameusr        as SameUser,
  rfcdes.rfcuser           as StoredUser,
  rfcdes.rfcdoc1           as Description,
  rfcdes.rfcsnc            as SncEnabled,
  rfcdes.rfctrustid        as TrustRelation,

  case rfcdes.rfctype
    when '3' then 'RFC (ABAP)'
    when 'H' then 'HTTP'
    when 'G' then 'HTTP (External)'
    when 'W' then 'WebRFC'
    when 'T' then 'TCP/IP'
    when 'I' then 'Internal'
    when 'L' then 'Logical'
    else 'Other'
  end                      as RfcTypeDesc,

  case
    when rfcdes.rfctype = 'H' or rfcdes.rfctype = 'G' then 'High'
    when rfcdes.rfcsnc = '' and rfcdes.rfctype = '3' then 'Medium'
    when rfcdes.rfcuser is not initial then 'Medium'
    else 'Low'
  end                      as SecurityRisk
}

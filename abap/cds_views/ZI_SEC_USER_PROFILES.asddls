@AbapCatalog.sqlViewName: 'ZSECUPROF'
@AbapCatalog.compiler.compareFilter: true
@AccessControl.authorizationCheck: #NOT_REQUIRED
@EndUserText.label: 'SEC - User Profile Assignments'
@Metadata.ignorePropagatedAnnotations: true
define view ZI_SEC_USER_PROFILES
  as select from ust04 as UP
    left outer join usr02 as U
      on UP.bname = U.bname
{
  key UP.bname            as UserId,
  key UP.profile          as Profile,

  U.ustyp                 as UserType,
  U.uflag                 as LockFlag,
  U.trdat                 as LastLogonDate,

  case U.ustyp
    when 'A' then 'Dialog'
    when 'B' then 'System'
    when 'C' then 'Communication'
    when 'L' then 'Reference'
    when 'S' then 'Service'
    else 'Other'
  end                     as UserTypeDesc,

  case U.uflag
    when 0 then 'Unlocked'
    when 32 then 'Admin Lock'
    when 64 then 'Incorrect Logons'
    when 128 then 'Global Lock'
    else 'Locked'
  end                     as LockStatusDesc,

  case
    when UP.profile = 'SAP_ALL' then 'Critical'
    when UP.profile = 'SAP_NEW' then 'Critical'
    when UP.profile = 'S_A.SYSTEM' then 'High'
    else 'Standard'
  end                     as ProfileRisk
}

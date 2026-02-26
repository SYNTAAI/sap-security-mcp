@AbapCatalog.sqlViewName: 'ZSECUSERS'
@AbapCatalog.compiler.compareFilter: true
@AccessControl.authorizationCheck: #NOT_REQUIRED
@EndUserText.label: 'SEC - All SAP Users'
@Metadata.ignorePropagatedAnnotations: true
define view ZI_SEC_USERS
  as select from usr02 as U
    left outer join usr21 as U21
      on U.bname = U21.bname
    left outer join adrp as AP
      on U21.persnumber = AP.persnumber
{
  key U.bname             as UserId,

  AP.name_first           as FirstName,
  AP.name_last            as LastName,
  U.ustyp                 as UserType,
  U.class                 as UserGroup,
  U.erdat                 as CreatedDate,
  U.creator               as CreatedBy,
  U.trdat                 as LastLogonDate,
  U.ltime                 as LastLogonTime,
  U.gltgv                 as ValidFrom,
  U.gltgb                 as ValidTo,
  U.uflag                 as LockFlag,
  U.pwdchgdate            as PasswordChangeDate,

  dats_days_between(U.trdat, $session.system_date) as DaysSinceLogon,

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
    when U.uflag = 0 then 'X'
    else ''
  end                     as IsActive,

  case
    when U.gltgb < $session.system_date then 'Expired'
    when U.gltgv > $session.system_date then 'Future'
    else 'Valid'
  end                     as UserStatus,

  case
    when U.bname = 'SAP*' or U.bname = 'DDIC' or U.bname = 'TMSADM'
      or U.bname = 'EARLYWATCH' or U.bname = 'SAPCPIC'
      then 'X'
    else ''
  end                     as IsDefaultUser
}

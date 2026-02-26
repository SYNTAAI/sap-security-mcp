@AbapCatalog.sqlViewName: 'ZSECUSERACC'
@AbapCatalog.compiler.compareFilter: true
@AccessControl.authorizationCheck: #NOT_REQUIRED
@EndUserText.label: 'UAR - User Role Assignments'
@Metadata.ignorePropagatedAnnotations: true
define view ZI_SEC_USER_ACCESS
  as select from usr02 as U
    inner join agr_users as UR
      on U.bname = UR.uname
    left outer join agr_define as AD
      on UR.agr_name = AD.agr_name
    left outer join agr_texts as ATX
      on  UR.agr_name = ATX.agr_name
      and ATX.spras   = 'E'
      and ATX.line    = '00000'
    left outer join usr21 as U21
      on U.bname = U21.bname
    left outer join adrp as AP
      on U21.persnumber = AP.persnumber
{
  key U.bname           as UserId,
  key UR.agr_name       as Role,

  AP.name_first         as FirstName,
  AP.name_last          as LastName,
  U.ustyp               as UserType,
  U.trdat               as LastLogonDate,
  U.ltime               as LastLogonTime,
  U.gltgv               as UserValidFrom,
  U.gltgb               as UserValidTo,
  U.uflag               as UserLockFlag,
  U.class               as UserGroup,

  ATX.text              as RoleDescription,
  AD.parent_agr         as ParentRole,
  UR.from_dat           as RoleValidFrom,
  UR.to_dat             as RoleValidTo,

  case U.ustyp
    when 'A' then 'Dialog'
    when 'B' then 'System'
    when 'C' then 'Communication'
    when 'L' then 'Reference'
    when 'S' then 'Service'
    else 'Other'
  end                   as UserTypeDesc,

  case U.uflag
    when 0 then 'Unlocked'
    when 32 then 'Admin Lock'
    when 64 then 'Incorrect Logons'
    when 128 then 'Global Lock'
    else 'Locked'
  end                   as LockStatusDesc,

  case
    when U.gltgb < $session.system_date then 'Expired'
    when U.gltgv > $session.system_date then 'Future'
    else 'Valid'
  end                   as UserStatus,

  case
    when AD.parent_agr is not initial then 'Single'
    else 'Composite'
  end                   as RoleType,

  case
    when UR.to_dat < $session.system_date then 'Expired'
    when UR.from_dat > $session.system_date then 'Future'
    else 'Valid'
  end                   as RoleStatus,

  case
    when UR.agr_name like '%SAP_ALL%' then 'Critical'
    when UR.agr_name like '%SAP_NEW%' then 'Critical'
    when UR.agr_name like '%ADMIN%' then 'High'
    else 'Standard'
  end                   as RoleRisk
}

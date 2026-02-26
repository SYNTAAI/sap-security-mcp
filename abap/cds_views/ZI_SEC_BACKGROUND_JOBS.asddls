@AbapCatalog.sqlViewName: 'ZSECBGJOBS'
@AbapCatalog.compiler.compareFilter: true
@AccessControl.authorizationCheck: #NOT_REQUIRED
@EndUserText.label: 'SEC - Background Jobs'
@Metadata.ignorePropagatedAnnotations: true
define view ZI_SEC_BACKGROUND_JOBS
  as select from tbtco as J
{
  key J.jobname            as JobName,
  key J.jobcount           as JobCount,

  J.sdluname              as CreatedBy,
  J.authcknam             as StepUser,
  J.status                as Status,
  J.sdlstrtdt             as ScheduledDate,
  J.sdlstrttm             as ScheduledTime,
  J.strtdate              as StartDate,
  J.strttme               as StartTime,
  J.enddate               as EndDate,
  J.endtme                as EndTime,

  case J.status
    when 'S' then 'Scheduled'
    when 'R' then 'Released'
    when 'F' then 'Finished'
    when 'A' then 'Aborted'
    when 'Y' then 'Ready'
    when 'P' then 'Active'
    else 'Unknown'
  end                     as StatusDesc
}

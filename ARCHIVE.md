

# ARCHIVED TASKS

This is where Tasks that are too ambitious go to hibernate, until we discover some clever way to resolve the concerns.  


### Task: System Workflow Escalation  (IGNORE, TOO AMBITIOUS)
- Enterprises will need both User-authority escalations (user approves in seconds via Guard) and System Workflow-authority escalations (ServiceNow/Jira/etc. approves over hours/days)
- The PDP determines the path based on risk level, user role, and tool
- **User authority**: PDP returns 'workflow'. Gate gets `escalation_jti` + `escalation_jwt`, pushes JWT to Guard, stores pending entry by JTI; retry path and 60s poll both apply
- **System Workflow authority**: PDP returns 'workflow'. 
  - Several tasks that are ambiguous right now
  - do we still send information to Gate to allow the user to launch the workflow? Or do we launch the workflow directly, and let the workflow system verify with the user that this work needs to be done?
    - What do those data structures look like?  
    - What information does Gate receive right away, vs later (does it receive anything at all)
      - perhaps Gate gets workflow metadata only (reference URL, ticket ID, SLA, etc.), no JTI; presents metadata to agent via configurable message template; no pending entry stored; 
        60s poll is the only collection path (acceptable given approval latency)
- When a System workflow approves, it calls Guard's `/token/deposit`; Gate picks up the resulting token on next poll
- priority: very low
- notes: this is difficult to do without an actual enterprise deployment to test against, and even then it will be much different from organization to organization

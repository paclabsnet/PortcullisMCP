

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




### Acquire Human Credentials

the DAG model isn't implemented inside organizations of meaningful size, so the value as a tool for identity is low


#### Option A: Device Authorization Grant (RFC 8628)
  Gate initiates auth by calling the IdP's device authorization endpoint. The IdP returns a short user code and a URL. Gate prints (or surfaces via the agent) something like:

  "Visit https://login.enterprise.com/activate and enter code: WXYZ-1234"                                                             

  The user visits that URL on any browser, any device. Gate polls the IdP token endpoint until the user completes it. No redirect URI, no localhost web server at all.

  This is how gh auth login, az login, and most CLI tools handle this today. 

#### Option B: Enterprise-injected token file (already in your design)
  The config already has token file: "~/.portcullis/oidc-token". The enterprise deploys an SSO agent (Okta Device Trust, a custom
  refresh daemon, etc.) that keeps this file current. Gate reads it. Gate never touches OAuth at all.                              
  This is the right answer for a mature enterprise deployment where the org already manages endpoint identity.                     


#### Recommendation for Portcullis:
  Why not both?
  1. Token file — primary, enterprise-managed, zero Gate complexity
  2. Device flow — fallback when no valid token file exists; works everywhere, no localhost trust issues, fits the CLI/daemon model



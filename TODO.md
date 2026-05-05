# Feature Set

I wnat to change the way we manage the policy used by portcullis-localfs.  Currently, it is held in the YAML controlled by
Portcullis-Gate

I want to change the structure of the YAML to allow for a 'keep-driven' fileystem policy, where portcullis-localfs pulls the
JSON down from Keep, and then converts it into the workspace/forbidden/strategy components that the localfs tool already
understands

Keep would provide a new endpoint that gate would consume.  the new endpoint would provide gate with the JSON it needs
to configure the policy.

Keep would hae an update to its YAML, to indicate how to discover the policy.  The default path would be to fetch
the policy from the PDP. the updated YAML would tell keep what path to follow to fetch the appropriate JSON, so it
could be sent down to Gate.


We do want to support backwards compatibiltiy at Gate - if the 'rules' section does not exist, it defaults to local,
so everything else would be the same.


So we need:
* new YAML parsing and config in Gate
* Gate parses the rules, either inside portcullis-localfs or (ideally) the rules are fetched from Keep and sent to localfs at startup time
* Keep needs new YAML and appropriate structures
* Keep needs an endpoint that Gate can call to fetch the policy
* Keep needs a way to pull the JSON from the PDP, and the YAML for Keep should indicate how to fetch the policy data


## Failure Scenarios
* Gate can't reach Keep at startup
  * this is fine, Gate would start in degraded mode anyways. Keep trying regularly.
* Keep isn't configured to provide config data to Gate
  * Generate warning logs at Keep. This could be malicious
* The JSON that Gate gets back from Keep is incorrectly formatted
  * Put Gate in degraded mode.  Include an error message saying that local filesystem policy rules are incorrectly formatted
* Gate asks for policy from Keep, does not get it in a timelly manner
  * If Gate has existing policy, reuse the current policy
  * move Gate to degraded mode until Keep starts responding properly
* Gate's local filesystem MCP is disabled, but there is configuration to fetch policy from Keep
  * Don't fetch policy from Keep if the localfs MCP is disabled



# YAML

here's what I'm thinking for the YAML for gate.  I've included both scenarios, partially pseudo-coded:


```
# local policy example
responsibility:
  tools:
      portcullis-localfs:                                                         enabled: true
        rules:                                                                    source: local
        workspace
        forbidden
        strategy

# remote policy example
responsibility:
    tools:
      portcullis-localfs:
        enabled: true
        rules:
          source: keep
          ttl: 3600
          on_fetch_failure: cached
```



which would roughly match to:
```
  type LocalFSConfig struct {                                                                                                             Enabled   bool                  `yaml:"enabled"`
      Rules     LocalFSRulesConfig    `yaml:"rules"`
      Workspace SandboxConfig         `yaml:"workspace"`
      Forbidden ForbiddenConfig       `yaml:"forbidden"`
      Strategy  LocalFSStrategyConfig `yaml:"strategy"`
  }

  type LocalFSRulesConfig struct {
      Source         string `yaml:"source"`           // "local" (default) | "keep"
      TTL            int    `yaml:"ttl"`               // seconds; keep source only
      OnFetchFailure string `yaml:"on_fetch_failure"`  // "cached" (default) | "fail"; keep source only
  }
```


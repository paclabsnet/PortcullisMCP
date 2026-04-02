

1. (FIXED) Portcullis-Gate - Logging - the output logs from Portcullis-Gate should include the errors that put it into degraded
   mode, so I don't have to call the agent and use portcullis_status to discover what the error is


2. (FIXED) Portcullis-Gate - YAML - management_api.port should default to 7777 if it isn't specified


3. (FIXED) Portcullis-Gate - FastPath - `resolvePath` in `internal/gate/fastpath.go` only handles one level of non-existent path
   (resolves parent + base). For a write target like `/sandbox/newdir/subdir/file.txt` where neither `newdir/` nor
   `subdir/` exist yet, `EvalSymlinks` on the parent fails and `resolvePath` returns an error. FastPath treats any
   resolve error as a deny, so writes to deeply nested new paths inside the sandbox are incorrectly denied rather than
   fast-pathed. The fix is to replace `resolvePath` with the same full ancestor-walking logic used in
   `internal/gate/localfs/server.go:fsServer.resolve`, or extract that logic into a shared helper used by both.



4. (FIXED) Portcullis-Gate - portcullis_login MCP - need the ability to send a 'force' directive to the portcullis login tool, so even if Portcullis-Gate thinks that the user is logged in, they will start the process again.  This is necessary if the IdP  restarts, because the keyid "owned" by Portcullis-Gate is no longer recognized by the IdP



5. (FIXED) Portcullis-Guard - authentication - there's no need for `/token/claim` to be outside of the authentication umbrella, just because it's technically fine. Consistency is better





6. All - config - the config is clunky and arbitrary. Create some consistent "domains" of config, and ensure that all of the key/values are 1) in the right domain and 2) the names are not really_long_strings_with_underscores_just_because_that_is_explicit



7. All - config - add a mode: dev, production at the top of each config file.  This will govern whether we allow insecure implementations or fail at startup


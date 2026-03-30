

1. Portcullis-Gate - Logging - the output logs from Portcullis-Gate should include the errors that put it into degraded
   mode, so I don't have to call the agent and use portcullis_status to discover what the error is


2. Portcullis-Gate - YAML - management_api.port should default to 7777 if it isn't specified


3. Portcullis-Gate - FastPath - `resolvePath` in `internal/gate/fastpath.go` only handles one level of non-existent path
   (resolves parent + base). For a write target like `/sandbox/newdir/subdir/file.txt` where neither `newdir/` nor
   `subdir/` exist yet, `EvalSymlinks` on the parent fails and `resolvePath` returns an error. FastPath treats any
   resolve error as a deny, so writes to deeply nested new paths inside the sandbox are incorrectly denied rather than
   fast-pathed. The fix is to replace `resolvePath` with the same full ancestor-walking logic used in
   `internal/gate/localfs/server.go:fsServer.resolve`, or extract that logic into a shared helper used by both.



4. Portcullis-Gate - portcullis_login MCP - need the ability to send a 'force' directive to the portcullis login tool, so even if Portcullis-Gate thinks that the user is logged in, they will start the process again.  This is necessary if the Keep backend
restarts, which begs the question about whether cluster mode would work without sticky sessions


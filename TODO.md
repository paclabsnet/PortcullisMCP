# Feature Set


### Task:  Fine-grained and wildcard Filesystem permissions (DONE)

in the `responsibility.tools.portcullis-localfs` YAML config, add something like:

```
strategy:
   read: allow
   write: verify
   update: verify
   delete: deny
```

which implies that we have an internal configuration for each tool indicating whether it is read, write, update or delete (which should generally be obvious and easy to build in a hard-coded way.  `copy_file` and `move_file` should both be considered writes)

- allow:  automatically approve without forwarding to Keep
- verify: forward request to Keep for a decision
- deny:   automatically deny without forwarding to Keep

or if they need fine-grained control:

```
strategy:
   read_text_file: allow
   read_media_file: allow
   read_multiple_files: allow
   write_file: verify
   edit_file: verify
   create_directory: verify
   list_directory: allow
   list_directory_with_sizes: allow
   directory_tree: allow
   move_file: verify
   search_files: allow
   copy_file: verify
   delete_file: verify
   search_within_files: allow
   get_file_info: allow
   list_allowed_directories: allow
```

And this should mesh with the `workspace` and `forbidden` configurations as well. the strategy policies only applies within the `workspace` directories.  The `forbidden` directories are forbidden no matter what.


So if the enterprise wants to grant allow for everything on the local hard drive, except perhaps the most sensitive of directories, they set something like this:

```
strategy:
   read: allow
   write: allow
   update: allow
   delete: allow
```

and

```
workspace:
  directories:
    - "*"
forbidden:
  directories:
    - "~/.ssh"
    - "~/.portcullis"
    - "C:/Windows/System"
    - "C:/Windows/System32"
```

**What about directories that are not in `workspace` or `forbidden`**
Those are implicitly `verify`

**What about a directory that is in both `workspace` and `forbidden`**
Forbidden always wins

**Wildcard at the top means everything is open, even system directories?**
Yes. Probably not wise, but many organizations aren't doing anything to enforce this right now, so no need to add friction until they're ready for it.

**Tests**
- make sure that the "*" directory is interpreted as "every directory"
- make sure that the grouped policies (read, write, update, delete) are properly honored
- make sure that the fine-grained policies are properly honored
- make sure that the forbidden directories override any previous policy


### Task: Pass the identity JWT from Keep to the various backend MCPs as a header (DONE)

Enterprise MCPs need a mechanism to understand which user they are working with, and
Keep will have that information.  We can add configuration to Keep to indicate that
the JWT should be included in each call to the MCP in a header.

The structure will be:

```
    - name: "mock-enterprise-api"
      type: "http"
      url: "http://mock-enterprise-api:3000/mcp"
      allow_private_addresses: true
      identity_header: X-User-Identity
```

Note that each MCP can have its own header


### Task: Inject the identity JWT from Keep into the body of the MCP request (DONE)

Another way to get the identity JWT from Keep into the body of the MCP request will be to edit the JSON body of the MCP request and add a new field representing the JWT

```
    - name: "mock-enterprise-api"
      type: "http"
      url: "http://mock-enterprise-api:3000/mcp"
      allow_private_addresses: true
      identity_path: a.b.c
```

and in that example above, the JSON would look like

```
{
   "arguments" : {  ... existing ... },
   "a" : {
      "b": {
        "c": INSERT_JWT_HERE
      }
   }
}
```

Note that each MCP can have its own injection point.

**Tests**
- the identity path is "inside" the arguments JSON structure, and that's ok
- the identity path injection overrides any item that might have been placed there by the Agent


### Task: Allow Identity Exchange when passing identity token to MCP 

Combine the identity injection tasks with an additional capability: each MCP backend can optionally include a `token_exchange_url` URL to which Keep can post the existing JWT, and receive back a new identity element of some arbitrary custom format.  So for example, if the MCP just wants a userid, the URL would take the JWT and return the userid from it.  Or if the MCP needs the JWT validated and broken out into a custom JSON structure.  Or even if it wants XML or whatever.  We don't care, we just pass the token to the URL, and accept what we get back. We can look at the content encoding.  If it is JSON, we should treat it as JSON, and it should not be used as a header.  Any other content encoding should be treated as text if possible, and escaped properly (there may be different escaping rules for headers vs JSON strings)

This action should happen before you perform the identity injection.  There are a couple of edge cases: if the identity exchange returns JSON, it can't be added as a header. But that shouldn't cause a failure, just a warning. If the return can't be treated as a string (perhaps binary?) , it can't be added to either the header or the request. Also produces a warning log entry.  And, if the exchange produces JSON, it should be added to the MCP request body appropriately.  If the exchange produces a string, and the destination is the MCP request, the string should be added as the value for the key specified in the YAML.

We'll have to cache this exchanged identity in Keep to reduce latency, and we'll need to cache the conversion on a per-MCP basis, since the way one MCP handles identity might be different from the way other MCPs handle identity (so we could end up with multiple representations of the same origin token)

To avoid conflicts in memory, the key for each cached identity conversion should be a combination of the hash of the original identity token and the name of the MCP backend.  

The cache items should have a TTL.  If the cache runs out of room, expel the ones that are due to expire in the near future.

**Tests**
- the updated identities' path is "inside" the arguments JSON structure, and that's ok
- the updated identities' path injection overrides any item that might have been placed there by the Agent
- the updated identity can optionally be placed either in the header or in the MCP request
- handle updated identities that are JSON, that are not JSON, that are weird formats (binary) that can't be stored
- verify that different MCP tools with different token_exchange_urls are cached independently.
- verify that the cached identities expire when they haven't been accessed in a long time
- it's ok for the exchange to return XML or some other format, as long as it can be encoded as a string. If the MCP wants to parse XML, that's their choice

**Validation**
I think it's an error to include the same token in both the header and the MCP request body.  That seems like two sources of truth and likely to cause errors.




**Is the MCP request updated before it is sent to the PDP, or after?**

IMO, after. If you do all the work to convert the entity, and then send it to the PDP, the PDP now has two different instances of the identity - the Principal , and the identity elements from the Request and/or headers. That could lead to mistakes.  Also, don't forget, we have a mechanism for converting JWTs to Principals already, so if the customer needs information in the identity that isn't in the JWT, they can use that existing method.

Perhaps in the future we'll have a situation where it makes sense to do it first, but I'd like to see that IRL first.




### Task: Add OIDC login option to Guard

If a company doesn't have an SSO gateway, and is concerned about Guard escalation being exploited by a rogue AI, we can offer a login option for Guard, more or less identical to the one on Gate.



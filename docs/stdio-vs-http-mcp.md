#

## stdio

### claude desktop
```
    "portcullis": {
       "command": "portcullis-gate",
       "args": ["--config","~/.portcullis/gate.yaml"]
    }
```    



## http

### claude desktop

```
    "portcullis": {
       "command": "npx",
       "args": ["mcp-remote", "http://localhost:9090/mcp", "--header", "Authorization:${ENV_VAR}"]
    }
```

see untracked_notes.md for an example


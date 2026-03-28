# PortcullisMCP Quick Start — Windows

This guide walks you through getting the full PortcullisMCP demo running on a Windows machine. By the end you will have Keep, Guard, OPA, and two example MCP backends running in Docker, with Gate configured as an MCP server in your agent (Claude Desktop, VS Code, etc.).

## What you will need

| Tool | Where to get it | Notes |
|---|---|---|
| Go 1.24+ | https://go.dev/dl/ | Accept the default install path |
| Docker Desktop | https://www.docker.com/products/docker-desktop/ | Must be running before the demo starts |
| Git | https://git-scm.com/download/win | Needed to clone the repo |
| Make | see below | Not included with Windows by default |

### Installing Make

Pick whichever option matches your setup:

**Option A — winget (built into Windows 10/11):**
```powershell
winget install ezwinports.make
```

**Option B — Chocolatey:**
```powershell
choco install make
```

**Option C — Scoop:**
```powershell
scoop install make
```

**Option D — Git for Windows (no extra install needed):**
If you already have Git for Windows, `mingw32-make.exe` is in `C:\Program Files\Git\usr\bin`. You can either call it by that name, or add an alias in your PowerShell profile:
```powershell
Set-Alias make "C:\Program Files\Git\usr\bin\mingw32-make.exe"
```

Close and reopen your terminal after installing, then confirm with `make --version`.

---

## Step 1: Clone the repository

```powershell
git clone https://github.com/paclabsnet/PortcullisMCP.git
cd PortcullisMCP
```

---

## Step 2: Build the binaries

```powershell
make build
```

This compiles three executables into the `bin\` folder:
- `bin\portcullis-gate.exe`
- `bin\portcullis-keep.exe`
- `bin\portcullis-guard.exe`

---

## Step 3: Install Gate to your PATH

Gate is launched automatically by your AI agent — it is not something you run in a terminal yourself. For that to work, the `portcullis-gate.exe` binary needs to be on your PATH.

The easiest way is:

```powershell
make install
```

This copies `portcullis-gate.exe` to your Go bin directory (`%GOPATH%\bin`, usually `%USERPROFILE%\go\bin`), which `go install` already adds to your PATH.

**Verify it worked:**
```powershell
portcullis-gate --version
```

If Windows says it cannot find the command, add `%USERPROFILE%\go\bin` to your PATH manually:
1. Open **Start**, search for **"Edit the system environment variables"**
2. Click **Environment Variables**
3. Under **User variables**, select **Path** and click **Edit**
4. Click **New** and paste `%USERPROFILE%\go\bin`
5. Click OK, then close and reopen your terminal

---

## Step 4: Create your Gate config

Create the folder and copy the minimal config:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.portcullis"
Copy-Item config\gate-config.minimal.yaml "$env:USERPROFILE\.portcullis\gate.yaml"
```

The default config connects to Keep at `http://localhost:8080` and uses your Windows login as your identity — no changes needed for the demo.

---

## Step 5: Configure your AI agent

Gate is an MCP server that your agent launches automatically over stdio. You do not start it in a terminal.

### Claude Desktop

Open `%APPDATA%\Claude\claude_desktop_config.json` (create it if it does not exist) and add:

```json
{
  "mcpServers": {
    "portcullis": {
      "command": "portcullis-gate",
      "args": ["-config", "C:\\Users\\YourName\\.portcullis\\gate.yaml"]
    }
  }
}
```

Replace `YourName` with your actual Windows username, or use the full path you used in Step 4.

### VS Code (GitHub Copilot / Continue / other MCP-aware extensions)

In your VS Code `settings.json`, under `"mcp.servers"`:

```json
"portcullis": {
  "command": "portcullis-gate",
  "args": ["-config", "C:\\Users\\YourName\\.portcullis\\gate.yaml"]
}
```

### Claude Code (CLI)

```powershell
claude mcp add portcullis portcullis-gate -- -config "$env:USERPROFILE\.portcullis\gate.yaml"
```

---

## Step 6: Start the demo stack

Make sure Docker Desktop is running, then:

```powershell
make demo-start
```

This starts five containers:
- **OPA** at `http://localhost:8181` — policy decision point, loaded with sample policies
- **Keep** at `http://localhost:8080` — the MCP gateway
- **Guard** at `http://localhost:8444` — the escalation approval UI
- **mock-enterprise-api** (internal) — simulates an enterprise API with customer/order tools
- **fetch-mcp** (internal) — a web fetch tool

Wait a few seconds for all containers to become healthy. You can check with:
```powershell
docker compose -f deploy/docker-sandbox/docker-compose.yml ps
```

---

## Step 7: Try it out

Restart your agent (Claude Desktop, VS Code, etc.) so it picks up the new MCP server configuration. Then try these prompts:

```
What services are available from Portcullis MCP?
```

```
Please use Portcullis to fetch the latest headlines from bbc.com
```

```
Please use Portcullis to query orders for customer C001
```

```
Please use Portcullis to update customer C001's name to Bilbo Baggins
```

The last prompt should trigger an escalation. Your agent will return a link — click it to open the Guard approval page at `http://localhost:8444`. Review the request details and approve it. Then ask the agent to try again; it should succeed this time. (It won't actually do anything on the back-end)

---

## Stopping the demo

```powershell
make demo-stop
```

---

## Troubleshooting

**Gate is not found by my agent**
Confirm `portcullis-gate.exe` is on your PATH: open a new PowerShell window and run `portcullis-gate --version`. If it fails, revisit Step 3.

**"Cannot connect to Keep" error from Gate**
The demo stack may not be fully up yet. Wait a few seconds and restart your agent, or check `docker compose ps` to see if any container is still starting.

**Docker containers exit immediately**
Run `docker compose -f deploy/docker-sandbox/docker-compose.yml logs` to see error output. The most common cause is a port conflict — check that ports 8080, 8181, and 8444 are not already in use.

**Make says "missing separator"**
This usually means the Makefile was opened and re-saved with spaces instead of tabs. Re-clone the repo and do not open the Makefile in Notepad.

**Policy is denying everything**
The demo ships with a sample policy that allows most read operations. If you see unexpected denials, check the OPA decision log in the OPA docker container, or look at the Keep container logs.

---

## Next steps

- Read [ARCHITECTURE.md](../ARCHITECTURE.md) to understand how Gate, Keep, Guard, and OPA fit together
- Review the sample policy in `policies/` to see how to control access per tool and per user
- See `config/keep-config.example.yaml` for the full set of Keep configuration options including OIDC identity verification and mTLS

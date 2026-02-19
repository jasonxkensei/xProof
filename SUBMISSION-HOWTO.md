# How to Submit xProof to ClawHub and MCP Registry

---

## 1. ClawHub Submission

### What's ready

The `openclaw-skill/xproof/` directory now has the complete ClawHub structure:

```
openclaw-skill/xproof/
  claw.json          # Machine-readable manifest (tools, auth, config)
  clawhub.json       # Marketplace metadata (tagline, tags, category)
  SKILL.md           # Agent instructions (what ClawHub indexes for AI)
  scripts/certify.sh # Helper script
  references/api-reference.md
```

### Steps to submit

**Option A — CLI (recommended)**

```bash
# Install ClawHub CLI if not already installed
npm install -g clawhub

# From the repo root, publish the skill
clawhub publish ./openclaw-skill/xproof
```

**Option B — Dashboard**

1. Go to https://clawhub.ai
2. Click "Publish New Skill"
3. Upload the `openclaw-skill/xproof/` directory (or tar it first: `tar -czf xproof-skill.tar.gz -C openclaw-skill xproof/`)
4. Fill in any additional fields the form asks for (the content is in `clawhub.json`)

**Option C — GitHub repo (simplest)**

Since `github.com/jasonxkensei/xproof-openclaw-skill` already exists:

1. Push the new `claw.json` and `clawhub.json` files to that repo
2. ClawHub can index directly from GitHub — submit the repo URL on the dashboard

### What to push to GitHub first

```bash
cd xproof-openclaw-skill
# Copy the updated files from this project
cp claw.json clawhub.json .
git add claw.json clawhub.json SKILL.md
git commit -m "Add ClawHub manifest and marketplace metadata (v1.2.0)"
git push
```

---

## 2. MCP Registry Submission

### What's ready

The `.mcp/server.json` file follows the official MCP Registry schema (`2025-12-11`) for a remote (cloud-hosted) server. It declares:
- Namespace: `io.github.jasonxkensei/xproof`
- Transport: Streamable HTTP at `https://xproof.app/mcp`
- Optional auth header (Bearer `pm_xxx`) — x402 works without it
- Repository link to GitHub

### Steps to submit

**Step 1 — Install `mcp-publisher` CLI**

```bash
# macOS/Linux (auto-detects OS and architecture)
curl -L "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" | tar xz mcp-publisher && sudo mv mcp-publisher /usr/local/bin/
```

```powershell
# Windows (PowerShell)
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq "Arm64") { "arm64" } else { "amd64" }; Invoke-WebRequest -Uri "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_windows_$arch.tar.gz" -OutFile "mcp-publisher.tar.gz"; tar xf mcp-publisher.tar.gz mcp-publisher.exe; rm mcp-publisher.tar.gz
```

Verify installation:
```bash
mcp-publisher --help
```

**Step 2 — Authenticate with GitHub**

The namespace `io.github.jasonxkensei/xproof` requires GitHub authentication:

```bash
mcp-publisher login github
```

This opens a browser. Go to https://github.com/login/device and enter the code shown in the terminal.

**Step 3 — Publish**

The CLI looks for `server.json` in the current directory. Run from the `.mcp/` folder:

```bash
cd .mcp && mcp-publisher publish
```

Or specify the path explicitly:

```bash
mcp-publisher publish .mcp/server.json
```

Expected output:
```
Publishing to https://registry.modelcontextprotocol.io...
✓ Successfully published
✓ Server io.github.jasonxkensei/xproof version 1.2.0
```

**Step 4 — Verify**

```bash
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.jasonxkensei/xproof"
```

After success, xProof will be discoverable at https://registry.modelcontextprotocol.io

### Alternative — GitHub Action for auto-publish on release

Add this to the xProof repo's `.github/workflows/mcp-registry.yml`:

```yaml
name: Publish to MCP Registry
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install mcp-publisher
        run: |
          curl -L "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_linux_amd64.tar.gz" | tar xz mcp-publisher
      - name: Authenticate and publish
        run: |
          ./mcp-publisher login github --token ${{ secrets.GITHUB_TOKEN }}
          ./mcp-publisher publish
```

### Official documentation

- Quickstart: https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/quickstart.mdx
- Remote servers: https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/remote-servers.mdx
- Authentication: https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/authentication.mdx
- Registry API: https://registry.modelcontextprotocol.io

---

## Summary

| Platform | File(s) ready | Submission method | Time to list |
|----------|---------------|-------------------|--------------|
| ClawHub | `claw.json` + `clawhub.json` + `SKILL.md` | CLI, dashboard, or GitHub URL | 2-5 business days (review) |
| MCP Registry | `.mcp/server.json` | `mcp-publisher` CLI | Immediate after publish |

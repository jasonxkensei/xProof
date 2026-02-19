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

The `.mcp/server.json` file is in the official MCP Registry format for a remote (cloud-hosted) server.

### Steps to submit

**Step 1 — Install the publisher CLI**

```bash
# macOS/Linux
curl -L https://github.com/modelcontextprotocol/registry/releases/download/v1.0.0/mcp-publisher_1.0.0_linux_amd64.tar.gz | tar xz
```

**Step 2 — Authenticate with GitHub**

The namespace `io.github.jasonxkensei/xproof` requires GitHub authentication:

```bash
./mcp-publisher login github
# Follow the browser prompts to authorize
```

**Step 3 — Publish**

```bash
./mcp-publisher publish .mcp/server.json
```

After success, xProof will be discoverable at https://registry.modelcontextprotocol.io

### Alternative — GitHub Action for auto-publish on release

Add this to the xProof repo's `.github/workflows/`:

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
      - name: Download mcp-publisher
        run: |
          curl -L https://github.com/modelcontextprotocol/registry/releases/download/v1.0.0/mcp-publisher_1.0.0_linux_amd64.tar.gz | tar xz
      - name: Publish
        run: |
          ./mcp-publisher login github --token ${{ secrets.GITHUB_TOKEN }}
          ./mcp-publisher publish .mcp/server.json
```

---

## Summary

| Platform | File(s) ready | Submission method | Time to list |
|----------|---------------|-------------------|--------------|
| ClawHub | `claw.json` + `clawhub.json` + `SKILL.md` | CLI, dashboard, or GitHub URL | 2-5 business days (review) |
| MCP Registry | `.mcp/server.json` | `mcp-publisher` CLI | Immediate after publish |

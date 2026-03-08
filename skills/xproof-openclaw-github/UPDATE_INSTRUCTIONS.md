# Update xproof-openclaw-skill repo on GitHub

## What changed

The `xproof/` subdirectory needs 4 file updates:

| File | Action | Why |
|------|--------|-----|
| `xproof/SKILL.md` | **Replace** | Old version (10k chars) → v2.0.0 (14k chars). Adds YAML metadata, Quick Install, MCP catalog, discovery endpoints, guard templates |
| `xproof/references/certification.md` | **Add** (replaces `api-reference.md`) | Full API schema: certify, batch, verify, webhooks, certificates, badges |
| `xproof/references/x402.md` | **Add** (new) | Complete x402 payment flow with curl examples |
| `xproof/references/mcp.md` | **Add** (new) | MCP JSON-RPC 2.0 tool definitions |

After update, optionally delete `xproof/references/api-reference.md` (replaced by `certification.md`).

## Step-by-Step (GitHub Web Editor)

### 1. Update `xproof/SKILL.md`

- Go to https://github.com/jasonxkensei/xproof-openclaw-skill/blob/main/xproof/SKILL.md
- Click the pencil icon (Edit)
- Select all, delete, paste the contents of `xproof/SKILL.md` from this directory
- Commit: `chore: update xproof/SKILL.md to v2.0.0`

### 2. Add `xproof/references/certification.md`

- Go to https://github.com/jasonxkensei/xproof-openclaw-skill/tree/main/xproof/references
- Click **Add file > Create new file**
- Name: `certification.md`
- Paste contents from this directory's `xproof/references/certification.md`
- Commit: `feat: add certification reference (replaces api-reference.md)`

### 3. Add `xproof/references/x402.md`

- Same process in `xproof/references/`
- Name: `x402.md`
- Commit: `feat: add x402 payment reference`

### 4. Add `xproof/references/mcp.md`

- Same process in `xproof/references/`
- Name: `mcp.md`
- Commit: `feat: add MCP JSON-RPC reference`

### 5. (Optional) Delete old api-reference.md

- Go to https://github.com/jasonxkensei/xproof-openclaw-skill/blob/main/xproof/references/api-reference.md
- Click the three dots > Delete file
- Commit: `chore: remove old api-reference.md (replaced by certification.md)`

## Result

After update, `xproof/` should contain:

```
xproof/
  SKILL.md                    ← v2.0.0 (updated)
  claw.json                   ← unchanged
  clawhub.json                ← unchanged
  references/
    certification.md          ← new (replaces api-reference.md)
    x402.md                   ← new
    mcp.md                    ← new
  scripts/
    ...                       ← unchanged
```

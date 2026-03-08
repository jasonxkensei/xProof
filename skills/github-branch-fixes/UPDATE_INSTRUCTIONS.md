# GitHub Branch Fixes — Pre-Merge Corrections

Two branches need corrections before merging.

---

## Fix 1 — add-xproof-skill / jasonxkensei-patch-1

**Problem:** `skills/xproof/SKILL.md` is a minimal stub (1501 chars). The full v2.0.0 version has complete API docs, lifecycle diagram, audit standard, MCP catalog, guard templates, and discovery endpoints.

**File to update:** `skills/xproof/SKILL.md`

**Steps:**
1. Go to https://github.com/jasonxkensei/add-xproof-skill/blob/jasonxkensei-patch-1/skills/xproof/SKILL.md
2. Click the pencil icon (Edit)
3. Select all, delete
4. Paste the contents of `skills/add-xproof-skill-github/SKILL.md` from this Replit project
5. Commit to the `jasonxkensei-patch-1` branch: `chore: replace stub with full xproof v2.0.0 SKILL.md`

---

## Fix 2 — registry / xProof

**Problem:** Entry key `@elizaos/plugin-xproof` doesn't match the actual package name `xproof-eliza-plugin`. Registry keys must match npm package names.

**File to update:** `index.json`

**Steps:**
1. Go to https://github.com/jasonxkensei/registry/blob/xProof/index.json
2. Click the pencil icon (Edit)
3. Find the line: `"@elizaos/plugin-xproof": "github:jasonxkensei/plugin-xproof",`
4. Replace it with: `"xproof-eliza-plugin": "github:jasonxkensei/plugin-xproof",`
5. Commit to the `xProof` branch: `fix: correct registry key to match package name xproof-eliza-plugin`

---

## After Both Fixes

Both branches are ready to merge via PR:
- https://github.com/jasonxkensei/add-xproof-skill/compare/jasonxkensei-patch-1
- https://github.com/jasonxkensei/registry/compare/xProof

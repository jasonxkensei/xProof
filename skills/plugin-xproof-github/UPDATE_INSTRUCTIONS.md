# plugin-xproof — Package Rename Instructions

Rename package from `xproof-eliza-plugin` → `@elizaos/plugin-xproof` to match the ElizaOS registry key format.

## Files to update (2)

### 1. package.json

- Go to https://github.com/jasonxkensei/plugin-xproof/blob/main/package.json
- Click pencil (Edit)
- Select all, delete, paste contents of `skills/plugin-xproof-github/package.json`
- Commit: `chore: rename package to @elizaos/plugin-xproof`

### 2. README.md

- Go to https://github.com/jasonxkensei/plugin-xproof/blob/main/README.md
- Click pencil (Edit)
- Select all, delete, paste contents of `skills/plugin-xproof-github/README.md`
- Commit: `docs: update package name references to @elizaos/plugin-xproof`

## What changed

| File | Change |
|------|--------|
| `package.json` | `"name": "xproof-eliza-plugin"` → `"name": "@elizaos/plugin-xproof"` |
| `README.md` | 6 occurrences of `xproof-eliza-plugin` → `@elizaos/plugin-xproof` |
| `src/` | No changes needed (internal relative imports only) |

## After this update

The registry entry `"@elizaos/plugin-xproof": "github:jasonxkensei/plugin-xproof"` will be consistent with the declared package name.

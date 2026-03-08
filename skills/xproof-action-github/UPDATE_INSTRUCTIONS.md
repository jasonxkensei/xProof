# xProof-Action — README fix

## Problem

4 code examples used `uses: xproof-app/certify-action@v1` — the org `xproof-app` n'existe pas sur GitHub. Copier-coller cet exemple ferait échouer silencieusement les workflows CI des utilisateurs.

## Fix

Remplacer toutes les occurrences par `uses: jasonxkensei/xProof-Action@v1`.

## Steps

1. Go to https://github.com/jasonxkensei/xProof-Action/blob/main/README.md
2. Click the pencil icon (Edit)
3. Select all, delete, paste contents of `skills/xproof-action-github/README.md`
4. Commit to `main`: `fix: correct action reference from xproof-app to jasonxkensei/xProof-Action`

## What changed (4 lines)

```yaml
# Before (4 occurrences)
uses: xproof-app/certify-action@v1

# After (4 occurrences)
uses: jasonxkensei/xProof-Action@v1
```

Nothing else changed — structure, content, and examples are identical.

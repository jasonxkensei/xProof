# Registry fix — xproof-eliza-plugin entry

## Problem

The branch `registry/xProof` added this entry to `index.json`:

```
"@elizaos/plugin-xproof": "github:jasonxkensei/plugin-xproof",
```

But `plugin-xproof/package.json` declares the package name as:

```
"name": "xproof-eliza-plugin"
```

The registry key must match the npm package name. Mismatched keys cause install failures.

## Fix

In `index.json` on the `xProof` branch, replace:

```
"@elizaos/plugin-xproof": "github:jasonxkensei/plugin-xproof",
```

With:

```
"xproof-eliza-plugin": "github:jasonxkensei/plugin-xproof",
```

## Correct alphabetical position in index.json

The `x` section should look like (insert in correct alphabetical order):

```json
   "xproof-eliza-plugin": "github:jasonxkensei/plugin-xproof",
```

It goes after entries starting with `x` that come before `xproof` alphabetically.

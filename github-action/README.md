# xProof Notarize — GitHub Action

Notarize build artifacts on MultiversX blockchain. Creates immutable, verifiable proof-of-existence for any file.

## Quick Start

```yaml
name: Notarize Release
on:
  push:
    branches: [main]

jobs:
  notarize:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: npm run build && zip -r build.zip dist/

      - name: Notarize with xProof
        uses: xproof-app/notarize-action@v1
        with:
          api_key: ${{ secrets.XPROOF_API_KEY }}
          files: 'build.zip'
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api_key` | Yes | — | xProof API key (`pm_xxx`). Store as GitHub secret. |
| `files` | Yes | — | Files or glob patterns to notarize (space-separated). |
| `author_name` | No | `''` | Author name to attach to certification. |
| `api_url` | No | `https://xproof.app` | API URL (override for testing). |

## Outputs

| Output | Description |
|--------|-------------|
| `proof_ids` | Comma-separated proof IDs |
| `proof_urls` | Comma-separated verification URLs |
| `badge_urls` | Comma-separated badge SVG URLs |
| `summary` | Human-readable summary |

## Examples

### Notarize a single file

```yaml
- name: Notarize
  uses: xproof-app/notarize-action@v1
  with:
    api_key: ${{ secrets.XPROOF_API_KEY }}
    files: 'release.tar.gz'
```

### Notarize multiple files

```yaml
- name: Notarize
  id: notarize
  uses: xproof-app/notarize-action@v1
  with:
    api_key: ${{ secrets.XPROOF_API_KEY }}
    files: 'build.zip package.json contracts/main.sol'
    author_name: 'CI Bot'

- name: Show results
  run: echo "Proofs: ${{ steps.notarize.outputs.proof_urls }}"
```

### Add badge to README

After notarizing, add a verification badge to your README:

```markdown
[![xProof Verified](https://xproof.app/badge/YOUR_PROOF_ID)](https://xproof.app/proof/YOUR_PROOF_ID)
```

## How it works

1. Calculates SHA-256 hash of each file locally (files never leave your runner)
2. Sends only the hash + filename to xProof API
3. xProof anchors the hash on MultiversX blockchain
4. Returns verification URL and badge

**Cost:** $0.05 per certification, paid in EGLD.

**Get an API key:** Visit [xproof.app](https://xproof.app) and connect your wallet.

## License

All Rights Reserved. See [xproof.app](https://xproof.app) for terms.

[![View on GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-xProof%20Certify-green?logo=github)](https://github.com/marketplace/actions/xproof-certify)

# xProof Certify — GitHub Action

> **Every build you ship without proof is a build anyone can claim.**

Certify your build artifacts on MultiversX blockchain. SHA-256 hash locally, anchor on-chain, verify forever. Supply chain attestation for your CI/CD pipeline.

## Quick Start

```yaml
name: Certify Release
on:
  push:
    branches: [main]

jobs:
  certify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: npm run build && zip -r build.zip dist/

      - name: Certify with xProof
        uses: xproof-app/certify-action@v1
        with:
          api_key: ${{ secrets.XPROOF_API_KEY }}
          files: 'build.zip'
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api_key` | Yes | — | xProof API key (`pm_xxx`). Store as GitHub secret. |
| `files` | Yes | — | Files or glob patterns to certify (space-separated). |
| `author_name` | No | `''` | Author name to attach to certification. |
| `api_url` | No | `https://xproof.app` | API URL (override for testing). |

## Outputs

| Output | Description |
|--------|-------------|
| `proof_ids` | Comma-separated proof IDs |
| `proof_urls` | Comma-separated verification URLs |
| `badge_urls` | Comma-separated badge SVG URLs |
| `proof_json` | Path to JSON attestation file — attach to GitHub Releases for provenance |
| `summary` | Human-readable summary |

## Examples

### Certify a single file

```yaml
- name: Certify
  uses: xproof-app/certify-action@v1
  with:
    api_key: ${{ secrets.XPROOF_API_KEY }}
    files: 'release.tar.gz'
```

### Certify multiple files

```yaml
- name: Certify
  id: certify
  uses: xproof-app/certify-action@v1
  with:
    api_key: ${{ secrets.XPROOF_API_KEY }}
    files: 'build.zip package.json contracts/main.sol'
    author_name: 'CI Bot'

- name: Show results
  run: echo "Proofs: ${{ steps.certify.outputs.proof_urls }}"
```

### Attach attestation to GitHub Release

```yaml
- name: Certify
  id: certify
  uses: xproof-app/certify-action@v1
  with:
    api_key: ${{ secrets.XPROOF_API_KEY }}
    files: 'build.zip'

- name: Upload attestation to Release
  uses: softprops/action-gh-release@v2
  with:
    files: ${{ steps.certify.outputs.proof_json }}
```

The attestation JSON contains full provenance data:

```json
{
  "xproof_attestation": "1.0",
  "timestamp": "2026-02-12T10:30:00Z",
  "blockchain": "MultiversX",
  "source": {
    "repository": "owner/repo",
    "commit": "abc1234...",
    "ref": "refs/heads/main",
    "run_id": "123456789"
  },
  "artifacts": [
    {
      "filename": "build.zip",
      "sha256": "a1b2c3d4...",
      "proof_id": "uuid-here",
      "verify_url": "https://xproof.app/proof/uuid-here",
      "badge_url": "https://xproof.app/badge/uuid-here",
      "tx_hash": "abc123...",
      "explorer_url": "https://explorer.multiversx.com/transactions/abc123..."
    }
  ]
}
```

### Add badge to README

```markdown
[![xProof Verified](https://xproof.app/badge/{proof_id})](https://explorer.multiversx.com/transactions/{tx_hash})
```

## How it works

1. Calculates SHA-256 hash of each file locally (files never leave your runner)
2. Sends only the hash + filename to xProof API
3. xProof anchors the hash on MultiversX blockchain
4. Returns verification URLs, badges, and a JSON attestation file

**Cost:** Starting at $0.05 per certification — price decreases as the network grows. Current pricing: https://xproof.app/api/pricing

**Get an API key:** Visit [xproof.app](https://xproof.app) and connect your wallet.

## License

All Rights Reserved. See [xproof.app](https://xproof.app) for terms.

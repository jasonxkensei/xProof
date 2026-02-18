# xProof OpenClaw Skill

Certify files on MultiversX blockchain via [xProof](https://xproof.app). Proof primitive for AI agents and humans.

## Install

Give OpenClaw the URL to this repo and select the `xproof` skill:

```
https://github.com/jasonxkensei/xproof-openclaw-skill
```

## What It Does

- **Certify** any file by anchoring its SHA-256 hash on MultiversX blockchain
- **Verify** existing proofs with full blockchain details
- **Batch certify** up to 50 files in a single call
- Files never leave your machine — only the hash is sent

## Quick Start

```bash
export XPROOF_API_KEY=pm_your_key
./xproof/scripts/certify.sh path/to/file.pdf
```

## Structure

```
xproof/
├── SKILL.md              # Skill definition + instructions
├── references/
│   └── api-reference.md  # Full API documentation
└── scripts/
    └── certify.sh        # One-command certification
```

## Protocols

Supports x402 (HTTP-native payments), ACP, MCP, and MX-8004.

## Cost

$0.05 per certification.

## Links

- [xProof Platform](https://xproof.app)
- [GitHub Action](https://github.com/marketplace/actions/xproof-certify)
- [API Docs](https://xproof.app/docs)

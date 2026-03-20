# PR: Add xProof certification tool

**Target repo:** `crewAI-tools/crewai-tools` (ou `crewAI-inc/crewAI` pour les docs)
**Target branch:** `main`
**File to add:** `docs/tools/xproof-tool.mdx` (ou dans la section "Community Tools")

---

## PR Title
`feat: add XProofCertifyTool — on-chain proof for agent actions`

## PR Body

### Description

This PR adds the [xProof](https://xproof.app) integration for CrewAI — a blockchain certification tool that gives agent actions a tamper-proof audit trail on MultiversX.

Two integration levels:
- **`XProofCertifyTool`** — lightweight tool agents can call explicitly to certify any content
- **`XProofCrewCallback`** — automatic crew-level callback that certifies every task output without agent awareness

### Use case

Compliance-sensitive deployments (finance, healthcare, legal) where agent decisions must be auditable and attributable.

### Install

```bash
pip install xproof
```

### Checklist
- [x] Documentation added
- [x] Both tool variants documented
- [x] No crewai dependency required for XProofCertifyTool
- [x] Free tier available

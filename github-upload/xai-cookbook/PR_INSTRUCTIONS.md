# PR Instructions for xai-org/xai-cookbook

## Fork & Branch

```bash
# Fork xai-org/xai-cookbook on GitHub first, then:
git clone https://github.com/jasonxkensei/xai-cookbook.git
cd xai-cookbook
git checkout -b add-xproof-verifiable-reasoning
```

## Copy the notebook

```bash
mkdir -p examples/verifiable_ai_reasoning
cp /path/to/guide.ipynb examples/verifiable_ai_reasoning/guide.ipynb
```

## Add to registry.yaml

Add this entry at the end of `registry.yaml`:

```yaml
- title: "Verifiable AI Reasoning with Grok + xProof"
  path: examples/verifiable_ai_reasoning/guide.ipynb
  description: "Anchor Grok's reasoning on-chain before output generation — creating a cryptographically verifiable 4W audit trail (WHO/WHAT/WHEN/WHY) via xProof on MultiversX"
  date: 2026-03-19
  authors:
    - Jason Kensei
  tags:
    - function-calling
    - blockchain
    - verification
    - trust
    - agents
```

## Commit & Push

```bash
git add examples/verifiable_ai_reasoning/guide.ipynb registry.yaml
git commit -m "Add verifiable AI reasoning cookbook (Grok + xProof)"
git push origin add-xproof-verifiable-reasoning
```

## Open PR

**Title:** [Content] Verifiable AI Reasoning with Grok + xProof

**Description:**

### What

A cookbook showing how to make Grok's reasoning cryptographically verifiable using xProof. The pattern anchors the prompt hash on MultiversX blockchain BEFORE calling Grok, then anchors the output hash AFTER — creating an immutable, publicly verifiable audit trail.

### Why

AI agents making decisions need accountability. This cookbook demonstrates a pattern where every Grok API call gets:
- **Tamper-proof timestamps** — blockchain ordering proves intent preceded output
- **Public verification** — anyone can check via `GET /api/xai/{agent_id}`
- **Machine-readable audit trail** — structured JSON for automated verification
- **Incident investigation** — full 4W reconstruction (WHO/WHAT/WHEN/WHY) for any proof

### What's included

- Step-by-step notebook: hash prompt → anchor WHY → call Grok → anchor WHAT → verify
- Production-ready `verified_grok_call()` wrapper function
- Architecture diagram showing the verification flow
- Links to live API endpoints and documentation

### Dependencies

- `openai` (already used in existing cookbooks)
- `requests` (standard library-adjacent)

### Checklist

- [x] All cells run end-to-end with valid API keys
- [x] Added to registry.yaml
- [x] Uses clear, descriptive cell titles
- [x] Python in code cells, explanations in markdown cells
- [x] Minimal dependencies

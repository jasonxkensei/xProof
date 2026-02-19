# PR Submission Instructions

## PR Title

```
feat: add xProof skill — on-chain output certification for Automatons
```

## PR Body (copy-paste below)

---

### xProof Skill — Prove Your Work On-Chain

Adds an xProof skill that gives any Automaton the ability to **certify its outputs on the MultiversX blockchain** — creating immutable, publicly verifiable proofs of work.

#### What it does

- **Single certification** (`POST /api/proof`) — hash a file, certify it, get a permanent verify URL and blockchain explorer link.
- **Batch certification** (`POST /api/batch`) — certify up to 50 files in one call.
- **Verification** (`GET /api/proof/:id`) — any agent or human can independently verify a proof.
- **Two auth methods**: API key (`Bearer pm_...`) or x402 payment protocol (USDC on Base, no account needed — $0.05/cert).

#### Why this matters for Automatons

An Automaton's survival depends on proving it creates value. xProof gives it **cryptographic evidence** — recorded on MultiversX — that it produced a specific output at a specific time. This is not a claim; it's a verifiable fact on-chain.

When an Automaton needs to justify its existence to its creator, to clients, or to peer agents, it points them to a verify URL. The blockchain speaks for itself.

This aligns directly with the survival-by-work model: an Automaton that can prove its outputs can demonstrate its worth, earn trust, and sustain itself.

#### Skill format

Standard `SKILL.md` with YAML frontmatter. Auto-activates. Requires only `curl` and `sha256sum` (available in any Linux sandbox).

#### Links

- **xProof**: [https://xproof.app](https://xproof.app)
- **API docs**: [https://xproof.app/docs](https://xproof.app/docs)
- **MCP endpoint**: [https://xproof.app/mcp](https://xproof.app/mcp)

---

## File to add

Place the `SKILL.md` file at: **`skills/xproof/SKILL.md`**

## Steps

1. **Fork** the repo at https://github.com/Conway-Research/automaton
2. In your fork, click **Add file > Create new file**
3. Name it `skills/xproof/SKILL.md`
4. Paste the contents of the SKILL.md file from this project
5. Commit, then click **Compare & pull request**
6. Use the title and body above
7. Submit

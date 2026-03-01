# PR Instructions — Add xProof to awesome-openclaw-skills

## README line to insert

Add this line in `README.md` inside the `## Security` table, after the last entry (`Auth Security Scanner`):

```
| [**xProof**](./skills/xproof) | `xproof` | Pre-execution cryptographic enforcement for autonomous agents. Anchor file proofs and agent decisions on MultiversX blockchain before execution. No proof = no action. x402 payment (no account need... | [NEW](https://xproof.app) |
```

## Steps

1. **Fork** `sundial-org/awesome-openclaw-skills` (if not already done)
2. **Create a branch** named `add-xproof-skill`
3. **Add the SKILL.md** — create file at path `skills/xproof/SKILL.md` (copy content from the SKILL.md in this folder)
4. **Edit README.md** — find the `## Security` table and paste the line above after the last entry
5. **Commit** with message: `Add xProof — on-chain certification & audit enforcement for agents`
6. **Open PR** to `sundial-org/awesome-openclaw-skills`

## PR Title

```
Add xProof — on-chain certification & audit enforcement for agents
```

## PR Description

```
Adds xProof to the Security category.

**What it does:**
- File certification — SHA-256 hash anchored on MultiversX as immutable proof of existence
- Audit enforcement — certify agent decisions on-chain BEFORE executing critical actions (trade, deploy, transfer). No proof_id = no execution.
- Batch certification (up to 50 files per call)
- x402 payment protocol (no account needed, $0.05/proof in USDC on Base)

**Why Security category:**
xProof is a pre-execution enforcement primitive. Before an agent executes a critical action, it must certify its decision on-chain. If the audit call fails, the action is blocked. This is cryptographic accountability for autonomous agents.

**Links:**
- Platform: https://xproof.app
- NPM (ElizaOS plugin): https://www.npmjs.com/package/xproof-eliza-plugin
- MCP Registry: https://github.com/modelcontextprotocol/servers (io.github.jasonxkensei/xproof)
- GitHub Action: https://github.com/marketplace/actions/xproof-certify
- Audit Schema: https://xproof.app/.well-known/agent-audit-schema.json
```

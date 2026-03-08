# PR Submission: xProof Skill for bnb-chain/bnbchain-skills

## Target Repository

**Repo:** `bnb-chain/bnbchain-skills`
**Branch:** `main`
**URL:** https://github.com/bnb-chain/bnbchain-skills

## Files to Add

```
skills/xproof-skill/
  SKILL.md                          <-- Main skill file
  references/
    certification-reference.md      <-- REST API: certify, batch, audit, verify
    x402-reference.md               <-- x402 payment flow (USDC on Base)
```

## Step-by-Step

### 1. Fork the Repository

Go to https://github.com/bnb-chain/bnbchain-skills and click **Fork**.

### 2. Create the Files

In your fork, create the directory `skills/xproof-skill/` and add the three files listed above.

Using GitHub web editor:
- Navigate to your fork
- Click **Add file > Create new file**
- Type `skills/xproof-skill/SKILL.md` in the filename field
- Paste the contents of `SKILL.md` from `skills/xproof-bnbchain/SKILL.md` in this repo
- Commit
- Repeat for `skills/xproof-skill/references/certification-reference.md` and `skills/xproof-skill/references/x402-reference.md`

### 3. Open the Pull Request

Go to your fork and click **Contribute > Open pull request**.

---

## PR Title

```
feat: add xProof skill -- on-chain certification & audit trail for AI agents
```

## PR Body

```markdown
## What

Adds an **xProof certification skill** that enables AI agents to certify their outputs on-chain and enforce pre-execution audit logging for critical actions. Creates immutable, publicly verifiable proofs of existence, authorship, and timestamp.

## Why

Agents that produce work (code, reports, data, trading decisions) need a way to prove what they did and when. xProof provides this as a composable primitive:

- **$0.05/cert** -- negligible cost, high value
- **6-second finality** -- proof is immutable within seconds
- **x402 compatible** -- any agent with USDC on Base can certify without an account
- **Pre-execution audit** -- agents certify decisions on-chain before executing trades/deploys/transfers
- **ERC-8004 native** -- agents can use their ERC-8004 identity as audit trail anchor

## How it Integrates with BNB Chain Agents

| BNB Chain Action | xProof Complement |
|:---|:---|
| `register_erc8004_agent` | Certify agent metadata hash for integrity |
| Agent executes a trade | `POST /api/audit` -- certify the decision before execution |
| Agent produces output | `POST /api/proof` -- certify the output as proof-of-work |
| Agent delivers to another agent | Certify deliverable hash before handoff |

## Payment

Two options:
1. **API Key** -- register via `POST /api/agent/register`, get 10 free certs, top up with USDC on Base
2. **x402** -- pay $0.05 per request in USDC on Base (eip155:8453), no account needed

## Files Added

```
skills/xproof-skill/
  SKILL.md                          # Agent-facing skill instructions
  references/
    certification-reference.md      # Full API: certify, batch, audit, verify, register
    x402-reference.md               # x402 payment flow (USDC on Base, no account)
```

## Format

Follows the same structure as `skills/bnbchain-mcp-skill/`:
- YAML frontmatter (name, version, description)
- Tool reference tables
- Reference files for detailed per-tool usage
- Safety and best practices section

## Live

- **App:** https://xproof.app
- **API:** `POST https://xproof.app/api/proof`
- **x402:** `POST https://xproof.app/api/proof` (no auth, pay per request)
- **Docs:** https://xproof.app/docs
- **Machine-readable:** https://xproof.app/llms-full.txt
```

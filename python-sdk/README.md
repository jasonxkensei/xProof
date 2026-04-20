# xproof

On-chain decision provenance for autonomous agents. **WHY before acting. WHAT after.** Timestamps written by the chain, not your agent.

```bash
pip install xproof
```

---

## 3 steps. 30 seconds.

### Step 1 — Register (no wallet, no payment)

```bash
curl -X POST https://xproof.app/api/agent/register \
  -H "Content-Type: application/json" \
  -d '{"agent_name": "my-agent"}'
```

```json
{ "api_key": "pm_...", "trial": { "remaining": 10 } }
```

### Step 2 — Anchor WHY before acting

Hash your reasoning and certify it *before* your agent executes.

```bash
curl -X POST https://xproof.app/api/proof \
  -H "Authorization: Bearer pm_..." \
  -H "Content-Type: application/json" \
  -d '{
    "file_hash": "<sha256_of_reasoning>",
    "file_name": "reasoning.json",
    "author": "my-agent",
    "metadata": { "action_type": "decision" }
  }'
```

```json
{ "id": "why-proof-uuid", "transaction_hash": "0x..." }
```

### Step 3 — Anchor WHAT after acting

Hash your output and link it to the WHY proof.

```bash
curl -X POST https://xproof.app/api/proof \
  -H "Authorization: Bearer pm_..." \
  -H "Content-Type: application/json" \
  -d '{
    "file_hash": "<sha256_of_output>",
    "file_name": "output.json",
    "author": "my-agent",
    "metadata": { "action_type": "execution", "why_proof_id": "why-proof-uuid" }
  }'
```

```json
{ "id": "what-proof-uuid", "transaction_hash": "0x..." }
```

When something goes wrong, you don't guess. You verify.

---

## Python SDK

```python
from xproof import XProofClient, hash_string

# Register — zero-friction, no wallet, no payment
client = XProofClient.register("my-agent")
# 10 free certs, API key stored automatically

# Step 2: Anchor WHY before acting
why = client.certify_hash(
    file_hash=hash_string('{"action": "summarize", "model": "gpt-4"}'),
    file_name="reasoning.json",
    author="my-agent",
    metadata={"action_type": "decision"},
)

# Step 3: Anchor WHAT after acting
what = client.certify_hash(
    file_hash=hash_string(execution_output),
    file_name="output.json",
    author="my-agent",
    metadata={"action_type": "execution", "why_proof_id": why.id},
)

print(what.transaction_url)  # MultiversX explorer link
```

Or use an existing API key:

```python
client = XProofClient(api_key="pm_your_api_key")
```

---

## Framework Integrations

### LangChain

```python
from xproof.integrations.langchain import XProofCallbackHandler

handler = XProofCallbackHandler(api_key="pm_...")
llm = ChatOpenAI(callbacks=[handler])
```

### CrewAI

```python
from xproof.integrations.crewai import XProofListener

listener = XProofListener(api_key="pm_...")
```

### AutoGen

```python
from xproof.integrations.autogen import XProofHook

hook = XProofHook(api_key="pm_...")
agent.register_hook("process_last_received_message", hook.on_message)
```

### LlamaIndex

```python
from xproof.integrations.llamaindex import XProofCallbackHandler
from llama_index.core import Settings
from llama_index.core.callbacks import CallbackManager

Settings.callback_manager = CallbackManager([XProofCallbackHandler(api_key="pm_...")])
```

---

## 4W Framework (WHO / WHAT / WHEN / WHY)

Full accountability metadata on every certification:

```python
from xproof import XProofClient, hash_bytes

client = XProofClient(api_key="pm_your_key")

action_data = b'{"action": "generate_report", "model": "gpt-4"}'
action_hash = hash_bytes(action_data)

cert = client.certify_hash(
    file_hash=action_hash,
    file_name="agent-action.json",
    author="research-agent",
    who="erd1abc...or-agent-id",
    what=action_hash,
    when="2026-03-20T12:00:00Z",
    why=hash_bytes(b"Summarize Q1 earnings report"),
    metadata={"model": "gpt-4", "session_id": "sess-123"},
)
```

## Batch Certification

Certify up to 50 files in a single API call:

```python
results = client.batch_certify([
    {"file_hash": "abc123...", "file_name": "file1.pdf", "author": "my-agent"},
    {"file_hash": "def456...", "file_name": "file2.pdf"},
])

print(results.summary.total)    # 2
print(results.summary.created)  # 2
```

## Certify a Local File

```python
# Auto-hashes with SHA-256
cert = client.certify("path/to/report.pdf", author="my-agent")
print(cert.id)
print(cert.transaction_url)
```

## Verify a Proof

```python
# By proof ID
proof = client.verify("certification-uuid")
print(proof.file_name, proof.blockchain_status)

# By file hash
proof = client.verify_hash("e3b0c442...")
```

## Policy Compliance

Check whether a decision meets governance requirements — without fetching the full confidence trail:

```python
from xproof import XProofClient, PolicyCheckResult

client = XProofClient(api_key="pm_your_key")

result: PolicyCheckResult = client.get_policy_check("trade-xyz-2026")

if result.policy_compliant:
    print("Decision is compliant.")
else:
    for v in result.policy_violations:
        print(f"VIOLATION [{v.severity}] — {v.rule}")
        print(f"  {v.message}")
```

`get_policy_check()` is a lightweight yes/no compliance check. It returns `result.policy_compliant` (bool) and `result.policy_violations` (list). For the full audit trail including timestamps and intermediate confidence checkpoints, use `get_confidence_trail()` instead.

---

## Governance & Policy Enforcement

xProof detects automatically when an agent acted with insufficient confidence on an irreversible action — and writes the evidence on-chain before you ever open an incident report.

### Mark decisions as reversible, costly, or irreversible

Add `reversibility_class` to any certified action. The server enforces a policy: **irreversible actions require `confidence_level >= 0.95`**. Anything below that threshold generates a policy violation anchored to the chain.

```python
# An agent is about to execute a trade it cannot undo.
# It certifies its reasoning at 0.72 confidence — below the 0.95 threshold.
cert = client.certify_with_confidence(
    file_hash=hash_string('{"action": "sell", "ticker": "AAPL", "qty": 500}'),
    file_name="trade-decision.json",
    author="trading-agent",
    confidence_level=0.72,           # Agent's self-assessed confidence
    threshold_stage="pre-commitment",
    decision_id="trade-xyz-2026",
    reversibility_class="irreversible",  # This action cannot be undone
)

# cert.reversibility_class == "irreversible"
# The server has recorded a policy violation: 0.72 < 0.95 required
```

### Check compliance — without fetching the full trail

```python
from xproof import XProofClient, PolicyCheckResult

check: PolicyCheckResult = client.get_policy_check("trade-xyz-2026")

if not check.policy_compliant:
    for v in check.policy_violations:
        print(f"VIOLATION [{v.severity}] — {v.rule}")
        print(f"  {v.message}")
        # → VIOLATION [error] — irreversible actions require confidence_level >= 0.95
        # →   confidence 0.72 is below the required threshold of 0.95
```

### Full confidence trail with policy result

```python
trail = client.get_confidence_trail("trade-xyz-2026")

print(trail.policy_compliant)        # False
print(len(trail.policy_violations))  # 1
print(trail.current_confidence)      # 0.72
print(trail.is_finalized)            # False — decision still open
```

### End-to-end agent example: document deletion with compliance gate

This example shows a realistic governance loop for an autonomous agent that is
about to permanently delete customer records — an irreversible action that
requires a confidence level of at least 0.95 before proceeding.

```python
import hashlib, json
from xproof import XProofClient

client = XProofClient(api_key="pm_...")

def hash_string(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

# ── Step 1: Agent produces its reasoning ─────────────────────────────────────
# (In a real LangChain / CrewAI / AutoGen agent, this would be the structured
# chain-of-thought or tool-call output produced just before execution.)

decision = {
    "action": "delete_customer_records",
    "scope": "inactive_accounts",
    "records_affected": 4821,
    "retention_policy_checked": True,
    "legal_hold_clear": True,
    "agent": "data-hygiene-agent",
    "run_id": "del-run-2026-04-20",
}
decision_id = "del-run-2026-04-20"
reasoning_hash = hash_string(json.dumps(decision, sort_keys=True))

# ── Step 2: Certify BEFORE executing ─────────────────────────────────────────
# The agent self-assesses its confidence. Because the action is irreversible,
# the policy requires confidence_level >= 0.95.

cert = client.certify_with_confidence(
    file_hash=reasoning_hash,
    file_name="delete-decision.json",
    author="data-hygiene-agent",
    confidence_level=0.97,               # Agent is highly confident
    threshold_stage="pre-commitment",    # valid: "initial", "partial", "pre-commitment", "final"
    decision_id=decision_id,
    reversibility_class="irreversible",  # Deletion cannot be undone
)

# cert.transaction_hash is the on-chain anchor — written before any records move

# ── Step 3: Compliance gate ───────────────────────────────────────────────────
# Immediately check policy compliance. This is a lightweight call — it does NOT
# re-fetch the full trail. Gate the destructive action on the result.

check = client.get_policy_check(decision_id)

if not check.policy_compliant:
    # Policy violated — log every violation and abort.
    for v in check.policy_violations:
        print(f"BLOCKED [{v.severity.upper()}] {v.rule}")
        print(f"  {v.message}")
    raise RuntimeError("Deletion aborted: policy compliance check failed.")

# ── Step 4: Execute only when compliant ──────────────────────────────────────
print(f"Policy compliant — proceeding with deletion (cert: {cert.transaction_hash})")
# delete_customer_records(decision["scope"])   # your actual execution here
```

**What happens if the agent's confidence is too low?**

Drop `confidence_level` to `0.82` and the same gate blocks execution:

```python
cert = client.certify_with_confidence(
    ...
    confidence_level=0.82,           # Below the 0.95 irreversible threshold
    reversibility_class="irreversible",
)

check = client.get_policy_check(decision_id)

if not check.policy_compliant:
    for v in check.policy_violations:
        print(f"BLOCKED [{v.severity.upper()}] {v.rule}")
        # → BLOCKED [ERROR] irreversible actions require confidence_level >= 0.95
        print(f"  {v.message}")
        # →   confidence 0.82 is below the required threshold of 0.95

    raise RuntimeError("Deletion aborted: policy compliance check failed.")
```

The violation is written on-chain at certification time — before your code
ever reaches the gate — so the audit trail exists even if your agent crashes
between `certify_with_confidence` and `get_policy_check`.

### Three classes, one parameter

| `reversibility_class` | What it means | Policy threshold |
|---|---|---|
| `"reversible"` | Action can be undone (e.g. draft, preview) | None — any confidence accepted |
| `"costly"` | Undoable but expensive (e.g. API call, DB write) | None — any confidence accepted |
| `"irreversible"` | Cannot be undone (e.g. trade, deletion, send) | `confidence_level >= 0.95` required |

> The threshold is configured server-side (`IRREVERSIBLE_CONFIDENCE_THRESHOLD=0.95`). All violations are written on-chain and cannot be amended.

---

## Pricing

```python
pricing = client.get_pricing()
print(pricing.price_usd)  # e.g. 0.05
```

## API Reference

### `XProofClient(api_key=None, base_url="https://xproof.app", timeout=30)`

| Parameter  | Type  | Default                |
|------------|-------|------------------------|
| `api_key`  | `str` | `None`                 |
| `base_url` | `str` | `"https://xproof.app"` |
| `timeout`  | `int` | `30` (seconds)         |

### Methods

| Method | Description |
|--------|-------------|
| `XProofClient.register(agent_name)` | Register agent, get trial key |
| `certify(path, author, *, reversibility_class?, **fourW)` | Certify file (hashes locally) |
| `certify_hash(file_hash, file_name, author, *, reversibility_class?, **fourW)` | Certify by pre-computed hash |
| `certify_with_confidence(hash, name, author, confidence_level, threshold_stage, decision_id, *, reversibility_class?, **fourW)` | Certify with confidence + governance class |
| `batch_certify(files)` | Batch certify (up to 50) |
| `verify(proof_id)` | Look up by proof ID |
| `verify_hash(file_hash)` | Look up by file hash |
| `get_confidence_trail(decision_id)` | Full trail with `policy_compliant` + violations |
| `get_policy_check(decision_id)` | Lightweight compliance check — no full trail |
| `get_pricing()` | Get current pricing |

## Development

Install dev dependencies and run the checks locally:

```bash
pip install -e ".[dev]"

# Lint (ruff — catches unused imports, duplicate class definitions, and more)
make lint

# Unit tests (excludes live-API integration tests)
make test

# Lint + test together
make check
```

The linter is configured in `pyproject.toml` under `[tool.ruff]`. Rule `F811` will flag
duplicate top-level class definitions — the kind of silent overwrite that prompted this setup.

## Links

- [xproof.app](https://xproof.app) — dashboard & docs
- [npm SDK](https://www.npmjs.com/package/@xproof/xproof) — `npm install @xproof/xproof`
- [Examples](https://github.com/jasonxkensei/xproof-examples) — LangChain, CrewAI, AutoGen, LlamaIndex

## License

MIT

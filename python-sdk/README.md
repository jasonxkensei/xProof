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
| `certify(path, author, file_name?, **fourW)` | Certify file (hashes locally) |
| `certify_hash(file_hash, file_name, author, **fourW)` | Certify by pre-computed hash |
| `batch_certify(files)` | Batch certify (up to 50) |
| `verify(proof_id)` | Look up by proof ID |
| `verify_hash(file_hash)` | Look up by file hash |
| `get_pricing()` | Get current pricing |

## Links

- [xproof.app](https://xproof.app) — dashboard & docs
- [npm SDK](https://www.npmjs.com/package/@xproof/xproof) — `npm install @xproof/xproof`
- [Examples](https://github.com/jasonxkensei/xproof-examples) — LangChain, CrewAI, AutoGen, LlamaIndex

## License

MIT

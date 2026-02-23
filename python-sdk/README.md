# xProof Python SDK

Python SDK for [xProof](https://xproof.app) — blockchain proof-of-existence on MultiversX.

Certify files, verify proofs, and interact with the xProof API from Python.

## Installation

```bash
pip install xproof
```

## Quick Start

```python
from xproof import XProofClient

client = XProofClient(api_key="pm_your_api_key")

# Certify a file (auto-hashes locally with SHA-256)
cert = client.certify("path/to/file.pdf", author="Alice")
print(cert.id)
print(cert.transaction_url)

# Certify with a pre-computed hash
cert = client.certify_hash(
    file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    file_name="report.pdf",
    author="Alice",
)

# Verify a proof by ID
proof = client.verify("certification-uuid")
print(proof.file_name, proof.blockchain_status)

# Verify by file hash
proof = client.verify_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

# Get current pricing
pricing = client.get_pricing()
print(pricing.price_usd)
```

## Batch Certification

Certify up to 50 files in a single API call:

```python
results = client.batch_certify([
    {"path": "file1.pdf", "author": "Alice"},
    {"path": "file2.pdf", "author": "Bob"},
])

print(results.summary.total)      # 2
print(results.summary.certified)  # 2
print(results.summary.failed)     # 0

for cert in results.results:
    print(cert.file_name, cert.transaction_url)
```

You can also use pre-computed hashes:

```python
results = client.batch_certify([
    {
        "file_hash": "abc123...",
        "file_name": "report.pdf",
        "author": "Alice",
    },
])
```

## File Hashing Utility

```python
from xproof import hash_file

sha256_hex = hash_file("path/to/file.pdf")
print(sha256_hex)  # 64-character hex string
```

## Error Handling

```python
from xproof import XProofClient, AuthenticationError, NotFoundError, ConflictError

client = XProofClient(api_key="pm_your_api_key")

try:
    cert = client.certify("file.pdf", author="Alice")
except AuthenticationError:
    print("Invalid API key")
except ConflictError as e:
    print(f"Already certified: {e.certification_id}")
except NotFoundError:
    print("Resource not found")
```

## API Reference

| Method | Description |
|---|---|
| `client.certify(path, author)` | Certify a file (auto-hashes locally) |
| `client.certify_hash(file_hash, file_name, author)` | Certify with a pre-computed hash |
| `client.batch_certify(files)` | Batch certify up to 50 files |
| `client.verify(proof_id)` | Retrieve a proof by ID |
| `client.verify_hash(file_hash)` | Look up a proof by SHA-256 hash |
| `client.get_pricing()` | Get current pricing info |
| `hash_file(path)` | Compute SHA-256 hex digest of a file |

## Models

- **`Certification`** — `id`, `file_name`, `file_hash`, `transaction_hash`, `transaction_url`, `created_at`, `author_name`, `blockchain_status`
- **`BatchResult`** — `results` (list of `Certification`), `summary` (`total`, `certified`, `failed`)
- **`PricingInfo`** — `protocol`, `version`, `price_usd`, `tiers`, `payment_methods`

## Exceptions

| Exception | HTTP Status | Description |
|---|---|---|
| `XProofError` | — | Base exception |
| `AuthenticationError` | 401/403 | Invalid or missing API key |
| `ValidationError` | 400 | Invalid request data |
| `NotFoundError` | 404 | Resource not found |
| `ConflictError` | 409 | File already certified |
| `RateLimitError` | 429 | Rate limit exceeded |
| `ServerError` | 5xx | Server error |

## Requirements

- Python 3.8+
- `requests >= 2.25.0`

## Links

- **Web App**: [https://xproof.app](https://xproof.app)
- **API Pricing**: [https://xproof.app/api/pricing](https://xproof.app/api/pricing)
- **GitHub**: [https://github.com/jasonxkensei/xproof](https://github.com/jasonxkensei/xproof)

## License

MIT

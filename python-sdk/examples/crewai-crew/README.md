# CrewAI + xProof Example

A 3-agent crew (researcher, writer, reviewer) where each agent's contribution
is independently certified and verifiable on-chain via xProof.

## Setup

```bash
cd python-sdk/examples/crewai-crew
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

The script will:
1. Register a trial xProof agent
2. Simulate 3 agents completing tasks (researcher → writer → reviewer)
3. Certify each agent's output on-chain
4. Certify the full crew execution with proof-ID chaining
5. Verify all certifications independently

Each proof is anchored on MultiversX and can be verified at
`https://xproof.app/verify/<proofId>`.

# xproof-examples

Standalone examples showing how to certify AI agent outputs on the **MultiversX blockchain** using [xProof](https://xproof.app).

xProof gives every agent action a tamper-proof audit trail anchored on-chain in ~6 seconds. Each certification records the **4W framework**: Who acted, What was produced, When it happened, and Why.

## Examples

| Framework | Language | Description |
|-----------|----------|-------------|
| [LangChain](./langchain/) | Python | Certify every LLM call via a callback handler |
| [CrewAI](./crewai/) | Python | Certify each agent's task output in a multi-agent crew |
| [LlamaIndex](./llamaindex/) | Python | Certify LLM calls and query completions |
| [OpenAI Agents SDK](./openai-agents/) | Python | Certify tool executions and agent completions via RunHooks or TracingProcessor |
| [Vercel AI SDK](./vercel/) | TypeScript | Certify AI generations in a Next.js API route |
| [AutoGen](./autogen/) | Python | Certify messages exchanged between AutoGen agents |
| [DeerFlow](./deerflow/) | Python | Certify DeerFlow agent outputs via a skill |

## Quick start

```bash
# Python frameworks
pip install xproof

# TypeScript / Vercel
npm install xproof
```

Get a free API key or start with the trial tier at **[xproof.app](https://xproof.app)**.

## Links

- PyPI: [pypi.org/project/xproof](https://pypi.org/project/xproof)
- npm: [npmjs.com/package/xproof](https://www.npmjs.com/package/xproof)
- Docs: [xproof.app/docs](https://xproof.app/docs)
- GitHub (SDK): [github.com/jasonxkensei/xproof](https://github.com/jasonxkensei/xproof)

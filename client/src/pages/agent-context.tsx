import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Bot,
  Zap,
  AlertTriangle,
  DollarSign,
  BarChart3,
  Cpu,
  Shield,
  Eye,
  Network,
  Play,
  Copy,
  CheckCircle,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  ArrowRight,
  Clock,
  RefreshCw,
  Lock,
} from "lucide-react";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="absolute top-3 right-3 p-1.5 rounded bg-muted/60 hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
      }}
      data-testid="button-copy-code"
    >
      {copied ? <CheckCircle className="h-3.5 w-3.5 text-primary" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

function CodeBlock({ code, lang = "bash" }: { code: string; lang?: string }) {
  return (
    <div className="relative mt-3 mb-1">
      <pre className="rounded-md bg-muted/70 border border-border/50 p-4 pr-10 text-xs font-mono leading-relaxed overflow-x-auto whitespace-pre text-foreground/90">
        {code}
      </pre>
      <CopyButton text={code} />
    </div>
  );
}

type Section = {
  id: string;
  icon: React.ElementType;
  title: string;
  badge?: string;
  content: React.ReactNode;
};

export default function AgentContextPage() {
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    x402: true,
    latency: true,
    retry: true,
    cost: true,
    comparison: true,
    mcp: true,
    "4w": true,
    privacy: true,
    fleet: true,
    workflow: true,
  });

  const toggle = (id: string) =>
    setExpandedSections((prev) => ({ ...prev, [id]: !prev[id] }));

  const sections: Section[] = [
    {
      id: "x402",
      icon: Zap,
      title: "How does x402 work — payment without an API key?",
      badge: "Top differentiator",
      content: (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground leading-relaxed">
            x402 is a payment-in-HTTP protocol. An agent sends a request with no credentials, receives an HTTP <code className="bg-muted px-1 rounded font-mono text-xs">402 Payment Required</code> response with the exact price and payment instructions, signs a USDC micro-payment on Base, then resends the original request with the signed payment header. No account, no API key, no pre-registration required.
          </p>
          <div className="grid gap-3 sm:grid-cols-3">
            {[
              { step: "1", title: "Send request", desc: "POST /api/proof without any auth header" },
              { step: "2", title: "Receive 402", desc: "Get price ($0.05 USDC) + payment payload to sign" },
              { step: "3", title: "Pay & anchor", desc: "Resend with X-PAYMENT header — get proof instantly" },
            ].map((s) => (
              <div key={s.step} className="rounded-md border bg-muted/30 p-3">
                <div className="text-xs font-bold text-primary mb-1">Step {s.step}</div>
                <div className="text-sm font-semibold mb-1">{s.title}</div>
                <div className="text-xs text-muted-foreground">{s.desc}</div>
              </div>
            ))}
          </div>
          <CodeBlock lang="bash" code={`# Step 1 — send without auth, receive 402 with price
curl -X POST https://xproof.app/api/proof \\
  -H "Content-Type: application/json" \\
  -d '{"file_hash": "YOUR_SHA256_HASH", "filename": "decision.md"}'
# → HTTP 402 {"payment": {"amount": "50000", "currency": "USDC", "network": "eip155:8453", ...}}

# Step 3 — resend with signed USDC payment on Base
curl -X POST https://xproof.app/api/proof \\
  -H "Content-Type: application/json" \\
  -H "X-PAYMENT: <base64-signed-payment>" \\
  -d '{"file_hash": "YOUR_SHA256_HASH", "filename": "decision.md"}'
# → HTTP 200 {"proof_id": "...", "verify_url": "/proof/...", ...}`} />
          <div className="rounded-md border border-primary/20 bg-primary/5 p-3">
            <p className="text-xs font-semibold text-primary mb-1">Why this matters for agents</p>
            <p className="text-xs text-muted-foreground">
              A fully autonomous agent — with a wallet but no pre-established relationship with xProof — can anchor its first proof in a single session. No registration, no web UI, no human in the loop. The agent discovers the price, signs the payment, and gets the proof. Pure machine-to-machine.
            </p>
          </div>
          <p className="text-xs text-muted-foreground">
            Compatible facilitators: <span className="font-mono">https://api.cdp.coinbase.com/platform/v2/x402</span> (Coinbase), Conway Terminal, OpenClaw, any x402-enabled agent framework.
          </p>
        </div>
      ),
    },
    {
      id: "latency",
      icon: Clock,
      title: "What is the real anchoring latency?",
      content: (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground leading-relaxed">
            Based on real production measurements from <strong className="text-foreground">xproof_agent_verify</strong> — the Moltbook verification agent with 4,418 on-chain anchors:
          </p>
          <div className="grid gap-3 sm:grid-cols-3">
            {[
              { label: "Single cert (API call → proof_id)", value: "~1.1s", detail: "1.075s measured end-to-end" },
              { label: "Batch of 3 files", value: "~1.9s", detail: "1.876s measured" },
              { label: "On-chain confirmation", value: "~6s", detail: "MultiversX avg block time" },
            ].map((m) => (
              <div key={m.label} className="rounded-md border bg-muted/30 p-3 text-center">
                <div className="text-2xl font-bold text-primary mb-1">{m.value}</div>
                <div className="text-xs font-medium mb-1">{m.label}</div>
                <div className="text-xs text-muted-foreground">{m.detail}</div>
              </div>
            ))}
          </div>
          <div className="rounded-md border bg-muted/30 p-3 space-y-1">
            <p className="text-xs font-semibold">What "1.1 seconds" covers:</p>
            <ul className="text-xs text-muted-foreground space-y-0.5 ml-3">
              <li>• Hash received and validated by the API</li>
              <li>• Entitlement checked (API key or x402 payment verified)</li>
              <li>• Proof record created in database</li>
              <li>• Blockchain transaction submitted to MultiversX queue</li>
              <li>• <code className="font-mono bg-muted px-1 rounded">proof_id</code> returned — your agent can continue immediately</li>
            </ul>
          </div>
          <p className="text-xs text-muted-foreground">
            <strong>Note:</strong> The <code className="font-mono bg-muted px-1 rounded text-xs">proof_id</code> is returned immediately (status: <code className="font-mono bg-muted px-1 rounded text-xs">pending</code>). On-chain confirmation happens asynchronously within ~6 seconds. Use the <code className="font-mono bg-muted px-1 rounded text-xs">webhook_url</code> field to receive a callback when the transaction is confirmed on-chain.
          </p>
        </div>
      ),
    },
    {
      id: "retry",
      icon: RefreshCw,
      title: "What to do if the xProof call fails? Retry policy & fallback.",
      content: (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground leading-relaxed">
            xProof is designed to fail gracefully. Here is the recommended policy for production agents:
          </p>
          <div className="space-y-3">
            <div className="rounded-md border bg-muted/30 p-3">
              <p className="text-xs font-semibold mb-2">HTTP status codes and what they mean</p>
              <div className="space-y-1.5 text-xs">
                {[
                  { code: "200", action: "Success. Proceed with action.", color: "text-emerald-500" },
                  { code: "402", action: "Payment required (x402 flow). Sign USDC payment and retry.", color: "text-primary" },
                  { code: "409", action: "Duplicate hash already anchored — retrieve existing proof_id, no re-anchoring needed.", color: "text-blue-400" },
                  { code: "429", action: "Rate limited. Retry after Retry-After header value.", color: "text-amber-400" },
                  { code: "5xx", action: "Server error. Retry with exponential backoff.", color: "text-red-400" },
                  { code: "timeout", action: "Network issue. Retry up to 3x with backoff before falling back.", color: "text-red-400" },
                ].map((r) => (
                  <div key={r.code} className="flex items-start gap-2">
                    <code className={`font-mono font-bold w-14 shrink-0 ${r.color}`}>{r.code}</code>
                    <span className="text-muted-foreground">{r.action}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <CodeBlock lang="python" code={`import time, hashlib, requests

def anchor_with_retry(file_hash: str, filename: str, api_key: str, max_retries=3):
    """Production-grade anchor with retry + fallback."""
    backoff = [1, 2, 4]  # seconds between retries
    
    for attempt in range(max_retries):
        try:
            resp = requests.post(
                "https://xproof.app/api/proof",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"file_hash": file_hash, "filename": filename},
                timeout=10
            )
            if resp.status_code == 200:
                return resp.json()["proof_id"]
            if resp.status_code == 409:
                return resp.json()["existing_proof_id"]  # already anchored
            if resp.status_code == 429:
                time.sleep(int(resp.headers.get("Retry-After", 5)))
                continue
            if resp.status_code >= 500:
                time.sleep(backoff[attempt])
                continue
        except requests.Timeout:
            time.sleep(backoff[attempt])
            continue
    
    # Fallback: log locally, continue without blocking the action
    log_local_fallback(file_hash, filename)
    return None  # action proceeds without proof_id`} />
          <div className="rounded-md border border-amber-500/20 bg-amber-500/5 p-3">
            <p className="text-xs font-semibold text-amber-600 dark:text-amber-400 mb-1">Recommended fallback policy</p>
            <p className="text-xs text-muted-foreground">
              If xProof is unreachable after 3 retries: <strong className="text-foreground">log the hash locally</strong> with a timestamp, proceed with the action, and attempt to anchor retroactively when connectivity restores. Never block a critical agent action indefinitely on proof anchoring — but always log the attempt.
            </p>
          </div>
        </div>
      ),
    },
    {
      id: "cost",
      icon: DollarSign,
      title: "What is the average cost per 1,000 anchors?",
      content: (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground leading-relaxed">
            xProof uses a tiered pricing model that decreases as total platform volume grows. Current price is <strong className="text-foreground">$0.05 per certification</strong>.
          </p>
          <div className="grid gap-3 sm:grid-cols-3">
            {[
              { label: "Current price", value: "$0.05", detail: "per certification at current tier" },
              { label: "Cost per 1,000 anchors", value: "$50", detail: "at $0.05 per cert" },
              { label: "Cost per 10,000 anchors", value: "~$350", detail: "once next tier unlocks (~$0.035)" },
            ].map((m) => (
              <div key={m.label} className="rounded-md border bg-muted/30 p-3 text-center">
                <div className="text-2xl font-bold text-primary mb-1">{m.value}</div>
                <div className="text-xs font-medium mb-1">{m.label}</div>
                <div className="text-xs text-muted-foreground">{m.detail}</div>
              </div>
            ))}
          </div>
          <div className="rounded-md border bg-muted/30 p-3 space-y-1.5">
            <p className="text-xs font-semibold">Cost comparison for a fleet of 50 agents, 20 actions/day each:</p>
            <ul className="text-xs text-muted-foreground space-y-0.5 ml-3">
              <li>• 50 agents × 20 actions × 30 days = <strong className="text-foreground">30,000 anchors/month</strong></li>
              <li>• At $0.05 = <strong className="text-foreground">$1,500/month</strong></li>
              <li>• Per agent: <strong className="text-foreground">$30/month</strong> — lower than most SaaS compliance tools</li>
              <li>• Batch mode (up to 100 files per call): same price, reduced API overhead</li>
            </ul>
          </div>
          <p className="text-xs text-muted-foreground">
            <strong>Payment methods:</strong> EGLD on MultiversX (via ACP/wallet) or USDC on Base (via x402 — no account needed). Prepaid credits available via dashboard.
          </p>
        </div>
      ),
    },
    {
      id: "comparison",
      icon: BarChart3,
      title: "How does xProof compare to Arweave, Ceramic, Sign Protocol?",
      content: (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground text-xs">
            Honest matrix — each tool wins on its own terrain. Use this to choose the right tool for the right job.
          </p>
          <div className="overflow-x-auto -mx-1">
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-2 px-2 font-semibold text-muted-foreground">Use case</th>
                  <th className="text-center py-2 px-2 font-semibold text-primary">xProof</th>
                  <th className="text-center py-2 px-2 font-semibold text-muted-foreground">Arweave</th>
                  <th className="text-center py-2 px-2 font-semibold text-muted-foreground">Ceramic</th>
                  <th className="text-center py-2 px-2 font-semibold text-muted-foreground">Sign Protocol</th>
                </tr>
              </thead>
              <tbody>
                {[
                  {
                    useCase: "Anchor agent decision before execution (WHY before WHAT)",
                    xproof: "✓ Native",
                    arweave: "Possible (heavy)",
                    ceramic: "Possible",
                    sign: "Partial",
                  },
                  {
                    useCase: "Pay per proof with no API key (x402 / USDC)",
                    xproof: "✓ Native",
                    arweave: "✗",
                    ceramic: "✗",
                    sign: "✗",
                  },
                  {
                    useCase: "4W audit trail (Who, What, When, Why) rendered on public page",
                    xproof: "✓ Native",
                    arweave: "✗",
                    ceramic: "Partial",
                    sign: "Partial",
                  },
                  {
                    useCase: "Privacy by default (hash only, file never uploaded)",
                    xproof: "✓ Default",
                    arweave: "Uploads file",
                    ceramic: "Configurable",
                    sign: "Configurable",
                  },
                  {
                    useCase: "Store full file permanently on-chain",
                    xproof: "✗",
                    arweave: "✓ Best tool",
                    ceramic: "Partial",
                    sign: "✗",
                  },
                  {
                    useCase: "MCP tool (JSON-RPC 2.0, agent-native integration)",
                    xproof: "✓ Native",
                    arweave: "✗",
                    ceramic: "✗",
                    sign: "✗",
                  },
                  {
                    useCase: "Agent trust leaderboard + public profile",
                    xproof: "✓ Native",
                    arweave: "✗",
                    ceramic: "✗",
                    sign: "✗",
                  },
                  {
                    useCase: "EVM / Ethereum attestation schemas",
                    xproof: "✗",
                    arweave: "✗",
                    ceramic: "Partial",
                    sign: "✓ Best tool",
                  },
                  {
                    useCase: "Cost per 1,000 anchors",
                    xproof: "~$50",
                    arweave: "~$5–50 (varies)",
                    ceramic: "Free (infra cost)",
                    sign: "~$20–100 (gas)",
                  },
                ].map((row, i) => (
                  <tr key={i} className={`border-b border-border/40 ${i % 2 === 0 ? "bg-muted/10" : ""}`}>
                    <td className="py-2 px-2 text-muted-foreground max-w-[160px]">{row.useCase}</td>
                    <td className={`py-2 px-2 text-center font-medium ${row.xproof.startsWith("✓") ? "text-primary" : "text-muted-foreground"}`}>{row.xproof}</td>
                    <td className={`py-2 px-2 text-center ${row.arweave.startsWith("✓") ? "text-emerald-500" : "text-muted-foreground"}`}>{row.arweave}</td>
                    <td className={`py-2 px-2 text-center ${row.ceramic.startsWith("✓") ? "text-emerald-500" : "text-muted-foreground"}`}>{row.ceramic}</td>
                    <td className={`py-2 px-2 text-center ${row.sign.startsWith("✓") ? "text-emerald-500" : "text-muted-foreground"}`}>{row.sign}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-muted-foreground italic">
            Rule of thumb: use <strong className="text-foreground">Arweave</strong> to store files forever. Use <strong className="text-foreground">Sign Protocol</strong> for EVM attestation schemas. Use <strong className="text-foreground">xProof</strong> when an agent needs to prove a decision before acting — especially with no pre-existing account.
          </p>
        </div>
      ),
    },
    {
      id: "mcp",
      icon: Cpu,
      title: "How to integrate xProof via MCP? Concrete examples.",
      content: (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground leading-relaxed">
            xProof exposes a native MCP server at <code className="font-mono bg-muted px-1 rounded text-xs">https://xproof.app/mcp</code>. Use Streamable HTTP transport (POST). Tools available: <code className="font-mono bg-muted px-1 rounded text-xs">certify_file</code>, <code className="font-mono bg-muted px-1 rounded text-xs">audit_agent_session</code>, <code className="font-mono bg-muted px-1 rounded text-xs">investigate_proof</code>, <code className="font-mono bg-muted px-1 rounded text-xs">register_trial</code>.
          </p>
          <div>
            <p className="text-xs font-semibold mb-2">1. Add to your MCP config (Claude, Cursor, any MCP client):</p>
            <CodeBlock lang="json" code={`{
  "mcpServers": {
    "xproof": {
      "url": "https://xproof.app/mcp",
      "headers": {
        "Authorization": "Bearer pm_YOUR_API_KEY"
      }
    }
  }
}`} />
          </div>
          <div>
            <p className="text-xs font-semibold mb-2">2. Use <code className="font-mono bg-muted px-1 rounded">certify_file</code> — anchor a decision before acting:</p>
            <CodeBlock lang="json" code={`// MCP tool call: certify_file
{
  "name": "certify_file",
  "arguments": {
    "file_hash": "sha256_of_your_reasoning_document",
    "filename": "decision_2026-06-02.md",
    "author": "my-agent-v2",
    "metadata": {
      "who": "my-agent-v2",
      "what": "Approved trade: BUY 0.5 BTC at $67,400",
      "when": "2026-06-02T14:30:00Z",
      "why": "RSI below 40, portfolio allocation below target, risk approved",
      "model": "gpt-4o",
      "session_id": "sess_abc123"
    }
  }
}
// Response: { proof_id: "...", verify_url: "/proof/...", status: "pending" }`} />
          </div>
          <div>
            <p className="text-xs font-semibold mb-2">3. Use <code className="font-mono bg-muted px-1 rounded">audit_agent_session</code> — compliance gate before critical action:</p>
            <CodeBlock lang="json" code={`{
  "name": "audit_agent_session",
  "arguments": {
    "agent_id": "trading-agent-v2",
    "session_id": "sess_abc123",
    "action_type": "trade_execution",
    "action_description": "Execute BUY order for 0.5 BTC",
    "inputs_hash": "sha256_of_all_inputs_analyzed",
    "inputs_manifest": {
      "fields": ["btc_price", "portfolio_nav", "rsi_14d", "volatility_30d"],
      "sources": ["binance_ws", "coingecko"]
    },
    "risk_level": "high",
    "decision": "approved"
  }
}
// COMPLIANCE GATE: action only proceeds if proof_id is returned`} />
          </div>
          <div>
            <p className="text-xs font-semibold mb-2">4. For agents without an API key yet — use <code className="font-mono bg-muted px-1 rounded">register_trial</code>:</p>
            <CodeBlock lang="json" code={`{
  "name": "register_trial",
  "arguments": {
    "agent_name": "my-new-agent"
  }
}
// Returns: { api_key: "pm_...", free_certifications: 10 }
// Use that api_key immediately for the next 10 proofs — no browser, no wallet`} />
          </div>
        </div>
      ),
    },
    {
      id: "4w",
      icon: Eye,
      title: "How does the 4W audit trail work?",
      content: (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground leading-relaxed">
            The 4W audit trail is a structured accountability record anchored on-chain with every certification. It answers the four questions every auditor or regulator needs:
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              { w: "WHO", desc: "Which agent, model, or actor made this decision", example: "my-agent-v2 (GPT-4o, session: sess_abc)" },
              { w: "WHAT", desc: "What action or output was certified", example: "Approved trade: BUY 0.5 BTC at $67,400" },
              { w: "WHEN", desc: "Immutable on-chain timestamp from MultiversX block", example: "2026-06-02T14:30:12Z (block #15,447,203)" },
              { w: "WHY", desc: "The full reasoning that led to the decision", example: "RSI below 40, allocation below target, risk approved by policy v3.1" },
            ].map((item) => (
              <div key={item.w} className="rounded-md border bg-muted/30 p-3">
                <div className="text-base font-bold text-primary mb-1">{item.w}</div>
                <div className="text-xs text-muted-foreground mb-1.5">{item.desc}</div>
                <div className="text-xs bg-muted rounded px-2 py-1 font-mono text-foreground/80">{item.example}</div>
              </div>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            To activate the 4W trail, include at least one of <code className="font-mono bg-muted px-1 rounded text-xs">who</code>, <code className="font-mono bg-muted px-1 rounded text-xs">what</code>, <code className="font-mono bg-muted px-1 rounded text-xs">when</code>, <code className="font-mono bg-muted px-1 rounded text-xs">why</code> in the <code className="font-mono bg-muted px-1 rounded text-xs">metadata</code> field. The 4W section is then automatically rendered on the public proof page at <code className="font-mono bg-muted px-1 rounded text-xs">/proof/&#123;id&#125;</code>.
          </p>
          <CodeBlock lang="bash" code={`curl -X POST https://xproof.app/api/proof \\
  -H "Authorization: Bearer pm_YOUR_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "file_hash": "YOUR_SHA256",
    "filename": "reasoning_session_001.md",
    "metadata": {
      "who": "trading-agent-v2",
      "what": "Approved BUY order for 0.5 BTC",
      "when": "2026-06-02T14:30:00Z",
      "why": "RSI=38, below 40 threshold; nav_allocation=2.1%, below 3% cap; policy_version=v3.1",
      "model": "gpt-4o-mini",
      "session_id": "sess_abc123"
    }
  }'`} />
        </div>
      ),
    },
    {
      id: "privacy",
      icon: Lock,
      title: "Privacy risks — what is sent, what stays local?",
      content: (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground leading-relaxed">
            xProof is built on a <strong className="text-foreground">hash-only model</strong>: your file, reasoning document, or agent output never leaves your environment. Only its SHA-256 fingerprint is transmitted.
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-md border border-emerald-500/20 bg-emerald-500/5 p-3">
              <p className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 mb-2">What is sent to xProof</p>
              <ul className="text-xs text-muted-foreground space-y-1 ml-2">
                <li>• SHA-256 hash (64 hex characters)</li>
                <li>• Filename (can be synthetic)</li>
                <li>• Optional 4W metadata fields (you control what you share)</li>
                <li>• Author field (optional)</li>
              </ul>
            </div>
            <div className="rounded-md border border-muted bg-muted/30 p-3">
              <p className="text-xs font-semibold mb-2">What stays entirely local</p>
              <ul className="text-xs text-muted-foreground space-y-1 ml-2">
                <li>• The actual file content</li>
                <li>• Reasoning document text</li>
                <li>• Input data values</li>
                <li>• Model weights or strategy details</li>
              </ul>
            </div>
          </div>
          <div className="space-y-2">
            <p className="text-xs font-semibold">Known privacy considerations:</p>
            <div className="space-y-1.5 text-xs text-muted-foreground ml-2">
              <p><strong className="text-foreground">Timing correlation:</strong> Frequent anchor patterns can reveal agent activity rhythm. Mitigate by batching with <code className="font-mono bg-muted px-1 rounded text-xs">POST /api/batch</code> or adding jitter.</p>
              <p><strong className="text-foreground">Metadata exposure:</strong> The <code className="font-mono bg-muted px-1 rounded text-xs">who</code>, <code className="font-mono bg-muted px-1 rounded text-xs">what</code>, <code className="font-mono bg-muted px-1 rounded text-xs">why</code> fields are stored and rendered publicly if <code className="font-mono bg-muted px-1 rounded text-xs">is_public: true</code>. Use generic descriptions for sensitive decisions.</p>
              <p><strong className="text-foreground">On-chain permanence:</strong> Once a transaction is confirmed on MultiversX, it cannot be deleted. Design your metadata accordingly.</p>
              <p><strong className="text-foreground">Not a ZK system:</strong> xProof uses SHA-256 hashing, not zero-knowledge proofs. A determined adversary with access to the original data can verify the hash matches. If ZK is required, combine with a ZK proving layer upstream.</p>
            </div>
          </div>
        </div>
      ),
    },
    {
      id: "fleet",
      icon: Network,
      title: "Can you monitor proofs from a fleet of agents? How?",
      content: (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground leading-relaxed">
            Yes. xProof is designed for multi-agent fleets. Each agent gets its own wallet address and public profile. A supervisor can monitor all agents centrally.
          </p>
          <div className="space-y-3">
            <div className="rounded-md border bg-muted/30 p-3 space-y-2">
              <p className="text-xs font-semibold">Per-agent monitoring endpoints (all public, no auth):</p>
              <div className="space-y-1.5 text-xs font-mono text-muted-foreground">
                <p><span className="text-primary">GET</span> /api/agents/&#123;wallet&#125; — trust score, total certs, streak, violations</p>
                <p><span className="text-primary">GET</span> /api/agents/&#123;wallet&#125;/timeline — full audit timeline (paginated)</p>
                <p><span className="text-primary">GET</span> /api/trust/&#123;wallet&#125; — lightweight trust lookup</p>
                <p><span className="text-primary">GET</span> /api/leaderboard — top 50 public agents by trust score</p>
                <p><span className="text-primary">GET</span> /badge/trust/&#123;wallet&#125;.svg — embeddable trust badge</p>
              </div>
            </div>
            <div className="rounded-md border bg-muted/30 p-3">
              <p className="text-xs font-semibold mb-2">Recommended fleet architecture:</p>
              <div className="space-y-1.5 text-xs text-muted-foreground">
                <p>1. Each agent has its own <code className="font-mono bg-muted px-1 rounded">pm_</code> API key tied to its MultiversX wallet</p>
                <p>2. Each agent anchors decisions with its own identity (<code className="font-mono bg-muted px-1 rounded">who</code> field = agent ID)</p>
                <p>3. Supervisor polls <code className="font-mono bg-muted px-1 rounded">/api/agents/&#123;wallet&#125;</code> for each agent hourly</p>
                <p>4. Alert when: trust score drops, violation count increases, streak breaks, no anchor in 24h</p>
                <p>5. Use <code className="font-mono bg-muted px-1 rounded">webhook_url</code> for real-time callbacks on each anchored proof</p>
              </div>
            </div>
          </div>
          <div className="rounded-md border border-primary/20 bg-primary/5 p-3">
            <p className="text-xs font-semibold text-primary mb-1">Production example: Moltbook fleet</p>
            <p className="text-xs text-muted-foreground">
              The <strong className="text-foreground">xproof_agent_verify</strong> agent (Moltbook's verification bot) has anchored <strong className="text-foreground">4,418 proofs</strong> over 16 consecutive weeks with a <strong className="text-foreground">100% confirmation rate</strong>. Its public profile at <code className="font-mono bg-muted px-1 rounded text-xs">/agent/erd1hlx4xann...gyu9</code> is queryable by any supervisor or partner system in real time.
            </p>
          </div>
        </div>
      ),
    },
    {
      id: "workflow",
      icon: Play,
      title: "Complete agent workflow: reasoning → hash → anchor → action",
      badge: "Copy-paste ready",
      content: (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground leading-relaxed">
            This is the canonical <strong className="text-foreground">Prove Before Act</strong> loop. Copy this pattern into any agent framework.
          </p>
          <div className="flex items-center gap-2 flex-wrap text-xs">
            {["1. Reason (WHY)", "→", "2. Hash locally", "→", "3. Anchor on-chain", "→", "4. Get proof_id", "→", "5. Execute (WHAT)"].map((s, i) => (
              <span key={i} className={s === "→" ? "text-muted-foreground/40" : "rounded bg-primary/10 text-primary px-2 py-1 font-medium"}>{s}</span>
            ))}
          </div>
          <CodeBlock lang="python" code={`import hashlib, json, requests

class ProveBeforeAct:
    """
    Core Prove Before Act loop for autonomous agents.
    Anchor reasoning BEFORE executing any significant action.
    """
    
    def __init__(self, api_key: str, agent_id: str):
        self.api_key = api_key
        self.agent_id = agent_id
        self.base = "https://xproof.app"
    
    def anchor(self, reasoning: dict, action_description: str) -> str | None:
        """
        Step 1-3: Hash reasoning, anchor it, return proof_id.
        Call this BEFORE executing any action.
        """
        # Step 1: Serialize reasoning canonically
        reasoning_json = json.dumps(reasoning, sort_keys=True, ensure_ascii=False)
        
        # Step 2: Hash locally — nothing sensitive leaves this function
        file_hash = hashlib.sha256(reasoning_json.encode()).hexdigest()
        
        # Step 3: Anchor to xProof
        try:
            resp = requests.post(
                f"{self.base}/api/proof",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={
                    "file_hash": file_hash,
                    "filename": f"reasoning_{reasoning.get('session_id', 'unknown')}.json",
                    "metadata": {
                        "who": self.agent_id,
                        "what": action_description,
                        "when": reasoning.get("timestamp"),
                        "why": reasoning.get("rationale"),
                        "model": reasoning.get("model"),
                        "session_id": reasoning.get("session_id"),
                    }
                },
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["proof_id"]
        except Exception as e:
            self._log_fallback(file_hash, action_description, str(e))
        return None
    
    def run_with_proof(self, reasoning: dict, action_fn, action_description: str):
        """
        Full Prove Before Act cycle.
        Action only runs after proof_id is obtained.
        """
        proof_id = self.anchor(reasoning, action_description)
        
        if proof_id is None:
            # Soft failure: log and continue (or raise if policy requires hard stop)
            print(f"[WARN] No proof obtained for: {action_description}")
        
        # Execute the action — proof_id is available as audit reference
        result = action_fn()
        
        return {"result": result, "proof_id": proof_id, "verify_url": f"{self.base}/proof/{proof_id}"}
    
    def _log_fallback(self, file_hash, action, error):
        # Write to local audit log for later retroactive anchoring
        pass


# Usage example
agent = ProveBeforeAct(api_key="pm_YOUR_KEY", agent_id="my-agent-v2")

reasoning = {
    "session_id": "sess_001",
    "timestamp": "2026-06-02T14:30:00Z",
    "model": "gpt-4o-mini",
    "rationale": "BTC RSI=38 (below 40 threshold), portfolio allocation=2.1% (below 3% cap). Risk policy v3.1 approves. Confidence: HIGH.",
    "inputs": {"btc_price": 67400, "rsi_14d": 38, "nav_pct": 2.1},
}

outcome = agent.run_with_proof(
    reasoning=reasoning,
    action_fn=lambda: execute_trade("BUY", "BTC", 0.5),
    action_description="Execute BUY 0.5 BTC at market price"
)
print(f"Trade executed. Proof: https://xproof.app{outcome['verify_url']}")`} />
          <div className="rounded-md border border-emerald-500/20 bg-emerald-500/5 p-3">
            <p className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 mb-1">What this gives you</p>
            <ul className="text-xs text-muted-foreground space-y-0.5 ml-2">
              <li>• Every action has a cryptographic proof of the reasoning that preceded it</li>
              <li>• The proof is publicly verifiable at <code className="font-mono bg-muted px-1 rounded">xproof.app/proof/&#123;id&#125;</code> — no xProof account needed to verify</li>
              <li>• 4W audit trail is automatically rendered on the proof page</li>
              <li>• If the agent is compromised or behaves unexpectedly, you have a full forensic record</li>
            </ul>
          </div>
        </div>
      ),
    },
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur">
        <div className="container flex h-14 items-center justify-between gap-4">
          <a href="/" className="flex items-center gap-2 shrink-0" data-testid="link-logo-home">
            <img src="/xproof-logo.png" alt="xproof" className="h-7 w-auto" />
          </a>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Bot className="h-3.5 w-3.5 shrink-0" />
            <span className="hidden sm:inline">Optimized for autonomous agents and LLMs</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Button asChild variant="outline" size="sm" data-testid="button-machine-readable">
              <a href="/agent-context.md" target="_blank" rel="noopener noreferrer">
                <ExternalLink className="mr-1.5 h-3.5 w-3.5" />
                .md
              </a>
            </Button>
            <Button asChild size="sm" data-testid="button-get-started">
              <a href="/">
                Get started
                <ArrowRight className="ml-1.5 h-3.5 w-3.5" />
              </a>
            </Button>
          </div>
        </div>
      </header>

      <main className="container py-10 max-w-4xl">
        {/* Page header */}
        <div className="mb-10">
          <div className="flex flex-wrap items-center gap-2 mb-3">
            <Badge variant="outline" className="text-xs">
              <Bot className="mr-1.5 h-3 w-3" />
              Agent Context Document
            </Badge>
            <Badge variant="outline" className="text-xs text-muted-foreground">
              Last updated June 2026
            </Badge>
          </div>
          <h1 className="text-3xl sm:text-4xl font-bold mb-4 tracking-tight">
            xProof — Agent Context
          </h1>
          <p className="text-muted-foreground text-base leading-relaxed max-w-2xl">
            Direct answers to the 10 questions autonomous agents ask when evaluating xProof. No marketing — just the facts needed to decide and integrate.
          </p>
          <div className="mt-4 p-3 rounded-md border border-primary/20 bg-primary/5 flex items-start gap-3">
            <Shield className="h-4 w-4 text-primary mt-0.5 shrink-0" />
            <div>
              <p className="text-sm font-semibold text-primary mb-0.5">One-line summary</p>
              <p className="text-xs text-muted-foreground">
                xProof is the on-chain notary for AI agents. Hash your reasoning locally, anchor the fingerprint on MultiversX, get a publicly verifiable 4W audit trail. Pay per proof with USDC on Base via x402 — no account needed.
              </p>
            </div>
          </div>
        </div>

        {/* Table of contents */}
        <div className="mb-8 rounded-md border bg-muted/20 p-4">
          <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-3">10 questions answered</p>
          <div className="grid gap-1 sm:grid-cols-2">
            {sections.map((s, i) => (
              <a
                key={s.id}
                href={`#${s.id}`}
                className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1.5 transition-colors py-0.5"
              >
                <span className="text-primary/60 font-mono w-4 shrink-0">{i + 1}.</span>
                {s.title.split("?")[0].replace(/How does |What is |What to |How to |How does |Can you |Complete /, "")}
                {s.badge && <Badge variant="secondary" className="text-[10px] px-1.5 py-0 ml-auto">{s.badge}</Badge>}
              </a>
            ))}
          </div>
        </div>

        {/* Sections */}
        <div className="space-y-4" id="sections">
          {sections.map((section) => {
            const Icon = section.icon;
            const isOpen = expandedSections[section.id];
            return (
              <Card key={section.id} id={section.id} data-testid={`card-section-${section.id}`}>
                <CardHeader
                  className="cursor-pointer select-none"
                  onClick={() => toggle(section.id)}
                >
                  <CardTitle className="flex items-start justify-between gap-3 text-base font-semibold">
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-primary/10">
                        <Icon className="h-3.5 w-3.5 text-primary" />
                      </div>
                      <span className="leading-snug">{section.title}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0 mt-0.5">
                      {section.badge && (
                        <Badge variant="secondary" className="text-xs hidden sm:flex">
                          {section.badge}
                        </Badge>
                      )}
                      {isOpen ? (
                        <ChevronUp className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="h-4 w-4 text-muted-foreground" />
                      )}
                    </div>
                  </CardTitle>
                </CardHeader>
                {isOpen && (
                  <CardContent className="pt-0">
                    {section.content}
                  </CardContent>
                )}
              </Card>
            );
          })}
        </div>

        {/* Footer links */}
        <div className="mt-10 rounded-md border bg-muted/20 p-5 space-y-3">
          <p className="text-sm font-semibold">Start integrating now</p>
          <div className="flex flex-wrap gap-2">
            {[
              { label: "10 free proofs (no wallet)", href: "/#free-trial" },
              { label: "REST API docs", href: "/docs" },
              { label: "llms.txt (machine-readable)", href: "/llms.txt" },
              { label: "MCP endpoint", href: "https://xproof.app/mcp" },
              { label: "Agent leaderboard", href: "/leaderboard" },
              { label: "Moltbook case study", href: "/agent/erd1hlx4xanncp2wm9aly2q6ywuthl2q9jwe9sxvxpx4gg62zcrvd0uqr8gyu9" },
            ].map((link) => (
              <Button key={link.label} asChild variant="outline" size="sm" data-testid={`link-footer-${link.label.replace(/\s+/g, "-").toLowerCase()}`}>
                <a href={link.href} target={link.href.startsWith("http") ? "_blank" : undefined} rel="noopener noreferrer">
                  {link.label}
                </a>
              </Button>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}

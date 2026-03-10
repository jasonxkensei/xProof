import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Shield,
  Copy,
  Check,
  ArrowLeft,
  User,
  Hash,
  Clock,
  Brain,
  Layers,
  Search,
  Terminal,
} from "lucide-react";

const BASE = "https://xproof.app";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button
      size="icon"
      variant="ghost"
      className="absolute top-2 right-2 opacity-0 group-hover/code:opacity-100 transition-opacity"
      onClick={handleCopy}
      data-testid="button-copy-code"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-primary" /> : <Copy className="h-3.5 w-3.5" />}
    </Button>
  );
}

function CodeBlock({ code }: { code: string }) {
  return (
    <div className="relative group/code">
      <pre className="bg-muted/50 rounded-md p-4 pr-10 text-xs font-mono overflow-x-auto whitespace-pre text-foreground leading-relaxed">
        {code}
      </pre>
      <CopyButton text={code} />
    </div>
  );
}

function SectionHeader({ icon: Icon, number, title }: { icon: typeof Shield; number: string; title: string }) {
  return (
    <div className="flex items-center gap-3 mb-4">
      <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary/10 shrink-0">
        <Icon className="h-4 w-4 text-primary" />
      </div>
      <div>
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{number}</p>
        <h2 className="text-lg font-semibold leading-tight">{title}</h2>
      </div>
    </div>
  );
}

const dualCertCode = `async function certifyAndAct(agent: AgentContext) {
  // ── Step 1: Certify WHY (before acting) ──
  const reasoning = {
    trigger: agent.trigger,
    prompt_hash: sha256(agent.prompt),
    decision: agent.decision,
    risk_level: agent.riskLevel,
    timestamp: new Date().toISOString(),
  };
  const whyHash = sha256(JSON.stringify(reasoning));

  const whyProof = await fetch('${BASE}/api/proof', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer YOUR_API_KEY',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      file_hash: whyHash,
      filename: 'decision_' + Date.now() + '.json',
      metadata: { type: 'decision', ...reasoning },
    }),
  }).then(r => r.json());

  // ── Step 2: Execute the action ──
  const result = await agent.execute();

  // ── Step 3: Certify WHAT (after acting) ──
  const outputHash = sha256(result.content);

  const whatProof = await fetch('${BASE}/api/proof', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer YOUR_API_KEY',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      file_hash: outputHash,
      filename: result.filename,
      metadata: {
        type: 'output',
        why_proof_id: whyProof.proof_id,
      },
    }),
  }).then(r => r.json());

  return {
    why_proof_id: whyProof.proof_id,
    what_proof_id: whatProof.proof_id,
    result,
  };
}`;

const sessionLogCode = `interface SessionLog {
  session_id: string;
  agent_id: string;
  who: string;           // wallet address or SIGIL identity
  actions: {
    why_proof_id: string; // decision certified BEFORE action
    what_proof_id: string; // output certified AFTER action
    when: string;         // block timestamp from proof response
    description: string;
  }[];
}

async function buildSessionLog(
  sessionId: string,
  agent: AgentContext,
  actions: ActionResult[]
): Promise<SessionLog> {
  return {
    session_id: sessionId,
    agent_id: agent.id,
    who: agent.wallet,
    actions: actions.map(a => ({
      why_proof_id: a.why_proof_id,
      what_proof_id: a.what_proof_id,
      when: a.server_timestamp,
      description: a.description,
    })),
  };
}

// Post the session log publicly for auditors
async function publishSessionLog(log: SessionLog) {
  const logHash = sha256(JSON.stringify(log));
  const proof = await fetch('${BASE}/api/proof', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer YOUR_API_KEY',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      file_hash: logHash,
      filename: 'session_log_' + log.session_id + '.json',
      metadata: { type: 'session_log', session_id: log.session_id },
    }),
  }).then(r => r.json());

  return { session_log_proof_id: proof.proof_id, log };
}`;

const verifyCode = `async function inspectSession(proofIds: string[]) {
  // Batch-verify all proofs in a single request (up to 50)
  const ids = proofIds.join(',');
  const res = await fetch(
    '${BASE}/api/proofs/status?ids=' + ids
  ).then(r => r.json());

  for (const proof of res.proofs) {
    console.log(
      proof.proof_id,
      proof.blockchain_status,  // "confirmed" | "pending"
      proof.transaction_hash,   // on-chain tx
      proof.verify_url          // public verification link
    );
  }

  return res.proofs;
}`;

const curlExamples = `# 1. Register and get 10 free certs
curl -X POST ${BASE}/api/agent/register \\
     -H 'Content-Type: application/json' \\
     -d '{"agent_name": "my-4w-agent"}'

# 2. Certify WHY (before acting)
curl -X POST ${BASE}/api/proof \\
     -H 'Authorization: Bearer YOUR_API_KEY' \\
     -H 'Content-Type: application/json' \\
     -d '{
       "file_hash": "sha256(decision_payload)",
       "filename": "decision_001.json",
       "metadata": {
         "type": "decision",
         "trigger": "price_alert",
         "decision": "approved",
         "risk_level": "medium"
       }
     }'

# 3. Certify WHAT (after acting)
curl -X POST ${BASE}/api/proof \\
     -H 'Authorization: Bearer YOUR_API_KEY' \\
     -H 'Content-Type: application/json' \\
     -d '{
       "file_hash": "sha256(output_content)",
       "filename": "output_001.json",
       "metadata": {
         "type": "output",
         "filename": "result.json",
         "why_proof_id": "prf_abc123"
       }
     }'

# 4. Batch-verify all session proofs
curl "${BASE}/api/proofs/status?ids=prf_abc123,prf_def456"`;

export default function Docs4WPage() {
  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Button asChild variant="ghost" size="icon" data-testid="button-back-docs">
              <a href="/docs"><ArrowLeft className="h-4 w-4" /></a>
            </Button>
            <a href="/" className="flex items-center gap-2" data-testid="link-logo">
              <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
                <Shield className="h-5 w-5 text-primary-foreground" />
              </div>
              <span className="text-xl font-bold tracking-tight">xproof</span>
            </a>
            <Badge variant="outline">Integration Guide</Badge>
          </div>
          <div className="flex items-center gap-2">
            <Button asChild variant="ghost" size="sm" data-testid="link-api-docs">
              <a href="/docs">API Reference</a>
            </Button>
            <Button asChild variant="ghost" size="sm" data-testid="link-trading-docs">
              <a href="/docs/trading">Trading Guide</a>
            </Button>
          </div>
        </div>
      </header>

      <div className="container py-10 max-w-3xl mx-auto">
        <div className="mb-10">
          <div className="flex items-center gap-2 mb-3">
            <Badge variant="secondary" className="text-xs">v1.0</Badge>
            <span className="text-xs text-muted-foreground">Integration Pattern</span>
          </div>
          <h1 className="text-3xl md:text-4xl font-bold mb-3" data-testid="text-page-title">
            The 4W Certification Workflow
          </h1>
          <p className="text-muted-foreground text-lg max-w-2xl">
            How autonomous agents prove WHO acted, WHAT was produced, WHEN it happened, and WHY the decision was made.
          </p>
          <Card className="mt-6 border-primary/30 bg-primary/5">
            <CardContent className="p-4 flex items-center gap-3">
              <Brain className="h-5 w-5 text-primary shrink-0" />
              <p className="text-sm font-medium">
                Key insight — <span className="text-muted-foreground font-normal">Certify WHY before acting, WHAT after. This proves intent preceded execution.</span>
              </p>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-10">
          <section data-testid="section-4w-framework">
            <SectionHeader icon={Layers} number="01" title="The 4W Framework" />
            <p className="text-sm text-muted-foreground mb-4">
              Every auditable agent action can be decomposed into four verifiable dimensions.
              Each W has a distinct source of truth and certification timing.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <Card className="border-primary/20">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary/10">
                      <User className="h-3.5 w-3.5 text-primary" />
                    </div>
                    <h3 className="text-sm font-semibold" data-testid="text-who-title">WHO</h3>
                  </div>
                  <p className="text-xs text-muted-foreground">Agent identity via SIGIL or wallet address. Continuous identity chain across sessions.</p>
                </CardContent>
              </Card>
              <Card className="border-primary/20">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary/10">
                      <Hash className="h-3.5 w-3.5 text-primary" />
                    </div>
                    <h3 className="text-sm font-semibold" data-testid="text-what-title">WHAT</h3>
                  </div>
                  <p className="text-xs text-muted-foreground">SHA-256 hash of exact content produced. Anchored after publication to prove output integrity.</p>
                </CardContent>
              </Card>
              <Card className="border-primary/20">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary/10">
                      <Brain className="h-3.5 w-3.5 text-primary" />
                    </div>
                    <h3 className="text-sm font-semibold" data-testid="text-why-title">WHY</h3>
                  </div>
                  <p className="text-xs text-muted-foreground">Decision chain: reasoning, trigger, prompt hash. Anchored BEFORE acting — the key differentiator.</p>
                </CardContent>
              </Card>
              <Card className="border-primary/20">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary/10">
                      <Clock className="h-3.5 w-3.5 text-primary" />
                    </div>
                    <h3 className="text-sm font-semibold" data-testid="text-when-title">WHEN</h3>
                  </div>
                  <p className="text-xs text-muted-foreground">MultiversX block timestamp. Independent of the agent — tamper-proof temporal anchor.</p>
                </CardContent>
              </Card>
            </div>
          </section>

          <section data-testid="section-dual-certification">
            <SectionHeader icon={Brain} number="02" title="The Pattern: Certify WHY before, WHAT after" />
            <p className="text-sm text-muted-foreground mb-4">
              The dual-certification pattern is what makes the 4W framework powerful.
              By certifying WHY before acting, you prove that the decision was made before the outcome was known.
              By certifying WHAT after, you prove the exact output that resulted.
            </p>
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-4 mb-4">
              <p className="text-sm">
                <strong>Step 1</strong>
                <span className="text-muted-foreground"> — Hash and certify the decision (WHY) before executing</span>
              </p>
              <p className="text-sm mt-1">
                <strong>Step 2</strong>
                <span className="text-muted-foreground"> — Execute the action</span>
              </p>
              <p className="text-sm mt-1">
                <strong>Step 3</strong>
                <span className="text-muted-foreground"> — Hash and certify the output (WHAT) after execution</span>
              </p>
              <p className="text-xs text-muted-foreground mt-2">
                The blockchain timestamps prove the order: WHY block &lt; WHAT block.
                This is cryptographic proof of intent preceding execution.
              </p>
            </div>
            <CodeBlock code={dualCertCode} />
          </section>

          <section data-testid="section-session-log">
            <SectionHeader icon={Layers} number="03" title="Session Log Assembly" />
            <p className="text-sm text-muted-foreground mb-4">
              Collect all 4W proof IDs from a session into a structured log.
              This log can be published publicly, allowing auditors to verify every action in the session.
            </p>
            <CodeBlock code={sessionLogCode} />
            <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="rounded-md border bg-muted/30 p-3">
                <p className="text-xs font-medium text-foreground mb-1 flex items-center gap-1.5">
                  <Layers className="h-3 w-3 text-primary" /> session_id
                </p>
                <p className="text-xs text-muted-foreground">Groups all actions within one agent run. Links WHY and WHAT proofs together.</p>
              </div>
              <div className="rounded-md border bg-muted/30 p-3">
                <p className="text-xs font-medium text-foreground mb-1 flex items-center gap-1.5">
                  <Shield className="h-3 w-3 text-primary" /> session_log_proof_id
                </p>
                <p className="text-xs text-muted-foreground">The session log itself is certified, creating a tamper-proof audit trail.</p>
              </div>
            </div>
          </section>

          <section data-testid="section-verification">
            <SectionHeader icon={Search} number="04" title="Verification / Inspect mode" />
            <p className="text-sm text-muted-foreground mb-4">
              An auditor can verify all 4W for any action using the batch status endpoint.
              Pass all proof IDs from a session log to <code className="text-primary">GET /api/proofs/status</code> and
              inspect blockchain status, transaction hashes, and verification URLs.
            </p>
            <CodeBlock code={verifyCode} />
            <div className="rounded-md border overflow-hidden mt-4">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Field</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">What it proves</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ["proof_id", "Unique identifier for the certified hash"],
                    ["blockchain_status", "\"confirmed\" = anchored on MultiversX"],
                    ["transaction_hash", "On-chain tx — verifiable on any explorer"],
                    ["verify_url", "Public link to verify the proof independently"],
                    ["block_timestamp", "WHEN — independent temporal proof"],
                  ].map(([field, meaning], i) => (
                    <tr key={i} className={`border-b last:border-0 ${i % 2 === 0 ? "" : "bg-muted/20"}`}>
                      <td className="px-4 py-2.5 font-mono text-xs text-primary">{field}</td>
                      <td className="px-4 py-2.5 text-sm text-muted-foreground">{meaning}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section data-testid="section-quickstart">
            <SectionHeader icon={Terminal} number="05" title="Quick start" />
            <p className="text-sm text-muted-foreground mb-4">
              Four curl commands demonstrate the full dual-certification flow.
              No account required for the first 10 free certifications.
            </p>
            <CodeBlock code={curlExamples} />
          </section>
        </div>

        <footer className="border-t mt-12 pt-8">
          <div className="text-center text-sm text-muted-foreground">
            <p className="mb-3">
              <a href="/docs/trading" className="text-primary hover:underline" data-testid="link-footer-trading">Trading Integration</a>
              {" · "}
              <a href="/docs" className="text-primary hover:underline" data-testid="link-footer-docs">API Reference</a>
              {" · "}
              <a href="/" className="text-primary hover:underline" data-testid="link-footer-home">xproof.app</a>
            </p>
            <p className="text-xs">
              If you can't prove intent, your audit trail is incomplete.
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
}

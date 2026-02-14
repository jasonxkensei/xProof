import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  Code,
  FileText,
  Globe,
  Terminal,
  Download,
  Check,
  X,
  ExternalLink,
  Copy,
  Zap,
  Bot,
  ArrowLeft,
  Hash,
  Lock,
  Activity,
  Settings,
  CheckCircle,
} from "lucide-react";

function CopyButton({ text, testId }: { text: string; testId?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
    }
  };

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={handleCopy}
      data-testid={testId || "button-copy-snippet"}
      className="shrink-0"
    >
      {copied ? <CheckCircle className="h-4 w-4 text-chart-2" /> : <Copy className="h-4 w-4" />}
    </Button>
  );
}

const guarantees = [
  { icon: Hash, text: "Immutable SHA-256 anchoring on MultiversX" },
  { icon: Zap, text: "Deterministic (same input = same output)" },
  { icon: Globe, text: "Verifiable without xproof (on-chain)" },
  { icon: Lock, text: "Non-custodial (files never leave client)" },
  { icon: Shield, text: "$0.05 per certification in EGLD" },
];

const notDoes = [
  "Store files",
  "Require human approval",
  "Need browser interaction",
  "Lock you into a platform",
];

const steps = [
  {
    number: 1,
    title: "Discover",
    description: "Fetch available products and pricing.",
    code: `curl https://xproof.app/api/acp/products`,
  },
  {
    number: 2,
    title: "Certify",
    description: "Submit a file hash for blockchain anchoring.",
    code: `curl -X POST https://xproof.app/api/acp/checkout \\
  -H "Authorization: Bearer pm_YOUR_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"file_hash":"sha256_hash","file_name":"document.pdf","file_size":1024}'`,
  },
  {
    number: 3,
    title: "Confirm",
    description: "Finalize the certification with the transaction hash.",
    code: `curl -X POST https://xproof.app/api/acp/confirm \\
  -H "Authorization: Bearer pm_YOUR_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"checkout_id":"...","tx_hash":"..."}'`,
  },
];

const discoveryEndpoints = [
  {
    icon: FileText,
    title: "llms.txt",
    url: "/llms.txt",
    description: "LLM-friendly summary (llms.txt standard)",
  },
  {
    icon: FileText,
    title: "llms-full.txt",
    url: "/llms-full.txt",
    description: "Extended documentation with full API details",
  },
  {
    icon: Bot,
    title: "mcp.json",
    url: "/.well-known/mcp.json",
    description: "Model Context Protocol manifest",
  },
  {
    icon: Bot,
    title: "agent.json",
    url: "/.well-known/agent.json",
    description: "Agent Protocol manifest",
  },
  {
    icon: Settings,
    title: "ai-plugin.json",
    url: "/.well-known/ai-plugin.json",
    description: "OpenAI plugin manifest",
  },
  {
    icon: Code,
    title: "openapi.json",
    url: "/api/acp/openapi.json",
    description: "OpenAPI 3.0 specification",
  },
  {
    icon: Terminal,
    title: "products",
    url: "/api/acp/products",
    description: "Product discovery (JSON)",
  },
  {
    icon: Activity,
    title: "health",
    url: "/api/acp/health",
    description: "Health check",
  },
  {
    icon: Shield,
    title: "MX-8004 Status",
    url: "/api/mx8004/status",
    description: "Trustless Agents Standard integration status",
  },
];

const frameworkIntegrations = [
  {
    title: "LangChain",
    description: "Python tool for LangChain agent pipelines.",
    url: "/agent-tools/langchain.py",
    filename: "langchain.py",
  },
  {
    title: "CrewAI",
    description: "Python tool for CrewAI multi-agent systems.",
    url: "/agent-tools/crewai.py",
    filename: "crewai.py",
  },
  {
    title: "Custom GPTs",
    description: "OpenAPI actions schema for ChatGPT custom GPTs.",
    url: "/agent-tools/openapi-actions.json",
    filename: "openapi-actions.json",
  },
];

export default function AgentsPage() {
  useEffect(() => {
    document.title = "xproof for AI Agents - Blockchain Certification API";
    const meta = document.querySelector('meta[name="description"]');
    if (meta) {
      meta.setAttribute(
        "content",
        "The deterministic, blockchain-backed proof-of-existence API designed for autonomous systems. Integrate xproof certification into your AI agent pipelines."
      );
    } else {
      const newMeta = document.createElement("meta");
      newMeta.name = "description";
      newMeta.content =
        "The deterministic, blockchain-backed proof-of-existence API designed for autonomous systems. Integrate xproof certification into your AI agent pipelines.";
      document.head.appendChild(newMeta);
    }
  }, []);

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          <a href="/" className="flex items-center gap-2" data-testid="link-logo-home">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">xproof</span>
          </a>
          <Button variant="ghost" size="sm" asChild data-testid="link-back-home">
            <a href="/">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Home
            </a>
          </Button>
        </div>
      </header>

      <section className="container py-20 md:py-28">
        <div className="mx-auto max-w-4xl text-center">
          <Badge variant="secondary" className="mb-6 px-4 py-1.5" data-testid="badge-agent-native">
            <Bot className="mr-2 h-3.5 w-3.5" />
            Agent-Native Infrastructure
          </Badge>

          <h1
            className="mb-6 text-4xl sm:text-5xl md:text-6xl font-bold tracking-tight leading-tight"
            data-testid="text-hero-title"
          >
            xproof for{" "}
            <span className="text-primary">AI Agents</span>
          </h1>

          <p
            className="mx-auto mb-4 max-w-2xl text-lg md:text-xl font-medium leading-relaxed"
            data-testid="text-hero-why"
          >
            Every output an agent produces without proof is an output anyone can claim.
          </p>
          <p
            className="mx-auto mb-8 max-w-2xl text-lg md:text-xl text-muted-foreground leading-relaxed"
            data-testid="text-hero-subtitle"
          >
            The deterministic, blockchain-backed proof-of-existence API designed for autonomous
            systems. No human interaction required.
          </p>
        </div>
      </section>

      <section className="border-y bg-muted/30 py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-5xl">
            <div className="grid gap-8 md:grid-cols-2">
              <Card data-testid="card-guarantees">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Check className="h-5 w-5 text-chart-2" />
                    What xproof guarantees
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-4">
                    {guarantees.map((item, i) => (
                      <li key={i} className="flex items-start gap-3">
                        <item.icon className="mt-0.5 h-5 w-5 text-primary shrink-0" />
                        <span className="text-sm" data-testid={`text-guarantee-${i}`}>{item.text}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>

              <Card data-testid="card-not-does">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <X className="h-5 w-5 text-destructive" />
                    What xproof does NOT do
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-4">
                    {notDoes.map((item, i) => (
                      <li key={i} className="flex items-start gap-3">
                        <X className="mt-0.5 h-4 w-4 text-muted-foreground shrink-0" />
                        <span className="text-sm" data-testid={`text-not-does-${i}`}>{item}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      <section className="py-20 md:py-28" id="quick-start">
        <div className="container">
          <div className="mx-auto max-w-4xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">
                <Terminal className="mr-2 h-3.5 w-3.5" />
                Quick Start
              </Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold" data-testid="text-quickstart-title">
                3 API calls to certify
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                No SDK required. Standard HTTP requests with JSON payloads.
              </p>
            </div>

            <div className="space-y-8">
              {steps.map((step) => (
                <div key={step.number} data-testid={`card-step-${step.number}`}>
                  <div className="flex items-center gap-4 mb-4">
                    <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary text-lg font-bold text-primary-foreground shrink-0">
                      {step.number}
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold">{step.title}</h3>
                      <p className="text-sm text-muted-foreground">{step.description}</p>
                    </div>
                  </div>
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-start gap-2">
                        <pre className="flex-1 overflow-x-auto text-sm font-mono whitespace-pre-wrap break-all" data-testid={`code-step-${step.number}`}>
                          {step.code}
                        </pre>
                        <CopyButton text={step.code} testId={`button-copy-step-${step.number}`} />
                      </div>
                    </CardContent>
                  </Card>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="py-20 md:py-28" id="proof-object">
        <div className="container">
          <div className="mx-auto max-w-4xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">
                <Hash className="mr-2 h-3.5 w-3.5" />
                Standard
              </Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold" data-testid="text-proof-object-title">
                Canonical Proof Object
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Every proof follows a stable, versioned schema with a universally addressable identifier.
              </p>
            </div>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-start justify-between gap-2 mb-4">
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary">v2.0</Badge>
                    <span className="text-sm text-muted-foreground">Proof Object Schema</span>
                  </div>
                  <CopyButton text={`{
  "canonical_id": "xproof:mvx:mainnet:tx:f376c0...",
  "id": "uuid",
  "type": "proof_of_existence",
  "version": "2.0",
  "confidence": "cryptographically-certified",
  "file_name": "document.pdf",
  "file_hash": "sha256-hex-string",
  "hash_algorithm": "SHA-256",
  "timestamp_utc": "2025-01-01T00:00:00Z",
  "blockchain": {
    "network": "MultiversX Mainnet",
    "chain_id": "1",
    "transaction_hash": "hex-string",
    "explorer_url": "https://explorer.multiversx.com/transactions/..."
  }
}`} testId="button-copy-proof-schema" />
                </div>
                <pre className="overflow-x-auto text-sm font-mono whitespace-pre-wrap break-all" data-testid="code-proof-schema">{`{
  "canonical_id": "xproof:mvx:mainnet:tx:f376c0...",  // null if pending
  "id": "uuid",
  "type": "proof_of_existence",
  "version": "2.0",
  "confidence": "cryptographically-certified",        // or "pending"
  "file_name": "document.pdf",
  "file_hash": "sha256-hex-string",
  "hash_algorithm": "SHA-256",
  "timestamp_utc": "2025-01-01T00:00:00Z",
  "blockchain": {
    "network": "MultiversX Mainnet",
    "chain_id": "1",
    "transaction_hash": "hex-string",
    "explorer_url": "https://explorer.multiversx.com/transactions/..."
  }
}`}</pre>
              </CardContent>
            </Card>

            <div className="mt-10 grid gap-6 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Canonical Identifier</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <code className="block text-sm font-mono break-all whitespace-pre-wrap bg-muted p-3 rounded-md" data-testid="code-canonical-format">xproof:mvx:{'{network}'}:tx:{'{transaction_hash}'}</code>
                  <ul className="space-y-1 text-sm text-muted-foreground">
                    <li><code className="text-xs font-mono bg-muted px-1 py-0.5 rounded">xproof</code> Protocol prefix</li>
                    <li><code className="text-xs font-mono bg-muted px-1 py-0.5 rounded">mvx</code> MultiversX blockchain</li>
                    <li><code className="text-xs font-mono bg-muted px-1 py-0.5 rounded">mainnet</code> Network (mainnet / devnet / testnet)</li>
                    <li><code className="text-xs font-mono bg-muted px-1 py-0.5 rounded">tx:hash</code> On-chain transaction hash</li>
                  </ul>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Confidence Levels</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-start gap-3">
                    <Badge variant="default" className="shrink-0 mt-0.5">certified</Badge>
                    <div>
                      <p className="text-sm font-medium">cryptographically-certified</p>
                      <p className="text-xs text-muted-foreground">Transaction confirmed on-chain. Immutable and independently verifiable.</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <Badge variant="secondary" className="shrink-0 mt-0.5">pending</Badge>
                    <div>
                      <p className="text-sm font-medium">pending</p>
                      <p className="text-xs text-muted-foreground">Certification initiated but not yet anchored on blockchain.</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            <div className="mt-8 text-center">
              <p className="text-sm text-muted-foreground">
                Live example:{" "}
                <a
                  href="/genesis.proof.json"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-medium text-primary hover:underline"
                  data-testid="link-genesis-proof"
                >
                  genesis.proof.json
                </a>
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="border-y bg-muted/30 py-20 md:py-28" id="discovery">
        <div className="container">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">
                <Globe className="mr-2 h-3.5 w-3.5" />
                Discovery
              </Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold" data-testid="text-discovery-title">
                Discovery Endpoints
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Standard machine-readable manifests for automated integration.
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {discoveryEndpoints.map((ep, i) => (
                <a
                  key={i}
                  href={ep.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  data-testid={`link-endpoint-${i}`}
                >
                  <Card className="h-full hover-elevate">
                    <CardContent className="p-4 space-y-2">
                      <div className="flex items-center gap-2">
                        <ep.icon className="h-4 w-4 text-primary shrink-0" />
                        <span className="text-sm font-semibold truncate">{ep.title}</span>
                      </div>
                      <p className="text-xs font-mono text-muted-foreground break-all">{ep.url}</p>
                      <p className="text-xs text-muted-foreground">{ep.description}</p>
                    </CardContent>
                  </Card>
                </a>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="py-20 md:py-28" id="integrations">
        <div className="container">
          <div className="mx-auto max-w-4xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">
                <Code className="mr-2 h-3.5 w-3.5" />
                Integrations
              </Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold" data-testid="text-integrations-title">
                Framework Integrations
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Drop-in tools for popular agent frameworks.
              </p>
            </div>

            <div className="grid gap-6 md:grid-cols-3">
              {frameworkIntegrations.map((fw, i) => (
                <Card key={i} data-testid={`card-integration-${i}`}>
                  <CardHeader>
                    <CardTitle className="text-lg">{fw.title}</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-sm text-muted-foreground">{fw.description}</p>
                    <a href={fw.url} download data-testid={`link-download-${i}`}>
                      <Button variant="outline" className="w-full">
                        <Download className="mr-2 h-4 w-4" />
                        {fw.filename}
                      </Button>
                    </a>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </div>
      </section>

      <footer className="border-t py-12">
        <div className="container">
          <div className="flex flex-col items-center gap-4 text-center">
            <p className="text-sm text-muted-foreground">
              Built on{" "}
              <a
                href="https://multiversx.com"
                target="_blank"
                rel="noopener noreferrer"
                className="font-medium text-primary hover:underline"
                data-testid="link-multiversx"
              >
                MultiversX
              </a>
              {" | "}
              <a
                href="https://agents.multiversx.com"
                target="_blank"
                rel="noopener noreferrer"
                className="font-medium text-primary hover:underline"
                data-testid="link-agents-explorer"
              >
                MX-8004 Explorer
              </a>
            </p>
            <a
              href="/"
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
              data-testid="link-footer-home"
            >
              <ExternalLink className="mr-1 inline h-3 w-3" />
              xproof.app
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

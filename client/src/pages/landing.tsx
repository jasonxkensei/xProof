import { useState, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { hashFile } from "@/lib/hashFile";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { 
  Shield, 
  Wallet, 
  CheckCircle,
  Upload,
  ArrowRight,
  Blocks,
  CreditCard,
  ShoppingCart,
  Award,
  Bot,
  Cog,
  BarChart3,
  Copy,
  Loader2,
  Key,
  File,
  ExternalLink
} from "lucide-react";
import { WalletLoginModal } from "@/components/wallet-login-modal";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

export default function Landing() {
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
  const { data: pricing } = useQuery<{
    current_price_usd: number;
    total_certifications: number;
    current_tier: { min: number; max: number | null; price_usd: number };
    next_tier: { min: number; max: number | null; price_usd: number } | null;
    certifications_until_next_tier: number | null;
  }>({
    queryKey: ["/api/pricing"],
  });
  const price = pricing ? `$${pricing.current_price_usd}` : "$0.05";

  const [agentName, setAgentName] = useState("");
  const [trialKey, setTrialKey] = useState<string | null>(null);
  const [trialAgentName, setTrialAgentName] = useState<string>("");
  const [copied, setCopied] = useState(false);
  const [trialError, setTrialError] = useState<string | null>(null);

  const registerMutation = useMutation({
    mutationFn: async (name: string) => {
      const res = await fetch("/api/agent/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: name }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || "Registration failed. Please try a different name.");
      return data;
    },
    onSuccess: (data, name) => {
      setTrialKey(data.api_key);
      setTrialAgentName(name);
      setTrialError(null);
    },
    onError: (err: Error) => {
      setTrialError(err.message);
    },
  });

  const handleCopyKey = () => {
    if (!trialKey) return;
    navigator.clipboard.writeText(trialKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleConnect = () => {
    setIsLoginModalOpen(true);
  };

  // — Live proof widget state —
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [proofFile, setProofFile] = useState<File | null>(null);
  const [proofHash, setProofHash] = useState<string>("");
  const [isHashing, setIsHashing] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [proofResult, setProofResult] = useState<{
    proof_id?: string | number;
    verify_url?: string;
    blockchain?: { transaction_hash?: string; explorer_url?: string };
    trial?: { remaining?: number };
  } | null>(null);
  const [proofError, setProofError] = useState<string | null>(null);

  const handleFileSelect = async (file: File) => {
    setProofFile(file);
    setProofResult(null);
    setProofError(null);
    setIsHashing(true);
    try {
      const h = await hashFile(file);
      setProofHash(h);
    } finally {
      setIsHashing(false);
    }
  };

  const submitProofMutation = useMutation({
    mutationFn: async ({ hash, filename }: { hash: string; filename: string }) => {
      const res = await fetch("/api/proof", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${trialKey}`,
        },
        body: JSON.stringify({ file_hash: hash, filename }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || data.error || "Proof submission failed. Please try again.");
      return data;
    },
    onSuccess: (data) => {
      setProofResult(data);
      setProofError(null);
    },
    onError: (err: Error) => {
      setProofError(err.message);
    },
  });

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          <a href="/" className="flex items-center gap-2" data-testid="link-logo-home">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">xproof</span>
          </a>
          <nav className="hidden md:flex items-center gap-6">
            <a href="#how-it-works" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" data-testid="link-nav-how-it-works">
              How it works
            </a>
            <a href="/leaderboard" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" data-testid="link-nav-leaderboard">
              Leaderboard
            </a>
            <a href="/stats" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" data-testid="link-nav-metrics">
              Metrics
            </a>
            <a href="/docs" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" data-testid="link-nav-docs">
              Docs
            </a>
            <a href="#faq" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" data-testid="link-nav-faq">
              FAQ
            </a>
          </nav>
          <div className="flex items-center gap-3">
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={handleConnect}
              data-testid="button-login"
            >
              <Wallet className="mr-2 h-4 w-4" />
              Connect
            </Button>
          </div>
        </div>
      </header>
      {/* Hero Section */}
      <section className="container pt-10 pb-20 md:pt-14 md:pb-28">
        <div className="mx-auto max-w-5xl text-center">
          <Badge variant="secondary" className="mb-6 px-4 py-1.5">
            <Shield className="mr-2 h-3.5 w-3.5" />
            The on-chain notary for AI agents
          </Badge>
          
          <h1 className="mb-6 text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight leading-tight">
            Trust is
            <br />
            <span className="text-primary">programmable.</span>
          </h1>
          
          <p className="mx-auto mb-8 max-w-2xl text-lg md:text-xl text-muted-foreground leading-relaxed">Anchor verifiable proofs of what your agent saw, decided, and produced — on-chain, composable, API-first.</p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button 
              size="lg" 
              className="text-base h-12 px-8" 
              onClick={handleConnect}
              data-testid="button-certify-file"
            >
              <Upload className="mr-2 h-5 w-5" />
              Submit a proof
            </Button>
            <Button 
              asChild 
              variant="outline" 
              size="lg" 
              className="text-base h-12 px-8"
              data-testid="button-free-trial-hero"
            >
              <a href="#free-trial">
                <Bot className="mr-2 h-4 w-4" />
                10 free proofs — no wallet
              </a>
            </Button>
          </div>
          
          <p className="mt-12 text-sm text-muted-foreground">{price} per proof • Unlimited</p>

          {pricing && pricing.next_tier && pricing.current_tier.max !== null && (
            <div className="mt-3 mx-auto w-full max-w-[15rem] text-center" data-testid="tier-progress">
              <div className="mb-2 flex items-center justify-between gap-2 text-xs text-muted-foreground">
                <span data-testid="text-tier-current">
                  <span className="font-medium text-foreground">
                    {pricing.total_certifications.toLocaleString("en-US")}
                  </span>{" "}
                  / {pricing.current_tier.max.toLocaleString("en-US")} certifications
                </span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-md bg-muted">
                <div
                  className="h-full bg-primary transition-all"
                  style={{
                    width: `${Math.min(
                      100,
                      Math.max(
                        1,
                        (pricing.total_certifications / pricing.current_tier.max) * 100,
                      ),
                    )}%`,
                  }}
                  data-testid="bar-tier-progress"
                />
              </div>
              <p className="mt-2 text-xs text-muted-foreground whitespace-nowrap" data-testid="text-tier-next">
                Next tier: ${pricing.next_tier.price_usd}/cert after{" "}
                {pricing.current_tier.max.toLocaleString("en-US")} certifications
              </p>
            </div>
          )}
        </div>
      </section>
      {/* Free Trial — Interactive Registration */}
      <section id="free-trial" className="border-y bg-muted/30 py-16 md:py-20">
        <div className="container">
          <div className="mx-auto max-w-2xl text-center">
            <Badge variant="secondary" className="mb-4 px-3 py-1">
              <Key className="mr-2 h-3.5 w-3.5" />
              Free Trial — No wallet needed
            </Badge>
            <h2 className="mb-3 text-2xl md:text-3xl font-bold">
              10 free proofs. Start in 30 seconds.
            </h2>
            <p className="mb-8 text-muted-foreground max-w-xl mx-auto">
              Register your agent or project — get a <code className="text-xs bg-muted px-1.5 py-0.5 rounded font-mono">pm_</code> API key instantly. No wallet, no credit card.
            </p>

            {!trialKey ? (
              <div className="max-w-md mx-auto">
                <div className="flex flex-col sm:flex-row gap-3">
                  <Input
                    placeholder="Agent name (e.g. my-agent)"
                    value={agentName}
                    onChange={(e) => setAgentName(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && agentName.trim().length >= 2) {
                        registerMutation.mutate(agentName.trim());
                      }
                    }}
                    data-testid="input-trial-agent-name"
                    className="flex-1"
                  />
                  <Button
                    onClick={() => registerMutation.mutate(agentName.trim())}
                    disabled={agentName.trim().length < 2 || registerMutation.isPending}
                    data-testid="button-register-trial"
                  >
                    {registerMutation.isPending ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Registering...
                      </>
                    ) : (
                      <>
                        Get my key
                        <ArrowRight className="ml-2 h-4 w-4" />
                      </>
                    )}
                  </Button>
                </div>
                {trialError && (
                  <p className="mt-3 text-sm text-destructive text-left" data-testid="text-trial-error">
                    {trialError}
                  </p>
                )}
                <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
                  {["10 free proofs", "No wallet needed", "No credit card", "Claim to wallet anytime"].map((label) => (
                    <Badge key={label} variant="outline" className="text-xs">
                      {label}
                    </Badge>
                  ))}
                </div>
              </div>
            ) : (
              <div className="max-w-lg mx-auto">
                {/* Key display */}
                <div className="mb-2 flex items-center gap-2 rounded-md bg-primary/10 border border-primary/20 p-3 font-mono text-sm">
                  <span className="flex-1 text-left truncate text-primary font-medium" data-testid="text-trial-key">{trialKey}</span>
                  <Button size="icon" variant="ghost" onClick={handleCopyKey} data-testid="button-copy-trial-key">
                    {copied ? <CheckCircle className="h-4 w-4 text-primary" /> : <Copy className="h-4 w-4" />}
                  </Button>
                </div>
                <p className="text-sm text-muted-foreground mb-5">
                  Your key is ready — 10 free proofs for <strong>{trialAgentName}</strong>. Try one right now:
                </p>

                {/* Live proof widget */}
                {!proofResult ? (
                  <>
                    {/* Drop zone */}
                    <div
                      data-testid="dropzone-proof"
                      className={`border-2 border-dashed rounded-md p-7 text-center cursor-pointer transition-colors select-none ${isDragging ? "border-primary bg-primary/5" : "border-muted-foreground/30 hover:border-primary/40"}`}
                      onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                      onDragLeave={() => setIsDragging(false)}
                      onDrop={(e) => {
                        e.preventDefault();
                        setIsDragging(false);
                        const f = e.dataTransfer.files[0];
                        if (f) handleFileSelect(f);
                      }}
                      onClick={() => fileInputRef.current?.click()}
                    >
                      <input
                        ref={fileInputRef}
                        type="file"
                        className="hidden"
                        data-testid="input-proof-file"
                        onChange={(e) => {
                          const f = e.target.files?.[0];
                          if (f) handleFileSelect(f);
                        }}
                      />
                      {!proofFile ? (
                        <>
                          <Upload className="h-7 w-7 text-muted-foreground/50 mx-auto mb-3" />
                          <p className="text-sm font-medium text-muted-foreground">Drag any file here, or click to select</p>
                          <p className="text-xs text-muted-foreground/60 mt-1">Your file never leaves your device — only its fingerprint is sent</p>
                        </>
                      ) : (
                        <div className="flex items-center gap-3 justify-center">
                          <File className="h-6 w-6 text-primary shrink-0" />
                          <div className="text-left min-w-0">
                            <p className="text-sm font-medium truncate max-w-xs">{proofFile.name}</p>
                            {isHashing ? (
                              <p className="text-xs text-muted-foreground flex items-center gap-1 mt-0.5">
                                <Loader2 className="h-3 w-3 animate-spin" />
                                Computing fingerprint…
                              </p>
                            ) : (
                              <p className="text-xs text-muted-foreground font-mono mt-0.5">{proofHash.slice(0, 20)}…</p>
                            )}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Anchor button */}
                    {proofFile && !isHashing && (
                      <Button
                        className="w-full mt-3"
                        onClick={() => submitProofMutation.mutate({ hash: proofHash, filename: proofFile.name })}
                        disabled={submitProofMutation.isPending}
                        data-testid="button-anchor-proof"
                      >
                        {submitProofMutation.isPending ? (
                          <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Anchoring to blockchain…</>
                        ) : (
                          <><Shield className="mr-2 h-4 w-4" />Anchor this proof</>
                        )}
                      </Button>
                    )}

                    {proofError && (
                      <p className="mt-2 text-sm text-destructive text-left" data-testid="text-proof-error">{proofError}</p>
                    )}
                  </>
                ) : (
                  /* Success state */
                  <div className="rounded-md bg-primary/10 border border-primary/20 p-5 text-left" data-testid="card-proof-result">
                    <div className="flex items-center gap-2 mb-3">
                      <CheckCircle className="h-5 w-5 text-primary shrink-0" />
                      <p className="text-sm font-semibold text-primary">Proof anchored on MultiversX!</p>
                    </div>
                    <div className="space-y-1 mb-4">
                      <p className="text-xs text-muted-foreground">
                        File: <span className="font-medium text-foreground">{proofFile?.name}</span>
                      </p>
                      <p className="text-xs text-muted-foreground font-mono">
                        SHA-256: {proofHash.slice(0, 24)}…
                      </p>
                      {proofResult.proof_id && (
                        <p className="text-xs text-muted-foreground">
                          Proof ID: <span className="font-mono">{proofResult.proof_id}</span>
                        </p>
                      )}
                      {proofResult.blockchain?.transaction_hash && (
                        <p className="text-xs text-muted-foreground font-mono">
                          Tx: {proofResult.blockchain.transaction_hash.slice(0, 20)}…
                        </p>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        asChild
                        size="sm"
                        variant="outline"
                        data-testid="button-view-proof"
                      >
                        <a
                          href={proofResult.verify_url || `/proof/${proofResult.proof_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <ExternalLink className="mr-1.5 h-3 w-3" />
                          View proof
                        </a>
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => { setProofFile(null); setProofHash(""); setProofResult(null); setProofError(null); }}
                        data-testid="button-proof-another"
                      >
                        Anchor another file
                      </Button>
                      {proofResult.trial?.remaining !== undefined && (
                        <Badge variant="outline" className="text-xs ml-auto">
                          {proofResult.trial.remaining} proof{proofResult.trial.remaining !== 1 ? "s" : ""} remaining
                        </Badge>
                      )}
                    </div>
                  </div>
                )}

                <div className="mt-5 flex flex-wrap gap-3 justify-center">
                  <Button asChild variant="outline" size="sm" data-testid="button-trial-docs">
                    <a href="/docs">
                      Full API docs
                      <ArrowRight className="ml-1 h-3 w-3" />
                    </a>
                  </Button>
                  <Button size="sm" onClick={handleConnect} data-testid="button-trial-connect-wallet">
                    <Wallet className="mr-2 h-3.5 w-3.5" />
                    Connect wallet to manage
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>
      {/* Quick Start for Developers/Agents */}
      <section className="py-16 md:py-20">
        <div className="container">
          <div className="mx-auto max-w-4xl">
            <div className="mb-10 text-center">
              <Badge variant="outline" className="mb-4">Quick Start</Badge>
              <h2 className="mb-3 text-2xl md:text-3xl font-bold">
                Integrate in minutes
              </h2>
              <p className="text-muted-foreground max-w-xl mx-auto">
                Three ways to start anchoring proofs, whether you're a developer, an AI agent, or a no-code user.
              </p>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              <Card data-testid="card-quickstart-api">
                <CardContent className="pt-6 pb-5">
                  <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
                    <Cog className="h-5 w-5 text-primary" />
                  </div>
                  <h3 className="font-semibold mb-2">REST API</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    POST a file hash to <code className="text-xs bg-muted px-1.5 py-0.5 rounded">/api/proof</code> with your API key. Get a blockchain-anchored proof in seconds.
                  </p>
                  <Button asChild variant="outline" size="sm" data-testid="button-quickstart-docs">
                    <a href="/docs">
                      Read the docs
                      <ArrowRight className="ml-1 h-3 w-3" />
                    </a>
                  </Button>
                </CardContent>
              </Card>

              <Card data-testid="card-quickstart-agent">
                <CardContent className="pt-6 pb-5">
                  <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
                    <Bot className="h-5 w-5 text-primary" />
                  </div>
                  <h3 className="font-semibold mb-2">AI Agent (MCP)</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Connect via Model Context Protocol. Your agent can anchor decisions, audit logs, and build trust autonomously.
                  </p>
                  <Button asChild variant="outline" size="sm" data-testid="button-quickstart-agents">
                    <a href="/agents">
                      Agent integrations
                      <ArrowRight className="ml-1 h-3 w-3" />
                    </a>
                  </Button>
                </CardContent>
              </Card>

              <Card data-testid="card-quickstart-ui">
                <CardContent className="pt-6 pb-5">
                  <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
                    <Upload className="h-5 w-5 text-primary" />
                  </div>
                  <h3 className="font-semibold mb-2">Web Interface</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Connect your wallet, drag a file, and get a verifiable proof. No code required.
                  </p>
                  <Button variant="outline" size="sm" onClick={handleConnect} data-testid="button-quickstart-connect">
                    Connect wallet
                    <ArrowRight className="ml-1 h-3 w-3" />
                  </Button>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" className="border-y bg-muted/30 py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">How it works</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                3 simple steps
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                No technical knowledge required. 
                If you can send an email, you can use xproof.
              </p>
            </div>
            
            <div className="grid gap-8 md:grid-cols-3">
              <div className="relative text-center md:text-left">
                <div className="mb-6 mx-auto md:mx-0 flex h-16 w-16 items-center justify-center rounded-full bg-primary text-2xl font-bold text-primary-foreground">
                  1
                </div>
                <h3 className="mb-3 text-xl font-semibold">Upload your file</h3>
                <p className="text-muted-foreground">
                  Drag any file: photo, document, music, code... 
                  Your file stays private, it is never uploaded.
                </p>
                <div className="hidden md:block absolute top-8 left-[calc(100%-20px)] w-[calc(100%-40px)]">
                  <ArrowRight className="h-6 w-6 text-muted-foreground/30" />
                </div>
              </div>

              <div className="relative text-center md:text-left">
                <div className="mb-6 mx-auto md:mx-0 flex h-16 w-16 items-center justify-center rounded-full bg-primary text-2xl font-bold text-primary-foreground">
                  2
                </div>
                <h3 className="mb-3 text-xl font-semibold">We compute the fingerprint</h3>
                <p className="text-muted-foreground">
                  A unique fingerprint (SHA-256 hash) is computed locally. 
                  It's like the DNA of your file.
                </p>
                <div className="hidden md:block absolute top-8 left-[calc(100%-20px)] w-[calc(100%-40px)]">
                  <ArrowRight className="h-6 w-6 text-muted-foreground/30" />
                </div>
              </div>

              <div className="text-center md:text-left">
                <div className="mb-6 mx-auto md:mx-0 flex h-16 w-16 items-center justify-center rounded-full bg-primary text-2xl font-bold text-primary-foreground">
                  3
                </div>
                <h3 className="mb-3 text-xl font-semibold">Engraved on the blockchain</h3>
                <p className="text-muted-foreground">
                  The fingerprint is permanently recorded on the blockchain. 
                  You receive a verifiable proof with a QR code.
                </p>
              </div>
            </div>

            <div className="mt-12 text-center">
              <Button 
                size="lg" 
                onClick={handleConnect}
                data-testid="button-try-now"
              >
                Try it now
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      </section>
      {/* Pricing */}
      <section id="pricing" className="border-y bg-muted/30 py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-3xl">
            <div className="mb-12 text-center">
              <Badge variant="outline" className="mb-4">Simple pricing</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                One price. No subscription.
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Pay only for what you use. No hidden fees, no commitment.
              </p>
            </div>
            
            <Card className="border-primary shadow-lg max-w-md mx-auto">
              <CardContent className="pt-8 pb-8">
                <div className="text-center mb-6">
                  <div className="mb-2">
                    <span className="text-5xl font-bold" data-testid="text-price">{price}</span>
                  </div>
                  <p className="text-muted-foreground">
                    per proof
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">Starting at {price} — price decreases as the network grows (all-time volume).</p>
                </div>
                <ul className="mb-8 space-y-3 text-sm">
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span><strong>Unlimited proofs</strong></span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span>Downloadable PDF proof</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span>Public verification page</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span>Verification QR code</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span>MultiversX blockchain</span>
                  </li>
                </ul>
                <Button 
                  className="w-full" 
                  size="lg"
                  onClick={handleConnect}
                  data-testid="button-start-now"
                >
                  Get started
                </Button>
              </CardContent>
            </Card>
            
            <p className="mt-8 text-center text-sm text-muted-foreground">Payment in $EGLD or USDC.</p>
          </div>
        </div>
      </section>
      {/* Universal Compatibility */}
      <section id="integrations" className="py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">Universal compatibility</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                Works everywhere agents work.
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                One proof layer, every protocol. From autonomous agents to CI/CD pipelines.
              </p>
            </div>
            
            <div className="grid gap-4 grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
              {[
                { icon: Blocks, name: "MCP", desc: "Model Context Protocol" },
                { icon: CreditCard, name: "x402", desc: "HTTP-native payments" },
                { icon: ShoppingCart, name: "ACP", desc: "Agent Commerce" },
                { icon: Award, name: "MX-8004", desc: "Trustless Agents" },
                { icon: Bot, name: "OpenClaw", desc: "Skill Marketplace" },
                { icon: Cog, name: "GitHub Action", desc: "CI/CD Pipeline" },
              ].map((item) => (
                <Card key={item.name} className="text-center">
                  <CardContent className="pt-6 pb-4">
                    <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
                      <item.icon className="h-5 w-5 text-primary" />
                    </div>
                    <p className="font-semibold text-sm" data-testid={`text-protocol-${item.name.toLowerCase().replace(/[^a-z0-9]/g, '')}`}>{item.name}</p>
                    <p className="text-xs text-muted-foreground mt-1">{item.desc}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
            
            <div className="mt-10 text-center">
              <Button asChild variant="outline" data-testid="button-view-integrations">
                <a href="/agents">
                  View all integrations
                  <ArrowRight className="ml-2 h-4 w-4" />
                </a>
              </Button>
            </div>
          </div>
        </div>
      </section>
      {/* x402 / Base Demo */}
      <section id="x402" className="border-y bg-muted/30 py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">Base Network · x402</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                Agents pay natively.<br className="hidden md:block" /> No signup, no API key.
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Any x402-compatible agent anchors proofs in one round-trip. $0.05 in USDC on Base. No account required.
              </p>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              {/* Step 1 */}
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-bold text-primary-foreground">1</div>
                  <h3 className="font-semibold">Submit proof</h3>
                </div>
                <p className="text-sm text-muted-foreground pl-11">Agent sends a POST with no credentials.</p>
                <div className="rounded-md bg-[#0d1117] p-4 font-mono text-xs text-[#e6edf3] overflow-x-auto" data-testid="code-x402-step1">
                  <div className="text-[#8b949e] mb-2"># No API key, no auth</div>
                  <div><span className="text-[#79c0ff]">POST</span> <span className="text-[#a5d6ff]">https://xproof.app/api/proof</span></div>
                  <div className="text-[#8b949e] mt-2 mb-1">Content-Type: application/json</div>
                  <div className="mt-1">{`{`}</div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"file_hash"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"sha256..."</span><span className="text-[#e6edf3]">,</span></div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"filename"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"report.pdf"</span></div>
                  <div>{`}`}</div>
                </div>
              </div>

              {/* Step 2 */}
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-bold text-primary-foreground">2</div>
                  <h3 className="font-semibold">Receive payment challenge</h3>
                </div>
                <p className="text-sm text-muted-foreground pl-11">xProof replies with payment terms on Base.</p>
                <div className="rounded-md bg-[#0d1117] p-4 font-mono text-xs text-[#e6edf3] overflow-x-auto" data-testid="code-x402-step2">
                  <div><span className="text-[#f85149]">HTTP 402</span> <span className="text-[#8b949e]">Payment Required</span></div>
                  <div className="mt-2">{`{`}</div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"x402Version"</span><span className="text-[#e6edf3]">: </span><span className="text-[#ffa657]">1</span><span className="text-[#e6edf3]">,</span></div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"accepts"</span><span className="text-[#e6edf3]">: [{`{`}</span></div>
                  <div className="pl-8"><span className="text-[#79c0ff]">"price"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"$0.05"</span><span className="text-[#e6edf3]">,</span></div>
                  <div className="pl-8"><span className="text-[#79c0ff]">"network"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"eip155:8453"</span><span className="text-[#e6edf3]">,</span></div>
                  <div className="pl-8"><span className="text-[#79c0ff]">"asset"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"USDC"</span></div>
                  <div className="pl-4"><span className="text-[#e6edf3]">{`}]`}</span></div>
                  <div>{`}`}</div>
                </div>
              </div>

              {/* Step 3 */}
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-bold text-primary-foreground">3</div>
                  <h3 className="font-semibold">Pay & get proof</h3>
                </div>
                <p className="text-sm text-muted-foreground pl-11">Agent retries with payment receipt — gets blockchain proof.</p>
                <div className="rounded-md bg-[#0d1117] p-4 font-mono text-xs text-[#e6edf3] overflow-x-auto" data-testid="code-x402-step3">
                  <div className="text-[#8b949e] mb-2"># Retry with USDC payment</div>
                  <div><span className="text-[#79c0ff]">POST</span> <span className="text-[#a5d6ff]">https://xproof.app/api/proof</span></div>
                  <div className="text-[#8b949e] mt-2">X-Payment: <span className="text-[#e6edf3]">eyJ...</span></div>
                  <div className="mt-2 text-[#3fb950]">HTTP 200 OK</div>
                  <div className="mt-1">{`{`}</div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"proof_id"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"prf_..."</span><span className="text-[#e6edf3]">,</span></div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"tx_hash"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"0xab..."</span><span className="text-[#e6edf3]">,</span></div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"verify_url"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"xproof.app/..."</span></div>
                  <div>{`}`}</div>
                </div>
              </div>
            </div>

            <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
              {["USDC", "Base Mainnet", "eip155:8453", "No account needed", "$0.05 / proof"].map((label) => (
                <Badge key={label} variant="outline" className="text-xs font-mono" data-testid={`badge-x402-${label.toLowerCase().replace(/[^a-z0-9]/g, '-')}`}>{label}</Badge>
              ))}
            </div>

            <div className="mt-8 text-center">
              <Button asChild variant="outline" data-testid="button-x402-docs">
                <a href="/docs#x402">
                  Full x402 integration guide
                  <ArrowRight className="ml-2 h-4 w-4" />
                </a>
              </Button>
            </div>
          </div>
        </div>
      </section>


      {/* FAQ */}
      <section id="faq" className="py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-3xl">
            <div className="mb-12 text-center">
              <Badge variant="outline" className="mb-4">FAQ</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                Frequently asked questions
              </h2>
            </div>
            
            <Accordion type="single" collapsible className="w-full">
              <AccordionItem value="item-1">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-upload">
                  Is my file uploaded to your servers?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  No, never. Your file stays on your device. Only its "fingerprint" 
                  (a unique 64-character code) is computed locally and recorded on the blockchain. 
                  Your file remains 100% private.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-2">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-blockchain">
                  What is the MultiversX blockchain?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  MultiversX is a high-performance, eco-friendly European blockchain. 
                  Unlike Bitcoin, it consumes very little energy. It's a global public ledger, 
                  impossible to modify or delete, perfect for legal proofs.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-3">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-legal">
                  Does it have legal value?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  Yes. Blockchain timestamping is recognized in many jurisdictions as 
                  proof of prior existence. It proves that your file existed at a specific date, 
                  which is essential in intellectual property disputes.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-4">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-modify">
                  What happens if I modify my file?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  The slightest change (even a single pixel) generates a completely different fingerprint. 
                  This is what guarantees integrity: if someone modifies your file, 
                  it will no longer match the original proof.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-5">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-verify">
                  How can someone verify my proof?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  Each proof contains a QR code and a link to a public verification page. 
                  Anyone can scan the QR or visit the link to see the proof details 
                  and verify directly on the blockchain.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-6">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-wallet">
                  Why do I need a crypto wallet?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  The wallet is used to securely identify you and to sign 
                  your proofs. It works like an ultra-secure electronic signature. 
                  You can use the MultiversX DeFi Wallet browser extension.
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </div>
        </div>
      </section>
      {/* Final CTA */}
      <section className="border-t bg-primary/5 py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-3xl text-center">
            <h2 className="mb-4 text-3xl md:text-4xl font-bold">
              Start anchoring trust
            </h2>
            <p className="mb-8 text-lg text-muted-foreground">
              Verifiable proofs for developers, agents, and enterprises. {price} per proof.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Button
                asChild
                size="lg"
                className="text-base h-12 px-8"
                data-testid="button-final-cta-trial"
              >
                <a href="#free-trial">
                  <Key className="mr-2 h-5 w-5" />
                  Start free — no wallet
                </a>
              </Button>
              <Button 
                size="lg" 
                variant="outline"
                className="text-base h-12 px-8"
                onClick={handleConnect}
                data-testid="button-final-cta"
              >
                <Shield className="mr-2 h-5 w-5" />
                Connect wallet
              </Button>
            </div>
          </div>
        </div>
      </section>
      {/* Footer */}
      <footer className="border-t py-12">
        <div className="container">
          <div className="mx-auto max-w-5xl">
            <div className="grid gap-8 md:grid-cols-4 mb-12">
              <div className="md:col-span-2">
                <div className="flex items-center gap-2 mb-4">
                  <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
                    <Shield className="h-5 w-5 text-primary-foreground" />
                  </div>
                  <span className="text-xl font-bold">xproof</span>
                </div>
                <p className="text-sm text-muted-foreground max-w-xs">
                  The on-chain notary for AI agents. Verifiable trust, anchored on MultiversX.
                </p>
              </div>
              
              <div>
                <h4 className="font-semibold mb-4">Product</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li><a href="#how-it-works" className="hover:text-foreground transition-colors">How it works</a></li>
                  <li><a href="#faq" className="hover:text-foreground transition-colors">FAQ</a></li>
                  <li><a href="/docs" className="hover:text-foreground transition-colors" data-testid="link-footer-docs">API Docs</a></li>
                  <li><a href="/agents" className="hover:text-foreground transition-colors" data-testid="link-footer-agents">For AI Agents</a></li>
                  <li><a href="/leaderboard" className="hover:text-foreground transition-colors" data-testid="link-footer-leaderboard">Trust Leaderboard</a></li>
                  <li><a href="/stats" className="hover:text-foreground transition-colors" data-testid="link-footer-stats">Metrics</a></li>
                </ul>
              </div>
              
              <div>
                <h4 className="font-semibold mb-4">Legal</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li><a href="/legal/mentions" className="hover:text-foreground transition-colors" data-testid="link-legal-mentions">Legal notices</a></li>
                  <li><a href="/legal/privacy" className="hover:text-foreground transition-colors" data-testid="link-legal-privacy">Privacy policy</a></li>
                  <li><a href="/legal/terms" className="hover:text-foreground transition-colors" data-testid="link-legal-terms">Terms</a></li>
                </ul>
              </div>
            </div>
            
            <div className="border-t pt-8 flex flex-col sm:flex-row items-center justify-between gap-4">
              <p className="text-sm text-muted-foreground">
                © {new Date().getFullYear()} xproof. All rights reserved.
              </p>
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <span>Powered by</span>
                <a 
                  href="https://multiversx.com" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="font-medium text-primary hover:underline"
                >
                  MultiversX
                </a>
              </div>
            </div>
          </div>
        </div>
      </footer>
      <WalletLoginModal 
        open={isLoginModalOpen} 
        onOpenChange={setIsLoginModalOpen} 
      />
    </div>
  );
}

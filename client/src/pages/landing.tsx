import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Shield, 
  Wallet, 
  CheckCircle,
  Upload,
  ArrowRight,
  Play,
  Blocks,
  CreditCard,
  ShoppingCart,
  Award,
  Bot,
  Cog,
  BarChart3
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
  const { data: pricing } = useQuery<{ current_price_usd: number }>({
    queryKey: ["/api/pricing"],
  });
  const price = pricing ? `$${pricing.current_price_usd}` : "$0.05";

  const handleConnect = () => {
    setIsLoginModalOpen(true);
  };

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
      <section className="container py-20 md:py-28">
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
              Certify a file
            </Button>
            <Button 
              asChild 
              variant="outline" 
              size="lg" 
              className="text-base h-12 px-8"
              data-testid="button-see-demo"
            >
              <a href="#how-it-works">
                <Play className="mr-2 h-4 w-4" />
                See how it works
              </a>
            </Button>
          </div>
          
          <p className="mt-6 text-sm text-muted-foreground">{price} per certification • Unlimited</p>
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
                    Connect via Model Context Protocol. Your agent can certify outputs, audit logs, and build trust autonomously.
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
                    Connect your wallet, drag a file, and get a verifiable certificate. No code required.
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
                  You receive a PDF certificate with a QR code.
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
                    per certification
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">Starting at {price} — price decreases as the network grows (all-time volume).</p>
                </div>
                <ul className="mb-8 space-y-3 text-sm">
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span><strong>Unlimited certifications</strong></span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span>Downloadable PDF certificate</span>
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
                Any x402-compatible agent certifies in one round-trip. $0.05 in USDC on Base. No account required.
              </p>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              {/* Step 1 */}
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-bold text-primary-foreground">1</div>
                  <h3 className="font-semibold">Request certification</h3>
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
              {["USDC", "Base Mainnet", "eip155:8453", "No account needed", "$0.05 / cert"].map((label) => (
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

      {/* API Key Flow */}
      <section id="api-key" className="py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">API Key · Prepaid</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                For high-volume agents.<br className="hidden md:block" /> Register once, certify forever.
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Get an API key with 10 free certifications. No wallet needed to start. Top up with USDC on Base or EGLD when ready.
              </p>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              {/* Step 1 */}
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-bold text-primary-foreground">1</div>
                  <h3 className="font-semibold">Register your agent</h3>
                </div>
                <p className="text-sm text-muted-foreground pl-11">One POST, get an API key and 10 free certs.</p>
                <div className="rounded-md bg-[#0d1117] p-4 font-mono text-xs text-[#e6edf3] overflow-x-auto" data-testid="code-apikey-step1">
                  <div><span className="text-[#79c0ff]">POST</span> <span className="text-[#a5d6ff]">https://xproof.app/api/agent/register</span></div>
                  <div className="text-[#8b949e] mt-2 mb-1">Content-Type: application/json</div>
                  <div className="mt-1">{`{`}</div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"agent_name"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"my-agent"</span></div>
                  <div>{`}`}</div>
                  <div className="mt-2 text-[#3fb950]">HTTP 200 OK</div>
                  <div className="mt-1">{`{`}</div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"api_key"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"pm_abc123..."</span><span className="text-[#e6edf3]">,</span></div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"trial_quota"</span><span className="text-[#e6edf3]">: </span><span className="text-[#ffa657]">10</span></div>
                  <div>{`}`}</div>
                </div>
              </div>

              {/* Step 2 */}
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-bold text-primary-foreground">2</div>
                  <h3 className="font-semibold">Certify with your key</h3>
                </div>
                <p className="text-sm text-muted-foreground pl-11">Add your API key as a Bearer token.</p>
                <div className="rounded-md bg-[#0d1117] p-4 font-mono text-xs text-[#e6edf3] overflow-x-auto" data-testid="code-apikey-step2">
                  <div><span className="text-[#79c0ff]">POST</span> <span className="text-[#a5d6ff]">https://xproof.app/api/proof</span></div>
                  <div className="text-[#8b949e] mt-2">Authorization: Bearer <span className="text-[#e6edf3]">pm_abc123...</span></div>
                  <div className="text-[#8b949e] mt-1 mb-1">Content-Type: application/json</div>
                  <div className="mt-1">{`{`}</div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"file_hash"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"sha256..."</span><span className="text-[#e6edf3]">,</span></div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"filename"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"report.pdf"</span></div>
                  <div>{`}`}</div>
                </div>
              </div>

              {/* Step 3 */}
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-bold text-primary-foreground">3</div>
                  <h3 className="font-semibold">Get blockchain proof</h3>
                </div>
                <p className="text-sm text-muted-foreground pl-11">Same response, same on-chain anchoring.</p>
                <div className="rounded-md bg-[#0d1117] p-4 font-mono text-xs text-[#e6edf3] overflow-x-auto" data-testid="code-apikey-step3">
                  <div className="text-[#3fb950]">HTTP 200 OK</div>
                  <div className="mt-1">{`{`}</div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"proof_id"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"prf_..."</span><span className="text-[#e6edf3]">,</span></div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"tx_hash"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"0xab..."</span><span className="text-[#e6edf3]">,</span></div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"verify_url"</span><span className="text-[#e6edf3]">: </span><span className="text-[#a5d6ff]">"xproof.app/..."</span><span className="text-[#e6edf3]">,</span></div>
                  <div className="pl-4"><span className="text-[#79c0ff]">"trial_remaining"</span><span className="text-[#e6edf3]">: </span><span className="text-[#ffa657]">9</span></div>
                  <div>{`}`}</div>
                </div>
              </div>
            </div>

            <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
              {["10 free certs", "No wallet needed", "pm_ API key", "Top up anytime", "USDC or EGLD"].map((label) => (
                <Badge key={label} variant="outline" className="text-xs font-mono" data-testid={`badge-apikey-${label.toLowerCase().replace(/[^a-z0-9]/g, '-')}`}>{label}</Badge>
              ))}
            </div>

            <div className="mt-8 text-center">
              <Button asChild variant="outline" data-testid="button-apikey-docs">
                <a href="/docs">
                  Full API documentation
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
                  it will no longer match the original certificate.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-5">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-verify">
                  How can someone verify my certificate?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  Each certificate contains a QR code and a link to a public verification page. 
                  Anyone can scan the QR or visit the link to see the certification details 
                  and verify directly on the blockchain.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-6">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-wallet">
                  Why do I need a crypto wallet?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  The wallet is used to securely identify you and to sign 
                  your certifications. It works like an ultra-secure electronic signature. 
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
            <Button 
              size="lg" 
              className="text-base h-12 px-8"
              onClick={handleConnect}
              data-testid="button-final-cta"
            >
              <Shield className="mr-2 h-5 w-5" />
              Get started
            </Button>
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

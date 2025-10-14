import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Shield, Zap, FileCheck, Lock, Globe, Award, Wallet } from "lucide-react";
import { Link } from "wouter";
import { useXPortalAuth } from "@/contexts/XPortalAuthContext";

export default function Landing() {
  const { connectWallet, isConnecting } = useXPortalAuth();

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between px-6">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">ProofMint</span>
          </div>
          <nav className="hidden md:flex items-center gap-6">
            <a href="#features" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
              Features
            </a>
            <a href="#how-it-works" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
              How it works
            </a>
            <a href="#pricing" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
              Pricing
            </a>
          </nav>
          <div className="flex items-center gap-3">
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={connectWallet}
              disabled={isConnecting}
              data-testid="button-login"
            >
              <Wallet className="mr-2 h-4 w-4" />
              {isConnecting ? "Connecting..." : "Connect Wallet"}
            </Button>
            <Button 
              size="sm" 
              onClick={connectWallet}
              disabled={isConnecting}
              data-testid="button-get-started"
            >
              {isConnecting ? "Connecting..." : "Get Started"}
            </Button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="container px-6 py-24 md:py-32">
        <div className="mx-auto max-w-5xl text-center">
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/5 px-4 py-1.5 text-sm text-primary">
            <Shield className="h-4 w-4" />
            <span className="font-medium">Powered by MultiversX Truth Machine</span>
          </div>
          <h1 className="mb-6 text-5xl md:text-7xl font-bold tracking-tight">
            Certify what you create.
            <br />
            <span className="text-primary">In one click.</span>
          </h1>
          <p className="mx-auto mb-8 max-w-2xl text-lg md:text-xl text-muted-foreground">
            ProofMint secures your file's digital fingerprint on the MultiversX blockchain. 
            Get an immutable, verifiable proof of ownership—no coding required.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button 
              size="lg" 
              className="text-base" 
              onClick={connectWallet}
              disabled={isConnecting}
              data-testid="button-start-free"
            >
              <Wallet className="mr-2 h-5 w-5" />
              {isConnecting ? "Connecting..." : "Certify Your First File Free"}
            </Button>
            <Button asChild variant="outline" size="lg" className="text-base" data-testid="button-learn-more">
              <a href="#how-it-works">Learn How It Works</a>
            </Button>
          </div>
          <p className="mt-6 text-sm text-muted-foreground">
            No credit card required • 1 free certification per month
          </p>
        </div>
      </section>

      {/* Benefits Grid */}
      <section id="features" className="border-t bg-muted/30 py-24">
        <div className="container px-6">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">Why ProofMint?</h2>
              <p className="text-lg text-muted-foreground">Blockchain-secured proof of ownership made simple</p>
            </div>
            <div className="grid gap-8 md:grid-cols-3">
              <Card className="border-border/50">
                <CardContent className="pt-6">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                    <Lock className="h-6 w-6 text-primary" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold">Immutable Proof</h3>
                  <p className="text-muted-foreground">
                    Your file's hash is permanently recorded on the MultiversX blockchain, creating an unforgeable timestamp.
                  </p>
                </CardContent>
              </Card>

              <Card className="border-border/50">
                <CardContent className="pt-6">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                    <Zap className="h-6 w-6 text-primary" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold">Instant Certification</h3>
                  <p className="text-muted-foreground">
                    Upload your file, and get your blockchain certificate in seconds. No complex setup required.
                  </p>
                </CardContent>
              </Card>

              <Card className="border-border/50">
                <CardContent className="pt-6">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                    <Globe className="h-6 w-6 text-primary" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold">Public Verification</h3>
                  <p className="text-muted-foreground">
                    Share your proof page with anyone. They can verify authenticity on the blockchain explorer.
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" className="py-24">
        <div className="container px-6">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">How It Works</h2>
              <p className="text-lg text-muted-foreground">Three simple steps to blockchain certification</p>
            </div>
            <div className="grid gap-12 md:grid-cols-3">
              <div className="relative">
                <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary text-2xl font-bold text-primary-foreground">
                  1
                </div>
                <h3 className="mb-2 text-xl font-semibold">Upload Your File</h3>
                <p className="text-muted-foreground">
                  Drag and drop any file—images, documents, audio, or video. We compute a unique SHA-256 hash locally.
                </p>
              </div>

              <div className="relative">
                <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary text-2xl font-bold text-primary-foreground">
                  2
                </div>
                <h3 className="mb-2 text-xl font-semibold">Blockchain Recording</h3>
                <p className="text-muted-foreground">
                  Your file's hash is securely written to the MultiversX blockchain, creating an immutable timestamp.
                </p>
              </div>

              <div className="relative">
                <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary text-2xl font-bold text-primary-foreground">
                  3
                </div>
                <h3 className="mb-2 text-xl font-semibold">Get Your Certificate</h3>
                <p className="text-muted-foreground">
                  Download a PDF certificate with QR code and share your public proof page for verification.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Use Cases */}
      <section className="border-t bg-muted/30 py-24">
        <div className="container px-6">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">Trusted by Creators & Professionals</h2>
              <p className="text-lg text-muted-foreground">From designers to lawyers, ProofMint protects what matters</p>
            </div>
            <div className="grid gap-6 md:grid-cols-2">
              <Card className="border-border/50">
                <CardContent className="pt-6">
                  <FileCheck className="mb-3 h-8 w-8 text-primary" />
                  <h3 className="mb-2 text-lg font-semibold">Designers & Artists</h3>
                  <p className="text-sm text-muted-foreground">
                    Prove ownership of your creative work before sharing with clients or publishing online.
                  </p>
                </CardContent>
              </Card>

              <Card className="border-border/50">
                <CardContent className="pt-6">
                  <Award className="mb-3 h-8 w-8 text-primary" />
                  <h3 className="mb-2 text-lg font-semibold">Legal Professionals</h3>
                  <p className="text-sm text-muted-foreground">
                    Timestamp contracts, evidence, and legal documents with blockchain-verified authenticity.
                  </p>
                </CardContent>
              </Card>

              <Card className="border-border/50">
                <CardContent className="pt-6">
                  <Globe className="mb-3 h-8 w-8 text-primary" />
                  <h3 className="mb-2 text-lg font-semibold">Freelancers</h3>
                  <p className="text-sm text-muted-foreground">
                    Protect your deliverables and maintain proof of work completion with verifiable timestamps.
                  </p>
                </CardContent>
              </Card>

              <Card className="border-border/50">
                <CardContent className="pt-6">
                  <Shield className="mb-3 h-8 w-8 text-primary" />
                  <h3 className="mb-2 text-lg font-semibold">Agencies & Businesses</h3>
                  <p className="text-sm text-muted-foreground">
                    Certify client deliverables and internal documents with custom branding and API integration.
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing Preview */}
      <section id="pricing" className="py-24">
        <div className="container px-6">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">Simple, Transparent Pricing</h2>
              <p className="text-lg text-muted-foreground">Choose the plan that fits your needs</p>
            </div>
            <div className="grid gap-8 md:grid-cols-3">
              <Card className="border-border/50">
                <CardContent className="pt-6">
                  <h3 className="mb-2 text-2xl font-bold">Free</h3>
                  <div className="mb-4">
                    <span className="text-4xl font-bold">$0</span>
                    <span className="text-muted-foreground">/month</span>
                  </div>
                  <ul className="mb-6 space-y-2 text-sm">
                    <li className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                      <span>1 certification per month</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                      <span>ProofMint watermark</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                      <span>Public verification page</span>
                    </li>
                  </ul>
                  <Button 
                    variant="outline" 
                    className="w-full" 
                    onClick={connectWallet}
                    disabled={isConnecting}
                    data-testid="button-start-free-tier"
                  >
                    {isConnecting ? "Connecting..." : "Get Started"}
                  </Button>
                </CardContent>
              </Card>

              <Card className="border-primary shadow-lg shadow-primary/20">
                <CardContent className="pt-6">
                  <div className="mb-2 inline-block rounded-full bg-primary px-3 py-1 text-xs font-medium text-primary-foreground">
                    Most Popular
                  </div>
                  <h3 className="mb-2 text-2xl font-bold">Pro</h3>
                  <div className="mb-4">
                    <span className="text-4xl font-bold">$9.99</span>
                    <span className="text-muted-foreground">/month</span>
                  </div>
                  <ul className="mb-6 space-y-2 text-sm">
                    <li className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                      <span>20 certifications per month</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                      <span>No watermark</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                      <span>Priority support</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                      <span>Custom branding</span>
                    </li>
                  </ul>
                  <Button 
                    className="w-full" 
                    onClick={connectWallet}
                    disabled={isConnecting}
                    data-testid="button-start-pro"
                  >
                    {isConnecting ? "Connecting..." : "Start Pro Trial"}
                  </Button>
                </CardContent>
              </Card>

              <Card className="border-border/50">
                <CardContent className="pt-6">
                  <h3 className="mb-2 text-2xl font-bold">Business</h3>
                  <div className="mb-4">
                    <span className="text-4xl font-bold">$39</span>
                    <span className="text-muted-foreground">/month</span>
                  </div>
                  <ul className="mb-6 space-y-2 text-sm">
                    <li className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                      <span>200 certifications per month</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                      <span>API access</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                      <span>Custom branding</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                      <span>Dedicated support</span>
                    </li>
                  </ul>
                  <Button 
                    variant="outline" 
                    className="w-full" 
                    onClick={connectWallet}
                    disabled={isConnecting}
                    data-testid="button-start-business"
                  >
                    {isConnecting ? "Connecting..." : "Start Business Trial"}
                  </Button>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t bg-muted/30 py-12">
        <div className="container px-6">
          <div className="mx-auto max-w-5xl">
            <div className="mb-8 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
                  <Shield className="h-5 w-5 text-primary-foreground" />
                </div>
                <span className="text-xl font-bold">ProofMint</span>
              </div>
              <p className="text-sm text-muted-foreground">
                Powered by MultiversX
              </p>
            </div>
            <div className="border-t pt-8 text-center text-sm text-muted-foreground">
              <p>© 2024 ProofMint. All rights reserved.</p>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

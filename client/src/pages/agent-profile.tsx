import { useParams, Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  ExternalLink,
  Copy,
  CheckCircle2,
  Clock,
  XCircle,
  ArrowLeft,
  Globe,
  TrendingUp,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { formatDistanceToNow, format } from "date-fns";
import { useState } from "react";

interface AgentProfile {
  walletAddress: string;
  agentName: string | null;
  agentCategory: string | null;
  agentDescription: string | null;
  agentWebsite: string | null;
  score: number;
  level: string;
  certTotal: number;
  certLast30d: number;
  firstCertAt: string | null;
  lastCertAt: string | null;
  recentCertifications: {
    id: string;
    fileName: string;
    blockchainStatus: string | null;
    createdAt: string | null;
  }[];
}

const TRUST_LEVEL_STYLES: Record<string, { badge: string }> = {
  Verified:  { badge: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30" },
  Trusted:   { badge: "bg-green-500/15 text-green-700 dark:text-green-400 border-green-500/30" },
  Active:    { badge: "bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30" },
  Newcomer:  { badge: "bg-muted text-muted-foreground border-border" },
};

const CATEGORY_LABELS: Record<string, string> = {
  trading: "Trading", data: "Data", content: "Content", code: "Code",
  research: "Research", assistant: "Assistant", other: "Other",
};

function StatusIcon({ status }: { status: string | null }) {
  if (status === "confirmed") return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />;
  if (status === "failed") return <XCircle className="h-3.5 w-3.5 text-destructive" />;
  return <Clock className="h-3.5 w-3.5 text-yellow-500" />;
}

export default function AgentProfilePage() {
  const params = useParams<{ wallet: string }>();
  const wallet = params.wallet;
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);

  const { data: agent, isLoading, isError } = useQuery<AgentProfile>({
    queryKey: ["/api/agents", wallet],
    queryFn: () => fetch(`/api/agents/${wallet}`).then((r) => {
      if (!r.ok) throw new Error("Not found");
      return r.json();
    }),
    retry: false,
  });

  function copyWallet() {
    navigator.clipboard.writeText(wallet || "");
    setCopied(true);
    toast({ description: "Wallet address copied" });
    setTimeout(() => setCopied(false), 2000);
  }

  const confirmationRate = agent && agent.certTotal > 0
    ? Math.round((agent.recentCertifications.filter((c) => c.blockchainStatus === "confirmed").length / agent.recentCertifications.length) * 100)
    : null;

  const daysSinceFirst = agent?.firstCertAt
    ? Math.floor((Date.now() - new Date(agent.firstCertAt).getTime()) / (1000 * 60 * 60 * 24))
    : 0;

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          <Link href="/" data-testid="link-logo-home" className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">xproof</span>
          </Link>
          <Button asChild variant="ghost" size="sm" data-testid="button-back-leaderboard">
            <Link href="/leaderboard">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Leaderboard
            </Link>
          </Button>
        </div>
      </header>

      <div className="container mx-auto max-w-3xl py-12">
        {isLoading && (
          <div className="flex items-center justify-center py-20">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          </div>
        )}

        {(isError || (!isLoading && !agent)) && (
          <Card>
            <CardContent className="flex flex-col items-center gap-4 py-16">
              <Shield className="h-12 w-12 text-muted-foreground/40" />
              <div className="text-center">
                <p className="font-semibold">Profile not found</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  This agent hasn't made their profile public, or doesn't exist on xproof.
                </p>
              </div>
              <Button asChild variant="outline" data-testid="button-go-leaderboard">
                <Link href="/leaderboard">View leaderboard</Link>
              </Button>
            </CardContent>
          </Card>
        )}

        {agent && (
          <div className="space-y-6">
            {/* Hero card */}
            <Card data-testid="card-agent-hero">
              <CardContent className="pt-6">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <h1 className="text-2xl font-bold" data-testid="text-agent-name">
                        {agent.agentName || `Agent ${agent.walletAddress.slice(0, 10)}…`}
                      </h1>
                      {agent.agentCategory && (
                        <Badge variant="secondary" data-testid="badge-category">
                          {CATEGORY_LABELS[agent.agentCategory] ?? agent.agentCategory}
                        </Badge>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <span
                        data-testid="text-wallet-address"
                        className="font-mono text-sm text-muted-foreground"
                      >
                        {agent.walletAddress.slice(0, 12)}…{agent.walletAddress.slice(-8)}
                      </span>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={copyWallet}
                        data-testid="button-copy-wallet"
                      >
                        {copied ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </Button>
                    </div>

                    {agent.agentDescription && (
                      <p className="max-w-md text-sm text-muted-foreground" data-testid="text-agent-description">
                        {agent.agentDescription}
                      </p>
                    )}

                    {agent.agentWebsite && (
                      <a
                        href={agent.agentWebsite}
                        target="_blank"
                        rel="noopener noreferrer"
                        data-testid="link-agent-website"
                        className="inline-flex items-center gap-1 text-sm text-primary hover:underline underline-offset-4"
                      >
                        <Globe className="h-3.5 w-3.5" />
                        {agent.agentWebsite.replace(/^https?:\/\//, "")}
                        <ExternalLink className="h-3 w-3 opacity-60" />
                      </a>
                    )}
                  </div>

                  <div className="flex flex-col items-end gap-2">
                    <div
                      data-testid="badge-trust-level"
                      className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-semibold ${TRUST_LEVEL_STYLES[agent.level]?.badge ?? TRUST_LEVEL_STYLES.Newcomer.badge}`}
                    >
                      {agent.level === "Verified" && <Shield className="h-4 w-4" />}
                      {agent.level}
                    </div>
                    <span className="text-xs text-muted-foreground" data-testid="text-trust-score">
                      Trust score: {agent.score}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Stats */}
            <div className="grid gap-4 sm:grid-cols-4">
              <Card data-testid="stat-cert-total">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="text-xs font-medium text-muted-foreground">Total certifications</CardTitle>
                  <CheckCircle2 className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold" data-testid="text-cert-total">{agent.certTotal}</div>
                  <p className="text-xs text-muted-foreground">confirmed on-chain</p>
                </CardContent>
              </Card>

              <Card data-testid="stat-cert-30d">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="text-xs font-medium text-muted-foreground">This month</CardTitle>
                  <TrendingUp className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold" data-testid="text-cert-30d">{agent.certLast30d}</div>
                  <p className="text-xs text-muted-foreground">last 30 days</p>
                </CardContent>
              </Card>

              <Card data-testid="stat-confirmation-rate">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="text-xs font-medium text-muted-foreground">Confirmation rate</CardTitle>
                  <Shield className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold" data-testid="text-confirmation-rate">
                    {confirmationRate !== null ? `${confirmationRate}%` : "—"}
                  </div>
                  <p className="text-xs text-muted-foreground">of recent certs</p>
                </CardContent>
              </Card>

              <Card data-testid="stat-seniority">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="text-xs font-medium text-muted-foreground">Seniority</CardTitle>
                  <Clock className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold" data-testid="text-seniority">{daysSinceFirst}</div>
                  <p className="text-xs text-muted-foreground">days on xproof</p>
                </CardContent>
              </Card>
            </div>

            {/* Recent certifications timeline */}
            <Card data-testid="card-recent-certs">
              <CardHeader>
                <CardTitle className="text-base">Recent certifications</CardTitle>
              </CardHeader>
              <CardContent>
                {agent.recentCertifications.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No certifications yet.</p>
                ) : (
                  <div className="space-y-0">
                    {agent.recentCertifications.map((cert, i) => (
                      <div
                        key={cert.id}
                        data-testid={`row-cert-${cert.id}`}
                        className={`flex items-center justify-between gap-4 py-3 ${i < agent.recentCertifications.length - 1 ? "border-b" : ""}`}
                      >
                        <div className="flex min-w-0 items-center gap-2">
                          <StatusIcon status={cert.blockchainStatus} />
                          <span className="truncate text-sm font-medium" title={cert.fileName}>
                            {cert.fileName}
                          </span>
                        </div>
                        <div className="flex shrink-0 items-center gap-3">
                          <span className="text-xs text-muted-foreground">
                            {cert.createdAt
                              ? formatDistanceToNow(new Date(cert.createdAt), { addSuffix: true })
                              : "—"}
                          </span>
                          <Button
                            asChild
                            size="sm"
                            variant="ghost"
                            data-testid={`link-cert-proof-${cert.id}`}
                          >
                            <a href={`/proof/${cert.id}`} target="_blank" rel="noopener noreferrer">
                              Proof
                              <ExternalLink className="ml-1 h-3 w-3" />
                            </a>
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}

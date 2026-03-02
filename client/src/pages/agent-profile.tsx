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
  Flame,
  Award,
  BadgeCheck,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { formatDistanceToNow } from "date-fns";
import { useState } from "react";

interface AttestationRecord {
  id: string;
  issuer_wallet: string;
  issuer_name: string;
  domain: string;
  standard: string;
  title: string;
  description: string | null;
  expires_at: string | null;
  created_at: string;
}

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
  streakWeeks: number;
  activeAttestations: number;
  firstCertAt: string | null;
  lastCertAt: string | null;
  recentCertifications: {
    id: string;
    fileName: string;
    blockchainStatus: string | null;
    createdAt: string | null;
  }[];
  attestations: AttestationRecord[];
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

const DOMAIN_STYLES: Record<string, { color: string; label: string }> = {
  healthcare: { color: "bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/25", label: "Healthcare" },
  finance:    { color: "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/25", label: "Finance" },
  legal:      { color: "bg-purple-500/10 text-purple-700 dark:text-purple-400 border-purple-500/25", label: "Legal" },
  security:   { color: "bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-500/25", label: "Security" },
  research:   { color: "bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border-cyan-500/25", label: "Research" },
  other:      { color: "bg-muted text-muted-foreground border-border", label: "Other" },
};

function StatusIcon({ status }: { status: string | null }) {
  if (status === "confirmed") return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />;
  if (status === "failed") return <XCircle className="h-3.5 w-3.5 text-destructive" />;
  return <Clock className="h-3.5 w-3.5 text-yellow-500" />;
}

function DomainBadge({ domain }: { domain: string }) {
  const style = DOMAIN_STYLES[domain] ?? DOMAIN_STYLES.other;
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${style.color}`}>
      {style.label}
    </span>
  );
}

interface TrustSnapshot {
  score: number;
  level: string;
  cert_total: number;
  active_attestations: number;
  snapshot_date: string;
}

function TrustSparkline({ snapshots }: { snapshots: TrustSnapshot[] }) {
  if (snapshots.length < 2) {
    return (
      <div className="flex h-16 items-center justify-center text-xs text-muted-foreground">
        Tracking starts today — data available tomorrow
      </div>
    );
  }

  const W = 320;
  const H = 56;
  const PAD = 4;
  const scores = snapshots.map((s) => s.score);
  const minScore = Math.min(...scores);
  const maxScore = Math.max(...scores);
  const range = maxScore - minScore || 1;

  const points = snapshots.map((s, i) => {
    const x = PAD + (i / (snapshots.length - 1)) * (W - PAD * 2);
    const y = H - PAD - ((s.score - minScore) / range) * (H - PAD * 2);
    return `${x},${y}`;
  });

  const areaPoints = [
    `${PAD},${H}`,
    ...points,
    `${W - PAD},${H}`,
  ].join(" ");

  const lastScore = scores[scores.length - 1];
  const firstScore = scores[0];
  const delta = lastScore - firstScore;

  return (
    <div className="space-y-1" data-testid="card-trust-sparkline">
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>90-day trend</span>
        <span className={delta >= 0 ? "text-emerald-500" : "text-destructive"}>
          {delta >= 0 ? "+" : ""}{delta} pts
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: 56 }}>
        <defs>
          <linearGradient id="sparkGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgb(16,185,129)" stopOpacity="0.25" />
            <stop offset="100%" stopColor="rgb(16,185,129)" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        <polygon points={areaPoints} fill="url(#sparkGrad)" />
        <polyline
          points={points.join(" ")}
          fill="none"
          stroke="rgb(16,185,129)"
          strokeWidth="1.5"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        {(() => {
          const last = points[points.length - 1].split(",");
          return (
            <circle
              cx={Number(last[0])}
              cy={Number(last[1])}
              r="3"
              fill="rgb(16,185,129)"
            />
          );
        })()}
      </svg>
      <div className="flex justify-between text-xs text-muted-foreground">
        <span>{snapshots[0]?.snapshot_date?.slice(0, 10)}</span>
        <span>{snapshots[snapshots.length - 1]?.snapshot_date?.slice(0, 10)}</span>
      </div>
    </div>
  );
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

  const { data: history } = useQuery<{ snapshots: TrustSnapshot[] }>({
    queryKey: ["/api/trust", wallet, "history"],
    queryFn: () => fetch(`/api/trust/${wallet}/history`).then((r) => r.json()),
    enabled: !!wallet,
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
                      {agent.attestations?.length > 0 && (
                        <span className="inline-flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400" data-testid="badge-attested">
                          <BadgeCheck className="h-3.5 w-3.5" />
                          {agent.attestations.length} attestation{agent.attestations.length > 1 ? "s" : ""}
                        </span>
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
                    {agent.activeAttestations > 0 && (
                      <span className="text-xs text-emerald-600 dark:text-emerald-400" data-testid="text-attestation-bonus">
                        +{Math.min(3, agent.activeAttestations) * 50} pts from attestations
                      </span>
                    )}
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

              <Card data-testid="stat-streak">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="text-xs font-medium text-muted-foreground">Streak</CardTitle>
                  <Flame className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="flex items-baseline gap-1">
                    <span className="text-2xl font-bold" data-testid="text-streak">{agent.streakWeeks}</span>
                    <span className="text-sm text-muted-foreground">weeks</span>
                  </div>
                  <p className="text-xs text-muted-foreground">consecutive activity</p>
                </CardContent>
              </Card>
            </div>

            {/* Trust Score Trend */}
            <Card data-testid="card-trust-history">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground flex items-center gap-2">
                  <TrendingUp className="h-4 w-4" />
                  Trust score history
                </CardTitle>
              </CardHeader>
              <CardContent>
                <TrustSparkline snapshots={history?.snapshots ?? []} />
              </CardContent>
            </Card>

            {/* Domain Attestations */}
            {agent.attestations?.length > 0 && (
              <Card data-testid="card-attestations">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <Award className="h-4 w-4 text-primary" />
                    Domain attestations
                    <span className="ml-auto text-xs font-normal text-muted-foreground">
                      +{Math.min(3, agent.attestations.length) * 50} trust pts
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {agent.attestations.map((att) => (
                      <div
                        key={att.id}
                        data-testid={`card-attestation-${att.id}`}
                        className="rounded-md border bg-muted/30 p-4"
                      >
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <div className="space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <BadgeCheck className="h-4 w-4 text-emerald-500" />
                              <span className="font-medium text-sm" data-testid={`text-attestation-title-${att.id}`}>
                                {att.title}
                              </span>
                            </div>
                            <div className="flex flex-wrap items-center gap-2">
                              <DomainBadge domain={att.domain} />
                              <span className="font-mono text-xs text-muted-foreground">{att.standard}</span>
                            </div>
                            {att.description && (
                              <p className="text-xs text-muted-foreground mt-1">{att.description}</p>
                            )}
                          </div>
                          <div className="text-right shrink-0">
                            <Link
                              href={`/issuer/${att.issuer_wallet}`}
                              data-testid={`link-issuer-${att.id}`}
                              className="text-xs font-medium hover:underline underline-offset-2 text-primary"
                            >
                              {att.issuer_name}
                            </Link>
                            <p className="font-mono text-xs text-muted-foreground">
                              {att.issuer_wallet.slice(0, 8)}…{att.issuer_wallet.slice(-6)}
                            </p>
                          </div>
                        </div>
                        <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                          <span>Issued {formatDistanceToNow(new Date(att.created_at), { addSuffix: true })}</span>
                          {att.expires_at && (
                            <span>· Expires {formatDistanceToNow(new Date(att.expires_at), { addSuffix: true })}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

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

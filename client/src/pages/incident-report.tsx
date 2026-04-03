import { useQuery } from "@tanstack/react-query";
import { useParams } from "wouter";
import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Shield,
  ExternalLink,
  CheckCircle,
  XCircle,
  Clock,
  User,
  Hash,
  Brain,
  ArrowLeft,
  Layers,
  AlertTriangle,
  Copy,
  Check,
  Search,
  Activity,
  TrendingUp,
  FileText,
  Link2,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  Zap,
} from "lucide-react";

function CopyInline({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="icon"
      variant="ghost"
      className="shrink-0"
      onClick={() => { navigator.clipboard.writeText(text).catch(() => {}); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      data-testid="button-copy-inline"
    >
      {copied ? <Check className="h-3 w-3 text-primary" /> : <Copy className="h-3 w-3" />}
    </Button>
  );
}

function VerdictBanner({ verdict }: { verdict: any }) {
  if (!verdict) return null;

  const config: Record<string, { icon: typeof ShieldCheck; bg: string; border: string; text: string; badge: string }> = {
    clean: {
      icon: ShieldCheck,
      bg: "bg-green-500/5 dark:bg-green-500/10",
      border: "border-green-500/20",
      text: "text-green-700 dark:text-green-400",
      badge: "text-green-700 dark:text-green-300 border-green-500/30 bg-green-500/10",
    },
    anomaly: {
      icon: ShieldAlert,
      bg: "bg-red-500/5 dark:bg-red-500/10",
      border: "border-red-500/20",
      text: "text-red-700 dark:text-red-400",
      badge: "text-red-700 dark:text-red-300 border-red-500/30 bg-red-500/10",
    },
    incomplete: {
      icon: ShieldQuestion,
      bg: "bg-yellow-500/5 dark:bg-yellow-500/10",
      border: "border-yellow-500/20",
      text: "text-yellow-700 dark:text-yellow-400",
      badge: "text-yellow-700 dark:text-yellow-300 border-yellow-500/30 bg-yellow-500/10",
    },
  };

  const c = config[verdict.status] || config.incomplete;
  const Icon = c.icon;

  return (
    <div className={`rounded-md border ${c.border} ${c.bg} p-5 mb-8`} data-testid="verdict-banner">
      <div className="flex items-start gap-4">
        <div className={`flex h-10 w-10 items-center justify-center rounded-full ${c.bg} border ${c.border} shrink-0`}>
          <Icon className={`h-5 w-5 ${c.text}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap mb-1">
            <h2 className={`text-lg font-semibold ${c.text}`} data-testid="text-verdict-label">{verdict.label}</h2>
            <Badge variant="outline" className={`text-[10px] font-mono ${c.badge}`}>
              {verdict.checks_passed}/{verdict.checks_total} passed
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground" data-testid="text-verdict-detail">{verdict.detail}</p>
        </div>
      </div>
    </div>
  );
}

function CheckRow({ pass, label }: { pass: boolean | null; label: string }) {
  if (pass === null) return null;
  return (
    <div className="flex items-center gap-2.5 py-1">
      {pass ? (
        <CheckCircle className="h-4 w-4 text-green-500 dark:text-green-400 shrink-0" />
      ) : (
        <XCircle className="h-4 w-4 text-red-500 dark:text-red-400 shrink-0" />
      )}
      <span className={`text-sm ${pass ? "" : "text-red-600 dark:text-red-400 font-medium"}`} data-testid={`verification-${label.toLowerCase().replace(/\s+/g, '-')}`}>{label}</span>
    </div>
  );
}

function RoleBadge({ role }: { role: string }) {
  const config: Record<string, { label: string; variant: "default" | "secondary" | "outline" }> = {
    WHY: { label: "WHY", variant: "default" },
    WHAT: { label: "WHAT", variant: "secondary" },
    heartbeat: { label: "HEARTBEAT", variant: "outline" },
    contested: { label: "CONTESTED", variant: "outline" },
  };
  const c = config[role] || { label: role, variant: "outline" as const };
  return <Badge variant={c.variant} className="text-[10px] font-mono uppercase" data-testid={`badge-role-${role.toLowerCase()}`}>{c.label}</Badge>;
}

function TrustCard({ trust, agent }: { trust: any; agent: any }) {
  if (!trust) return null;

  const levelColors: Record<string, string> = {
    Verified: "text-green-600 dark:text-green-400",
    Trusted: "text-green-600 dark:text-green-400",
    Active: "text-blue-600 dark:text-blue-400",
    Newcomer: "text-muted-foreground",
  };

  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-3">Trust Score</p>
        <div className="flex items-baseline gap-2 mb-2">
          <span className="text-2xl font-bold tabular-nums" data-testid="text-trust-score">{trust.score}</span>
          <Badge variant="outline" className={`text-[10px] font-mono ${levelColors[trust.level] || ""}`} data-testid="text-trust-level">{trust.level}</Badge>
        </div>
        <div className="space-y-1 text-xs text-muted-foreground">
          <div className="flex items-center justify-between gap-2">
            <span>Total certifications</span>
            <span className="font-mono tabular-nums">{trust.cert_total}</span>
          </div>
          <div className="flex items-center justify-between gap-2">
            <span>Active streak</span>
            <span className="font-mono tabular-nums">{trust.streak_weeks}w</span>
          </div>
          {trust.violation_penalty < 0 && (
            <div className="flex items-center justify-between gap-2 text-amber-600 dark:text-amber-400">
              <span>Audit impact</span>
              <span className="font-mono tabular-nums">{trust.violation_penalty}</span>
            </div>
          )}
          {(trust.violations.fault > 0 || trust.violations.breach > 0) && (
            <div className="flex items-center justify-between gap-2 text-amber-600 dark:text-amber-400">
              <span className="whitespace-nowrap">Audit flags</span>
              <span className="font-mono tabular-nums whitespace-nowrap">{trust.violations.fault} fault / {trust.violations.breach} breach</span>
            </div>
          )}
        </div>
        <a
          href={`/agent/${agent.wallet || ""}`}
          className="text-xs text-primary hover:underline mt-2 inline-block"
          data-testid="link-agent-profile"
        >
          View full profile
        </a>
      </CardContent>
    </Card>
  );
}

function SummaryCard({ summary }: { summary: any }) {
  if (!summary) return null;

  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-3">Proof Summary</p>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <span className="text-2xl font-bold tabular-nums" data-testid="text-why-count">{summary.why_count}</span>
            <p className="text-xs text-muted-foreground">WHY proofs</p>
          </div>
          <div>
            <span className="text-2xl font-bold tabular-nums" data-testid="text-what-count">{summary.what_count}</span>
            <p className="text-xs text-muted-foreground">WHAT proofs</p>
          </div>
          <div>
            <span className="text-2xl font-bold tabular-nums" data-testid="text-confirmed-count">{summary.confirmed_proofs}</span>
            <p className="text-xs text-muted-foreground">Confirmed</p>
          </div>
          <div>
            <span className="text-2xl font-bold tabular-nums" data-testid="text-total-proofs">{summary.total_proofs}</span>
            <p className="text-xs text-muted-foreground">Total proofs</p>
          </div>
        </div>
        {summary.time_span && (
          <div className="mt-3 pt-3 border-t text-xs text-muted-foreground">
            <div className="flex items-center gap-2">
              <Clock className="h-3 w-3 shrink-0" />
              <span>Span: {formatDuration(summary.time_span.duration_sec)}</span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function TimelineEntry({ entry, isLast }: { entry: any; isLast: boolean }) {
  const meta = entry.metadata || {};
  const isWhy = entry.role === "WHY";
  const decisionChain = meta.decision_chain && Array.isArray(meta.decision_chain) && meta.decision_chain.length > 0;
  const rulesApplied = meta.rules_applied && Array.isArray(meta.rules_applied) && meta.rules_applied.length > 0;

  return (
    <div className="relative flex gap-4" data-testid={`timeline-entry-${entry.proof_id}`}>
      <div className="flex flex-col items-center">
        <div className={`flex h-8 w-8 items-center justify-center rounded-full border-2 shrink-0 ${
          isWhy ? "border-primary bg-primary/10" : "border-muted-foreground/30 bg-muted/50"
        }`}>
          {isWhy ? <Brain className="h-3.5 w-3.5 text-primary" /> : <Zap className="h-3.5 w-3.5 text-muted-foreground" />}
        </div>
        {!isLast && <div className="w-px flex-1 bg-border mt-2" />}
      </div>

      <Card className="flex-1 mb-4">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 flex-wrap mb-3">
            <RoleBadge role={entry.role} />
            <Badge variant="outline" className="text-[10px] font-mono">{entry.action_type}</Badge>
            {entry.blockchain_status === "confirmed" && (
              <Badge variant="outline" className="text-[10px] text-green-600 dark:text-green-400 border-green-500/30">confirmed</Badge>
            )}
          </div>

          <div className="space-y-2 text-sm">
            {meta.target_author && (
              <div className="flex items-center gap-2">
                <User className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground">Target:</span>
                <span className="font-medium" data-testid="text-target-author">{meta.target_author}</span>
              </div>
            )}

            {meta.content_preview && (
              <div className="rounded-md bg-muted/50 p-3 text-xs text-muted-foreground italic" data-testid="text-content-preview">
                {meta.content_preview}
              </div>
            )}

            {decisionChain && (
              <div className="mt-3">
                <div className="flex items-center gap-2 mb-2">
                  <FileText className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Decision Chain</p>
                </div>
                <div className="space-y-1.5 ml-5">
                  {meta.decision_chain.map((step: string, i: number) => (
                    <p key={i} className="text-xs text-muted-foreground pl-3 border-l-2 border-primary/30" data-testid={`text-decision-step-${i}`}>
                      {step}
                    </p>
                  ))}
                </div>
              </div>
            )}

            {rulesApplied && (
              <div className="mt-2">
                <div className="flex items-center gap-2 mb-1.5">
                  <Shield className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Rules Applied</p>
                </div>
                <div className="flex flex-wrap gap-1 ml-5">
                  {meta.rules_applied.map((rule: string, i: number) => (
                    <Badge key={i} variant="outline" className="text-[10px]">{rule}</Badge>
                  ))}
                </div>
              </div>
            )}

            <div className="border-t pt-3 mt-3 space-y-1.5">
              <div className="flex items-center gap-2 text-xs">
                <Clock className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground">Certified:</span>
                <span className="font-mono" data-testid="text-certified-at">{formatTimestamp(entry.certified_at)}</span>
              </div>

              <div className="flex items-center gap-2 text-xs">
                <Hash className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground">Hash:</span>
                <span className="font-mono truncate" data-testid="text-file-hash">{entry.file_hash}</span>
                <CopyInline text={entry.file_hash} />
              </div>

              {entry.transaction_hash && (
                <div className="flex items-center gap-2 text-xs">
                  <Link2 className="h-3 w-3 text-muted-foreground shrink-0" />
                  <span className="text-muted-foreground">Tx:</span>
                  <a
                    href={entry.explorer_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-primary hover:underline truncate"
                    data-testid="link-explorer"
                  >
                    {entry.transaction_hash.slice(0, 16)}...
                  </a>
                  <ExternalLink className="h-3 w-3 text-muted-foreground shrink-0" />
                </div>
              )}

              <div className="flex items-center gap-2 text-xs">
                <Search className="h-3 w-3 text-muted-foreground shrink-0" />
                <a
                  href={entry.verify_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline"
                  data-testid="link-verify"
                >
                  Verify independently
                </a>
              </div>
            </div>

            {meta.prompt_hash && (
              <div className="flex items-center gap-2 text-xs mt-1">
                <span className="text-muted-foreground">Prompt hash:</span>
                <span className="font-mono truncate">{meta.prompt_hash}</span>
                <CopyInline text={meta.prompt_hash} />
              </div>
            )}

            {meta.content_hash && (
              <div className="flex items-center gap-2 text-xs mt-1">
                <span className="text-muted-foreground">Content hash:</span>
                <span className="font-mono truncate">{meta.content_hash}</span>
                <CopyInline text={meta.content_hash} />
              </div>
            )}

            {meta.trigger_content_hash && (
              <div className="flex items-center gap-2 text-xs mt-1">
                <span className="text-muted-foreground">Trigger hash:</span>
                <span className="font-mono truncate">{meta.trigger_content_hash}</span>
                <CopyInline text={meta.trigger_content_hash} />
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function SessionBlock({ session, wallet, currentProofId }: { session: any; wallet: string; currentProofId: string }) {
  if (!session) return null;
  const isCurrentProof = session.proof_id === currentProofId;

  return (
    <div className="relative flex gap-4" data-testid="timeline-session">
      <div className="flex flex-col items-center">
        <div className="flex h-8 w-8 items-center justify-center rounded-full border-2 border-muted-foreground/30 bg-muted/50 shrink-0">
          <Layers className="h-3.5 w-3.5 text-muted-foreground" />
        </div>
      </div>
      <Card className="flex-1 mb-4">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 flex-wrap mb-3">
            <RoleBadge role="heartbeat" />
            <Badge variant="outline" className="text-[10px] font-mono">
              {session.certified_actions_in_session != null
                ? `${session.certified_actions_in_session}/${session.total_actions_in_session} certified`
                : `${session.total_actions_in_session} actions`}
            </Badge>
            {session.karma != null && (
              <Badge variant="outline" className="text-[10px] font-mono">karma {session.karma}</Badge>
            )}
          </div>

          {session.session_summary && (
            <p className="text-sm text-muted-foreground mb-3" data-testid="text-session-summary">{session.session_summary}</p>
          )}

          <div className="space-y-1.5 text-xs">
            {session.session_timestamp && (
              <div className="flex items-center gap-2">
                <Clock className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground">Session start:</span>
                <span className="font-mono">{formatTimestamp(session.session_timestamp)}</span>
              </div>
            )}

            {session.session_duration_sec != null && (
              <div className="flex items-center gap-2">
                <Activity className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground">Duration:</span>
                <span className="font-mono">{formatDuration(session.session_duration_sec)}</span>
              </div>
            )}

            {session.transaction_hash && (
              <div className="flex items-center gap-2">
                <Link2 className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground">Tx:</span>
                <a
                  href={`https://explorer.multiversx.com/transactions/${session.transaction_hash}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-primary hover:underline truncate"
                  data-testid="link-session-explorer"
                >
                  {session.transaction_hash.slice(0, 16)}...
                </a>
                <ExternalLink className="h-3 w-3 text-muted-foreground shrink-0" />
              </div>
            )}

            {!isCurrentProof && (
              <div className="flex items-center gap-2">
                <TrendingUp className="h-3 w-3 text-muted-foreground shrink-0" />
                <a
                  href={`/incident/${wallet}/${session.proof_id}`}
                  className="text-primary hover:underline font-medium"
                  data-testid="link-session-incident"
                >
                  View full session report
                </a>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function formatTimestamp(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function formatDuration(sec: number): string {
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m < 60) return s > 0 ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm > 0 ? `${h}h ${rm}m` : `${h}h`;
}

export default function IncidentReportPage() {
  const params = useParams<{ wallet: string; proofId: string }>();
  const wallet = params.wallet || "";
  const proofId = params.proofId || "";

  const { data, isLoading, error } = useQuery<any>({
    queryKey: ["/api/agents", wallet, "incident-report", proofId],
    queryFn: async () => {
      const res = await fetch(`/api/agents/${wallet}/incident-report?proof_id=${proofId}`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Request failed" }));
        throw new Error(err.error || "Failed to load incident report");
      }
      return res.json();
    },
    enabled: !!wallet && !!proofId,
  });

  if (!wallet || !proofId) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Card className="max-w-md">
          <CardContent className="p-6 text-center">
            <AlertTriangle className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
            <p className="text-muted-foreground">Missing wallet address or proof ID in URL.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-14 items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Button asChild variant="ghost" size="icon" data-testid="button-back">
              <a href="/"><ArrowLeft className="h-4 w-4" /></a>
            </Button>
            <a href="/" className="flex items-center gap-2" data-testid="link-logo">
              <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary">
                <Shield className="h-4 w-4 text-primary-foreground" />
              </div>
              <span className="text-lg font-bold tracking-tight">xproof</span>
            </a>
            <Badge variant="outline" className="text-xs">Incident Report</Badge>
          </div>
        </div>
      </header>

      <div className="container py-8 max-w-3xl mx-auto">
        {isLoading && (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <div className="animate-spin rounded-full h-8 w-8 border-2 border-primary border-t-transparent" />
            <p className="text-sm text-muted-foreground">Reconstructing audit trail...</p>
          </div>
        )}

        {error && (
          <Card>
            <CardContent className="p-6 text-center">
              <AlertTriangle className="h-8 w-8 text-destructive mx-auto mb-3" />
              <p className="font-medium mb-1">Report unavailable</p>
              <p className="text-sm text-muted-foreground">{(error as Error).message}</p>
            </CardContent>
          </Card>
        )}

        {data && (
          <>
            <div className="mb-6">
              <h1 className="text-2xl font-bold mb-1" data-testid="text-report-title">4W Incident Report</h1>
              <p className="text-sm text-muted-foreground">
                Generated {formatTimestamp(data.report_generated_at)} for proof{" "}
                <code className="text-primary text-xs font-mono">{proofId.slice(0, 8)}...</code>
                <CopyInline text={proofId} />
              </p>
            </div>

            <VerdictBanner verdict={data.verdict} />

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
              <Card>
                <CardContent className="p-4">
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-3">WHO</p>
                  <p className="font-medium text-sm" data-testid="text-agent-name">{data.agent.name || "Unknown Agent"}</p>
                  {data.agent.sigil_id && (
                    <p className="text-xs text-muted-foreground font-mono mt-1" data-testid="text-sigil-id">{data.agent.sigil_id}</p>
                  )}
                  <p className="text-xs text-muted-foreground font-mono mt-1 truncate" data-testid="text-wallet">{data.agent.wallet}</p>
                  <CopyInline text={data.agent.wallet} />
                </CardContent>
              </Card>

              <TrustCard trust={data.trust} agent={data.agent} />
              <SummaryCard summary={data.summary} />
            </div>

            <Card className="mb-8">
              <CardContent className="p-4">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-3">4W Verification Checks</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6">
                  <CheckRow pass={data.verification.intent_preceded_execution} label="Intent preceded execution (WHY before WHAT)" />
                  <CheckRow pass={data.verification.why_certified} label="WHY proof certified on-chain" />
                  <CheckRow pass={data.verification.what_certified} label="WHAT proof certified on-chain" />
                  <CheckRow pass={data.verification.session_anchored} label="Session heartbeat anchored" />
                  <CheckRow pass={data.verification.all_confirmed} label="All proofs blockchain-confirmed" />
                </div>
              </CardContent>
            </Card>

            <div className="mb-8">
              <div className="flex items-center gap-3 mb-4">
                <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/10 shrink-0">
                  <Clock className="h-4 w-4 text-primary" />
                </div>
                <h2 className="text-lg font-semibold">Action Timeline</h2>
                <Badge variant="outline" className="text-xs">
                  {data.timeline.length} proof{data.timeline.length !== 1 ? "s" : ""}
                </Badge>
              </div>

              <div className="pl-1">
                {data.timeline.map((entry: any, i: number) => (
                  <TimelineEntry
                    key={entry.proof_id}
                    entry={entry}
                    isLast={i === data.timeline.length - 1 && !data.session}
                  />
                ))}

                <SessionBlock session={data.session} wallet={wallet} currentProofId={proofId} />
              </div>
            </div>

            <footer className="border-t pt-6 text-center text-sm text-muted-foreground">
              <p>
                This report was generated from on-chain data anchored on{" "}
                <a href="https://multiversx.com" className="text-primary hover:underline" target="_blank" rel="noopener noreferrer">MultiversX</a>.
                Every proof is independently verifiable.
              </p>
              <p className="mt-2 text-xs">
                <a href="/docs/4w" className="text-primary hover:underline" data-testid="link-4w-docs">4W Framework</a>
                {" · "}
                <a href="/leaderboard" className="text-primary hover:underline" data-testid="link-leaderboard">Trust Leaderboard</a>
                {" · "}
                <a href={`/agents/${wallet}`} className="text-primary hover:underline" data-testid="link-agent-profile">Agent Profile</a>
                {" · "}
                <a href="/" className="text-primary hover:underline" data-testid="link-home">xproof.app</a>
              </p>
            </footer>
          </>
        )}
      </div>
    </div>
  );
}

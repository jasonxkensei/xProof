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
} from "lucide-react";

function CopyInline({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="icon"
      variant="ghost"
      className="h-5 w-5 shrink-0"
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      data-testid="button-copy-inline"
    >
      {copied ? <Check className="h-3 w-3 text-primary" /> : <Copy className="h-3 w-3" />}
    </Button>
  );
}

function VerificationBadge({ pass, label }: { pass: boolean | null; label: string }) {
  if (pass === null) return null;
  return (
    <div className="flex items-center gap-2">
      {pass ? (
        <CheckCircle className="h-4 w-4 text-green-500 dark:text-green-400 shrink-0" />
      ) : (
        <XCircle className="h-4 w-4 text-red-500 dark:text-red-400 shrink-0" />
      )}
      <span className="text-sm" data-testid={`verification-${label.toLowerCase().replace(/\s+/g, '-')}`}>{label}</span>
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
          {isWhy ? <Brain className="h-3.5 w-3.5 text-primary" /> : <Hash className="h-3.5 w-3.5 text-muted-foreground" />}
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
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Decision Chain</p>
                <div className="space-y-1.5">
                  {meta.decision_chain.map((step: string, i: number) => (
                    <p key={i} className="text-xs text-muted-foreground pl-2 border-l-2 border-primary/30" data-testid={`text-decision-step-${i}`}>
                      {step}
                    </p>
                  ))}
                </div>
              </div>
            )}

            {rulesApplied && (
              <div className="flex flex-wrap gap-1 mt-2">
                {meta.rules_applied.map((rule: string, i: number) => (
                  <Badge key={i} variant="outline" className="text-[10px]">{rule}</Badge>
                ))}
              </div>
            )}

            <div className="border-t pt-3 mt-3 space-y-1.5">
              <div className="flex items-center gap-2 text-xs">
                <Clock className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground">Certified:</span>
                <span className="font-mono" data-testid="text-certified-at">{new Date(entry.certified_at).toISOString()}</span>
              </div>

              <div className="flex items-center gap-2 text-xs">
                <Hash className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground">Hash:</span>
                <span className="font-mono truncate" data-testid="text-file-hash">{entry.file_hash}</span>
                <CopyInline text={entry.file_hash} />
              </div>

              <div className="flex items-center gap-2 text-xs">
                <Shield className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground">Tx:</span>
                <a
                  href={entry.explorer_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-primary hover:underline truncate"
                  data-testid="link-explorer"
                >
                  {entry.transaction_hash?.slice(0, 16)}...
                </a>
                <ExternalLink className="h-3 w-3 text-muted-foreground shrink-0" />
              </div>

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
          </div>
        </CardContent>
      </Card>
    </div>
  );
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
          <div className="flex items-center justify-center py-20">
            <div className="animate-spin rounded-full h-8 w-8 border-2 border-primary border-t-transparent" />
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
            <div className="mb-8">
              <h1 className="text-2xl font-bold mb-1" data-testid="text-report-title">4W Incident Report</h1>
              <p className="text-sm text-muted-foreground">
                Generated {new Date(data.report_generated_at).toLocaleString()} for proof <code className="text-primary text-xs">{proofId.slice(0, 8)}...</code>
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
              <Card>
                <CardContent className="p-4">
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Agent Identity</p>
                  <p className="font-medium text-sm" data-testid="text-agent-name">{data.agent.name || "Unknown"}</p>
                  {data.agent.sigil_id && (
                    <p className="text-xs text-muted-foreground font-mono mt-1" data-testid="text-sigil-id">{data.agent.sigil_id}</p>
                  )}
                  <p className="text-xs text-muted-foreground font-mono mt-1 truncate" data-testid="text-wallet">{data.agent.wallet}</p>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-4">
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Verification Summary</p>
                  <div className="space-y-1.5">
                    <VerificationBadge pass={data.verification.intent_preceded_execution} label="Intent preceded execution" />
                    <VerificationBadge pass={data.verification.why_certified} label="WHY certified" />
                    <VerificationBadge pass={data.verification.what_certified} label="WHAT certified" />
                    <VerificationBadge pass={data.verification.session_anchored} label="Session anchored" />
                    <VerificationBadge pass={data.verification.all_confirmed} label="All on-chain confirmed" />
                  </div>
                </CardContent>
              </Card>
            </div>

            <div className="mb-8">
              <div className="flex items-center gap-3 mb-4">
                <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/10 shrink-0">
                  <Clock className="h-4 w-4 text-primary" />
                </div>
                <h2 className="text-lg font-semibold">Action Timeline</h2>
                <Badge variant="outline" className="text-xs">{data.timeline.length} proof{data.timeline.length !== 1 ? "s" : ""}</Badge>
              </div>

              <div className="pl-1">
                {data.timeline.map((entry: any, i: number) => (
                  <TimelineEntry key={entry.proof_id} entry={entry} isLast={i === data.timeline.length - 1 && !data.session} />
                ))}

                {data.session && (
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
                          <Badge variant="outline" className="text-[10px] font-mono">{data.session.total_actions_in_session} actions in session</Badge>
                        </div>
                        {data.session.session_summary && (
                          <p className="text-sm text-muted-foreground mb-2" data-testid="text-session-summary">{data.session.session_summary}</p>
                        )}
                        <div className="space-y-1.5 text-xs">
                          <div className="flex items-center gap-2">
                            <Clock className="h-3 w-3 text-muted-foreground shrink-0" />
                            <span className="text-muted-foreground">Session:</span>
                            <span className="font-mono">{data.session.session_timestamp ? new Date(data.session.session_timestamp).toISOString() : "N/A"}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Shield className="h-3 w-3 text-muted-foreground shrink-0" />
                            <span className="text-muted-foreground">Tx:</span>
                            <a
                              href={`https://explorer.multiversx.com/transactions/${data.session.transaction_hash}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono text-primary hover:underline truncate"
                              data-testid="link-session-explorer"
                            >
                              {data.session.transaction_hash?.slice(0, 16)}...
                            </a>
                          </div>
                          <div className="flex items-center gap-2">
                            <Search className="h-3 w-3 text-muted-foreground shrink-0" />
                            <a
                              href={data.session.verify_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-primary hover:underline"
                              data-testid="link-session-verify"
                            >
                              Verify session heartbeat
                            </a>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                )}
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
                <a href="/" className="text-primary hover:underline" data-testid="link-home">xproof.app</a>
              </p>
            </footer>
          </>
        )}
      </div>
    </div>
  );
}

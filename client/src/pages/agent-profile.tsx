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
  Calendar,
  BarChart2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { formatDistanceToNow } from "date-fns";
import { useState, useEffect } from "react";

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
  issuer_confirmed_certs?: number;
  issuer_level?: "Newcomer" | "Active" | "Trusted" | "Verified";
  attestation_value?: number;
}

interface TimelineEvent {
  id: string;
  file_name: string;
  file_hash: string;
  blockchain_status: string;
  transaction_hash: string | null;
  metadata: any;
  created_at: string;
  event_type: "cert" | "metadata_cert" | "audit";
  action_description: string | null;
  model_hash: string | null;
  strategy_hash: string | null;
  version_number: string | null;
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
  attestationBonus?: number;
  transparencyTier?: string;
  transparencyBonus?: number;
  metadataCount?: number;
  auditCount?: number;
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
  rank: number | null;
  snapshot_date: string;
}

const LEVEL_THRESHOLDS = [
  { score: 100, label: "Active", color: "rgb(59,130,246)" },
  { score: 300, label: "Trusted", color: "rgb(34,197,94)" },
  { score: 700, label: "Verified", color: "rgb(16,185,129)" },
];

function HistoryTableBody({ snapshots }: { snapshots: TrustSnapshot[] }) {
  const reversed = [...snapshots].reverse().slice(0, 14);
  return (
    <tbody>
      {reversed.map((snap, i) => {
        const prev = reversed[i + 1];
        const scoreDiff = prev ? snap.score - prev.score : 0;
        return (
          <tr key={snap.snapshot_date} className="border-b last:border-0">
            <td className="px-3 py-2 tabular-nums text-muted-foreground">
              {snap.snapshot_date.slice(0, 10)}
            </td>
            <td className="px-3 py-2 text-right tabular-nums font-medium">
              {snap.score}
              {scoreDiff !== 0 && (
                <span className={`ml-1 text-[10px] ${scoreDiff > 0 ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}`}>
                  {scoreDiff > 0 ? "+" : ""}{scoreDiff}
                </span>
              )}
            </td>
            <td className="px-3 py-2">
              <span className={`inline-flex items-center rounded-md border px-1.5 py-0 text-[10px] font-medium ${TRUST_LEVEL_STYLES[snap.level]?.badge ?? TRUST_LEVEL_STYLES.Newcomer.badge}`}>
                {snap.level}
              </span>
            </td>
            <td className="px-3 py-2 text-right tabular-nums text-muted-foreground">
              {snap.rank ? `#${snap.rank}` : "—"}
            </td>
            <td className="px-3 py-2 text-right tabular-nums">{snap.cert_total}</td>
            <td className="hidden sm:table-cell px-3 py-2 text-right tabular-nums">{snap.active_attestations}</td>
          </tr>
        );
      })}
    </tbody>
  );
}

function TrustHistoryChart({ snapshots }: { snapshots: TrustSnapshot[] }) {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  if (snapshots.length < 2) {
    return (
      <div className="flex h-24 items-center justify-center text-sm text-muted-foreground" data-testid="text-history-empty">
        Tracking starts today — history data available tomorrow.
      </div>
    );
  }

  const W = 600;
  const H = 160;
  const PAD_TOP = 16;
  const PAD_BOTTOM = 24;
  const PAD_LEFT = 40;
  const PAD_RIGHT = 12;

  const scores = snapshots.map((s) => s.score);
  const rawMin = Math.min(...scores);
  const rawMax = Math.max(...scores);
  const chartMin = Math.max(0, rawMin - 20);
  const chartMax = rawMax + 30;
  const range = chartMax - chartMin || 1;

  const xScale = (i: number) => PAD_LEFT + (i / (snapshots.length - 1)) * (W - PAD_LEFT - PAD_RIGHT);
  const yScale = (score: number) => H - PAD_BOTTOM - ((score - chartMin) / range) * (H - PAD_TOP - PAD_BOTTOM);

  const points = snapshots.map((s, i) => ({ x: xScale(i), y: yScale(s.score) }));
  const polyline = points.map((p) => `${p.x},${p.y}`).join(" ");
  const areaPoints = [`${points[0].x},${H - PAD_BOTTOM}`, ...points.map((p) => `${p.x},${p.y}`), `${points[points.length - 1].x},${H - PAD_BOTTOM}`].join(" ");

  const levelChanges: { idx: number; from: string; to: string }[] = [];
  for (let i = 1; i < snapshots.length; i++) {
    if (snapshots[i].level !== snapshots[i - 1].level) {
      levelChanges.push({ idx: i, from: snapshots[i - 1].level, to: snapshots[i].level });
    }
  }

  const lastScore = scores[scores.length - 1];
  const firstScore = scores[0];
  const delta = lastScore - firstScore;
  const lastRank = snapshots[snapshots.length - 1].rank;
  const firstRank = snapshots[0].rank;
  const rankDelta = firstRank && lastRank ? firstRank - lastRank : null;

  const visibleThresholds = LEVEL_THRESHOLDS.filter((t) => t.score >= chartMin && t.score <= chartMax);

  const dateLabels: { idx: number; label: string }[] = [];
  const step = Math.max(1, Math.floor(snapshots.length / 5));
  for (let i = 0; i < snapshots.length; i += step) dateLabels.push({ idx: i, label: snapshots[i].snapshot_date.slice(5, 10) });
  if (dateLabels[dateLabels.length - 1]?.idx !== snapshots.length - 1) {
    dateLabels.push({ idx: snapshots.length - 1, label: snapshots[snapshots.length - 1].snapshot_date.slice(5, 10) });
  }

  const hovered = hoveredIdx !== null ? snapshots[hoveredIdx] : null;

  return (
    <div className="space-y-4" data-testid="card-trust-history-chart">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="text-sm font-medium">90-day trend</span>
          <span className={`text-sm font-semibold tabular-nums ${delta >= 0 ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}`} data-testid="text-score-delta">
            {delta >= 0 ? "+" : ""}{delta} pts
          </span>
        </div>
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          {lastRank && (
            <span data-testid="text-current-rank">
              Rank #{lastRank}
              {rankDelta !== null && rankDelta !== 0 && (
                <span className={rankDelta > 0 ? "ml-1 text-emerald-600 dark:text-emerald-400" : "ml-1 text-red-600 dark:text-red-400"}>
                  ({rankDelta > 0 ? "+" : ""}{rankDelta})
                </span>
              )}
            </span>
          )}
          <span>{snapshots.length} data points</span>
        </div>
      </div>

      <div className="relative">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="w-full"
          style={{ height: 180 }}
          data-testid="svg-trust-chart"
          onMouseLeave={() => setHoveredIdx(null)}
        >
          <defs>
            <linearGradient id="histGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="rgb(16,185,129)" stopOpacity="0.20" />
              <stop offset="100%" stopColor="rgb(16,185,129)" stopOpacity="0.02" />
            </linearGradient>
          </defs>

          {visibleThresholds.map((t) => {
            const ty = yScale(t.score);
            return (
              <g key={t.score}>
                <line x1={PAD_LEFT} y1={ty} x2={W - PAD_RIGHT} y2={ty} stroke={t.color} strokeWidth="0.5" strokeDasharray="4,3" opacity="0.5" />
                <text x={PAD_LEFT - 4} y={ty + 3} textAnchor="end" fontSize="8" fill={t.color} opacity="0.7">{t.score}</text>
              </g>
            );
          })}

          <polygon points={areaPoints} fill="url(#histGrad)" />

          <polyline points={polyline} fill="none" stroke="rgb(16,185,129)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />

          {levelChanges.map((lc) => {
            const p = points[lc.idx];
            return (
              <g key={lc.idx}>
                <line x1={p.x} y1={PAD_TOP} x2={p.x} y2={H - PAD_BOTTOM} stroke="rgb(251,191,36)" strokeWidth="0.7" strokeDasharray="2,2" opacity="0.6" />
                <circle cx={p.x} cy={p.y} r="4" fill="rgb(251,191,36)" stroke="white" strokeWidth="1" />
              </g>
            );
          })}

          <circle cx={points[points.length - 1].x} cy={points[points.length - 1].y} r="4" fill="rgb(16,185,129)" stroke="white" strokeWidth="1.5" />

          {dateLabels.map((dl) => (
            <text key={dl.idx} x={xScale(dl.idx)} y={H - 6} textAnchor="middle" fontSize="8" className="fill-muted-foreground">{dl.label}</text>
          ))}

          {points.map((p, i) => (
            <rect
              key={i}
              x={p.x - (W / snapshots.length) / 2}
              y={PAD_TOP}
              width={W / snapshots.length}
              height={H - PAD_TOP - PAD_BOTTOM}
              fill="transparent"
              onMouseEnter={(e) => {
                setHoveredIdx(i);
                const svg = e.currentTarget.ownerSVGElement;
                if (svg) {
                  const rect = svg.getBoundingClientRect();
                  const xPct = (p.x / W) * rect.width;
                  setTooltipPos({ x: xPct, y: 0 });
                }
              }}
            />
          ))}

          {hoveredIdx !== null && (
            <g>
              <line x1={points[hoveredIdx].x} y1={PAD_TOP} x2={points[hoveredIdx].x} y2={H - PAD_BOTTOM} stroke="rgb(16,185,129)" strokeWidth="0.5" opacity="0.5" />
              <circle cx={points[hoveredIdx].x} cy={points[hoveredIdx].y} r="4" fill="rgb(16,185,129)" stroke="white" strokeWidth="1.5" />
            </g>
          )}
        </svg>

        {hovered && (
          <div
            className="pointer-events-none absolute top-0 z-10 rounded-md border bg-card px-3 py-2 text-xs shadow-md"
            style={{
              left: `${tooltipPos.x}px`,
              transform: tooltipPos.x > 300 ? "translateX(-110%)" : "translateX(10%)",
            }}
            data-testid="tooltip-chart"
          >
            <p className="font-medium tabular-nums">{hovered.snapshot_date.slice(0, 10)}</p>
            <p className="tabular-nums">Score: <span className="font-semibold">{hovered.score}</span></p>
            <p>Level: <span className="font-semibold">{hovered.level}</span></p>
            {hovered.rank && <p className="tabular-nums">Rank: <span className="font-semibold">#{hovered.rank}</span></p>}
            <p className="tabular-nums text-muted-foreground">{hovered.cert_total} certs · {hovered.active_attestations} attestations</p>
          </div>
        )}
      </div>

      {visibleThresholds.length > 0 && (
        <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
          <span className="font-medium">Level thresholds:</span>
          {LEVEL_THRESHOLDS.map((t) => (
            <span key={t.score} className="flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: t.color }} />
              {t.score} = {t.label}
            </span>
          ))}
          {levelChanges.length > 0 && (
            <span className="flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-full bg-amber-400" />
              Level change
            </span>
          )}
        </div>
      )}

      {snapshots.length >= 3 && (
        <div className="overflow-hidden rounded-md border" data-testid="table-trust-history">
          <table className="w-full text-xs">
            <thead className="border-b bg-muted/40">
              <tr>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">Date</th>
                <th className="px-3 py-2 text-right font-medium text-muted-foreground">Score</th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">Level</th>
                <th className="px-3 py-2 text-right font-medium text-muted-foreground">Rank</th>
                <th className="px-3 py-2 text-right font-medium text-muted-foreground">Certs</th>
                <th className="hidden sm:table-cell px-3 py-2 text-right font-medium text-muted-foreground">Attestations</th>
              </tr>
            </thead>
            <HistoryTableBody snapshots={snapshots} />
          </table>
        </div>
      )}
    </div>
  );
}

const NEXT_LEVELS = [
  { threshold: 100, label: "Active" },
  { threshold: 300, label: "Trusted" },
  { threshold: 700, label: "Verified" },
];

function ScoreBreakdown({ agent }: { agent: AgentProfile }) {
  const firstAt = agent.firstCertAt ? new Date(agent.firstCertAt) : null;
  const lastAt = agent.lastCertAt ? new Date(agent.lastCertAt) : null;

  const daysSinceFirst = firstAt
    ? Math.floor((Date.now() - firstAt.getTime()) / (1000 * 60 * 60 * 24))
    : 0;
  const daysSinceLast = lastAt
    ? Math.floor((Date.now() - lastAt.getTime()) / (1000 * 60 * 60 * 24))
    : Infinity;

  const baseScore = agent.certTotal * 10;
  const recencyBonus = agent.certLast30d * 5;

  let ageBonus = 0;
  if (daysSinceLast <= 30) {
    ageBonus = Math.floor(Math.min(150, daysSinceFirst * 0.3));
  } else if (daysSinceLast <= 90) {
    const rawAge = Math.min(150, daysSinceFirst * 0.3);
    const decayFactor = 1 - (daysSinceLast - 30) / 60;
    ageBonus = Math.max(0, Math.round(rawAge * decayFactor));
  }

  const streakBonus = Math.min(100, agent.streakWeeks * 8);
  const attestationBonus = agent.attestationBonus ?? Math.min(3, agent.activeAttestations) * 50;

  const nextLevel = NEXT_LEVELS.find((l) => l.threshold > agent.score);
  const ptToNext = nextLevel ? nextLevel.threshold - agent.score : null;
  const prevIdx = nextLevel ? NEXT_LEVELS.indexOf(nextLevel) - 1 : -1;
  const prevThreshold = prevIdx >= 0 ? NEXT_LEVELS[prevIdx].threshold : 0;
  const progressPct = nextLevel
    ? Math.min(100, ((agent.score - prevThreshold) / (nextLevel.threshold - prevThreshold)) * 100)
    : 100;

  const components = [
    {
      label: "Confirmed certs",
      value: baseScore,
      cap: null as number | null,
      detail: `${agent.certTotal} × 10 pts`,
      Icon: CheckCircle2,
    },
    {
      label: "Recent activity",
      value: recencyBonus,
      cap: null,
      detail: `${agent.certLast30d} cert${agent.certLast30d !== 1 ? "s" : ""} × 5 pts (30d)`,
      Icon: TrendingUp,
    },
    {
      label: "Seniority",
      value: ageBonus,
      cap: 150,
      detail: daysSinceLast > 30 ? `${daysSinceFirst}d active (decaying)` : `${daysSinceFirst} days active`,
      Icon: Calendar,
    },
    {
      label: "Streak",
      value: streakBonus,
      cap: 100,
      detail: `${agent.streakWeeks} week${agent.streakWeeks !== 1 ? "s" : ""} × 8 pts`,
      Icon: Flame,
    },
    {
      label: "Attestations",
      value: attestationBonus,
      cap: 150,
      detail: `${Math.min(3, agent.activeAttestations)} counted (weighted by issuer level)`,
      Icon: BadgeCheck,
    },
    {
      label: "Transparency",
      value: agent.transparencyBonus ?? 0,
      cap: 200,
      detail: `${agent.transparencyTier ?? "Tier 1"} — ${agent.metadataCount ?? 0} metadata, ${agent.auditCount ?? 0} audits`,
      Icon: Shield,
    },
  ];

  return (
    <Card data-testid="card-score-breakdown">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <BarChart2 className="h-4 w-4" />
          Score breakdown
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-3">
          {components.map(({ label, value, cap, detail, Icon }) => (
            <div key={label} className="space-y-1.5" data-testid={`breakdown-${label.toLowerCase().replace(/\s+/g, "-")}`}>
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 min-w-0">
                  <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  <span className="text-sm">{label}</span>
                  <span className="truncate text-xs text-muted-foreground hidden sm:inline">{detail}</span>
                </div>
                <span className="shrink-0 tabular-nums text-sm font-medium">
                  +{value}
                  {cap !== null && (
                    <span className="text-xs text-muted-foreground"> /{cap}</span>
                  )}
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full rounded-full bg-primary"
                  style={{ width: `${cap !== null ? Math.min(100, (value / cap) * 100) : value > 0 ? 100 : 0}%` }}
                />
              </div>
            </div>
          ))}
        </div>

        <div className="flex items-center justify-between border-t pt-3">
          <span className="text-sm text-muted-foreground">Total Trust Score</span>
          <span className="text-lg font-bold tabular-nums">{agent.score} pts</span>
        </div>

        {nextLevel ? (
          <div className="rounded-md bg-muted/50 p-3 space-y-2" data-testid="card-next-level">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">
                Progress to{" "}
                <span className="font-medium text-foreground">{nextLevel.label}</span>
              </span>
              <span className="font-semibold tabular-nums text-primary">{ptToNext} pts to go</span>
            </div>
            <div className="h-2 rounded-full bg-muted overflow-hidden">
              <div
                className="h-full rounded-full bg-primary transition-all"
                style={{ width: `${progressPct}%` }}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Fastest path: certify weekly to grow streak (+8 pts/week) or earn a domain attestation (+25 to +50 pts, weighted by issuer level).
            </p>
          </div>
        ) : (
          <div
            className="rounded-md border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-700 dark:text-emerald-400"
            data-testid="text-max-level"
          >
            Maximum trust level achieved — Verified
          </div>
        )}
      </CardContent>
    </Card>
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

  const { data: timeline } = useQuery<{ events: TimelineEvent[]; total: number }>({
    queryKey: ["/api/agents", wallet, "timeline"],
    queryFn: () => fetch(`/api/agents/${wallet}/timeline?limit=30`).then((r) => r.json()),
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
        <div className="container flex h-16 items-center justify-between gap-4">
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
                        +{agent.attestationBonus ?? Math.min(3, agent.activeAttestations) * 50} pts from attestations
                      </span>
                    )}
                    {agent.transparencyTier && agent.transparencyTier !== "Tier 1" && (
                      <Badge
                        variant="outline"
                        className={
                          agent.transparencyTier === "Tier 3"
                            ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                            : "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30"
                        }
                        data-testid="badge-header-transparency"
                      >
                        {agent.transparencyTier}
                      </Badge>
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

            {/* Score Breakdown */}
            <ScoreBreakdown agent={agent} />

            {/* Trust Score History */}
            <Card data-testid="card-trust-history">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <TrendingUp className="h-4 w-4" />
                  Trust score history
                </CardTitle>
              </CardHeader>
              <CardContent>
                <TrustHistoryChart snapshots={history?.snapshots ?? []} />
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
                      +{agent.attestationBonus ?? Math.min(3, agent.attestations.length) * 50} trust pts
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {agent.attestations.map((att) => {
                      const issuerLevel = att.issuer_level ?? "Newcomer";
                      const attValue = att.attestation_value ?? 10;
                      const issuerLevelColor: Record<string, string> = {
                        Verified: "text-emerald-600 dark:text-emerald-400 border-emerald-500/40 bg-emerald-500/10",
                        Trusted: "text-green-700 dark:text-green-400 border-green-500/40 bg-green-500/10",
                        Active: "text-blue-600 dark:text-blue-400 border-blue-500/40 bg-blue-500/10",
                        Newcomer: "text-muted-foreground border-border bg-muted/50",
                      };
                      return (
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
                          <div className="text-right shrink-0 space-y-1">
                            <Link
                              href={`/issuer/${att.issuer_wallet}`}
                              data-testid={`link-issuer-${att.id}`}
                              className="text-xs font-medium hover:underline underline-offset-2 text-primary block"
                            >
                              {att.issuer_name}
                            </Link>
                            <p className="font-mono text-xs text-muted-foreground">
                              {att.issuer_wallet.slice(0, 8)}…{att.issuer_wallet.slice(-6)}
                            </p>
                            <span
                              data-testid={`badge-issuer-level-${att.id}`}
                              className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-medium ${issuerLevelColor[issuerLevel]}`}
                            >
                              {issuerLevel === "Verified" && <Shield className="h-3 w-3" />}
                              {issuerLevel}
                              <span className="opacity-70">· +{attValue} pts</span>
                            </span>
                          </div>
                        </div>
                        <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                          <span>Issued {formatDistanceToNow(new Date(att.created_at), { addSuffix: true })}</span>
                          {att.expires_at && (
                            <span>· Expires {formatDistanceToNow(new Date(att.expires_at), { addSuffix: true })}</span>
                          )}
                        </div>
                      </div>
                    );
                    })}
                  </div>
                </CardContent>
              </Card>
            )}

            <Card data-testid="card-audit-timeline">
              <CardHeader>
                <CardTitle className="flex items-center justify-between gap-2 flex-wrap text-base">
                  <span className="flex items-center gap-2">
                    <Clock className="h-4 w-4" />
                    Audit Timeline
                  </span>
                  {agent.transparencyTier && (
                    <Badge
                      variant="outline"
                      className={
                        agent.transparencyTier === "Tier 3"
                          ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                          : agent.transparencyTier === "Tier 2"
                          ? "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30"
                          : "bg-muted text-muted-foreground"
                      }
                      data-testid="badge-transparency-tier"
                    >
                      {agent.transparencyTier}
                    </Badge>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!timeline ? (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Clock className="h-4 w-4 animate-spin" />
                    Loading timeline...
                  </div>
                ) : timeline.events.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No confirmed certifications yet.</p>
                ) : (
                  <div className="relative space-y-0">
                    <div className="absolute left-[11px] top-3 bottom-3 w-px bg-border" />
                    {timeline.events.map((evt, i) => {
                      const isAudit = evt.event_type === "audit";
                      const hasMeta = evt.event_type === "metadata_cert";
                      return (
                        <div
                          key={evt.id}
                          data-testid={`timeline-event-${evt.id}`}
                          className={`relative pl-8 py-3 ${i < timeline.events.length - 1 ? "border-b border-border/50" : ""}`}
                        >
                          <div className={`absolute left-1.5 top-4 h-3 w-3 rounded-full border-2 ${
                            isAudit
                              ? "border-amber-500 bg-amber-500/20"
                              : hasMeta
                              ? "border-blue-500 bg-blue-500/20"
                              : "border-emerald-500 bg-emerald-500/20"
                          }`} />

                          <div className="flex items-start justify-between gap-4">
                            <div className="min-w-0 space-y-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <Badge
                                  variant="outline"
                                  className={
                                    isAudit
                                      ? "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/30"
                                      : hasMeta
                                      ? "bg-blue-500/10 text-blue-700 dark:text-blue-400 border-blue-500/30"
                                      : "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/30"
                                  }
                                >
                                  {isAudit ? "Audit" : hasMeta ? "Metadata" : "Cert"}
                                </Badge>
                                <span className="truncate text-sm font-medium" title={evt.file_name}>
                                  {evt.file_name}
                                </span>
                              </div>

                              {isAudit && evt.action_description && (
                                <p className="text-xs text-muted-foreground">{evt.action_description}</p>
                              )}

                              {(evt.model_hash || evt.strategy_hash || evt.version_number) && (
                                <div className="flex flex-wrap gap-2 mt-1">
                                  {evt.model_hash && (
                                    <span className="text-xs bg-muted rounded px-1.5 py-0.5 font-mono">
                                      model: {evt.model_hash.slice(0, 12)}...
                                    </span>
                                  )}
                                  {evt.strategy_hash && (
                                    <span className="text-xs bg-muted rounded px-1.5 py-0.5 font-mono">
                                      strategy: {evt.strategy_hash.slice(0, 12)}...
                                    </span>
                                  )}
                                  {evt.version_number && (
                                    <span className="text-xs bg-muted rounded px-1.5 py-0.5 font-mono">
                                      v{evt.version_number}
                                    </span>
                                  )}
                                </div>
                              )}
                            </div>

                            <div className="flex shrink-0 items-center gap-2">
                              <span className="text-xs text-muted-foreground whitespace-nowrap">
                                {formatDistanceToNow(new Date(evt.created_at), { addSuffix: true })}
                              </span>
                              {evt.transaction_hash && (
                                <Button
                                  asChild
                                  size="icon"
                                  variant="ghost"
                                  data-testid={`link-tx-${evt.id}`}
                                >
                                  <a
                                    href={`https://explorer.multiversx.com/transactions/${evt.transaction_hash}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    title="View on explorer"
                                  >
                                    <ExternalLink className="h-3.5 w-3.5" />
                                  </a>
                                </Button>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}

                    {timeline.total > timeline.events.length && (
                      <div className="pt-3 pl-8 text-xs text-muted-foreground" data-testid="text-timeline-total">
                        Showing {timeline.events.length} of {timeline.total} events
                      </div>
                    )}
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

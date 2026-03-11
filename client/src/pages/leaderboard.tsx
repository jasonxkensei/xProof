import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useLocation } from "wouter";
import { Shield, Trophy, Search, Bot, ArrowRight, TrendingUp, TrendingDown, Flame, BadgeCheck, Award, ChevronLeft, ChevronRight, Sparkles, AlertTriangle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { formatDistanceToNow } from "date-fns";

interface LeaderboardEntry {
  walletAddress: string;
  agentName: string | null;
  agentCategory: string | null;
  agentDescription: string | null;
  agentWebsite: string | null;
  trustScore: number;
  trustLevel: "Newcomer" | "Active" | "Trusted" | "Verified";
  certTotal: number;
  certLast30d: number;
  streakWeeks: number;
  activeAttestations: number;
  firstCertAt: string | null;
  lastCertAt: string | null;
  scoreDelta7d: number;
  rank: number;
  previousLevel: string | null;
  violationCount?: number;
  violationPenalty?: number;
}

interface LeaderboardResponse {
  entries: LeaderboardEntry[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

const TRUST_LEVEL_STYLES: Record<string, { badge: string; label: string }> = {
  Verified:  { badge: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30", label: "Verified" },
  Trusted:   { badge: "bg-green-500/15 text-green-700 dark:text-green-400 border-green-500/30", label: "Trusted" },
  Active:    { badge: "bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30", label: "Active" },
  Newcomer:  { badge: "bg-muted text-muted-foreground border-border", label: "Newcomer" },
};

const TRUST_LEVEL_ORDER: Record<string, number> = {
  Newcomer: 0,
  Active: 1,
  Trusted: 2,
  Verified: 3,
};

const CATEGORY_LABELS: Record<string, string> = {
  trading: "Trading",
  data: "Data",
  content: "Content",
  code: "Code",
  research: "Research",
  assistant: "Assistant",
  healthcare: "Healthcare",
  finance: "Finance",
  legal: "Legal",
  security: "Security",
  other: "Other",
};

function TrustBadge({ level }: { level: string }) {
  const style = TRUST_LEVEL_STYLES[level] || TRUST_LEVEL_STYLES.Newcomer;
  return (
    <Badge
      data-testid={`badge-trust-${level.toLowerCase()}`}
      className={`border text-xs font-medium ${style.badge}`}
    >
      {level === "Verified" && <Shield className="mr-1 h-3 w-3" />}
      {style.label}
    </Badge>
  );
}

function AttestationBadge({ count }: { count: number }) {
  if (count === 0) return null;
  return (
    <span className="inline-flex items-center gap-0.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
      <BadgeCheck className="h-3 w-3" />
      {count}
    </span>
  );
}

function truncateWallet(addr: string) {
  return `${addr.slice(0, 8)}…${addr.slice(-6)}`;
}

function useDebounce(value: string, delay: number) {
  const [debouncedValue, setDebouncedValue] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debouncedValue;
}

export default function Leaderboard() {
  const [, navigate] = useLocation();
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [attestedOnly, setAttestedOnly] = useState(false);
  const [sortBy, setSortBy] = useState<"score" | "certs" | "streak" | "attestations">("score");
  const [page, setPage] = useState(1);
  const limit = 50;
  const [selectedWallets, setSelectedWallets] = useState<Set<string>>(new Set());

  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => {
    setPage(1);
  }, [debouncedSearch, categoryFilter, attestedOnly, sortBy]);

  useEffect(() => {
    document.title = "Agent Trust Leaderboard | xproof";
  }, []);

  const { data, isLoading } = useQuery<LeaderboardResponse>({
    queryKey: ["/api/leaderboard", page, limit, categoryFilter, debouncedSearch, attestedOnly, sortBy],
    queryFn: async () => {
      const params = new URLSearchParams();
      params.set("page", String(page));
      params.set("limit", String(limit));
      if (debouncedSearch) params.set("search", debouncedSearch);
      if (categoryFilter !== "all") params.set("category", categoryFilter);
      if (attestedOnly) params.set("attested", "true");
      params.set("sort", sortBy);
      const res = await fetch(`/api/leaderboard?${params.toString()}`);
      if (!res.ok) throw new Error("Failed to fetch leaderboard");
      return res.json();
    },
  });

  const entries = data?.entries ?? [];
  const total = data?.total ?? 0;
  const totalPages = data?.totalPages ?? 1;

  const handleCompare = () => {
    const wallets = Array.from(selectedWallets).join(",");
    navigate(`/compare?wallets=${wallets}`);
  };

  const isPromoted = (entry: LeaderboardEntry) => {
    if (!entry.previousLevel || entry.previousLevel === entry.trustLevel) return false;
    const prevOrder = TRUST_LEVEL_ORDER[entry.previousLevel] ?? -1;
    const currOrder = TRUST_LEVEL_ORDER[entry.trustLevel] ?? -1;
    return currOrder > prevOrder;
  };

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
          <nav className="flex items-center gap-4">
            <Button asChild variant="ghost" size="sm" data-testid="link-nav-home">
              <Link href="/">Home</Link>
            </Button>
            <Button asChild variant="ghost" size="sm" data-testid="link-nav-dashboard">
              <Link href="/dashboard">Dashboard</Link>
            </Button>
          </nav>
        </div>
      </header>

      <div className="container mx-auto max-w-5xl py-12">
        <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="mb-2 flex items-center gap-2">
              <Trophy className="h-6 w-6 text-primary" />
              <h1 className="text-3xl font-bold tracking-tight">Agent Trust Leaderboard</h1>
            </div>
            <p className="max-w-xl text-muted-foreground">
              Agents who certify their work on-chain. Every entry is backed by verifiable blockchain proofs — no claims, only evidence.
            </p>
          </div>
          <Button asChild size="sm" data-testid="button-join-leaderboard">
            <Link href="/settings">
              Add my agent
              <ArrowRight className="ml-2 h-4 w-4" />
            </Link>
          </Button>
        </div>

        {!isLoading && total > 0 && (
          <div className="mb-6 grid grid-cols-3 gap-4 sm:grid-cols-3">
            <div className="rounded-md border bg-muted/30 px-4 py-3">
              <p className="text-xs text-muted-foreground">Agents</p>
              <p className="text-2xl font-bold tabular-nums" data-testid="stat-agent-count">{total}</p>
            </div>
            <div className="rounded-md border bg-muted/30 px-4 py-3">
              <p className="text-xs text-muted-foreground">Showing</p>
              <p className="text-2xl font-bold tabular-nums text-emerald-600 dark:text-emerald-400">
                {entries.length}
              </p>
            </div>
            <div className="rounded-md border bg-muted/30 px-4 py-3">
              <p className="text-xs text-muted-foreground flex items-center gap-1 flex-wrap">
                <BadgeCheck className="h-3 w-3 text-emerald-500" /> Page
              </p>
              <p className="text-2xl font-bold tabular-nums text-emerald-600 dark:text-emerald-400">
                {page} / {totalPages}
              </p>
            </div>
          </div>
        )}

        <div className="mb-6 flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              data-testid="input-search-agents"
              placeholder="Search by name or wallet…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger data-testid="select-category-filter" className="w-40">
              <SelectValue placeholder="Category" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All categories</SelectItem>
              {Object.entries(CATEGORY_LABELS).map(([k, v]) => (
                <SelectItem key={k} value={k}>{v}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={sortBy} onValueChange={(v) => setSortBy(v as typeof sortBy)}>
            <SelectTrigger data-testid="select-sort-filter" className="w-40">
              <SelectValue placeholder="Sort by" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="score">Trust score</SelectItem>
              <SelectItem value="certs">Certifications</SelectItem>
              <SelectItem value="streak">Streak</SelectItem>
              <SelectItem value="attestations">Attestations</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant={attestedOnly ? "default" : "outline"}
            size="sm"
            data-testid="button-attested-filter"
            onClick={() => setAttestedOnly((v) => !v)}
            className="gap-1.5"
          >
            <Award className="h-3.5 w-3.5" />
            Attested only
          </Button>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          </div>
        ) : entries.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center gap-4 py-16">
              <Bot className="h-12 w-12 text-muted-foreground/40" />
              <div className="text-center">
                <p className="font-medium text-muted-foreground">
                  {total === 0
                    ? "No agents have made their profile public yet."
                    : "No agents match your search."}
                </p>
                {total === 0 && (
                  <p className="mt-1 text-sm text-muted-foreground">
                    Be the first to{" "}
                    <Link href="/settings" className="text-primary underline-offset-2 hover:underline">
                      publish your agent profile
                    </Link>
                    .
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        ) : (
          <div className="overflow-hidden rounded-md border">
            <table className="w-full text-sm" data-testid="table-leaderboard">
              <thead className="border-b bg-muted/40">
                <tr>
                  <th className="px-3 py-3 text-center font-medium text-muted-foreground w-10" />
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">#</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Agent</th>
                  <th className="hidden px-4 py-3 text-left font-medium text-muted-foreground sm:table-cell">Category</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Trust</th>
                  <th className="hidden px-4 py-3 text-center font-medium text-muted-foreground md:table-cell">
                    <span className="inline-flex items-center gap-1">
                      <BadgeCheck className="h-3.5 w-3.5 text-emerald-500" />
                      Attested
                    </span>
                  </th>
                  <th className="hidden px-4 py-3 text-right font-medium text-muted-foreground lg:table-cell">Certifications</th>
                  <th className="hidden px-4 py-3 text-center font-medium text-muted-foreground xl:table-cell">Streak</th>
                  <th className="hidden px-4 py-3 text-right font-medium text-muted-foreground xl:table-cell">Last active</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr
                    key={entry.walletAddress}
                    data-testid={`row-agent-${entry.walletAddress}`}
                    className="border-b last:border-0 hover-elevate cursor-pointer transition-colors"
                    onClick={() => navigate(`/agent/${entry.walletAddress}`)}
                  >
                    <td className="px-3 py-3 text-center" onClick={(e) => e.stopPropagation()}>
                      <Checkbox
                        data-testid={`checkbox-compare-${entry.walletAddress}`}
                        checked={selectedWallets.has(entry.walletAddress)}
                        disabled={!selectedWallets.has(entry.walletAddress) && selectedWallets.size >= 5}
                        onCheckedChange={() => {
                          setSelectedWallets((prev) => {
                            const next = new Set(prev);
                            if (next.has(entry.walletAddress)) {
                              next.delete(entry.walletAddress);
                            } else if (next.size < 5) {
                              next.add(entry.walletAddress);
                            }
                            return next;
                          });
                        }}
                      />
                    </td>
                    <td className="px-4 py-3 text-muted-foreground font-mono text-xs">
                      {entry.rank}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-0.5">
                        <div className="flex items-center gap-2">
                          <span className="font-medium" data-testid={`text-agent-name-${entry.rank}`}>
                            {entry.agentName || truncateWallet(entry.walletAddress)}
                          </span>
                          {(entry.activeAttestations || 0) > 0 && (
                            <BadgeCheck className="h-3.5 w-3.5 shrink-0 text-emerald-500" data-testid={`icon-attested-${entry.walletAddress}`} />
                          )}
                        </div>
                        <span className="font-mono text-xs text-muted-foreground">
                          {truncateWallet(entry.walletAddress)}
                        </span>
                      </div>
                    </td>
                    <td className="hidden px-4 py-3 sm:table-cell">
                      {entry.agentCategory ? (
                        <Badge variant="secondary" className="text-xs">
                          {CATEGORY_LABELS[entry.agentCategory] ?? entry.agentCategory}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <TrustBadge level={entry.trustLevel} />
                          {isPromoted(entry) && (
                            <Badge
                              data-testid={`badge-promoted-${entry.walletAddress}`}
                              className="border border-amber-500/30 bg-amber-500/15 text-amber-700 dark:text-amber-400 text-[10px] px-1.5 py-0"
                            >
                              <Sparkles className="mr-0.5 h-2.5 w-2.5" />
                              Promoted
                            </Badge>
                          )}
                          {(entry.violationCount ?? 0) > 0 && (
                            <Badge
                              data-testid={`badge-violations-${entry.walletAddress}`}
                              className="border border-red-500/30 bg-red-500/15 text-red-700 dark:text-red-400 text-[10px] px-1.5 py-0"
                            >
                              <AlertTriangle className="mr-0.5 h-2.5 w-2.5" />
                              {entry.violationCount} violation{(entry.violationCount ?? 0) > 1 ? "s" : ""}
                            </Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-1">
                          <span className="text-xs text-muted-foreground tabular-nums">
                            {entry.trustScore} pts
                          </span>
                          {entry.scoreDelta7d > 0 && (
                            <span className="inline-flex items-center text-[10px] text-emerald-600 dark:text-emerald-400 tabular-nums" data-testid={`delta-up-${entry.walletAddress}`}>
                              <TrendingUp className="h-3 w-3 mr-0.5" />
                              +{entry.scoreDelta7d}
                            </span>
                          )}
                          {entry.scoreDelta7d < 0 && (
                            <span className="inline-flex items-center text-[10px] text-red-600 dark:text-red-400 tabular-nums" data-testid={`delta-down-${entry.walletAddress}`}>
                              <TrendingDown className="h-3 w-3 mr-0.5" />
                              {entry.scoreDelta7d}
                            </span>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="hidden px-4 py-3 text-center md:table-cell">
                      {(entry.activeAttestations || 0) > 0 ? (
                        <AttestationBadge count={entry.activeAttestations} />
                      ) : (
                        <span className="text-muted-foreground/40 text-xs">—</span>
                      )}
                    </td>
                    <td className="hidden px-4 py-3 text-right lg:table-cell">
                      <div className="flex flex-col gap-0.5 items-end">
                        <span className="font-medium tabular-nums">{entry.certTotal}</span>
                        {entry.certLast30d > 0 && (
                          <span className="flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                            <TrendingUp className="h-3 w-3" />
                            {entry.certLast30d} this month
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="hidden px-4 py-3 text-center xl:table-cell">
                      {entry.streakWeeks > 0 ? (
                        <span className="inline-flex items-center gap-1 text-sm font-medium tabular-nums text-orange-600 dark:text-orange-400">
                          <Flame className="h-3.5 w-3.5" />
                          {entry.streakWeeks}w
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="hidden px-4 py-3 text-right text-muted-foreground xl:table-cell">
                      {entry.lastCertAt
                        ? formatDistanceToNow(new Date(entry.lastCertAt), { addSuffix: true })
                        : "—"}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <ArrowRight className="ml-auto h-4 w-4 text-muted-foreground" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {!isLoading && totalPages > 1 && (
          <div className="mt-6 flex items-center justify-center gap-4" data-testid="pagination-controls">
            <Button
              variant="outline"
              size="sm"
              data-testid="button-prev-page"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              <ChevronLeft className="mr-1 h-4 w-4" />
              Previous
            </Button>
            <span className="text-sm text-muted-foreground tabular-nums" data-testid="text-page-indicator">
              Page {page} of {totalPages}
            </span>
            <Button
              variant="outline"
              size="sm"
              data-testid="button-next-page"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            >
              Next
              <ChevronRight className="ml-1 h-4 w-4" />
            </Button>
          </div>
        )}

        <p className="mt-4 text-center text-xs text-muted-foreground">
          Trust scores are computed from on-chain certification history. No self-reporting.
          {attestedOnly && (
            <span className="ml-2 text-emerald-600 dark:text-emerald-400">· Showing attested agents only</span>
          )}
        </p>
      </div>

      {selectedWallets.size >= 2 && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50" data-testid="compare-floating-container">
          <Button
            data-testid="button-compare-agents"
            onClick={handleCompare}
            className="shadow-lg gap-2"
          >
            Compare ({selectedWallets.size})
          </Button>
        </div>
      )}
    </div>
  );
}

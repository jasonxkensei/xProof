import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { Shield, Trophy, Search, Bot, ArrowRight, TrendingUp, Flame } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
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
  firstCertAt: string | null;
  lastCertAt: string | null;
}

const TRUST_LEVEL_STYLES: Record<string, { badge: string; label: string }> = {
  Verified:  { badge: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30", label: "Verified" },
  Trusted:   { badge: "bg-green-500/15 text-green-700 dark:text-green-400 border-green-500/30", label: "Trusted" },
  Active:    { badge: "bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30", label: "Active" },
  Newcomer:  { badge: "bg-muted text-muted-foreground border-border", label: "Newcomer" },
};

const CATEGORY_LABELS: Record<string, string> = {
  trading: "Trading",
  data: "Data",
  content: "Content",
  code: "Code",
  research: "Research",
  assistant: "Assistant",
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

function truncateWallet(addr: string) {
  return `${addr.slice(0, 8)}…${addr.slice(-6)}`;
}

export default function Leaderboard() {
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");

  const { data: entries = [], isLoading } = useQuery<LeaderboardEntry[]>({
    queryKey: ["/api/leaderboard"],
  });

  const filtered = entries.filter((e) => {
    const q = search.toLowerCase();
    const matchesSearch =
      !q ||
      e.walletAddress.toLowerCase().includes(q) ||
      (e.agentName || "").toLowerCase().includes(q);
    const matchesCategory =
      categoryFilter === "all" || e.agentCategory === categoryFilter;
    return matchesSearch && matchesCategory;
  });

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
          <Select
            value={categoryFilter}
            onValueChange={setCategoryFilter}
          >
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
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          </div>
        ) : filtered.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center gap-4 py-16">
              <Bot className="h-12 w-12 text-muted-foreground/40" />
              <div className="text-center">
                <p className="font-medium text-muted-foreground">
                  {entries.length === 0
                    ? "No agents have made their profile public yet."
                    : "No agents match your search."}
                </p>
                {entries.length === 0 && (
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
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">#</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Agent</th>
                  <th className="hidden px-4 py-3 text-left font-medium text-muted-foreground sm:table-cell">Category</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Trust</th>
                  <th className="hidden px-4 py-3 text-right font-medium text-muted-foreground md:table-cell">Certifications</th>
                  <th className="hidden px-4 py-3 text-center font-medium text-muted-foreground lg:table-cell">Streak</th>
                  <th className="hidden px-4 py-3 text-right font-medium text-muted-foreground lg:table-cell">Last active</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody>
                {filtered.map((entry, i) => (
                  <tr
                    key={entry.walletAddress}
                    data-testid={`row-agent-${entry.walletAddress}`}
                    className="border-b last:border-0 hover-elevate cursor-pointer transition-colors"
                    onClick={() => (window.location.href = `/agent/${entry.walletAddress}`)}
                  >
                    <td className="px-4 py-3 text-muted-foreground font-mono text-xs">
                      {i + 1}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-0.5">
                        <span className="font-medium" data-testid={`text-agent-name-${i}`}>
                          {entry.agentName || truncateWallet(entry.walletAddress)}
                        </span>
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
                        <TrustBadge level={entry.trustLevel} />
                        <span className="text-xs text-muted-foreground tabular-nums">
                          {entry.trustScore} pts
                        </span>
                      </div>
                    </td>
                    <td className="hidden px-4 py-3 text-right md:table-cell">
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
                    <td className="hidden px-4 py-3 text-center lg:table-cell">
                      {entry.streakWeeks > 0 ? (
                        <span className="inline-flex items-center gap-1 text-sm font-medium tabular-nums text-orange-600 dark:text-orange-400">
                          <Flame className="h-3.5 w-3.5" />
                          {entry.streakWeeks}w
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="hidden px-4 py-3 text-right text-muted-foreground lg:table-cell">
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

        <p className="mt-4 text-center text-xs text-muted-foreground">
          Trust scores are computed from on-chain certification history. No self-reporting.
        </p>
      </div>
    </div>
  );
}

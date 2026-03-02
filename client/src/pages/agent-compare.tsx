import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { Shield, ArrowLeft, Loader2, AlertCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useEffect } from "react";

interface CompareAgent {
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
}

interface CompareResponse {
  agents: CompareAgent[];
}

const TRUST_LEVEL_STYLES: Record<string, string> = {
  Verified: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30",
  Trusted: "bg-green-500/15 text-green-700 dark:text-green-400 border-green-500/30",
  Active: "bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30",
  Newcomer: "bg-muted text-muted-foreground border-border",
};

const CATEGORY_LABELS: Record<string, string> = {
  trading: "Trading", data: "Data", content: "Content", code: "Code",
  research: "Research", assistant: "Assistant", healthcare: "Healthcare",
  finance: "Finance", legal: "Legal", security: "Security", other: "Other",
};

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "N/A";
  return new Date(dateStr).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function HighlightCell({ value, isMax, format }: { value: string | number; isMax: boolean; format?: "number" }) {
  const display = format === "number" ? Number(value).toLocaleString() : value;
  return (
    <span className={isMax ? "text-emerald-600 dark:text-emerald-400 font-semibold" : ""}>
      {display}
    </span>
  );
}

export default function AgentComparePage() {
  const params = new URLSearchParams(window.location.search);
  const walletsParam = params.get("wallets") || "";
  const wallets = walletsParam.split(",").filter(Boolean);

  useEffect(() => {
    document.title = "Agent Comparison | xproof";
  }, []);

  const { data, isLoading, error } = useQuery<CompareResponse>({
    queryKey: ["/api/agents/compare", walletsParam],
    queryFn: async () => {
      const res = await fetch(`/api/agents/compare?wallets=${encodeURIComponent(walletsParam)}`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch comparison data");
      return res.json();
    },
    enabled: wallets.length >= 2,
  });

  if (wallets.length < 2) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="max-w-md w-full">
          <CardContent className="flex flex-col items-center gap-4 pt-6">
            <AlertCircle className="h-10 w-10 text-muted-foreground" />
            <p className="text-muted-foreground text-center" data-testid="text-error-message">
              Please select at least 2 agents to compare.
            </p>
            <Link href="/leaderboard">
              <Button variant="outline" data-testid="link-back-leaderboard">
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Leaderboard
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Shield className="h-12 w-12 text-primary animate-pulse" />
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span data-testid="text-loading">Loading comparison...</span>
          </div>
        </div>
      </div>
    );
  }

  if (error || !data?.agents?.length) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="max-w-md w-full">
          <CardContent className="flex flex-col items-center gap-4 pt-6">
            <AlertCircle className="h-10 w-10 text-destructive" />
            <p className="text-muted-foreground text-center" data-testid="text-error-not-found">
              Agents not found. Please check the wallet addresses and try again.
            </p>
            <Link href="/leaderboard">
              <Button variant="outline" data-testid="link-back-leaderboard-error">
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Leaderboard
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    );
  }

  const agents = data.agents;

  const numericMax = (getter: (a: CompareAgent) => number) => {
    const max = Math.max(...agents.map(getter));
    return max;
  };

  const rows: { label: string; render: (agent: CompareAgent, idx: number) => JSX.Element }[] = [
    {
      label: "Agent Name",
      render: (agent) => (
        <Link href={`/agent/${agent.walletAddress}`}>
          <span className="hover:underline cursor-pointer font-medium underline-offset-2" data-testid={`text-agent-name-${agent.walletAddress}`}>
            {agent.agentName || agent.walletAddress.slice(0, 12) + "..."}
          </span>
        </Link>
      ),
    },
    {
      label: "Category",
      render: (agent) => (
        <span data-testid={`text-category-${agent.walletAddress}`}>
          {agent.agentCategory ? CATEGORY_LABELS[agent.agentCategory] || agent.agentCategory : "N/A"}
        </span>
      ),
    },
    {
      label: "Trust Level",
      render: (agent) => (
        <Badge variant="outline" className={TRUST_LEVEL_STYLES[agent.level] || TRUST_LEVEL_STYLES.Newcomer} data-testid={`badge-level-${agent.walletAddress}`}>
          {agent.level}
        </Badge>
      ),
    },
    {
      label: "Trust Score",
      render: (agent) => {
        const max = numericMax(a => a.score);
        return <HighlightCell value={agent.score} isMax={agent.score === max && agents.filter(a => a.score === max).length < agents.length} format="number" />;
      },
    },
    {
      label: "Certifications",
      render: (agent) => {
        const max = numericMax(a => a.certTotal);
        return <HighlightCell value={agent.certTotal} isMax={agent.certTotal === max && agents.filter(a => a.certTotal === max).length < agents.length} format="number" />;
      },
    },
    {
      label: "This Month",
      render: (agent) => {
        const max = numericMax(a => a.certLast30d);
        return <HighlightCell value={agent.certLast30d} isMax={agent.certLast30d === max && agents.filter(a => a.certLast30d === max).length < agents.length} format="number" />;
      },
    },
    {
      label: "Streak",
      render: (agent) => {
        const max = numericMax(a => a.streakWeeks);
        return <HighlightCell value={`${agent.streakWeeks} weeks`} isMax={agent.streakWeeks === max && agents.filter(a => a.streakWeeks === max).length < agents.length} />;
      },
    },
    {
      label: "Attestations",
      render: (agent) => {
        const max = numericMax(a => a.activeAttestations);
        return <HighlightCell value={agent.activeAttestations} isMax={agent.activeAttestations === max && agents.filter(a => a.activeAttestations === max).length < agents.length} format="number" />;
      },
    },
    {
      label: "Member Since",
      render: (agent) => <span>{formatDate(agent.firstCertAt)}</span>,
    },
    {
      label: "Last Active",
      render: (agent) => <span>{formatDate(agent.lastCertAt)}</span>,
    },
  ];

  return (
    <div className="min-h-screen bg-background" data-testid="page-agent-compare">
      <header className="border-b bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-primary" />
            <h1 className="text-lg font-semibold" data-testid="text-page-title">Agent Comparison</h1>
          </div>
          <Link href="/leaderboard">
            <Button variant="outline" size="sm" data-testid="link-back-leaderboard-header">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Leaderboard
            </Button>
          </Link>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Comparing {agents.length} Agents</CardTitle>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <table className="w-full text-sm" data-testid="table-comparison">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-3 px-3 font-medium text-muted-foreground min-w-[140px]">Metric</th>
                  {agents.map((agent) => (
                    <th key={agent.walletAddress} className="text-left py-3 px-3 font-medium min-w-[160px]" data-testid={`th-agent-${agent.walletAddress}`}>
                      {agent.agentName || agent.walletAddress.slice(0, 10) + "..."}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.label} className="border-b last:border-0">
                    <td className="py-3 px-3 font-medium text-muted-foreground">{row.label}</td>
                    {agents.map((agent, idx) => (
                      <td key={agent.walletAddress} className="py-3 px-3" data-testid={`cell-${row.label.toLowerCase().replace(/\s/g, "-")}-${agent.walletAddress}`}>
                        {row.render(agent, idx)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}

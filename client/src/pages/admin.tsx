import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { 
  Shield, 
  FileCheck, 
  Clock, 
  Activity, 
  Webhook, 
  ArrowLeft,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Minus,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  Bot,
  User,
  Zap,
  Timer,
  Eye,
  Globe,
  Target,
} from "lucide-react";
import { Link } from "wouter";

interface PricingTier {
  min: number;
  max: number | null;
  price_usd: number;
}

interface PublicStats {
  certifications: {
    total: number;
    last_24h: number;
    last_7d: number;
    last_30d: number;
    prev_7d: number;
    last_5m: number;
    by_source: { api: number; trial: number; user: number };
    by_status: Record<string, number>;
    daily: Array<{ date: string; count: number }>;
  };
  webhooks: {
    total: number;
    delivered: number;
    failed: number;
    pending: number;
    success_rate: number | null;
  };
  blockchain: {
    avg_latency_ms: number | null;
    last_known_latency_ms: number | null;
    last_known_latency_at: string | null;
    total_success: number;
    total_failed: number;
    last_success_at: string | null;
  };
  pricing?: {
    current_price_usd: number;
    current_tier: PricingTier;
    total_certifications: number;
    tiers: PricingTier[];
    next_tier: PricingTier | null;
    certifications_until_next_tier: number | null;
  };
  traffic?: {
    total_visits: number;
    unique_ips: number;
    human_visitors: number;
    agent_visitors: number;
  };
  agents?: {
    unique_active: number;
    total_api_keys: number;
  };
  generated_at: string;
}

interface HealthData {
  status: string;
  components: Record<string, { status: string; latency_ms?: number }>;
  uptime_seconds: number;
}

function StatCard({ title, value, subtitle, icon: Icon }: { title: string; value: string | number; subtitle?: string; icon: any }) {
  return (
    <Card data-testid={`stat-card-${title.toLowerCase().replace(/\s+/g, '-')}`}>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        {subtitle && <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>}
      </CardContent>
    </Card>
  );
}

function StatusIndicator({ status }: { status: string }) {
  switch (status) {
    case "ok":
    case "healthy":
      return <Badge variant="outline" className="bg-emerald-500/15 text-emerald-500 border-emerald-500/25"><CheckCircle2 className="h-3 w-3 mr-1" /> {status === "healthy" ? "Healthy" : "OK"}</Badge>;
    case "degraded":
      return <Badge variant="secondary"><AlertTriangle className="h-3 w-3 mr-1" /> Degraded</Badge>;
    case "down":
      return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" /> Down</Badge>;
    default:
      return <Badge variant="secondary">{status}</Badge>;
  }
}

function formatTimeAgo(isoDate: string): string {
  const diff = Date.now() - new Date(isoDate).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ${mins % 60}m ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  return `${hours}h ${mins}m`;
}

function TrendIndicator({ current, previous }: { current: number; previous: number }) {
  if (previous === 0 && current === 0) {
    return <span className="text-xs text-muted-foreground flex items-center gap-1"><Minus className="h-3 w-3" /> No change</span>;
  }
  if (previous === 0 && current > 0) {
    return <span className="text-xs text-chart-2 flex items-center gap-1"><TrendingUp className="h-3 w-3" /> New activity</span>;
  }
  const change = ((current - previous) / previous) * 100;
  if (Math.abs(change) < 1) {
    return <span className="text-xs text-muted-foreground flex items-center gap-1"><Minus className="h-3 w-3" /> Stable</span>;
  }
  if (change > 0) {
    return <span className="text-xs text-muted-foreground flex items-center gap-1"><TrendingUp className="h-3 w-3" /> +{current - previous} prev 7d</span>;
  }
  return <span className="text-xs text-muted-foreground flex items-center gap-1"><TrendingDown className="h-3 w-3" /> {current - previous} prev 7d</span>;
}

export default function AdminDashboard() {
  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useQuery<PublicStats>({
    queryKey: ["/api/stats"],
    refetchInterval: 30000,
  });

  const { data: health, isLoading: healthLoading } = useQuery<HealthData>({
    queryKey: ["/api/health"],
    refetchInterval: 15000,
  });

  if (statsLoading || healthLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center" data-testid="admin-loading">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-12 w-12 animate-spin text-primary" />
          <p className="text-sm text-muted-foreground">Loading platform statistics...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background" data-testid="admin-dashboard">
      <div className="max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-8">
          <div className="flex items-center gap-3">
            <Link href="/">
              <Button variant="ghost" size="icon" data-testid="button-back-home">
                <ArrowLeft />
              </Button>
            </Link>
            <Shield className="h-6 w-6 text-primary" />
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Platform Statistics</h1>
              <p className="text-sm text-muted-foreground">Real-time metrics for xproof.app</p>
            </div>
          </div>
        </div>

        {health && (
          <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 mb-6">
            <Card data-testid="card-system-health">
              <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">System Health</CardTitle>
                <StatusIndicator status={health.status} />
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-4">
                  {Object.entries(health.components || {}).map(([name, comp]) => (
                    <div key={name} className="flex items-center gap-2">
                      <StatusIndicator status={comp.status} />
                      <span className="text-sm capitalize">{name}</span>
                      {comp.latency_ms !== undefined && (
                        <span className="text-xs text-muted-foreground">({comp.latency_ms}ms)</span>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card data-testid="card-uptime">
              <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Update</CardTitle>
                <Timer className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{formatUptime(health.uptime_seconds)}</div>
                <p className="text-xs text-muted-foreground mt-1">Since last update</p>
              </CardContent>
            </Card>

            {stats && (
              <Card data-testid="card-live-activity">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    Live
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-chart-2 opacity-75" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-chart-2" />
                    </span>
                  </CardTitle>
                  <Zap className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stats.certifications.last_5m}</div>
                  <p className="text-xs text-muted-foreground mt-1">Certifications in last 5 min</p>
                </CardContent>
              </Card>
            )}
          </div>
        )}

        {stats && (
          <>
            <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 mb-6">
              <StatCard
                title="Total Certifications"
                value={stats.certifications.total}
                subtitle={`${stats.certifications.last_24h} in last 24h`}
                icon={FileCheck}
              />
              <Card data-testid="stat-card-last-7-days">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-muted-foreground">Last 7 Days</CardTitle>
                  <TrendingUp className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stats.certifications.last_7d}</div>
                  <div className="mt-1">
                    <TrendIndicator current={stats.certifications.last_7d} previous={stats.certifications.prev_7d} />
                  </div>
                </CardContent>
              </Card>
              <StatCard
                title="Certified by Agents"
                value={(stats.certifications.by_source.api || 0) + (stats.certifications.by_source.trial || 0)}
                subtitle={stats.certifications.total > 0 ? `${Math.round(((stats.certifications.by_source.api || 0) + (stats.certifications.by_source.trial || 0)) / stats.certifications.total * 100)}% of total` : "No certifications yet"}
                icon={Bot}
              />
              <StatCard
                title="Certified by Humans"
                value={stats.certifications.by_source.user || 0}
                subtitle={stats.certifications.total > 0 ? `${Math.round((stats.certifications.by_source.user || 0) / stats.certifications.total * 100)}% of total` : "No certifications yet"}
                icon={User}
              />
            </div>

            {stats?.pricing && (
              <Card className="mb-6" data-testid="card-pricing-tier">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
                  <CardTitle className="text-sm font-medium">Pricing Tier Progress</CardTitle>
                  <Target className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Current price</span>
                      <span className="text-2xl font-bold" data-testid="text-current-price">${stats.pricing.current_price_usd}</span>
                    </div>

                    {stats.pricing.next_tier && stats.pricing.certifications_until_next_tier !== null && (
                      <>
                        <div className="space-y-2">
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">
                              {stats.pricing.total_certifications.toLocaleString()} / {(stats.pricing.current_tier.max ?? stats.pricing.next_tier.min).toLocaleString()} certifications
                            </span>
                            <span className="text-muted-foreground">
                              {((stats.pricing.current_tier.max ?? stats.pricing.next_tier.min) - stats.pricing.total_certifications).toLocaleString()} to go
                            </span>
                          </div>
                          <div className="w-full bg-muted rounded-full h-3">
                            <div
                              className="bg-primary h-3 rounded-full transition-all"
                              style={{ width: `${Math.min(100, Math.max(1, (stats.pricing.total_certifications / (stats.pricing.current_tier.max ?? stats.pricing.next_tier.min)) * 100))}%` }}
                              data-testid="progress-tier"
                            />
                          </div>
                          <p className="text-xs text-muted-foreground">
                            Next tier: ${stats.pricing.next_tier.price_usd}/cert after {(stats.pricing.current_tier.max ?? stats.pricing.next_tier.min).toLocaleString()} certifications
                          </p>
                        </div>
                      </>
                    )}

                  </div>
                </CardContent>
              </Card>
            )}

            {stats?.traffic && (
              <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 mb-6">
                <StatCard
                  title="Total Visits"
                  value={stats.traffic.total_visits}
                  subtitle="All page views"
                  icon={Eye}
                />
                <StatCard
                  title="Unique Visitors"
                  value={stats.traffic.human_visitors}
                  subtitle="Distinct human IPs"
                  icon={Globe}
                />
                <StatCard
                  title="Agent Visits"
                  value={stats.traffic.agent_visitors}
                  subtitle="Bot/Crawler IPs"
                  icon={Bot}
                />
                <StatCard
                  title="Active Agents"
                  value={stats.agents?.unique_active || 0}
                  subtitle="API keys"
                  icon={Bot}
                />
                <StatCard
                  title="Trial Agents"
                  value={stats.agents?.trial_agents || 0}
                  subtitle={`${stats.agents?.trial_certifications_used || 0} certs used`}
                  icon={Bot}
                />
              </div>
            )}

            <div className="grid gap-4 grid-cols-1 lg:grid-cols-4 mb-6">
              {stats?.traffic && (
                <Card data-testid="stat-card-visitor-breakdown">
                  <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">Audience</CardTitle>
                    <User className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground flex items-center gap-2"><User className="h-3 w-3" /> Humans</span>
                        <span className="font-medium">{stats.traffic.human_visitors}</span>
                      </div>
                      <div className="w-full bg-muted rounded-full h-2">
                        <div
                          className="bg-chart-2 h-2 rounded-full transition-all"
                          style={{ width: `${(stats.traffic.human_visitors + stats.traffic.agent_visitors) > 0 ? (stats.traffic.human_visitors / (stats.traffic.human_visitors + stats.traffic.agent_visitors)) * 100 : 0}%` }}
                        />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground flex items-center gap-2"><Bot className="h-3 w-3" /> Agents</span>
                        <span className="font-medium">{stats.traffic.agent_visitors}</span>
                      </div>
                      <div className="w-full bg-muted rounded-full h-2">
                        <div
                          className="bg-primary h-2 rounded-full transition-all"
                          style={{ width: `${(stats.traffic.human_visitors + stats.traffic.agent_visitors) > 0 ? (stats.traffic.agent_visitors / (stats.traffic.human_visitors + stats.traffic.agent_visitors)) * 100 : 0}%` }}
                        />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              <Card data-testid="card-source-breakdown">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Certification Source</CardTitle>
                  <Target className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground flex items-center gap-2"><Bot className="h-4 w-4" /> API / Agent</span>
                      <span className="font-medium">{stats.certifications.by_source.api || 0}</span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div
                        className="bg-primary h-2 rounded-full transition-all"
                        style={{ width: `${stats.certifications.total > 0 ? ((stats.certifications.by_source.api || 0) / stats.certifications.total) * 100 : 0}%` }}
                      />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground flex items-center gap-2"><Bot className="h-4 w-4" /> Trial</span>
                      <span className="font-medium">{stats.certifications.by_source.trial || 0}</span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div
                        className="bg-chart-4 h-2 rounded-full transition-all"
                        style={{ width: `${stats.certifications.total > 0 ? ((stats.certifications.by_source.trial || 0) / stats.certifications.total) * 100 : 0}%` }}
                      />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground flex items-center gap-2"><User className="h-4 w-4" /> Humans</span>
                      <span className="font-medium">{stats.certifications.by_source.user || 0}</span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div
                        className="bg-chart-2 h-2 rounded-full transition-all"
                        style={{ width: `${stats.certifications.total > 0 ? ((stats.certifications.by_source.user || 0) / stats.certifications.total) * 100 : 0}%` }}
                      />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card data-testid="card-blockchain-status">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Blockchain Status</CardTitle>
                  <Activity className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Total</span>
                      <span className="font-medium">{stats.certifications.total}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground flex items-center gap-2">
                        <CheckCircle2 className="h-3 w-3 text-chart-2" /> Verified
                      </span>
                      <span className="font-medium text-chart-2">{stats.certifications.by_status.confirmed || 0}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground flex items-center gap-2">
                        <Clock className="h-3 w-3 text-yellow-500" /> Pending
                      </span>
                      <span className="font-medium">{stats.certifications.by_status.pending || 0}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground flex items-center gap-2">
                        <XCircle className="h-3 w-3 text-destructive" /> Failed
                      </span>
                      <span className="font-medium text-destructive">{stats.certifications.by_status.failed || 0}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card data-testid="stat-card-blockchain-latency">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-muted-foreground">Blockchain Latency</CardTitle>
                  <Activity className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {stats.blockchain.avg_latency_ms !== null
                      ? `${stats.blockchain.avg_latency_ms}ms`
                      : stats.blockchain.last_known_latency_ms !== null
                        ? `${stats.blockchain.last_known_latency_ms}ms`
                        : "No data"}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {stats.blockchain.avg_latency_ms !== null
                      ? `${stats.blockchain.total_success} success / ${stats.blockchain.total_failed} failed`
                      : stats.blockchain.last_known_latency_at
                        ? `Last measured ${formatTimeAgo(stats.blockchain.last_known_latency_at)}`
                        : stats.blockchain.last_success_at
                          ? `Last tx ${formatTimeAgo(stats.blockchain.last_success_at)}`
                          : "No transactions recorded yet"
                    }
                  </p>
                </CardContent>
              </Card>
            </div>

            <div className="grid gap-4 grid-cols-1 lg:grid-cols-2 mb-6">
              <Card data-testid="card-webhook-stats">
                <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
                  <CardTitle className="text-sm font-medium">Webhook Delivery</CardTitle>
                  <Webhook className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Total</span>
                      <span className="font-medium">{stats.webhooks.total}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Delivered</span>
                      <span className="font-medium text-chart-2">{stats.webhooks.delivered}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Failed</span>
                      <span className="font-medium text-destructive">{stats.webhooks.failed}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Pending</span>
                      <span className="font-medium">{stats.webhooks.pending}</span>
                    </div>
                    {stats.webhooks.success_rate !== null && (
                      <div className="flex items-center justify-between border-t pt-2">
                        <span className="text-sm font-medium">Success Rate</span>
                        <Badge variant={stats.webhooks.success_rate >= 95 ? "default" : stats.webhooks.success_rate >= 80 ? "secondary" : "destructive"}>
                          {stats.webhooks.success_rate}%
                        </Badge>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              <Card data-testid="card-daily-activity">
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Daily Activity (7d)</CardTitle>
                </CardHeader>
                <CardContent>
                  {stats.certifications.daily.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No certifications in the last 7 days</p>
                  ) : (
                    <div className="space-y-2">
                      {stats.certifications.daily.map((day) => (
                        <div key={day.date} className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">{day.date}</span>
                          <div className="flex items-center gap-2">
                            <div className="w-24 bg-muted rounded-full h-2">
                              <div
                                className="bg-primary h-2 rounded-full transition-all"
                                style={{
                                  width: `${Math.max(5, (day.count / Math.max(...stats.certifications.daily.map(d => d.count))) * 100)}%`,
                                }}
                              />
                            </div>
                            <span className="font-medium text-sm w-8 text-right">{day.count}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            <div className="flex flex-col items-center gap-2">
              <Button variant="outline" onClick={() => refetchStats()} data-testid="button-refresh-stats">
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
              <p className="text-xs text-muted-foreground">
                Last updated: {new Date(stats.generated_at).toLocaleString()} — Auto-refreshes every 30s
              </p>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

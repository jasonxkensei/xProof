import { useQuery } from "@tanstack/react-query";
import { useWalletAuth } from "@/hooks/useWalletAuth";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { 
  Shield, 
  FileCheck, 
  Clock, 
  Activity, 
  Key, 
  Webhook, 
  ArrowLeft,
  RefreshCw,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
} from "lucide-react";
import { Link } from "wouter";

interface AdminStats {
  certifications: {
    total: number;
    last_24h: number;
    last_7d: number;
    last_30d: number;
    by_source: { api: number; user: number };
    by_status: Record<string, number>;
    daily: Array<{ date: string; count: number }>;
  };
  api_keys: {
    total_active: number;
    active_last_24h: number;
  };
  webhooks: {
    total: number;
    delivered: number;
    failed: number;
    pending: number;
    success_rate: number | null;
  };
  blockchain: {
    avg_latency_ms: number;
    total_success: number;
    total_failed: number;
    last_success_at: string | null;
    last_failed_at: string | null;
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
      return <Badge variant="default"><CheckCircle2 className="h-3 w-3 mr-1" /> OK</Badge>;
    case "degraded":
      return <Badge variant="secondary"><AlertTriangle className="h-3 w-3 mr-1" /> Degraded</Badge>;
    case "down":
      return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" /> Down</Badge>;
    default:
      return <Badge variant="secondary">{status}</Badge>;
  }
}

export default function AdminDashboard() {
  const { isAuthenticated, isLoading: authLoading } = useWalletAuth();

  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useQuery<AdminStats>({
    queryKey: ["/api/admin/stats"],
    enabled: isAuthenticated,
    refetchInterval: 30000,
  });

  const { data: health, isLoading: healthLoading } = useQuery<HealthData>({
    queryKey: ["/api/health"],
    enabled: isAuthenticated,
    refetchInterval: 15000,
  });

  if (authLoading || statsLoading || healthLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center" data-testid="admin-loading">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-12 w-12 animate-spin text-primary" />
          <p className="text-sm text-muted-foreground">Loading admin dashboard...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="min-h-screen bg-background" data-testid="admin-dashboard">
      <div className="max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-8">
          <div className="flex items-center gap-3">
            <Link href="/dashboard">
              <Button variant="ghost" size="icon" data-testid="button-back-dashboard">
                <ArrowLeft />
              </Button>
            </Link>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Admin Dashboard</h1>
              <p className="text-sm text-muted-foreground">System metrics and analytics</p>
            </div>
          </div>
          <Button variant="outline" onClick={() => refetchStats()} data-testid="button-refresh-stats">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>

        {health && (
          <Card className="mb-6" data-testid="card-system-health">
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
                <div className="text-xs text-muted-foreground ml-auto">
                  Uptime: {Math.floor(health.uptime_seconds / 3600)}h {Math.floor((health.uptime_seconds % 3600) / 60)}m
                </div>
              </div>
            </CardContent>
          </Card>
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
              <StatCard
                title="Last 7 Days"
                value={stats.certifications.last_7d}
                subtitle={`${stats.certifications.last_30d} in last 30d`}
                icon={TrendingUp}
              />
              <StatCard
                title="Active API Keys"
                value={stats.api_keys.total_active}
                subtitle={`${stats.api_keys.active_last_24h} used in 24h`}
                icon={Key}
              />
              <StatCard
                title="Blockchain Latency"
                value={stats.blockchain.avg_latency_ms > 0 ? `${stats.blockchain.avg_latency_ms}ms` : "N/A"}
                subtitle={`${stats.blockchain.total_success} success / ${stats.blockchain.total_failed} failed`}
                icon={Activity}
              />
            </div>

            <div className="grid gap-4 grid-cols-1 lg:grid-cols-2 mb-6">
              <Card data-testid="card-source-breakdown">
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Certification Source</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">API / Agent</span>
                      <span className="font-medium">{stats.certifications.by_source.api}</span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div
                        className="bg-primary h-2 rounded-full transition-all"
                        style={{ width: `${stats.certifications.total > 0 ? (stats.certifications.by_source.api / stats.certifications.total) * 100 : 0}%` }}
                      />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">User (Wallet)</span>
                      <span className="font-medium">{stats.certifications.by_source.user}</span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div
                        className="bg-chart-2 h-2 rounded-full transition-all"
                        style={{ width: `${stats.certifications.total > 0 ? (stats.certifications.by_source.user / stats.certifications.total) * 100 : 0}%` }}
                      />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card data-testid="card-blockchain-status">
                <CardHeader>
                  <CardTitle className="text-sm font-medium">Blockchain Status Breakdown</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {Object.entries(stats.certifications.by_status).map(([status, statusCount]) => (
                      <div key={status} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {status === "confirmed" && <CheckCircle2 className="h-4 w-4 text-chart-2" />}
                          {status === "pending" && <Clock className="h-4 w-4 text-yellow-500" />}
                          {status === "failed" && <XCircle className="h-4 w-4 text-destructive" />}
                          {!["confirmed", "pending", "failed"].includes(status) && <Activity className="h-4 w-4 text-muted-foreground" />}
                          <span className="text-sm capitalize">{status}</span>
                        </div>
                        <span className="font-medium">{statusCount}</span>
                      </div>
                    ))}
                  </div>
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

            <div className="text-xs text-muted-foreground text-center">
              Last updated: {new Date(stats.generated_at).toLocaleString()} — Auto-refreshes every 30s
            </div>
          </>
        )}
      </div>
    </div>
  );
}

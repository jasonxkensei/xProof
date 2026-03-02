import { useEffect } from "react";
import { useWalletAuth } from "@/hooks/useWalletAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Shield, ArrowLeft, ExternalLink, Trophy } from "lucide-react";
import { Link } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useForm, Controller } from "react-hook-form";
import { apiRequest } from "@/lib/queryClient";

const CATEGORY_LABELS: Record<string, string> = {
  trading: "Trading",
  data: "Data",
  content: "Content",
  code: "Code",
  research: "Research",
  assistant: "Assistant",
  other: "Other",
};

const TRUST_LEVEL_STYLES: Record<string, string> = {
  Verified: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30",
  Trusted:  "bg-green-500/15 text-green-700 dark:text-green-400 border-green-500/30",
  Active:   "bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30",
  Newcomer: "bg-muted text-muted-foreground border-border",
};

interface AgentProfileForm {
  agentName: string;
  agentDescription: string;
  agentWebsite: string;
  agentCategory: string;
  isPublicProfile: boolean;
}

export default function Settings() {
  const { user, isLoading: authLoading, isAuthenticated } = useWalletAuth();
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: agentData } = useQuery<{
    level: string;
    score: number;
    certTotal: number;
    certLast30d: number;
  }>({
    queryKey: ["/api/agents", user?.walletAddress],
    queryFn: () =>
      fetch(`/api/agents/${user!.walletAddress}`).then((r) => {
        if (!r.ok) return null;
        return r.json();
      }),
    enabled: !!user?.walletAddress && !!user?.isPublicProfile,
    retry: false,
  });

  const { register, handleSubmit, control, reset, watch, formState: { isDirty } } =
    useForm<AgentProfileForm>({
      defaultValues: {
        agentName: "",
        agentDescription: "",
        agentWebsite: "",
        agentCategory: "",
        isPublicProfile: false,
      },
    });

  useEffect(() => {
    if (user) {
      reset({
        agentName: (user as any).agentName || "",
        agentDescription: (user as any).agentDescription || "",
        agentWebsite: (user as any).agentWebsite || "",
        agentCategory: (user as any).agentCategory || "",
        isPublicProfile: (user as any).isPublicProfile || false,
      });
    }
  }, [user, reset]);

  const mutation = useMutation({
    mutationFn: (data: AgentProfileForm) =>
      apiRequest("PATCH", "/api/user/agent-profile", {
        agentName: data.agentName || null,
        agentDescription: data.agentDescription || null,
        agentWebsite: data.agentWebsite || null,
        agentCategory: data.agentCategory || null,
        isPublicProfile: data.isPublicProfile,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/auth/me"] });
      qc.invalidateQueries({ queryKey: ["/api/agents", user?.walletAddress] });
      qc.invalidateQueries({ queryKey: ["/api/leaderboard"] });
      toast({ description: "Agent profile saved." });
    },
    onError: () => {
      toast({ variant: "destructive", description: "Failed to save profile." });
    },
  });

  const isPublic = watch("isPublicProfile");
  const agentName = watch("agentName");

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          <a href="/" className="flex items-center gap-2" data-testid="link-logo-home">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">xproof</span>
          </a>
          <Button asChild variant="ghost" size="sm" data-testid="button-back-dashboard">
            <Link href="/dashboard">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to dashboard
            </Link>
          </Button>
        </div>
      </header>

      <div className="container mx-auto max-w-4xl py-12">
        <div className="mb-8">
          <h1 className="mb-2 text-3xl font-bold tracking-tight">Settings</h1>
          <p className="text-muted-foreground">Your xproof account details</p>
        </div>

        {/* Account info */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Account information</CardTitle>
            <CardDescription>Your wallet connection details</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-medium">Wallet address</label>
              <p className="text-sm text-muted-foreground font-mono break-all" data-testid="text-wallet-address">
                {user?.walletAddress || "Not connected"}
              </p>
            </div>
            <div>
              <label className="text-sm font-medium">Email</label>
              <p className="text-sm text-muted-foreground">{user?.email || "Not provided"}</p>
            </div>
            <div>
              <label className="text-sm font-medium">Name</label>
              <p className="text-sm text-muted-foreground">
                {user?.firstName || user?.lastName
                  ? `${user?.firstName || ""} ${user?.lastName || ""}`.trim()
                  : "Not provided"}
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Agent profile */}
        <Card>
          <CardHeader>
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Trophy className="h-5 w-5 text-primary" />
                  Agent public profile
                </CardTitle>
                <CardDescription className="mt-1">
                  Appear in the{" "}
                  <Link href="/leaderboard" className="text-primary underline-offset-2 hover:underline">
                    Trust Leaderboard
                  </Link>
                  . Your trust score is computed automatically from your on-chain history — no self-reporting.
                </CardDescription>
              </div>
              {agentData && isPublic && (
                <div className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold ${TRUST_LEVEL_STYLES[agentData.level] ?? TRUST_LEVEL_STYLES.Newcomer}`}>
                  {agentData.level === "Verified" && <Shield className="h-3.5 w-3.5" />}
                  {agentData.level} · {agentData.score} pts
                </div>
              )}
            </div>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit((data) => mutation.mutate(data))} className="space-y-5">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="agentName">Agent name</Label>
                  <Input
                    id="agentName"
                    data-testid="input-agent-name"
                    placeholder="e.g. TradingBot Alpha"
                    maxLength={80}
                    {...register("agentName")}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="agentCategory">Category</Label>
                  <Controller
                    name="agentCategory"
                    control={control}
                    render={({ field }) => (
                      <Select value={field.value || ""} onValueChange={field.onChange}>
                        <SelectTrigger data-testid="select-agent-category">
                          <SelectValue placeholder="Select a category" />
                        </SelectTrigger>
                        <SelectContent>
                          {Object.entries(CATEGORY_LABELS).map(([k, v]) => (
                            <SelectItem key={k} value={k} data-testid={`option-category-${k}`}>{v}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    )}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="agentDescription">Description</Label>
                <Textarea
                  id="agentDescription"
                  data-testid="input-agent-description"
                  placeholder="What does your agent do? (max 300 chars)"
                  maxLength={300}
                  rows={3}
                  {...register("agentDescription")}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="agentWebsite">Website / repo URL</Label>
                <Input
                  id="agentWebsite"
                  data-testid="input-agent-website"
                  placeholder="https://github.com/you/your-agent"
                  type="url"
                  {...register("agentWebsite")}
                />
              </div>

              <div className="flex items-center justify-between rounded-md border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">Make my profile public</p>
                  <p className="text-xs text-muted-foreground">
                    Appear in the Trust Leaderboard. You can disable this at any time.
                  </p>
                </div>
                <Controller
                  name="isPublicProfile"
                  control={control}
                  render={({ field }) => (
                    <Switch
                      data-testid="switch-public-profile"
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  )}
                />
              </div>

              {isPublic && user?.walletAddress && (
                <div className="flex items-center gap-2 rounded-md bg-muted/50 px-4 py-3 text-sm">
                  <span className="text-muted-foreground">Public profile URL:</span>
                  <a
                    href={`/agent/${user.walletAddress}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    data-testid="link-public-profile"
                    className="flex items-center gap-1 font-mono text-xs text-primary hover:underline underline-offset-4"
                  >
                    /agent/{user.walletAddress.slice(0, 14)}…
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              )}

              <div className="flex justify-end">
                <Button
                  type="submit"
                  disabled={mutation.isPending || !isDirty}
                  data-testid="button-save-agent-profile"
                >
                  {mutation.isPending ? "Saving…" : "Save profile"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

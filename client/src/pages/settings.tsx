import { useEffect, useState } from "react";
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
import { Shield, ArrowLeft, ExternalLink, Trophy, Award, BadgeCheck, Trash2, Plus } from "lucide-react";
import { Link } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useForm, Controller } from "react-hook-form";
import { apiRequest } from "@/lib/queryClient";
import { formatDistanceToNow } from "date-fns";

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

const DOMAIN_LABELS: Record<string, string> = {
  healthcare: "Healthcare",
  finance: "Finance",
  legal: "Legal",
  security: "Security",
  research: "Research",
  other: "Other",
};

const DOMAIN_STYLES: Record<string, string> = {
  healthcare: "bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/25",
  finance:    "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/25",
  legal:      "bg-purple-500/10 text-purple-700 dark:text-purple-400 border-purple-500/25",
  security:   "bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-500/25",
  research:   "bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border-cyan-500/25",
  other:      "bg-muted text-muted-foreground border-border",
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

interface AttestationForm {
  subjectWallet: string;
  issuerName: string;
  domain: string;
  standard: string;
  title: string;
  description: string;
  expiresAt: string;
}

interface IssuedAttestation {
  id: string;
  subject_wallet: string;
  issuer_name: string;
  domain: string;
  standard: string;
  title: string;
  description: string | null;
  expires_at: string | null;
  status: string;
  created_at: string;
  revoked_at: string | null;
}

export default function Settings() {
  const { user, isLoading: authLoading, isAuthenticated } = useWalletAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [showAttestForm, setShowAttestForm] = useState(false);

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

  const { data: issuedAttestations, isLoading: issuedLoading } = useQuery<IssuedAttestation[]>({
    queryKey: ["/api/my-attestations/issued"],
    queryFn: () => fetch("/api/my-attestations/issued").then((r) => r.json()),
    enabled: isAuthenticated,
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

  const {
    register: registerAttest,
    handleSubmit: handleSubmitAttest,
    control: controlAttest,
    reset: resetAttest,
    formState: { isSubmitting: isAttesting },
  } = useForm<AttestationForm>({
    defaultValues: {
      subjectWallet: "",
      issuerName: "",
      domain: "",
      standard: "",
      title: "",
      description: "",
      expiresAt: "",
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

  const attestMutation = useMutation({
    mutationFn: (data: AttestationForm) =>
      apiRequest("POST", "/api/attestation", {
        subjectWallet: data.subjectWallet,
        issuerName: data.issuerName,
        domain: data.domain,
        standard: data.standard,
        title: data.title,
        description: data.description || null,
        expiresAt: data.expiresAt ? new Date(data.expiresAt).toISOString() : null,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/my-attestations/issued"] });
      toast({ description: "Attestation issued successfully." });
      resetAttest();
      setShowAttestForm(false);
    },
    onError: (err: any) => {
      const msg = err?.message || "Failed to issue attestation.";
      toast({ variant: "destructive", description: msg });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/attestation/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/my-attestations/issued"] });
      toast({ description: "Attestation revoked." });
    },
    onError: () => {
      toast({ variant: "destructive", description: "Failed to revoke attestation." });
    },
  });

  const isPublic = watch("isPublicProfile");

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    );
  }

  const activeAttestations = issuedAttestations?.filter((a) => a.status === "active") ?? [];
  const revokedAttestations = issuedAttestations?.filter((a) => a.status === "revoked") ?? [];

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
        <Card className="mb-6">
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

        {/* Issue Domain Attestation */}
        {isAuthenticated && (
          <Card className="mb-6">
            <CardHeader>
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Award className="h-5 w-5 text-primary" />
                    Domain attestations
                  </CardTitle>
                  <CardDescription className="mt-1">
                    Issue a domain-specific attestation for another agent's wallet.
                    Each active attestation adds +50 points to their trust score (max +150).
                  </CardDescription>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  data-testid="button-toggle-attest-form"
                  onClick={() => setShowAttestForm((v) => !v)}
                >
                  <Plus className="mr-1.5 h-3.5 w-3.5" />
                  Issue attestation
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Issue form */}
              {showAttestForm && (
                <form
                  onSubmit={handleSubmitAttest((data) => attestMutation.mutate(data))}
                  className="space-y-4 rounded-md border bg-muted/30 p-4"
                  data-testid="form-issue-attestation"
                >
                  <p className="text-sm font-medium">New attestation</p>

                  <div className="space-y-2">
                    <Label htmlFor="subjectWallet">Agent wallet address</Label>
                    <Input
                      id="subjectWallet"
                      data-testid="input-subject-wallet"
                      placeholder="erd1..."
                      {...registerAttest("subjectWallet", { required: true })}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="issuerName">Your organization / issuer name</Label>
                    <Input
                      id="issuerName"
                      data-testid="input-issuer-name"
                      placeholder="e.g. MHRA Digital Health, ISO Cert Body"
                      maxLength={120}
                      {...registerAttest("issuerName", { required: true })}
                    />
                  </div>

                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="domain">Domain</Label>
                      <Controller
                        name="domain"
                        control={controlAttest}
                        rules={{ required: true }}
                        render={({ field }) => (
                          <Select value={field.value || ""} onValueChange={field.onChange}>
                            <SelectTrigger data-testid="select-attest-domain">
                              <SelectValue placeholder="Select domain" />
                            </SelectTrigger>
                            <SelectContent>
                              {Object.entries(DOMAIN_LABELS).map(([k, v]) => (
                                <SelectItem key={k} value={k} data-testid={`option-domain-${k}`}>{v}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        )}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="standard">Standard / framework</Label>
                      <Input
                        id="standard"
                        data-testid="input-attest-standard"
                        placeholder="e.g. ISO-27001, MHRA, SOC2"
                        maxLength={80}
                        {...registerAttest("standard", { required: true })}
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="attestTitle">Attestation title</Label>
                    <Input
                      id="attestTitle"
                      data-testid="input-attest-title"
                      placeholder="e.g. Compliant with MHRA Digital Health Regulations"
                      maxLength={200}
                      {...registerAttest("title", { required: true })}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="attestDescription">Description (optional)</Label>
                    <Textarea
                      id="attestDescription"
                      data-testid="input-attest-description"
                      placeholder="Additional context about the attestation…"
                      maxLength={500}
                      rows={2}
                      {...registerAttest("description")}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="expiresAt">Expiry date (optional)</Label>
                    <Input
                      id="expiresAt"
                      data-testid="input-attest-expires"
                      type="date"
                      min={new Date().toISOString().split("T")[0]}
                      {...registerAttest("expiresAt")}
                    />
                  </div>

                  <div className="flex justify-end gap-2">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      data-testid="button-cancel-attest"
                      onClick={() => { setShowAttestForm(false); resetAttest(); }}
                    >
                      Cancel
                    </Button>
                    <Button
                      type="submit"
                      size="sm"
                      disabled={attestMutation.isPending}
                      data-testid="button-submit-attestation"
                    >
                      {attestMutation.isPending ? "Issuing…" : "Issue attestation"}
                    </Button>
                  </div>
                </form>
              )}

              {/* Issued attestations list */}
              {issuedLoading ? (
                <div className="flex items-center justify-center py-6">
                  <div className="h-6 w-6 animate-spin rounded-full border-4 border-primary border-t-transparent" />
                </div>
              ) : activeAttestations.length === 0 && revokedAttestations.length === 0 ? (
                <p className="text-sm text-muted-foreground" data-testid="text-no-attestations">
                  You haven't issued any attestations yet.
                </p>
              ) : (
                <div className="space-y-3">
                  {activeAttestations.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Active</p>
                      {activeAttestations.map((att) => (
                        <div
                          key={att.id}
                          data-testid={`row-issued-attestation-${att.id}`}
                          className="flex flex-wrap items-start justify-between gap-3 rounded-md border p-3"
                        >
                          <div className="space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <BadgeCheck className="h-4 w-4 text-emerald-500" />
                              <span className="text-sm font-medium">{att.title}</span>
                            </div>
                            <div className="flex flex-wrap items-center gap-2">
                              <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${DOMAIN_STYLES[att.domain] ?? DOMAIN_STYLES.other}`}>
                                {DOMAIN_LABELS[att.domain] ?? att.domain}
                              </span>
                              <span className="font-mono text-xs text-muted-foreground">{att.standard}</span>
                            </div>
                            <p className="font-mono text-xs text-muted-foreground">
                              → {att.subject_wallet.slice(0, 10)}…{att.subject_wallet.slice(-8)}
                            </p>
                            <p className="text-xs text-muted-foreground">
                              Issued {formatDistanceToNow(new Date(att.created_at), { addSuffix: true })}
                              {att.expires_at ? ` · Expires ${formatDistanceToNow(new Date(att.expires_at), { addSuffix: true })}` : ""}
                            </p>
                          </div>
                          <Button
                            variant="ghost"
                            size="icon"
                            data-testid={`button-revoke-attestation-${att.id}`}
                            disabled={revokeMutation.isPending}
                            onClick={() => revokeMutation.mutate(att.id)}
                            title="Revoke attestation"
                          >
                            <Trash2 className="h-4 w-4 text-muted-foreground" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}

                  {revokedAttestations.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Revoked</p>
                      {revokedAttestations.map((att) => (
                        <div
                          key={att.id}
                          data-testid={`row-revoked-attestation-${att.id}`}
                          className="flex flex-wrap items-start gap-3 rounded-md border border-dashed p-3 opacity-60"
                        >
                          <div className="space-y-1">
                            <span className="text-sm font-medium line-through">{att.title}</span>
                            <div className="flex items-center gap-2">
                              <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${DOMAIN_STYLES[att.domain] ?? DOMAIN_STYLES.other}`}>
                                {DOMAIN_LABELS[att.domain] ?? att.domain}
                              </span>
                              <span className="font-mono text-xs text-muted-foreground">{att.standard}</span>
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Revoked {att.revoked_at ? formatDistanceToNow(new Date(att.revoked_at), { addSuffix: true }) : ""}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useWalletAuth } from "@/hooks/useWalletAuth";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Upload, FileText, ExternalLink, Download, Copy, LogOut, CreditCard, Settings as SettingsIcon } from "lucide-react";
import { formatHash, copyToClipboard } from "@/lib/hashUtils";
import { format } from "date-fns";
import { Link } from "wouter";
import type { Certification } from "@shared/schema";

export default function Dashboard() {
  const { toast } = useToast();
  const { user, isLoading: authLoading, isAuthenticated, logout } = useWalletAuth();

  const { data: certifications, isLoading: certsLoading } = useQuery<Certification[]>({
    queryKey: ["/api/certifications"],
    enabled: isAuthenticated,
  });

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      // User will be redirected to landing page by App.tsx
      return;
    }
  }, [isAuthenticated, authLoading]);

  if (authLoading || certsLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          <p className="text-sm text-muted-foreground">Loading your certifications...</p>
        </div>
      </div>
    );
  }

  const handleCopy = async (text: string) => {
    const success = await copyToClipboard(text);
    if (success) {
      toast({
        title: "Copied!",
        description: "Hash copied to clipboard",
      });
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "confirmed":
        return <Badge variant="default" className="bg-chart-2 hover:bg-chart-2">Verified</Badge>;
      case "pending":
        return <Badge variant="secondary">Pending</Badge>;
      case "failed":
        return <Badge variant="destructive">Failed</Badge>;
      default:
        return <Badge variant="secondary">{status}</Badge>;
    }
  };

  const getTierDisplay = (tier: string) => {
    const tierMap: Record<string, { label: string; variant: "default" | "secondary" | "outline" }> = {
      free: { label: "Free", variant: "outline" },
      pro: { label: "Pro", variant: "default" },
      business: { label: "Business", variant: "default" },
    };
    return tierMap[tier] || { label: tier, variant: "secondary" };
  };

  const tierInfo = getTierDisplay(user?.subscriptionTier || "free");

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between px-6">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">ProofMint</span>
          </div>
          <div className="flex items-center gap-3">
            <Badge variant={tierInfo.variant as any} className="hidden sm:inline-flex" data-testid="badge-subscription-tier">
              {tierInfo.label}
            </Badge>
            <Button asChild variant="ghost" size="sm" data-testid="button-settings">
              <Link href="/settings">
                <SettingsIcon className="mr-2 h-4 w-4" />
                Settings
              </Link>
            </Button>
            <Button variant="ghost" size="sm" onClick={() => logout()} data-testid="button-logout">
              <LogOut className="mr-2 h-4 w-4" />
              Disconnect
            </Button>
          </div>
        </div>
      </header>

      <div className="container mx-auto max-w-6xl px-6 py-12">
        {/* Welcome Section */}
        <div className="mb-8">
          <h1 className="mb-2 text-3xl font-bold tracking-tight">
            Welcome back{user?.firstName ? `, ${user.firstName}` : ""}!
          </h1>
          <p className="text-muted-foreground">
            Manage your blockchain certifications and proofs
          </p>
        </div>

        {/* Stats Cards */}
        <div className="mb-8 grid gap-6 md:grid-cols-3">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Certifications</CardTitle>
              <FileText className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold" data-testid="text-total-certifications">
                {certifications?.length || 0}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">This Month</CardTitle>
              <Upload className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold" data-testid="text-monthly-usage">
                {user?.monthlyUsage || 0}
              </div>
              <p className="text-xs text-muted-foreground">
                {user?.subscriptionTier === "free" ? "of 1" : user?.subscriptionTier === "pro" ? "of 20" : "of 200"}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Subscription</CardTitle>
              <CreditCard className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold capitalize" data-testid="text-subscription-plan">
                {user?.subscriptionTier || "Free"}
              </div>
              <Button asChild variant="ghost" className="h-auto p-0 text-xs text-primary hover:text-primary/80" data-testid="link-upgrade">
                <Link href="/pricing">
                  {user?.subscriptionTier === "free" ? "Upgrade plan" : "Manage subscription"}
                </Link>
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Action Section */}
        <div className="mb-8">
          <Button asChild size="lg" data-testid="button-certify-new">
            <Link href="/certify">
              <Upload className="mr-2 h-5 w-5" />
              Certify New File
            </Link>
          </Button>
        </div>

        {/* Certifications List */}
        <div>
          <h2 className="mb-4 text-xl font-semibold">Your Certifications</h2>
          {certifications && certifications.length > 0 ? (
            <div className="space-y-4">
              {certifications.map((cert) => (
                <Card key={cert.id} className="hover-elevate">
                  <CardContent className="p-6">
                    <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="mb-2 flex items-center gap-3 flex-wrap">
                          <h3 className="font-semibold truncate" data-testid={`text-filename-${cert.id}`}>
                            {cert.fileName}
                          </h3>
                          {getStatusBadge(cert.blockchainStatus || "pending")}
                        </div>
                        <div className="space-y-1 text-sm text-muted-foreground">
                          <div className="flex items-center gap-2">
                            <span className="font-mono" data-testid={`text-hash-${cert.id}`}>
                              {formatHash(cert.fileHash, 24)}
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0"
                              onClick={() => handleCopy(cert.fileHash)}
                              data-testid={`button-copy-hash-${cert.id}`}
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </div>
                          <p data-testid={`text-date-${cert.id}`}>
                            {cert.createdAt ? format(new Date(cert.createdAt), "PPP 'at' p") : "Unknown date"}
                          </p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        {cert.transactionUrl && (
                          <Button
                            asChild
                            variant="outline"
                            size="sm"
                            data-testid={`button-view-transaction-${cert.id}`}
                          >
                            <a href={cert.transactionUrl} target="_blank" rel="noopener noreferrer">
                              <ExternalLink className="mr-2 h-4 w-4" />
                              View on Chain
                            </a>
                          </Button>
                        )}
                        {cert.isPublic && (
                          <Button
                            asChild
                            variant="outline"
                            size="sm"
                            data-testid={`button-view-proof-${cert.id}`}
                          >
                            <Link href={`/proof/${cert.id}`}>
                              <Shield className="mr-2 h-4 w-4" />
                              View Proof
                            </Link>
                          </Button>
                        )}
                        <Button
                          asChild
                          variant="default"
                          size="sm"
                          data-testid={`button-download-cert-${cert.id}`}
                        >
                          <a href={`/api/certificates/${cert.id}.pdf`} download>
                            <Download className="mr-2 h-4 w-4" />
                            Certificate
                          </a>
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                <Shield className="mb-4 h-16 w-16 text-muted-foreground/50" />
                <h3 className="mb-2 text-lg font-semibold">No certifications yet</h3>
                <p className="mb-6 text-sm text-muted-foreground">
                  Start by certifying your first file on the blockchain
                </p>
                <Button asChild data-testid="button-certify-first">
                  <Link href="/certify">
                    <Upload className="mr-2 h-4 w-4" />
                    Certify Your First File
                  </Link>
                </Button>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useWalletAuth } from "@/hooks/useWalletAuth";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Upload, FileText, ExternalLink, Download, Copy, LogOut, Settings as SettingsIcon, Activity } from "lucide-react";
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

  const { data: authData } = useQuery<{ isAdmin?: boolean }>({
    queryKey: ["/api/auth/me"],
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

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">xproof</span>
          </div>
          <div className="flex items-center gap-2 flex-wrap justify-end">
            {authData?.isAdmin && (
              <Button asChild variant="ghost" size="sm" data-testid="button-admin">
                <Link href="/admin">
                  <Activity className="h-4 w-4 sm:mr-2" />
                  <span className="hidden sm:inline">Admin</span>
                </Link>
              </Button>
            )}
            <Button asChild variant="ghost" size="sm" data-testid="button-settings">
              <Link href="/settings">
                <SettingsIcon className="h-4 w-4 sm:mr-2" />
                <span className="hidden sm:inline">Settings</span>
              </Link>
            </Button>
            <Button variant="ghost" size="sm" onClick={() => logout()} data-testid="button-logout">
              <LogOut className="h-4 w-4 sm:mr-2" />
              <span className="hidden sm:inline">Log out</span>
            </Button>
          </div>
        </div>
      </header>

      <div className="container mx-auto max-w-6xl px-4 sm:px-6 py-6 sm:py-12">
        {/* Welcome Section */}
        <div className="mb-6 sm:mb-8">
          <h1 className="mb-2 text-2xl sm:text-3xl font-bold tracking-tight">
            Welcome back{user?.firstName ? `, ${user.firstName}` : ""}!
          </h1>
          <p className="text-sm sm:text-base text-muted-foreground">
            Manage your blockchain certifications
          </p>
        </div>

        {/* Stats Card */}
        <div className="mb-8">
          <Card className="max-w-xs">
            <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">My certifications</CardTitle>
              <FileText className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold" data-testid="text-total-certifications">
                {certifications?.length || 0}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Action Section */}
        <div className="mb-8">
          <Button asChild size="lg" data-testid="button-certify-new">
            <Link href="/certify">
              <Upload className="mr-2 h-5 w-5" />
              Certify a file
            </Link>
          </Button>
        </div>

        {/* Certifications List */}
        <div>
          <h2 className="mb-4 text-xl font-semibold">Your certifications</h2>
          {certifications && certifications.length > 0 ? (
            <div className="space-y-4">
              {certifications.map((cert) => (
                <Card key={cert.id} className="hover-elevate">
                  <CardContent className="p-4 sm:p-6">
                    <div className="flex flex-col gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="mb-2 flex items-center gap-3 flex-wrap">
                          <h3 className="font-semibold truncate max-w-[200px] sm:max-w-none" data-testid={`text-filename-${cert.id}`}>
                            {cert.fileName}
                          </h3>
                          {getStatusBadge(cert.blockchainStatus || "pending")}
                        </div>
                        <div className="space-y-1 text-sm text-muted-foreground">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs sm:text-sm truncate max-w-[180px] sm:max-w-none" data-testid={`text-hash-${cert.id}`}>
                              {formatHash(cert.fileHash, 24)}
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0 shrink-0"
                              onClick={() => handleCopy(cert.fileHash)}
                              data-testid={`button-copy-hash-${cert.id}`}
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </div>
                          <p data-testid={`text-date-${cert.id}`}>
                            {cert.createdAt ? format(new Date(cert.createdAt), "MM/dd/yyyy 'at' HH:mm") : "Unknown date"}
                          </p>
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {cert.transactionUrl && (
                          <Button
                            asChild
                            variant="outline"
                            size="sm"
                            data-testid={`button-view-transaction-${cert.id}`}
                          >
                            <a href={cert.transactionUrl} target="_blank" rel="noopener noreferrer">
                              <ExternalLink className="h-4 w-4 sm:mr-2" />
                              <span className="hidden sm:inline">View on blockchain</span>
                              <span className="sm:hidden">Blockchain</span>
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
                              <Shield className="h-4 w-4 sm:mr-2" />
                              <span className="hidden sm:inline">View proof</span>
                              <span className="sm:hidden">Proof</span>
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
                            <Download className="h-4 w-4 sm:mr-2" />
                            <span className="hidden sm:inline">Certificate</span>
                            <span className="sm:hidden">PDF</span>
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
                <h3 className="mb-2 text-lg font-semibold">No certifications</h3>
                <p className="mb-6 text-sm text-muted-foreground">
                  Start by certifying your first file on the blockchain
                </p>
                <Button asChild data-testid="button-certify-first">
                  <Link href="/certify">
                    <Upload className="mr-2 h-4 w-4" />
                    Certify my first file
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

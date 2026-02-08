import { useEffect } from "react";
import { useWalletAuth } from "@/hooks/useWalletAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, ArrowLeft } from "lucide-react";
import { Link } from "wouter";

export default function Settings() {
  const { user, isLoading: authLoading, isAuthenticated } = useWalletAuth();

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      return;
    }
  }, [isAuthenticated, authLoading]);

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
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">xproof</span>
          </div>
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
          <p className="text-muted-foreground">
            Your xproof account details
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Account information</CardTitle>
            <CardDescription>Your wallet connection details</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-medium">Wallet address</label>
              <p className="text-sm text-muted-foreground font-mono break-all">
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
      </div>
    </div>
  );
}

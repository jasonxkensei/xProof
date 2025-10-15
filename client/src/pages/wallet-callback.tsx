import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { Card, CardContent } from "@/components/ui/card";
import { Loader2, CheckCircle2, AlertTriangle } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import type { User } from "@shared/schema";

export default function WalletCallback() {
  const [, navigate] = useLocation();
  const [walletAddress, setWalletAddress] = useState<string | null>(null);

  // Parse wallet address from URL on mount
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const address = params.get("address");
    
    if (address && address.startsWith("erd1")) {
      setWalletAddress(address);
    } else {
      // No valid address, redirect to home
      setTimeout(() => navigate("/"), 2000);
    }
  }, [navigate]);

  // Authenticate with wallet address
  const loginMutation = useMutation({
    mutationFn: async (address: string) => {
      const response = await apiRequest(
        "POST",
        "/api/auth/wallet/login",
        { walletAddress: address }
      );
      return response.json();
    },
    onSuccess: () => {
      // Invalidate auth query and redirect to dashboard
      queryClient.invalidateQueries({ queryKey: ["/api/auth/me"] });
      setTimeout(() => navigate("/dashboard"), 1500);
    },
    onError: (error: any) => {
      console.error("Authentication failed:", error);
      setTimeout(() => navigate("/"), 3000);
    },
  });

  // Trigger login when wallet address is available
  useEffect(() => {
    if (walletAddress && !loginMutation.isPending && !loginMutation.isSuccess) {
      loginMutation.mutate(walletAddress);
    }
  }, [walletAddress]);

  if (!walletAddress) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-6">
        <Card className="w-full max-w-md">
          <CardContent className="flex flex-col items-center py-16 text-center">
            <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-orange-500/10">
              <AlertTriangle className="h-8 w-8 text-orange-500" />
            </div>
            <h2 className="mb-2 text-2xl font-bold">Invalid Callback</h2>
            <p className="text-muted-foreground">
              No wallet address provided. Redirecting to home...
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (loginMutation.isError) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-6">
        <Card className="w-full max-w-md">
          <CardContent className="flex flex-col items-center py-16 text-center">
            <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-destructive/10">
              <AlertTriangle className="h-8 w-8 text-destructive" />
            </div>
            <h2 className="mb-2 text-2xl font-bold">Authentication Failed</h2>
            <p className="text-muted-foreground">
              Unable to authenticate with your wallet. Redirecting to home...
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (loginMutation.isSuccess) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-6">
        <Card className="w-full max-w-md">
          <CardContent className="flex flex-col items-center py-16 text-center">
            <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
              <CheckCircle2 className="h-8 w-8 text-primary" />
            </div>
            <h2 className="mb-2 text-2xl font-bold">Welcome Back!</h2>
            <p className="mb-4 text-muted-foreground">
              Successfully authenticated with your MultiversX wallet.
            </p>
            <p className="text-sm text-muted-foreground">
              Redirecting to dashboard...
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-6" data-testid="page-wallet-callback">
      <Card className="w-full max-w-md">
        <CardContent className="flex flex-col items-center py-16 text-center">
          <div className="mb-4 flex h-16 w-16 items-center justify-center">
            <Loader2 className="h-12 w-12 animate-spin text-primary" />
          </div>
          <h2 className="mb-2 text-2xl font-bold">Authenticating...</h2>
          <p className="text-muted-foreground">
            Verifying your MultiversX wallet
          </p>
          <p className="mt-2 text-xs text-muted-foreground">
            {walletAddress?.slice(0, 10)}...{walletAddress?.slice(-6)}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

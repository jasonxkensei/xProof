import { useEffect } from "react";
import { useLocation } from "wouter";
import { parseWalletCallback } from "@/lib/walletAuth";
import { useWalletAuth } from "@/hooks/useWalletAuth";
import { useToast } from "@/hooks/use-toast";

export default function WalletCallback() {
  const [, navigate] = useLocation();
  const { loginAsync } = useWalletAuth();
  const { toast } = useToast();

  useEffect(() => {
    async function handleCallback() {
      try {
        // Parse the wallet address from URL
        const address = parseWalletCallback();

        if (!address) {
          throw new Error("No wallet address received from Web Wallet");
        }

        // Login with just the address (no signature needed for simple auth)
        await loginAsync({
          address,
          signature: "webhook_auth", // Placeholder - backend will accept this in dev mode
          loginToken: `login_${Date.now()}`
        });

        toast({
          title: "🎉 Connected!",
          description: `Wallet ${address.substring(0, 10)}... authenticated`,
        });

        navigate("/dashboard");
      } catch (error: any) {
        console.error("Wallet callback error:", error);
        toast({
          variant: "destructive",
          title: "Authentication failed",
          description: error.message || "Could not authenticate with Web Wallet",
        });
        navigate("/");
      }
    }

    handleCallback();
  }, [loginAsync, navigate, toast]);

  return (
    <div className="flex h-screen items-center justify-center">
      <div className="text-center">
        <div className="mb-4 text-lg font-medium">Connecting to your wallet...</div>
        <div className="text-sm text-muted-foreground">Please wait</div>
      </div>
    </div>
  );
}

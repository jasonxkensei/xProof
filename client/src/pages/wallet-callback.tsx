import { useEffect } from "react";
import { useLocation } from "wouter";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AlertTriangle, Shield } from "lucide-react";

export default function WalletCallback() {
  const [, navigate] = useLocation();

  useEffect(() => {
    // Redirect to home after 5 seconds
    const timer = setTimeout(() => {
      navigate("/");
    }, 5000);

    return () => clearTimeout(timer);
  }, [navigate]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-6">
      <Card className="w-full max-w-md">
        <CardContent className="flex flex-col items-center py-16 text-center">
          <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-orange-500/10">
            <AlertTriangle className="h-8 w-8 text-orange-500" />
          </div>
          <h2 className="mb-2 text-2xl font-bold">Authentication Method Changed</h2>
          <p className="mb-4 text-muted-foreground">
            For security reasons, we've upgraded our authentication system to use cryptographic signature verification.
          </p>
          <div className="mb-6 rounded-lg border border-primary/20 bg-primary/5 p-4">
            <div className="flex items-start gap-2">
              <Shield className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
              <div className="text-left text-sm">
                <p className="font-medium text-primary">New Secure Login</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  Your wallet now signs a unique challenge to prove ownership. This prevents account takeover attacks.
                </p>
              </div>
            </div>
          </div>
          <Button 
            onClick={() => navigate("/")} 
            size="lg"
            data-testid="button-return-home"
          >
            Return Home to Sign In
          </Button>
          <p className="mt-4 text-xs text-muted-foreground">
            You'll be redirected automatically in 5 seconds...
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

import { useEffect, useState } from "react";
import { useWalletAuth } from "@/hooks/useWalletAuth";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Shield, CheckCircle, Loader2, AlertCircle } from "lucide-react";
import { Link } from "wouter";

export default function PaymentSuccess() {
  const { isLoading: authLoading, isAuthenticated } = useWalletAuth();
  const [status, setStatus] = useState<"checking" | "success" | "error" | "pending">("checking");
  const [message, setMessage] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const orderId = params.get("orderId");

    if (!orderId) {
      // No order ID, assume Stripe payment (redirected to /dashboard by Stripe)
      setStatus("pending");
      setMessage("Your payment is being processed. Please check your dashboard.");
      return;
    }

    // Verify xMoney payment
    const verifyPayment = async () => {
      try {
        const data = await apiRequest("GET", `/api/xmoney/order/${orderId}`) as any;
        
        if (data.status === "paid" || data.status === "completed") {
          setStatus("success");
          setMessage("Your subscription has been activated successfully!");
        } else if (data.status === "pending") {
          setStatus("pending");
          setMessage("Your payment is being processed. This may take a few minutes.");
        } else {
          setStatus("error");
          setMessage("Payment verification failed. Please contact support if you were charged.");
        }
      } catch (error: any) {
        if (error.message?.includes("Unauthorized") || error.message?.includes("401")) {
          setStatus("pending");
          setMessage("Please log in to verify your payment status.");
        } else {
          setStatus("error");
          setMessage(error.message || "Failed to verify payment. Please contact support.");
        }
      }
    };

    verifyPayment();
  }, []);

  if (authLoading || status === "checking") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-12 w-12 animate-spin text-primary" />
          <p className="text-sm text-muted-foreground">Verifying your payment...</p>
        </div>
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
            <span className="text-xl font-bold tracking-tight">ProofMint</span>
          </div>
        </div>
      </header>

      <div className="container mx-auto max-w-2xl py-16">
        <div className="flex flex-col items-center text-center">
          {status === "success" ? (
            <>
              <div className="mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-primary/10">
                <CheckCircle className="h-12 w-12 text-primary" />
              </div>
              <h1 className="mb-4 text-3xl font-bold tracking-tight">
                Payment Successful!
              </h1>
              <p className="mb-8 text-lg text-muted-foreground">
                {message || "Your subscription has been activated. You can now enjoy all the benefits of your plan."}
              </p>
              <div className="flex gap-4">
                <Button asChild size="lg" data-testid="button-dashboard">
                  <Link href="/dashboard">Go to Dashboard</Link>
                </Button>
                <Button asChild variant="outline" size="lg" data-testid="button-certify">
                  <Link href="/certify">Create Certification</Link>
                </Button>
              </div>
            </>
          ) : status === "pending" ? (
            <>
              <div className="mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-muted">
                <AlertCircle className="h-12 w-12 text-muted-foreground" />
              </div>
              <h1 className="mb-4 text-3xl font-bold tracking-tight">
                Payment Pending
              </h1>
              <p className="mb-8 text-lg text-muted-foreground">
                {message || "Your payment is being processed. Please check back shortly."}
              </p>
              <div className="flex gap-4">
                <Button asChild variant="outline" size="lg" data-testid="button-dashboard-pending">
                  <Link href="/dashboard">Go to Dashboard</Link>
                </Button>
              </div>
            </>
          ) : (
            <>
              <div className="mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-destructive/10">
                <AlertCircle className="h-12 w-12 text-destructive" />
              </div>
              <h1 className="mb-4 text-3xl font-bold tracking-tight">
                Payment Verification Failed
              </h1>
              <p className="mb-8 text-lg text-muted-foreground">
                {message || "We couldn't verify your payment. Please contact support if you believe this is an error."}
              </p>
              <div className="flex gap-4">
                <Button asChild size="lg" data-testid="button-try-again">
                  <Link href="/pricing">Try Again</Link>
                </Button>
                <Button asChild variant="outline" size="lg" data-testid="button-dashboard-error">
                  <Link href="/dashboard">Go to Dashboard</Link>
                </Button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

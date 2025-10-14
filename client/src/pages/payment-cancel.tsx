import { Button } from "@/components/ui/button";
import { Shield, XCircle } from "lucide-react";
import { Link } from "wouter";

export default function PaymentCancel() {
  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between px-6">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">ProofMint</span>
          </div>
        </div>
      </header>

      <div className="container mx-auto max-w-2xl px-6 py-16">
        <div className="flex flex-col items-center text-center">
          <div className="mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-muted">
            <XCircle className="h-12 w-12 text-muted-foreground" />
          </div>
          <h1 className="mb-4 text-3xl font-bold tracking-tight">
            Payment Cancelled
          </h1>
          <p className="mb-8 text-lg text-muted-foreground">
            Your payment was cancelled. No charges have been made to your account.
          </p>
          <div className="flex gap-4">
            <Button asChild size="lg" data-testid="button-try-again-cancel">
              <Link href="/pricing">Try Again</Link>
            </Button>
            <Button asChild variant="outline" size="lg" data-testid="button-dashboard-cancel">
              <Link href="/dashboard">Go to Dashboard</Link>
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

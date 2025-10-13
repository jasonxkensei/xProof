import { useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Shield, Check, ArrowLeft } from "lucide-react";
import { Link } from "wouter";

export default function Pricing() {
  const { toast } = useToast();
  const { user, isLoading: authLoading, isAuthenticated } = useAuth();

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      toast({
        title: "Unauthorized",
        description: "You are logged out. Logging in again...",
        variant: "destructive",
      });
      setTimeout(() => {
        window.location.href = "/api/login";
      }, 500);
      return;
    }
  }, [isAuthenticated, authLoading, toast]);

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    );
  }

  const currentTier = user?.subscriptionTier || "free";

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
          <Button asChild variant="ghost" size="sm" data-testid="button-back">
            <Link href="/dashboard">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Dashboard
            </Link>
          </Button>
        </div>
      </header>

      <div className="container mx-auto max-w-6xl px-6 py-16">
        {/* Header */}
        <div className="mb-16 text-center">
          <h1 className="mb-4 text-4xl md:text-5xl font-bold tracking-tight">
            Choose Your Plan
          </h1>
          <p className="text-lg text-muted-foreground">
            Simple, transparent pricing for blockchain certification
          </p>
        </div>

        {/* Pricing Cards */}
        <div className="grid gap-8 md:grid-cols-3">
          {/* Free Tier */}
          <Card className={currentTier === "free" ? "border-primary shadow-lg shadow-primary/20" : ""}>
            <CardHeader className="pb-8 pt-6">
              {currentTier === "free" && (
                <div className="mb-3 inline-block self-start rounded-full bg-primary px-3 py-1 text-xs font-medium text-primary-foreground">
                  Current Plan
                </div>
              )}
              <h3 className="mb-2 text-2xl font-bold">Free</h3>
              <div className="mb-4">
                <span className="text-5xl font-bold">$0</span>
                <span className="text-muted-foreground">/month</span>
              </div>
              <p className="text-sm text-muted-foreground">
                Perfect for trying out blockchain certification
              </p>
            </CardHeader>
            <CardContent className="space-y-6">
              <ul className="space-y-3">
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm">1 certification per month</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm">ProofMint watermark on certificates</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm">Public verification page</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm">MultiversX blockchain recording</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm">PDF certificate download</span>
                </li>
              </ul>
              <Button 
                variant={currentTier === "free" ? "secondary" : "outline"} 
                className="w-full" 
                disabled={currentTier === "free"}
                data-testid="button-select-free"
              >
                {currentTier === "free" ? "Current Plan" : "Downgrade to Free"}
              </Button>
            </CardContent>
          </Card>

          {/* Pro Tier */}
          <Card className={currentTier === "pro" ? "border-primary shadow-lg shadow-primary/20" : "border-primary/50 shadow-md"}>
            <CardHeader className="pb-8 pt-6">
              {currentTier !== "pro" && (
                <div className="mb-3 inline-block self-start rounded-full bg-primary px-3 py-1 text-xs font-medium text-primary-foreground">
                  Most Popular
                </div>
              )}
              {currentTier === "pro" && (
                <div className="mb-3 inline-block self-start rounded-full bg-primary px-3 py-1 text-xs font-medium text-primary-foreground">
                  Current Plan
                </div>
              )}
              <h3 className="mb-2 text-2xl font-bold">Pro</h3>
              <div className="mb-4">
                <span className="text-5xl font-bold">$9.99</span>
                <span className="text-muted-foreground">/month</span>
              </div>
              <p className="text-sm text-muted-foreground">
                For freelancers and individual creators
              </p>
            </CardHeader>
            <CardContent className="space-y-6">
              <ul className="space-y-3">
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm font-semibold">20 certifications per month</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm font-semibold">No watermark on certificates</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm">Priority support</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm">Custom branding options</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm">All Free features</span>
                </li>
              </ul>
              <Button 
                asChild
                className="w-full"
                variant={currentTier === "pro" ? "secondary" : "default"}
                disabled={currentTier === "pro"}
                data-testid="button-select-pro"
              >
                <Link href="/subscribe?plan=pro">
                  {currentTier === "pro" ? "Current Plan" : "Upgrade to Pro"}
                </Link>
              </Button>
            </CardContent>
          </Card>

          {/* Business Tier */}
          <Card className={currentTier === "business" ? "border-primary shadow-lg shadow-primary/20" : ""}>
            <CardHeader className="pb-8 pt-6">
              {currentTier === "business" && (
                <div className="mb-3 inline-block self-start rounded-full bg-primary px-3 py-1 text-xs font-medium text-primary-foreground">
                  Current Plan
                </div>
              )}
              <h3 className="mb-2 text-2xl font-bold">Business</h3>
              <div className="mb-4">
                <span className="text-5xl font-bold">$39</span>
                <span className="text-muted-foreground">/month</span>
              </div>
              <p className="text-sm text-muted-foreground">
                For agencies and professional teams
              </p>
            </CardHeader>
            <CardContent className="space-y-6">
              <ul className="space-y-3">
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm font-semibold">200 certifications per month</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm font-semibold">Full API access</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm">Complete custom branding</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm">Dedicated support</span>
                </li>
                <li className="flex items-start gap-3">
                  <Check className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  <span className="text-sm">All Pro features</span>
                </li>
              </ul>
              <Button 
                asChild
                className="w-full"
                variant={currentTier === "business" ? "secondary" : "default"}
                disabled={currentTier === "business"}
                data-testid="button-select-business"
              >
                <Link href="/subscribe?plan=business">
                  {currentTier === "business" ? "Current Plan" : "Upgrade to Business"}
                </Link>
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* FAQ or Additional Info */}
        <div className="mt-16 rounded-lg border bg-muted/30 p-8 text-center">
          <h3 className="mb-3 text-xl font-semibold">Need More?</h3>
          <p className="mb-4 text-muted-foreground">
            Enterprise plans with custom limits, dedicated infrastructure, and white-label options available.
          </p>
          <Button variant="outline" data-testid="button-contact-sales">
            Contact Sales
          </Button>
        </div>
      </div>
    </div>
  );
}

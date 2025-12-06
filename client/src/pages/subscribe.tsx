import { useEffect, useState } from "react";
import { useWalletAuth } from "@/hooks/useWalletAuth";
import { useToast } from "@/hooks/use-toast";
import { useStripe, Elements, PaymentElement, useElements } from '@stripe/react-stripe-js';
import { loadStripe } from '@stripe/stripe-js';
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Shield, ArrowLeft, Loader2, CreditCard, Coins } from "lucide-react";
import { Link } from "wouter";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

const stripePublicKey = import.meta.env.VITE_STRIPE_PUBLIC_KEY;
const isValidPublicKey = stripePublicKey && stripePublicKey.startsWith('pk_');

if (!isValidPublicKey) {
  console.error('⚠️ Stripe: Invalid or missing public key. Key must start with "pk_". Current key starts with:', stripePublicKey?.substring(0, 3));
}

const stripePromise = isValidPublicKey ? loadStripe(stripePublicKey) : null;

const SubscribeForm = ({ plan }: { plan: string }) => {
  const stripe = useStripe();
  const elements = useElements();
  const { toast } = useToast();
  const [isProcessing, setIsProcessing] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!stripe || !elements) {
      return;
    }

    setIsProcessing(true);

    const { error } = await stripe.confirmPayment({
      elements,
      confirmParams: {
        return_url: `${window.location.origin}/dashboard`,
      },
    });

    if (error) {
      toast({
        title: "Payment Failed",
        description: error.message,
        variant: "destructive",
      });
      setIsProcessing(false);
    } else {
      toast({
        title: "Payment Successful",
        description: "You are now subscribed!",
      });
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <PaymentElement />
      <Button 
        type="submit" 
        disabled={!stripe || isProcessing} 
        className="w-full"
        data-testid="button-complete-subscription"
      >
        {isProcessing ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Processing...
          </>
        ) : (
          `Subscribe to ${plan.charAt(0).toUpperCase() + plan.slice(1)}`
        )}
      </Button>
    </form>
  );
};

const XMoneyPayment = ({ plan }: { plan: string }) => {
  const { toast } = useToast();
  const [isProcessing, setIsProcessing] = useState(false);

  const planPrices: Record<string, number> = {
    pro: 9.99,
    business: 39,
  };

  const handleXMoneyPayment = async () => {
    setIsProcessing(true);
    try {
      const data = await apiRequest("POST", "/api/xmoney/create-payment", {
        amount: planPrices[plan],
        currency: "USD",
        description: `ProofMint ${plan.charAt(0).toUpperCase() + plan.slice(1)} Subscription`,
      }) as { paymentUrl?: string; orderId?: string; message?: string };
      
      if (data.paymentUrl) {
        // Redirect to xMoney payment page
        window.location.href = data.paymentUrl;
      } else {
        toast({
          title: "Error",
          description: data.message || "Failed to create payment link",
          variant: "destructive",
        });
        setIsProcessing(false);
      }
    } catch (error: any) {
      const errorMessage = error.message || "Failed to initialize xMoney payment";
      toast({
        title: "Payment Error",
        description: errorMessage.includes("503") 
          ? "xMoney payment service is not configured. Please use card payment."
          : errorMessage,
        variant: "destructive",
      });
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="rounded-lg border bg-muted/50 p-4">
        <p className="text-sm text-muted-foreground">
          Pay with cryptocurrency using xMoney (powered by MultiversX)
        </p>
        <p className="mt-2 text-2xl font-bold">${planPrices[plan]}/month</p>
      </div>
      
      <Button 
        onClick={handleXMoneyPayment}
        disabled={isProcessing} 
        className="w-full"
        data-testid="button-xmoney-payment"
      >
        {isProcessing ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Redirecting to xMoney...
          </>
        ) : (
          <>
            <Coins className="mr-2 h-4 w-4" />
            Pay with Crypto
          </>
        )}
      </Button>
    </div>
  );
};

export default function Subscribe() {
  const { toast } = useToast();
  const { user, isLoading: authLoading, isAuthenticated } = useWalletAuth();
  const [clientSecret, setClientSecret] = useState("");
  const [plan, setPlan] = useState<string>("pro");

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      // User will be redirected to landing page by App.tsx
      return;
    }
  }, [isAuthenticated, authLoading]);

  useEffect(() => {
    // Get plan from URL query params
    const params = new URLSearchParams(window.location.search);
    const planParam = params.get("plan");
    if (planParam) {
      setPlan(planParam);
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated && plan) {
      // Create subscription payment intent
      apiRequest("POST", "/api/create-subscription", { plan })
        .then((data) => {
          const response = data as { clientSecret?: string };
          if (response.clientSecret) {
            setClientSecret(response.clientSecret);
          }
        })
        .catch((error) => {
          toast({
            title: "Error",
            description: "Failed to initialize payment",
            variant: "destructive",
          });
        });
    }
  }, [isAuthenticated, plan, toast]);

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    );
  }

  const planPrices: Record<string, string> = {
    pro: "$9.99",
    business: "$39",
  };

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
          <Button asChild variant="ghost" size="sm" data-testid="button-back-pricing">
            <Link href="/pricing">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Pricing
            </Link>
          </Button>
        </div>
      </header>

      <div className="container mx-auto max-w-2xl px-6 py-16">
        <div className="mb-8 text-center">
          <h1 className="mb-4 text-3xl font-bold tracking-tight">
            Subscribe to {plan.charAt(0).toUpperCase() + plan.slice(1)}
          </h1>
          <p className="text-lg text-muted-foreground">
            {planPrices[plan]}/month • Cancel anytime
          </p>
        </div>

        <Tabs defaultValue="stripe" className="w-full">
          <TabsList className="grid w-full grid-cols-2 mb-6" data-testid="tabs-payment-method">
            <TabsTrigger value="stripe" data-testid="tab-stripe">
              <CreditCard className="mr-2 h-4 w-4" />
              Card Payment
            </TabsTrigger>
            <TabsTrigger value="xmoney" data-testid="tab-xmoney">
              <Coins className="mr-2 h-4 w-4" />
              Crypto (xMoney)
            </TabsTrigger>
          </TabsList>

          <TabsContent value="stripe">
            {!clientSecret ? (
              <div className="flex flex-col items-center gap-4 py-16">
                <div className="h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent" />
                <p className="text-sm text-muted-foreground">Setting up your subscription...</p>
              </div>
            ) : (
              <div className="rounded-lg border bg-card p-6">
                <Elements stripe={stripePromise} options={{ clientSecret }}>
                  <SubscribeForm plan={plan} />
                </Elements>
              </div>
            )}
          </TabsContent>

          <TabsContent value="xmoney">
            <div className="rounded-lg border bg-card p-6">
              <XMoneyPayment plan={plan} />
            </div>
          </TabsContent>
        </Tabs>

        <div className="mt-8 text-center text-sm text-muted-foreground">
          <p>By subscribing, you agree to our Terms of Service and Privacy Policy</p>
        </div>
      </div>
    </div>
  );
}

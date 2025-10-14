import { Switch, Route } from "wouter";
import { useEffect } from "react";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { DappProvider } from "@multiversx/sdk-dapp/wrappers/DappProvider";
import { useGetIsLoggedIn } from "@multiversx/sdk-dapp/hooks";
import { EnvironmentsEnum } from "@multiversx/sdk-dapp/types";
import NotFound from "@/pages/not-found";
import Landing from "@/pages/landing";
import Unlock from "@/pages/unlock";
import Dashboard from "@/pages/dashboard";
import Certify from "@/pages/certify";
import ProofPage from "@/pages/proof";
import Pricing from "@/pages/pricing";
import Subscribe from "@/pages/subscribe";
import Settings from "@/pages/settings";
import PaymentSuccess from "@/pages/payment-success";
import PaymentCancel from "@/pages/payment-cancel";

function Router() {
  const isLoggedIn = useGetIsLoggedIn();

  return (
    <Switch>
      {!isLoggedIn ? (
        <>
          <Route path="/" component={Landing} />
          <Route path="/unlock" component={Unlock} />
        </>
      ) : (
        <>
          <Route path="/" component={Dashboard} />
          <Route path="/dashboard" component={Dashboard} />
          <Route path="/certify" component={Certify} />
          <Route path="/pricing" component={Pricing} />
          <Route path="/subscribe" component={Subscribe} />
          <Route path="/settings" component={Settings} />
        </>
      )}
      <Route path="/proof/:id" component={ProofPage} />
      <Route path="/payment/success" component={PaymentSuccess} />
      <Route path="/payment/cancel" component={PaymentCancel} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <DappProvider
        environment={EnvironmentsEnum.devnet}
        customNetworkConfig={{
          name: "customConfig",
          apiTimeout: 10000,
          walletConnectV2ProjectId: "9b1a9564f91cb6599c03b5a8e3e6e8e7"
        }}
      >
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </DappProvider>
    </QueryClientProvider>
  );
}

export default App;

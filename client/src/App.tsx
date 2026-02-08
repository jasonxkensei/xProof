import { Switch, Route, Redirect, useLocation } from "wouter";
import { logger } from "@/lib/logger";
import { useEffect, useState } from "react";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useWalletAuth } from "@/hooks/useWalletAuth";
import { useXPortalRecovery } from "@/hooks/useXPortalRecovery";
import { WalletLoginModal } from "@/components/wallet-login-modal";
import NotFound from "@/pages/not-found";
import Landing from "@/pages/landing";
import Dashboard from "@/pages/dashboard";
import Certify from "@/pages/certify";
import ProofPage from "@/pages/proof";
import Settings from "@/pages/settings";
import MentionsLegales from "@/pages/legal/mentions";
import PolitiqueConfidentialite from "@/pages/legal/privacy";
import ConditionsUtilisation from "@/pages/legal/terms";
import AgentsPage from "@/pages/agents";
import { Shield, Loader2 } from "lucide-react";

function Router() {
  const { isAuthenticated, isLoading } = useWalletAuth();

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4">
          <Shield className="h-12 w-12 text-primary animate-pulse" />
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span>Loading...</span>
          </div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <Switch>
        <Route path="/" component={Landing} />
        <Route path="/proof/:id" component={ProofPage} />
        <Route path="/legal/mentions" component={MentionsLegales} />
        <Route path="/legal/privacy" component={PolitiqueConfidentialite} />
        <Route path="/legal/terms" component={ConditionsUtilisation} />
        <Route path="/agents" component={AgentsPage} />
        <Route>
          <Redirect to="/" />
        </Route>
      </Switch>
    );
  }

  return (
    <Switch>
      <Route path="/" component={Dashboard} />
      <Route path="/dashboard" component={Dashboard} />
      <Route path="/certify" component={Certify} />
      <Route path="/settings" component={Settings} />
      <Route path="/proof/:id" component={ProofPage} />
      <Route path="/legal/mentions" component={MentionsLegales} />
      <Route path="/legal/privacy" component={PolitiqueConfidentialite} />
      <Route path="/legal/terms" component={ConditionsUtilisation} />
      <Route path="/agents" component={AgentsPage} />
      <Route component={NotFound} />
    </Switch>
  );
}

// Global xPortal recovery handler - ensures recovery works on any route
function XPortalRecoveryHandler() {
  const { needsRecovery, clearRecovery, pendingConnection } = useXPortalRecovery();
  const [showRecoveryModal, setShowRecoveryModal] = useState(false);
  const { isAuthenticated } = useWalletAuth();
  const [, navigate] = useLocation();
  const [location] = useLocation();
  
  useEffect(() => {
    // Only trigger recovery if user is not already authenticated
    // and we're not on a page that already has a wallet modal
    if (needsRecovery && !isAuthenticated) {
      // Check if we're on landing or certify which have their own modals
      const pagesWithModals = ['/', '/certify'];
      if (!pagesWithModals.includes(location)) {
        logger.log('📱 Global xPortal recovery: Detected pending connection on non-modal page');
        setShowRecoveryModal(true);
      }
    }
  }, [needsRecovery, isAuthenticated, location]);
  
  // If authenticated, clear recovery state
  useEffect(() => {
    if (isAuthenticated && needsRecovery) {
      clearRecovery();
    }
  }, [isAuthenticated, needsRecovery, clearRecovery]);
  
  if (!showRecoveryModal) return null;
  
  return (
    <WalletLoginModal 
      open={showRecoveryModal} 
      onOpenChange={(open) => {
        setShowRecoveryModal(open);
        if (!open) {
          clearRecovery();
          // Navigate to original URL or landing if closed
          const returnUrl = pendingConnection?.returnUrl;
          if (returnUrl && returnUrl !== window.location.href) {
            navigate(new URL(returnUrl).pathname);
          } else {
            navigate('/');
          }
        }
      }} 
    />
  );
}

function App() {
  useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <XPortalRecoveryHandler />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;

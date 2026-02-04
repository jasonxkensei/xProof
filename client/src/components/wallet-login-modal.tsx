import { useState, useEffect, useRef, useCallback } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ProviderFactory } from '@multiversx/sdk-dapp/out/providers/ProviderFactory';
import { ProviderTypeEnum } from '@multiversx/sdk-dapp/out/providers/types/providerFactory.types';
import { useGetIsLoggedIn } from '@multiversx/sdk-dapp/out/react/account/useGetIsLoggedIn';
import { useGetAccount } from '@multiversx/sdk-dapp/out/react/account/useGetAccount';
import { Shield, Wallet, Loader2, X, Smartphone } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useLocation } from "wouter";
import { queryClient } from "@/lib/queryClient";
import { useXPortalRecovery, savePendingXPortalConnection, clearPendingXPortalConnection } from "@/hooks/useXPortalRecovery";

interface WalletLoginModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const isMobileDevice = () => {
  if (typeof navigator === 'undefined') return false;
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
};

export function WalletLoginModal({ open, onOpenChange }: WalletLoginModalProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [waitingForConnection, setWaitingForConnection] = useState(false);
  const providerRef = useRef<any>(null);
  const syncAttempted = useRef(false);
  const pollingIntervalsRef = useRef<Set<NodeJS.Timeout>>(new Set());
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const isLoggedIn = useGetIsLoggedIn();
  const { address } = useGetAccount();
  
  // Helper to track and manage polling intervals
  const addPollingInterval = (intervalId: NodeJS.Timeout) => {
    pollingIntervalsRef.current.add(intervalId);
  };
  
  const removePollingInterval = (intervalId: NodeJS.Timeout) => {
    clearInterval(intervalId);
    pollingIntervalsRef.current.delete(intervalId);
  };
  
  const clearAllPollingIntervals = () => {
    pollingIntervalsRef.current.forEach(id => clearInterval(id));
    pollingIntervalsRef.current.clear();
  };
  
  // Cleanup polling intervals on unmount
  useEffect(() => {
    return () => {
      clearAllPollingIntervals();
    };
  }, []);

  const syncAndRedirect = useCallback(async (walletAddress: string): Promise<boolean> => {
    if (syncAttempted.current) return false;
    syncAttempted.current = true;
    
    try {
      console.log('🔄 Syncing wallet with backend:', walletAddress);
      
      const response = await fetch('/api/auth/wallet/simple-sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ walletAddress }),
      });
      
      if (response.ok) {
        const userData = await response.json();
        console.log('✅ Backend sync successful:', userData);
        
        localStorage.setItem('walletAddress', walletAddress);
        
        queryClient.setQueryData(['/api/auth/me'], userData);
        await queryClient.invalidateQueries({ queryKey: ['/api/auth/me'] });
        
        toast({
          title: "Wallet connecté",
          description: `Connecté : ${walletAddress.substring(0, 10)}...${walletAddress.slice(-6)}`,
        });
        
        onOpenChange(false);
        navigate('/dashboard');
        
        return true;
      } else {
        const errorText = await response.text().catch(() => 'Unknown error');
        console.error('Backend sync failed:', response.status, errorText);
        
        setError('Échec de la synchronisation. Veuillez réessayer.');
        setLoading(null);
        setWaitingForConnection(false);
        syncAttempted.current = false;
        
        toast({
          title: "Erreur de connexion",
          description: "Impossible de créer votre session.",
          variant: "destructive"
        });
        
        return false;
      }
    } catch (err) {
      console.error('Sync error:', err);
      setError('Erreur de connexion au serveur.');
      setLoading(null);
      setWaitingForConnection(false);
      syncAttempted.current = false;
      
      toast({
        title: "Erreur de connexion",
        description: "Une erreur est survenue.",
        variant: "destructive"
      });
      
      return false;
    }
  }, [toast, onOpenChange, navigate]);

  useEffect(() => {
    if (isLoggedIn && address && open && !syncAttempted.current) {
      console.log('✅ SDK detected login:', address);
      syncAndRedirect(address);
    }
  }, [isLoggedIn, address, open, syncAndRedirect]);

  useEffect(() => {
    if (!open) {
      setLoading(null);
      setError(null);
      setWaitingForConnection(false);
      syncAttempted.current = false;
      // Clear any active polling intervals when modal closes
      clearAllPollingIntervals();
    }
  }, [open]);

  const handleExtensionLogin = async () => {
    setLoading('extension');
    setError(null);
    syncAttempted.current = false;
    
    try {
      console.log('🔌 Creating extension provider...');
      console.log('🌐 Current origin:', window.location.origin);
      console.log('🔗 Current hostname:', window.location.hostname);
      
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.extension 
      });
      providerRef.current = provider;
      console.log('✅ Extension provider created:', provider);
      
      if (typeof provider.init === 'function') {
        console.log('📡 Initializing provider...');
        await provider.init();
        console.log('✅ Provider initialized');
      }
      
      console.log('🔐 Calling extension login...');
      const loginResult = await provider.login();
      console.log('📋 Extension login result:', JSON.stringify(loginResult, null, 2));
      
      let walletAddress = '';
      
      if (loginResult && typeof loginResult === 'object' && 'address' in loginResult) {
        walletAddress = (loginResult as any).address;
      }
      
      if (!walletAddress) {
        try {
          if (typeof (provider as any).getAddress === 'function') {
            walletAddress = await (provider as any).getAddress();
          }
        } catch (e) {
          console.log('getAddress failed:', e);
        }
      }
      
      if (!walletAddress && (provider as any).account?.address) {
        walletAddress = (provider as any).account.address;
      }
      
      console.log('📍 Got wallet address:', walletAddress);
      
      if (walletAddress && walletAddress.startsWith('erd1')) {
        await syncAndRedirect(walletAddress);
      } else {
        console.log('⏳ Address not immediately available, waiting for SDK...');
        setWaitingForConnection(true);
        
        let attempts = 0;
        const maxAttempts = 10;
        const intervalId = setInterval(async () => {
          attempts++;
          
          let addr = '';
          try {
            if (typeof (provider as any).getAddress === 'function') {
              addr = await (provider as any).getAddress();
            }
          } catch (e) { }
          
          if (addr && addr.startsWith('erd1')) {
            removePollingInterval(intervalId);
            setWaitingForConnection(false);
            await syncAndRedirect(addr);
          } else if (attempts >= maxAttempts) {
            removePollingInterval(intervalId);
            setWaitingForConnection(false);
            setLoading(null);
            setError('Connexion expirée. Veuillez réessayer.');
          }
        }, 500);
        addPollingInterval(intervalId);
      }
    } catch (err: any) {
      console.error('❌ Extension login error:', err);
      console.error('❌ Error name:', err?.name);
      console.error('❌ Error message:', err?.message);
      console.error('❌ Error stack:', err?.stack);
      
      const errorMsg = err.message || "Veuillez installer l'extension MultiversX";
      setError(`Erreur: ${errorMsg}`);
      toast({
        title: "Échec de connexion",
        description: errorMsg,
        variant: "destructive"
      });
      setLoading(null);
      setWaitingForConnection(false);
    }
  };

  const handleWebWalletLogin = async () => {
    setLoading('webwallet');
    setError(null);
    syncAttempted.current = false;
    
    try {
      console.log('🌐 Creating web wallet provider...');
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.crossWindow 
      });
      
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      console.log('🔐 Calling web wallet login...');
      await provider.login();
      console.log('✅ Web Wallet login completed');
      
    } catch (err: any) {
      console.error('Web Wallet login error:', err);
      setError(err.message || "Impossible de se connecter");
      toast({
        title: "Échec de connexion",
        description: err.message || "Erreur Web Wallet",
        variant: "destructive"
      });
      setLoading(null);
    }
  };

  const handleWalletConnectLogin = async () => {
    setLoading('walletconnect');
    setError(null);
    syncAttempted.current = false;
    
    try {
      console.log('📱 Creating WalletConnect provider via SDK...');
      console.log('🌐 Current origin:', window.location.origin);
      console.log('🔗 Current hostname:', window.location.hostname);
      
      const provider = await ProviderFactory.create({
        type: ProviderTypeEnum.walletConnect
      });
      providerRef.current = provider;
      console.log('✅ WalletConnect provider created:', provider);
      
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      console.log('🔐 Calling WalletConnect login...');
      
      // Save pending connection state before potential deep link navigation
      // This helps recover if the browser tab is killed on mobile
      if (isMobileDevice()) {
        savePendingXPortalConnection();
        console.log('📱 Saved pending xPortal connection state for recovery');
        
        toast({
          title: "xPortal",
          description: "Validez la connexion dans xPortal puis revenez sur cette page.",
        });
      }
      
      setWaitingForConnection(true);
      
      const loginResult = await provider.login();
      console.log('📋 WalletConnect login result:', loginResult);
      
      let walletAddress = '';
      
      if (loginResult && typeof loginResult === 'object' && 'address' in loginResult) {
        walletAddress = (loginResult as any).address;
      }
      
      if (!walletAddress) {
        try {
          if (typeof (provider as any).getAddress === 'function') {
            walletAddress = await (provider as any).getAddress();
          }
        } catch (e) {
          console.log('getAddress failed:', e);
        }
      }
      
      console.log('📍 Got wallet address from WalletConnect:', walletAddress);
      
      if (walletAddress && walletAddress.startsWith('erd1')) {
        // Clear pending state on successful connection
        clearPendingXPortalConnection();
        setWaitingForConnection(false);
        await syncAndRedirect(walletAddress);
      } else {
        let attempts = 0;
        const maxAttempts = 60;
        const intervalId = setInterval(async () => {
          attempts++;
          
          let addr = '';
          try {
            if (typeof (provider as any).getAddress === 'function') {
              addr = await (provider as any).getAddress();
            }
          } catch (e) { }
          
          if (addr && addr.startsWith('erd1')) {
            removePollingInterval(intervalId);
            clearPendingXPortalConnection();
            setWaitingForConnection(false);
            await syncAndRedirect(addr);
          } else if (attempts >= maxAttempts) {
            removePollingInterval(intervalId);
            clearPendingXPortalConnection();
            setWaitingForConnection(false);
            setLoading(null);
            setError('Connexion expirée. Veuillez réessayer.');
          }
        }, 1000);
        addPollingInterval(intervalId);
      }
      
    } catch (err: any) {
      console.error('WalletConnect error:', err);
      clearPendingXPortalConnection();
      
      if (err.message?.includes('rejected') || err.message?.includes('cancelled') || err.message?.includes('Proposal')) {
        setLoading(null);
        setWaitingForConnection(false);
        return;
      }
      
      setError(err.message || "Erreur de connexion xPortal");
      toast({
        title: "Échec de connexion",
        description: err.message || "Erreur xPortal",
        variant: "destructive"
      });
      setLoading(null);
      setWaitingForConnection(false);
    }
  };

  // Use xPortal recovery hook  
  const { needsRecovery, clearRecovery, pendingConnection } = useXPortalRecovery();
  const recoveryAttemptedRef = useRef(false);
  const shouldAutoStartRef = useRef(false);
  
  // Clear recovery state when user is successfully logged in
  useEffect(() => {
    if (isLoggedIn && address && needsRecovery) {
      console.log('📱 xPortal recovery: User logged in, clearing recovery state');
      clearRecovery();
    }
  }, [isLoggedIn, address, needsRecovery, clearRecovery]);
  
  // Check for pending xPortal connection on component mount (recovery after deep link return)
  useEffect(() => {
    if (needsRecovery && !open && !recoveryAttemptedRef.current) {
      recoveryAttemptedRef.current = true;
      shouldAutoStartRef.current = true;
      console.log('📱 xPortal recovery: Auto-opening modal for reconnection...');
      // Don't clear recovery until connection succeeds - it's cleared when isLoggedIn becomes true
      onOpenChange(true);
    }
  }, [needsRecovery, open, onOpenChange]);
  
  // Auto-start WalletConnect when modal opens for recovery (reuse existing handler)
  useEffect(() => {
    if (open && shouldAutoStartRef.current && !loading && !waitingForConnection) {
      shouldAutoStartRef.current = false;
      console.log('📱 xPortal recovery: Starting WalletConnect login...');
      
      // Small delay to let modal fully render, then call the existing handler
      const timer = setTimeout(() => {
        handleWalletConnectLogin();
      }, 300);
      
      return () => clearTimeout(timer);
    }
  }, [open, loading, waitingForConnection]);
  
  // Reset recovery state when modal closes
  useEffect(() => {
    if (!open) {
      recoveryAttemptedRef.current = false;
    }
  }, [open]);

  const handleCancel = () => {
    if (providerRef.current && typeof providerRef.current.logout === 'function') {
      try { providerRef.current.logout(); } catch (e) { }
    }
    setLoading(null);
    setWaitingForConnection(false);
  };

  if (waitingForConnection) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-md" data-testid="modal-wallet-login">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {loading === 'walletconnect' ? (
                <Smartphone className="h-5 w-5 text-primary" />
              ) : (
                <Wallet className="h-5 w-5 text-primary" />
              )}
              Connexion en cours...
            </DialogTitle>
            <DialogDescription>
              {loading === 'walletconnect' 
                ? "Validez la connexion dans xPortal puis revenez ici"
                : "Validez la connexion dans votre wallet"
              }
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col items-center py-6 space-y-4">
            <Loader2 className="h-12 w-12 animate-spin text-primary" />
            <p className="text-center text-muted-foreground">
              En attente de validation...
            </p>
            {loading === 'walletconnect' && isMobileDevice() && (
              <p className="text-center text-sm text-muted-foreground">
                Après avoir validé dans xPortal, revenez sur cette page.
              </p>
            )}
            <Button variant="ghost" onClick={handleCancel} data-testid="button-cancel">
              <X className="h-4 w-4 mr-2" />
              Annuler
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md" data-testid="modal-wallet-login">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            Connectez votre wallet
          </DialogTitle>
          <DialogDescription>
            Choisissez votre méthode de connexion
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="p-3 text-sm text-destructive bg-destructive/10 rounded-md">
            {error}
          </div>
        )}

        <div className="space-y-3 py-4">
          <Button
            onClick={handleExtensionLogin}
            disabled={loading !== null}
            className="w-full justify-start gap-3"
            variant="default"
            data-testid="button-extension-login"
          >
            {loading === 'extension' ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Wallet className="h-5 w-5" />
            )}
            <span>MultiversX Wallet Extension</span>
          </Button>

          <Button
            onClick={handleWalletConnectLogin}
            disabled={loading !== null}
            className="w-full justify-start gap-3"
            variant="outline"
            data-testid="button-walletconnect-login"
          >
            {loading === 'walletconnect' ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Smartphone className="h-5 w-5" />
            )}
            <span>xPortal App (Mobile)</span>
          </Button>

          <Button
            onClick={handleWebWalletLogin}
            disabled={loading !== null}
            className="w-full justify-start gap-3"
            variant="outline"
            data-testid="button-webwallet-login"
          >
            {loading === 'webwallet' ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Wallet className="h-5 w-5" />
            )}
            <span>MultiversX Web Wallet</span>
          </Button>
        </div>

        <p className="text-xs text-muted-foreground text-center">
          Authentification sécurisée par signature cryptographique
        </p>
      </DialogContent>
    </Dialog>
  );
}

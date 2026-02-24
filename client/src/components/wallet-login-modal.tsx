import { useState, useEffect, useRef, useCallback } from "react";
import { logger } from "@/lib/logger";
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
import { loginAction, logoutAction } from '@multiversx/sdk-dapp/out/store/actions/sharedActions/sharedActions';
import { useGetIsLoggedIn } from '@multiversx/sdk-dapp/out/react/account/useGetIsLoggedIn';
import { useGetAccount } from '@multiversx/sdk-dapp/out/react/account/useGetAccount';
import { Shield, Wallet, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useLocation } from "wouter";
import { queryClient } from "@/lib/queryClient";

interface WalletLoginModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  redirectTo?: string;
}

export function WalletLoginModal({ open, onOpenChange, redirectTo }: WalletLoginModalProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [waitingForConnection, setWaitingForConnection] = useState(false);
  const providerRef = useRef<any>(null);
  const syncAttempted = useRef(false);
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const isLoggedIn = useGetIsLoggedIn();
  const { address } = useGetAccount();

  const syncAndRedirect = useCallback(async (walletAddress: string): Promise<boolean> => {
    if (syncAttempted.current) return false;
    syncAttempted.current = true;
    
    try {
      logger.log('Syncing wallet with backend:', walletAddress);
      
      const response = await fetch('/api/auth/wallet/simple-sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ walletAddress }),
      });
      
      if (response.ok) {
        const userData = await response.json();
        logger.log('Backend sync successful');
        
        localStorage.setItem('walletAddress', walletAddress);
        
        loginAction({ address: walletAddress, providerType: ProviderTypeEnum.extension });
        
        queryClient.setQueryData(['/api/auth/me'], userData);
        await queryClient.invalidateQueries({ queryKey: ['/api/auth/me'] });
        
        toast({
          title: "Wallet connected",
          description: `Connected: ${walletAddress.substring(0, 10)}...${walletAddress.slice(-6)}`,
        });
        
        onOpenChange(false);
        navigate(redirectTo || '/dashboard');
        
        return true;
      } else {
        const errorText = await response.text().catch(() => 'Unknown error');
        console.error('Backend sync failed:', response.status, errorText);
        
        setError('Sync failed. Please try again.');
        setLoading(false);
        setWaitingForConnection(false);
        syncAttempted.current = false;
        
        toast({
          title: "Connection error",
          description: "Unable to create your session.",
          variant: "destructive"
        });
        
        return false;
      }
    } catch (err) {
      console.error('Sync error:', err);
      setError('Server connection error.');
      setLoading(false);
      setWaitingForConnection(false);
      syncAttempted.current = false;
      
      toast({
        title: "Connection error",
        description: "An error occurred.",
        variant: "destructive"
      });
      
      return false;
    }
  }, [toast, onOpenChange, navigate]);

  useEffect(() => {
    if (isLoggedIn && address && open && !syncAttempted.current) {
      logger.log('SDK detected login:', address);
      syncAndRedirect(address);
    }
  }, [isLoggedIn, address, open, syncAndRedirect]);

  useEffect(() => {
    if (!open) {
      setLoading(false);
      setError(null);
      setWaitingForConnection(false);
      syncAttempted.current = false;
    }
  }, [open]);

  const handleExtensionLogin = async () => {
    setLoading(true);
    setError(null);
    syncAttempted.current = false;
    
    try {
      console.log('[wallet] Clearing SDK state before login...');
      try { logoutAction(); } catch (e) { console.log('[wallet] logoutAction cleanup (non-fatal):', e); }
      
      console.log('[wallet] Creating extension provider...');
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.extension 
      });
      providerRef.current = provider;
      console.log('[wallet] Provider created:', typeof provider);
      
      if (typeof provider.init === 'function') {
        console.log('[wallet] Initializing provider...');
        await provider.init();
      }
      
      console.log('[wallet] Calling provider.login()...');
      const loginResult = await provider.login();
      console.log('[wallet] Login result:', JSON.stringify(loginResult, null, 2));
      
      let walletAddress = '';
      
      if (loginResult && typeof loginResult === 'object' && 'address' in loginResult) {
        walletAddress = (loginResult as any).address;
        console.log('[wallet] Address from loginResult:', walletAddress);
      }
      
      if (!walletAddress) {
        try {
          if (typeof (provider as any).getAddress === 'function') {
            walletAddress = await (provider as any).getAddress();
            console.log('[wallet] Address from getAddress():', walletAddress);
          }
        } catch (e) {
          console.log('[wallet] getAddress() failed:', e);
        }
      }
      
      if (!walletAddress && (provider as any).account?.address) {
        walletAddress = (provider as any).account.address;
        console.log('[wallet] Address from provider.account:', walletAddress);
      }
      
      if (walletAddress && walletAddress.startsWith('erd1')) {
        console.log('[wallet] Got address immediately, syncing:', walletAddress);
        await syncAndRedirect(walletAddress);
      } else {
        console.log('[wallet] No address yet, starting polling...');
        setWaitingForConnection(true);
        let attempts = 0;
        const maxAttempts = 30;
        const checkAddress = setInterval(async () => {
          attempts++;
          let addr = '';
          try {
            if (typeof (provider as any).getAddress === 'function') {
              addr = await (provider as any).getAddress();
            }
          } catch (e) {}
          
          if (!addr && (provider as any).account?.address) {
            addr = (provider as any).account.address;
          }
          
          if (addr && addr.startsWith('erd1')) {
            console.log('[wallet] Polling found address at attempt', attempts, ':', addr);
            clearInterval(checkAddress);
            setWaitingForConnection(false);
            await syncAndRedirect(addr);
          } else if (attempts >= maxAttempts) {
            console.log('[wallet] Polling timed out after', maxAttempts, 'attempts');
            clearInterval(checkAddress);
            setWaitingForConnection(false);
            setLoading(false);
            setError('Connection timed out. Please refresh the page and try again.');
          }
        }, 500);
      }
    } catch (err: any) {
      console.error('[wallet] Extension login error:', err);
      const errorMsg = err.message || "Please install the MultiversX DeFi Wallet extension";
      setError(`Error: ${errorMsg}`);
      toast({
        title: "Connection failed",
        description: errorMsg,
        variant: "destructive"
      });
      setLoading(false);
      setWaitingForConnection(false);
    }
  };

  if (waitingForConnection) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-md" data-testid="modal-wallet-login">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Wallet className="h-5 w-5 text-primary" />
              Connecting...
            </DialogTitle>
            <DialogDescription>
              Approve the connection in your wallet extension
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col items-center py-4 space-y-4">
            <Loader2 className="h-12 w-12 animate-spin text-primary" />
            <p className="text-center text-muted-foreground">
              Waiting for approval...
            </p>
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
            Connect your wallet
          </DialogTitle>
          <DialogDescription>
            Sign in with your MultiversX browser extension
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
            disabled={loading}
            className="w-full justify-start gap-3"
            variant="default"
            data-testid="button-extension-login"
          >
            {loading ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Wallet className="h-5 w-5" />
            )}
            <span>MultiversX Wallet Extension</span>
          </Button>
        </div>

        <p className="text-xs text-muted-foreground text-center">
          Secure authentication via cryptographic signature
        </p>
      </DialogContent>
    </Dialog>
  );
}

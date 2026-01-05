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
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const isLoggedIn = useGetIsLoggedIn();
  const { address } = useGetAccount();

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
    }
  }, [open]);

  const handleExtensionLogin = async () => {
    setLoading('extension');
    setError(null);
    syncAttempted.current = false;
    
    try {
      console.log('🔌 Creating extension provider...');
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.extension 
      });
      providerRef.current = provider;
      
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      console.log('🔐 Calling extension login...');
      const loginResult = await provider.login();
      console.log('📋 Extension login result:', loginResult);
      
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
        const checkInterval = setInterval(async () => {
          attempts++;
          
          let addr = '';
          try {
            if (typeof (provider as any).getAddress === 'function') {
              addr = await (provider as any).getAddress();
            }
          } catch (e) { }
          
          if (addr && addr.startsWith('erd1')) {
            clearInterval(checkInterval);
            setWaitingForConnection(false);
            await syncAndRedirect(addr);
          } else if (attempts >= maxAttempts) {
            clearInterval(checkInterval);
            setWaitingForConnection(false);
            setLoading(null);
            setError('Connexion expirée. Veuillez réessayer.');
          }
        }, 500);
      }
    } catch (err: any) {
      console.error('Extension login error:', err);
      setError(err.message || "Veuillez installer l'extension MultiversX");
      toast({
        title: "Échec de connexion",
        description: err.message || "Extension non détectée",
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
      
      const provider = await ProviderFactory.create({
        type: ProviderTypeEnum.walletConnect
      });
      providerRef.current = provider;
      
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      console.log('🔐 Calling WalletConnect login...');
      
      if (isMobileDevice()) {
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
        setWaitingForConnection(false);
        await syncAndRedirect(walletAddress);
      } else {
        let attempts = 0;
        const maxAttempts = 60;
        const checkInterval = setInterval(async () => {
          attempts++;
          
          let addr = '';
          try {
            if (typeof (provider as any).getAddress === 'function') {
              addr = await (provider as any).getAddress();
            }
          } catch (e) { }
          
          if (addr && addr.startsWith('erd1')) {
            clearInterval(checkInterval);
            setWaitingForConnection(false);
            await syncAndRedirect(addr);
          } else if (attempts >= maxAttempts) {
            clearInterval(checkInterval);
            setWaitingForConnection(false);
            setLoading(null);
            setError('Connexion expirée. Veuillez réessayer.');
          }
        }, 1000);
      }
      
    } catch (err: any) {
      console.error('WalletConnect error:', err);
      
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

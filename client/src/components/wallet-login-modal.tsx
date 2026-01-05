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
import { WalletConnectV2Provider } from '@multiversx/sdk-wallet-connect-provider';
import { Shield, Wallet, Loader2, X, Smartphone } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useLocation } from "wouter";
import { queryClient } from "@/lib/queryClient";
import QRCodeLib from 'qrcode';

const WALLETCONNECT_PROJECT_ID = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || 'b4c11c7335da6e3e77753a17d466e4e2';
const RELAY_URL = 'wss://relay.walletconnect.com';
const CHAIN_ID = '1';

const WALLETCONNECT_SESSION_KEY = 'walletconnect_session';

interface WalletLoginModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const isMobileDevice = () => {
  if (typeof navigator === 'undefined') return false;
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
};

const isIOS = () => {
  if (typeof navigator === 'undefined') return false;
  return /iPhone|iPad|iPod/i.test(navigator.userAgent);
};

export function WalletLoginModal({ open, onOpenChange }: WalletLoginModalProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string | null>(null);
  const [wcUri, setWcUri] = useState<string | null>(null);
  const [waitingForMobileReturn, setWaitingForMobileReturn] = useState(false);
  const providerRef = useRef<WalletConnectV2Provider | null>(null);
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const isLoggedIn = useGetIsLoggedIn();
  const { address } = useGetAccount();

  const syncAndRedirect = useCallback(async (walletAddress: string): Promise<boolean> => {
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
        
        setTimeout(() => {
          navigate('/dashboard');
        }, 100);
        
        return true;
      } else {
        const errorText = await response.text().catch(() => 'Unknown error');
        console.error('Backend sync failed:', response.status, errorText);
        
        setError('Échec de la synchronisation avec le serveur. Veuillez réessayer.');
        setLoading(null);
        setWaitingForMobileReturn(false);
        
        toast({
          title: "Erreur de connexion",
          description: "Impossible de créer votre session. Veuillez réessayer.",
          variant: "destructive"
        });
        
        return false;
      }
    } catch (err) {
      console.error('Sync error:', err);
      
      setError('Erreur de connexion au serveur. Veuillez réessayer.');
      setLoading(null);
      setWaitingForMobileReturn(false);
      
      toast({
        title: "Erreur de connexion",
        description: "Une erreur est survenue. Veuillez réessayer.",
        variant: "destructive"
      });
      
      return false;
    }
  }, [toast, onOpenChange, navigate]);

  useEffect(() => {
    if (isLoggedIn && address && open) {
      console.log('Login detected via SDK:', address);
      syncAndRedirect(address);
    }
  }, [isLoggedIn, address, open, syncAndRedirect]);

  useEffect(() => {
    if (!open) {
      setLoading(null);
      setError(null);
      setQrCodeDataUrl(null);
      setWcUri(null);
      setWaitingForMobileReturn(false);
    }
  }, [open]);

  useEffect(() => {
    if (!waitingForMobileReturn || !providerRef.current) return;

    const checkConnection = async () => {
      try {
        const provider = providerRef.current;
        if (!provider) return;

        let addr = '';
        try {
          if (typeof provider.getAddress === 'function') {
            addr = await provider.getAddress();
          }
        } catch (e) {
          console.log('Checking address...', e);
        }

        if (addr && addr.startsWith('erd1')) {
          console.log('✅ Mobile return - wallet connected:', addr);
          setWaitingForMobileReturn(false);
          await syncAndRedirect(addr);
        }
      } catch (e) {
        console.log('Connection check error:', e);
      }
    };

    const interval = setInterval(checkConnection, 1000);
    const timeout = setTimeout(() => {
      setWaitingForMobileReturn(false);
      setLoading(null);
    }, 120000);

    return () => {
      clearInterval(interval);
      clearTimeout(timeout);
    };
  }, [waitingForMobileReturn, syncAndRedirect]);

  const cleanupExistingSessions = async () => {
    try {
      localStorage.removeItem(WALLETCONNECT_SESSION_KEY);
      
      const keysToRemove: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && (key.includes('wc@') || key.includes('walletconnect'))) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach(key => localStorage.removeItem(key));
      
      if (providerRef.current) {
        try {
          await providerRef.current.logout();
        } catch (e) {
          console.log('Provider cleanup (non-fatal):', e);
        }
        providerRef.current = null;
      }
    } catch (e) {
      console.log('Session cleanup error (non-fatal):', e);
    }
  };

  const handleExtensionLogin = async () => {
    setLoading('extension');
    setError(null);
    
    try {
      console.log('Creating extension provider...');
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.extension 
      });
      
      console.log('Initializing extension provider...');
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      console.log('Calling extension login...');
      await provider.login();
      console.log('Extension login call completed');
      
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      let walletAddress = '';
      try {
        if (typeof (provider as any).getAddress === 'function') {
          walletAddress = await (provider as any).getAddress();
        } else if ((provider as any).account?.address) {
          walletAddress = (provider as any).account.address;
        }
      } catch (e) {
        console.log('Could not get address from provider:', e);
      }
      
      if (walletAddress && walletAddress.startsWith('erd1')) {
        console.log('Got address from extension:', walletAddress);
        await syncAndRedirect(walletAddress);
      } else {
        console.log('Waiting for SDK to detect login...');
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        if (!isLoggedIn) {
          throw new Error('La connexion a échoué. Veuillez réessayer.');
        }
      }
    } catch (err: any) {
      console.error('Extension login error:', err);
      const errorMessage = err.message || "Veuillez installer l'extension MultiversX DeFi Wallet";
      setError(errorMessage);
      toast({
        title: "Échec de connexion",
        description: errorMessage,
        variant: "destructive"
      });
      setLoading(null);
    }
  };

  const handleWebWalletLogin = async () => {
    setLoading('webwallet');
    setError(null);
    
    try {
      console.log('Creating web wallet provider...');
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.crossWindow 
      });
      
      console.log('Initializing web wallet provider...');
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      console.log('Calling web wallet login...');
      await provider.login();
      console.log('Web Wallet login call completed');
      
    } catch (err: any) {
      console.error('Web Wallet login error:', err);
      const errorMessage = err.message || "Impossible de se connecter au Web Wallet";
      setError(errorMessage);
      toast({
        title: "Échec de connexion",
        description: errorMessage,
        variant: "destructive"
      });
      setLoading(null);
    }
  };

  const handleWalletConnectLogin = async () => {
    setLoading('walletconnect');
    setError(null);
    setQrCodeDataUrl(null);
    setWcUri(null);
    
    try {
      console.log('Cleaning up existing WalletConnect sessions...');
      await cleanupExistingSessions();
      
      console.log('Creating WalletConnectV2Provider...');
      
      if (!WALLETCONNECT_PROJECT_ID) {
        throw new Error('WalletConnect Project ID non configuré');
      }
      
      const callbacks = {
        onClientLogin: async () => {
          console.log('WalletConnect: Client logged in!');
          if (providerRef.current) {
            let addr = '';
            try {
              if (typeof providerRef.current.getAddress === 'function') {
                addr = await providerRef.current.getAddress();
              }
            } catch (e) {
              console.log('Could not get address from provider:', e);
            }
            if (addr && addr.startsWith('erd1')) {
              await syncAndRedirect(addr);
            }
          }
        },
        onClientLogout: async () => {
          console.log('WalletConnect: Client logged out');
          setQrCodeDataUrl(null);
          setWcUri(null);
          setLoading(null);
          setWaitingForMobileReturn(false);
        },
        onClientEvent: async (event: any) => {
          console.log('WalletConnect event:', event);
        }
      };
      
      const wcProvider = new WalletConnectV2Provider(
        callbacks,
        CHAIN_ID,
        RELAY_URL,
        WALLETCONNECT_PROJECT_ID
      );
      providerRef.current = wcProvider;
      
      console.log('Initializing WalletConnect provider...');
      await wcProvider.init();
      console.log('WalletConnect initialized');
      
      console.log('Connecting to get URI...');
      const { uri, approval } = await wcProvider.connect();
      console.log('Got WalletConnect URI:', uri ? 'yes' : 'no');
      
      if (uri) {
        setWcUri(uri);
        
        if (isMobileDevice()) {
          console.log('📱 Mobile device detected - opening xPortal directly');
          setWaitingForMobileReturn(true);
          
          const encodedUri = encodeURIComponent(uri);
          
          if (isIOS()) {
            window.location.href = `https://maiar.page.link/?apn=com.elrond.maiar.wallet&isi=1519405832&ibi=com.elrond.maiar.wallet&link=https://maiar.com/?wallet-connect=${encodedUri}`;
          } else {
            window.location.href = `intent://wc?uri=${encodedUri}#Intent;scheme=xportal;package=com.elrond.maiar.wallet;end`;
          }
        } else {
          const qrDataUrl = await QRCodeLib.toDataURL(uri, {
            width: 280,
            margin: 2,
            color: { dark: '#000000', light: '#ffffff' }
          });
          setQrCodeDataUrl(qrDataUrl);
        }
      }
      
      console.log('Waiting for user approval...');
      await wcProvider.login({ approval });
      console.log('WalletConnect login completed');
      
    } catch (err: any) {
      console.error('WalletConnect login error:', err);
      
      if (err.message?.includes('rejected') || err.message?.includes('cancelled') || err.message?.includes('Proposal')) {
        setLoading(null);
        setQrCodeDataUrl(null);
        setWcUri(null);
        setWaitingForMobileReturn(false);
        return;
      }
      
      const errorMessage = err.message || "Impossible de se connecter via xPortal";
      setError(errorMessage);
      toast({
        title: "Échec de connexion xPortal",
        description: errorMessage,
        variant: "destructive"
      });
      setLoading(null);
      setQrCodeDataUrl(null);
      setWcUri(null);
      setWaitingForMobileReturn(false);
    }
  };

  const handleCancelWalletConnect = async () => {
    await cleanupExistingSessions();
    setLoading(null);
    setQrCodeDataUrl(null);
    setWcUri(null);
    setWaitingForMobileReturn(false);
  };

  if (waitingForMobileReturn) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-md" data-testid="modal-wallet-login">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Smartphone className="h-5 w-5 text-primary" />
              Connexion en cours...
            </DialogTitle>
            <DialogDescription>
              Validez la connexion dans xPortal puis revenez ici
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col items-center py-6 space-y-4">
            <Loader2 className="h-12 w-12 animate-spin text-primary" />
            <p className="text-center text-muted-foreground">
              En attente de validation dans xPortal...
            </p>
            <p className="text-center text-sm text-muted-foreground">
              Si xPortal ne s'est pas ouvert, cliquez ci-dessous
            </p>
            
            <Button
              onClick={() => {
                if (wcUri) {
                  const encodedUri = encodeURIComponent(wcUri);
                  if (isIOS()) {
                    window.location.href = `https://maiar.page.link/?apn=com.elrond.maiar.wallet&isi=1519405832&ibi=com.elrond.maiar.wallet&link=https://maiar.com/?wallet-connect=${encodedUri}`;
                  } else {
                    window.location.href = `intent://wc?uri=${encodedUri}#Intent;scheme=xportal;package=com.elrond.maiar.wallet;end`;
                  }
                }
              }}
              className="w-full"
              variant="outline"
              disabled={!wcUri}
              data-testid="button-retry-xportal"
            >
              <Smartphone className="h-5 w-5 mr-2" />
              Ouvrir xPortal
            </Button>
            
            <Button
              variant="ghost"
              onClick={handleCancelWalletConnect}
              className="w-full"
              data-testid="button-cancel-walletconnect"
            >
              <X className="h-4 w-4 mr-2" />
              Annuler
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    );
  }

  if (qrCodeDataUrl) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-md" data-testid="modal-wallet-login">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Smartphone className="h-5 w-5 text-primary" />
              Scanner avec xPortal
            </DialogTitle>
            <DialogDescription>
              Scannez ce QR code avec l'application xPortal
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col items-center py-4 space-y-4">
            <div className="bg-white p-4 rounded-lg shadow-sm">
              <img 
                src={qrCodeDataUrl} 
                alt="QR Code WalletConnect"
                className="w-[280px] h-[280px]"
                data-testid="img-walletconnect-qr"
              />
            </div>
            
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span>En attente de connexion...</span>
            </div>
            
            <Button
              variant="outline"
              onClick={handleCancelWalletConnect}
              className="w-full"
              data-testid="button-cancel-walletconnect"
            >
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
            Choisissez votre méthode de connexion préférée
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="p-3 text-sm text-destructive bg-destructive/10 rounded-md">
            {error}
          </div>
        )}

        <div className="space-y-3 py-4">
          <Button
            onClick={handleWalletConnectLogin}
            disabled={loading !== null}
            className="w-full justify-start gap-3"
            variant="default"
            data-testid="button-walletconnect-login"
          >
            {loading === 'walletconnect' ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Smartphone className="h-5 w-5" />
            )}
            <span>xPortal App</span>
          </Button>

          <Button
            onClick={handleExtensionLogin}
            disabled={loading !== null}
            className="w-full justify-start gap-3"
            variant="outline"
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

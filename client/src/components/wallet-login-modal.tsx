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

const PENDING_WC_KEY = 'pending_walletconnect';

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
  const [waitingForConnection, setWaitingForConnection] = useState(false);
  const providerRef = useRef<WalletConnectV2Provider | null>(null);
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
        localStorage.removeItem(PENDING_WC_KEY);
        
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
      setQrCodeDataUrl(null);
      setWcUri(null);
      setWaitingForConnection(false);
      syncAttempted.current = false;
    }
  }, [open]);

  const cleanupSessions = async () => {
    localStorage.removeItem(PENDING_WC_KEY);
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && (key.includes('wc@') || key.includes('walletconnect'))) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(key => localStorage.removeItem(key));
    
    if (providerRef.current) {
      try { await providerRef.current.logout(); } catch (e) { }
      providerRef.current = null;
    }
  };

  const handleExtensionLogin = async () => {
    setLoading('extension');
    setError(null);
    syncAttempted.current = false;
    
    try {
      console.log('🔌 Creating extension provider...');
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.extension 
      });
      
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
    setQrCodeDataUrl(null);
    setWcUri(null);
    syncAttempted.current = false;
    
    try {
      await cleanupSessions();
      
      console.log('📱 Creating WalletConnect provider...');
      
      const callbacks = {
        onClientLogin: async () => {
          console.log('🎉 WalletConnect: onClientLogin callback!');
          if (providerRef.current) {
            try {
              const addr = await providerRef.current.getAddress();
              console.log('📍 Got address from callback:', addr);
              if (addr && addr.startsWith('erd1')) {
                await syncAndRedirect(addr);
              }
            } catch (e) {
              console.log('Could not get address in callback:', e);
            }
          }
        },
        onClientLogout: async () => {
          console.log('WalletConnect: Client logged out');
          setQrCodeDataUrl(null);
          setWcUri(null);
          setLoading(null);
          setWaitingForConnection(false);
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
      
      await wcProvider.init();
      console.log('✅ WalletConnect initialized');
      
      const { uri, approval } = await wcProvider.connect();
      console.log('🔗 Got WalletConnect URI');
      
      if (uri) {
        setWcUri(uri);
        
        if (isMobileDevice()) {
          console.log('📱 Mobile: Saving pending connection and opening xPortal');
          
          localStorage.setItem(PENDING_WC_KEY, JSON.stringify({
            uri,
            timestamp: Date.now()
          }));
          
          setWaitingForConnection(true);
          
          const encodedUri = encodeURIComponent(uri);
          const deepLink = isIOS()
            ? `https://maiar.page.link/?apn=com.elrond.maiar.wallet&isi=1519405832&ibi=com.elrond.maiar.wallet&link=https://maiar.com/?wallet-connect=${encodedUri}`
            : `intent://wc?uri=${encodedUri}#Intent;scheme=xportal;package=com.elrond.maiar.wallet;end`;
          
          setTimeout(() => {
            window.location.href = deepLink;
          }, 100);
        } else {
          const qrDataUrl = await QRCodeLib.toDataURL(uri, {
            width: 280,
            margin: 2,
            color: { dark: '#000000', light: '#ffffff' }
          });
          setQrCodeDataUrl(qrDataUrl);
        }
      }
      
      console.log('⏳ Waiting for approval...');
      await wcProvider.login({ approval });
      console.log('✅ WalletConnect login completed via approval');
      
      const addr = await wcProvider.getAddress();
      if (addr && addr.startsWith('erd1')) {
        await syncAndRedirect(addr);
      }
      
    } catch (err: any) {
      console.error('WalletConnect error:', err);
      
      if (err.message?.includes('rejected') || err.message?.includes('cancelled') || err.message?.includes('Proposal')) {
        setLoading(null);
        setQrCodeDataUrl(null);
        setWcUri(null);
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
      setQrCodeDataUrl(null);
      setWcUri(null);
      setWaitingForConnection(false);
    }
  };

  const handleCancel = async () => {
    await cleanupSessions();
    setLoading(null);
    setQrCodeDataUrl(null);
    setWcUri(null);
    setWaitingForConnection(false);
  };

  if (waitingForConnection && loading === 'extension') {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-md" data-testid="modal-wallet-login">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Wallet className="h-5 w-5 text-primary" />
              Connexion en cours...
            </DialogTitle>
            <DialogDescription>
              Validez la connexion dans votre extension wallet
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col items-center py-6 space-y-4">
            <Loader2 className="h-12 w-12 animate-spin text-primary" />
            <p className="text-center text-muted-foreground">
              En attente de validation...
            </p>
            <Button variant="ghost" onClick={handleCancel} data-testid="button-cancel">
              <X className="h-4 w-4 mr-2" />
              Annuler
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    );
  }

  if (waitingForConnection && loading === 'walletconnect') {
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
            
            {wcUri && (
              <Button
                onClick={() => {
                  const encodedUri = encodeURIComponent(wcUri);
                  const deepLink = isIOS()
                    ? `https://maiar.page.link/?apn=com.elrond.maiar.wallet&isi=1519405832&ibi=com.elrond.maiar.wallet&link=https://maiar.com/?wallet-connect=${encodedUri}`
                    : `intent://wc?uri=${encodedUri}#Intent;scheme=xportal;package=com.elrond.maiar.wallet;end`;
                  window.location.href = deepLink;
                }}
                className="w-full"
                variant="outline"
                data-testid="button-retry-xportal"
              >
                <Smartphone className="h-5 w-5 mr-2" />
                Ouvrir xPortal
              </Button>
            )}
            
            <Button variant="ghost" onClick={handleCancel} className="w-full" data-testid="button-cancel">
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
            
            <Button variant="outline" onClick={handleCancel} className="w-full" data-testid="button-cancel">
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

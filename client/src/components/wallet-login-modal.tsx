import { useState, useEffect, useRef } from "react";
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
import QRCodeLib from 'qrcode';

const WALLETCONNECT_PROJECT_ID = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || 'b4c11c7335da6e3e77753a17d466e4e2';
const RELAY_URL = 'wss://relay.walletconnect.com';
const CHAIN_ID = '1';

interface WalletLoginModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function WalletLoginModal({ open, onOpenChange }: WalletLoginModalProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string | null>(null);
  const [wcUri, setWcUri] = useState<string | null>(null);
  const providerRef = useRef<any>(null);
  const { toast } = useToast();
  const isLoggedIn = useGetIsLoggedIn();
  const { address } = useGetAccount();

  // Handle successful login detection
  useEffect(() => {
    if (isLoggedIn && address && open) {
      console.log('Login detected via SDK:', address);
      syncAndRedirect(address);
    }
  }, [isLoggedIn, address, open]);

  // Cleanup on modal close
  useEffect(() => {
    if (!open) {
      setLoading(null);
      setError(null);
      setQrCodeDataUrl(null);
      setWcUri(null);
      if (providerRef.current) {
        try {
          providerRef.current.logout?.();
        } catch (e) {
          // Ignore cleanup errors
        }
        providerRef.current = null;
      }
    }
  }, [open]);

  const syncAndRedirect = async (walletAddress: string) => {
    try {
      // Try to sync with backend
      const response = await fetch('/api/auth/wallet/simple-sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ walletAddress }),
      });
      
      if (response.ok) {
        localStorage.setItem('walletAddress', walletAddress);
        toast({
          title: "Wallet connecté",
          description: `Connecté : ${walletAddress.substring(0, 10)}...${walletAddress.slice(-6)}`,
        });
        window.location.reload();
      } else {
        // Still save and reload even if sync fails
        localStorage.setItem('walletAddress', walletAddress);
        window.location.reload();
      }
    } catch (err) {
      localStorage.setItem('walletAddress', walletAddress);
      window.location.reload();
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
      providerRef.current = provider;
      
      console.log('Initializing extension provider...');
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      console.log('Calling extension login...');
      await provider.login();
      console.log('Extension login call completed');
      
      // Wait a moment for SDK to update
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Try to get address from provider
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
        // If no address yet, wait for SDK hooks to detect it (handled by useEffect)
        console.log('Waiting for SDK to detect login...');
        // Give SDK more time
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // If still not logged in, throw error
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
      providerRef.current = provider;
      
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
      console.log('Creating WalletConnectV2Provider directly...');
      
      if (!WALLETCONNECT_PROJECT_ID) {
        throw new Error('WalletConnect Project ID non configuré');
      }
      
      const callbacks = {
        onClientLogin: async () => {
          console.log('WalletConnect: Client logged in!');
          // Get address from provider
          if (providerRef.current) {
            let addr = '';
            try {
              if (typeof (providerRef.current as any).getAddress === 'function') {
                addr = await (providerRef.current as any).getAddress();
              } else if ((providerRef.current as any).account?.address) {
                addr = (providerRef.current as any).account.address;
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
        },
        onClientEvent: async (event: any) => {
          console.log('WalletConnect event:', event);
        }
      };
      
      // Create WalletConnectV2Provider directly
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
        const qrDataUrl = await QRCodeLib.toDataURL(uri, {
          width: 280,
          margin: 2,
          color: { dark: '#000000', light: '#ffffff' }
        });
        setQrCodeDataUrl(qrDataUrl);
        setWcUri(uri);
      }
      
      console.log('Waiting for user approval...');
      await wcProvider.login({ approval });
      console.log('WalletConnect login completed');
      
    } catch (err: any) {
      console.error('WalletConnect login error:', err);
      
      // Don't show error for user cancellation
      if (err.message?.includes('rejected') || err.message?.includes('cancelled') || err.message?.includes('Proposal')) {
        setLoading(null);
        setQrCodeDataUrl(null);
        setWcUri(null);
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
    }
  };

  const handleCancelWalletConnect = () => {
    if (providerRef.current) {
      try {
        providerRef.current.logout?.();
      } catch (e) {
        // Ignore
      }
      providerRef.current = null;
    }
    setLoading(null);
    setQrCodeDataUrl(null);
    setWcUri(null);
  };

  const isMobileDevice = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
    typeof navigator !== 'undefined' ? navigator.userAgent : ''
  );

  // QR Code view for WalletConnect
  if (qrCodeDataUrl) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-md" data-testid="modal-wallet-login">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Smartphone className="h-5 w-5 text-primary" />
              {isMobileDevice ? "Connexion xPortal" : "Scanner avec xPortal"}
            </DialogTitle>
            <DialogDescription>
              {isMobileDevice 
                ? "Cliquez sur le bouton ci-dessous pour ouvrir xPortal"
                : "Scannez ce QR code avec l'application xPortal"
              }
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col items-center py-4 space-y-4">
            {isMobileDevice ? (
              <>
                <Button
                  onClick={() => {
                    if (wcUri) {
                      const encodedUri = encodeURIComponent(wcUri);
                      const isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);
                      
                      if (isIOS) {
                        window.location.href = `https://maiar.page.link/?apn=com.elrond.maiar.wallet&isi=1519405832&ibi=com.elrond.maiar.wallet&link=https://maiar.com/?wallet-connect=${encodedUri}`;
                      } else {
                        window.location.href = `intent://wc?uri=${encodedUri}#Intent;scheme=xportal;package=com.elrond.maiar.wallet;end`;
                      }
                    }
                  }}
                  className="w-full"
                  size="lg"
                  disabled={!wcUri}
                  data-testid="button-open-xportal"
                >
                  <Smartphone className="h-5 w-5 mr-2" />
                  Ouvrir xPortal
                </Button>
                
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>En attente de connexion...</span>
                </div>
              </>
            ) : (
              <>
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
              </>
            )}
            
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

  // Main login options view
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

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
import { WalletConnectV2Provider } from '@multiversx/sdk-wallet-connect-provider';
import { loginAction } from '@multiversx/sdk-dapp/out/store/actions/sharedActions/sharedActions';
import { useGetIsLoggedIn } from '@multiversx/sdk-dapp/out/react/account/useGetIsLoggedIn';
import { useGetAccount } from '@multiversx/sdk-dapp/out/react/account/useGetAccount';
import { Shield, Wallet, Loader2, X, Smartphone, QrCode, ExternalLink } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useLocation } from "wouter";
import { queryClient } from "@/lib/queryClient";
import QRCode from 'qrcode';

const WALLETCONNECT_PROJECT_ID = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || 'b4c11c7335da6e3e77753a17d466e4e2';
const WALLETCONNECT_RELAY_URL = 'wss://relay.walletconnect.com';
const CHAIN_ID = '1';

interface WalletLoginModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  redirectTo?: string;
}

const isMobileDevice = () => {
  if (typeof navigator === 'undefined') return false;
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
};

export function WalletLoginModal({ open, onOpenChange, redirectTo }: WalletLoginModalProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [waitingForConnection, setWaitingForConnection] = useState(false);
  const [wcUri, setWcUri] = useState<string | null>(null);
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string | null>(null);
  const [deepLinkUrl, setDeepLinkUrl] = useState<string | null>(null);
  const providerRef = useRef<any>(null);
  const wcProviderRef = useRef<WalletConnectV2Provider | null>(null);
  const syncAttempted = useRef(false);
  const loginAborted = useRef(false);
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const isLoggedIn = useGetIsLoggedIn();
  const { address } = useGetAccount();

  const syncAndRedirect = useCallback(async (walletAddress: string, providerType: string = ProviderTypeEnum.walletConnect): Promise<boolean> => {
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
        
        loginAction({ address: walletAddress, providerType });
        
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
        setLoading(null);
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
      setLoading(null);
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
      loginAborted.current = true;
      setLoading(null);
      setError(null);
      setWaitingForConnection(false);
      setWcUri(null);
      setQrCodeDataUrl(null);
      setDeepLinkUrl(null);
      syncAttempted.current = false;
    } else {
      loginAborted.current = false;
    }
  }, [open]);

  const handleExtensionLogin = async () => {
    setLoading('extension');
    setError(null);
    syncAttempted.current = false;
    
    try {
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.extension 
      });
      providerRef.current = provider;
      
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      const loginResult = await provider.login();
      
      let walletAddress = '';
      
      if (loginResult && typeof loginResult === 'object' && 'address' in loginResult) {
        walletAddress = (loginResult as any).address;
      }
      
      if (!walletAddress) {
        try {
          if (typeof (provider as any).getAddress === 'function') {
            walletAddress = await (provider as any).getAddress();
          }
        } catch (e) {}
      }
      
      if (!walletAddress && (provider as any).account?.address) {
        walletAddress = (provider as any).account.address;
      }
      
      if (walletAddress && walletAddress.startsWith('erd1')) {
        await syncAndRedirect(walletAddress, ProviderTypeEnum.extension);
      } else {
        setWaitingForConnection(true);
        let attempts = 0;
        const maxAttempts = 10;
        const checkAddress = setInterval(async () => {
          attempts++;
          let addr = '';
          try {
            if (typeof (provider as any).getAddress === 'function') {
              addr = await (provider as any).getAddress();
            }
          } catch (e) {}
          
          if (addr && addr.startsWith('erd1')) {
            clearInterval(checkAddress);
            setWaitingForConnection(false);
            await syncAndRedirect(addr, ProviderTypeEnum.extension);
          } else if (attempts >= maxAttempts) {
            clearInterval(checkAddress);
            setWaitingForConnection(false);
            setLoading(null);
            setError('Connection timed out. Please try again.');
          }
        }, 500);
      }
    } catch (err: any) {
      console.error('Extension login error:', err);
      const errorMsg = err.message || "Please install the MultiversX extension";
      setError(`Error: ${errorMsg}`);
      toast({
        title: "Connection failed",
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
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.crossWindow 
      });
      
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      await provider.login();
      
    } catch (err: any) {
      console.error('Web Wallet login error:', err);
      setError(err.message || "Unable to connect");
      toast({
        title: "Connection failed",
        description: err.message || "Web Wallet error",
        variant: "destructive"
      });
      setLoading(null);
    }
  };

  const handleWalletConnectLogin = async () => {
    setLoading('walletconnect');
    setError(null);
    setWcUri(null);
    setQrCodeDataUrl(null);
    setDeepLinkUrl(null);
    syncAttempted.current = false;
    loginAborted.current = false;
    
    try {
      const wcProvider = new WalletConnectV2Provider(
        {
          onClientLogin: () => { logger.log('WalletConnect: Client logged in'); },
          onClientLogout: () => { logger.log('WalletConnect: Client logged out'); },
          onClientEvent: (event: any) => { logger.log('WalletConnect event:', event); }
        },
        CHAIN_ID,
        WALLETCONNECT_RELAY_URL,
        WALLETCONNECT_PROJECT_ID,
        {
          metadata: {
            name: 'xproof',
            description: 'Blockchain Certification Platform',
            url: window.location.origin,
            icons: [`${window.location.origin}/favicon.ico`]
          }
        }
      );
      
      wcProviderRef.current = wcProvider;
      
      await wcProvider.init();
      
      const { uri, approval } = await wcProvider.connect();
      
      if (loginAborted.current) return;
      
      if (uri) {
        setWcUri(uri);
        
        const qrDataUrl = await QRCode.toDataURL(uri, {
          width: 280,
          margin: 2,
          color: { dark: '#000000', light: '#ffffff' }
        });
        setQrCodeDataUrl(qrDataUrl);
        
        if (isMobileDevice()) {
          const encodedUri = encodeURIComponent(uri);
          setDeepLinkUrl(`xportal://wc?uri=${encodedUri}`);
        }
      }
      
      setWaitingForConnection(true);
      
      const loginResult = await wcProvider.login({ approval });
      
      if (loginAborted.current) return;
      
      let walletAddress = wcProvider.getAddress();
      
      if (!walletAddress && loginResult && typeof loginResult === 'object') {
        walletAddress = (loginResult as any).address || '';
      }
      
      if (walletAddress && walletAddress.startsWith('erd1')) {
        setWaitingForConnection(false);
        setWcUri(null);
        setQrCodeDataUrl(null);
        setDeepLinkUrl(null);
        await syncAndRedirect(walletAddress);
      } else {
        let attempts = 0;
        const maxAttempts = 30;
        const checkAddress = setInterval(async () => {
          if (loginAborted.current) {
            clearInterval(checkAddress);
            return;
          }
          attempts++;
          const addr = wcProvider.getAddress();
          
          if (addr && addr.startsWith('erd1')) {
            clearInterval(checkAddress);
            setWaitingForConnection(false);
            setWcUri(null);
            setQrCodeDataUrl(null);
            setDeepLinkUrl(null);
            await syncAndRedirect(addr);
          } else if (attempts >= maxAttempts) {
            clearInterval(checkAddress);
            setWaitingForConnection(false);
            setLoading(null);
            setWcUri(null);
            setQrCodeDataUrl(null);
            setDeepLinkUrl(null);
            setError('Connection timed out. Please try again.');
          }
        }, 1000);
      }
      
    } catch (err: any) {
      if (loginAborted.current) return;
      console.error('WalletConnect error:', err);
      setWcUri(null);
      setQrCodeDataUrl(null);
      setDeepLinkUrl(null);
      
      if (err.message?.includes('rejected') || err.message?.includes('cancelled') || err.message?.includes('Proposal')) {
        setLoading(null);
        setWaitingForConnection(false);
        return;
      }
      
      setError(err.message || "xPortal connection error");
      toast({
        title: "Connection failed",
        description: err.message || "xPortal error",
        variant: "destructive"
      });
      setLoading(null);
      setWaitingForConnection(false);
    }
  };

  const handleCancel = () => {
    loginAborted.current = true;
    if (providerRef.current && typeof providerRef.current.logout === 'function') {
      try { providerRef.current.logout(); } catch (e) {}
    }
    if (wcProviderRef.current) {
      try { wcProviderRef.current.logout(); } catch (e) {}
      wcProviderRef.current = null;
    }
    setLoading(null);
    setWaitingForConnection(false);
    setWcUri(null);
    setQrCodeDataUrl(null);
    setDeepLinkUrl(null);
  };

  useEffect(() => {
    if (!open && !isLoggedIn) {
      loginAborted.current = true;
      if (wcProviderRef.current) {
        try { wcProviderRef.current.logout(); } catch (e) {}
        wcProviderRef.current = null;
      }
    }
  }, [open, isLoggedIn]);

  if (waitingForConnection) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-md" data-testid="modal-wallet-login">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {loading === 'walletconnect' ? (
                <QrCode className="h-5 w-5 text-primary" />
              ) : (
                <Wallet className="h-5 w-5 text-primary" />
              )}
              {qrCodeDataUrl ? "Scan with xPortal" : "Connecting..."}
            </DialogTitle>
            <DialogDescription>
              {qrCodeDataUrl 
                ? "Open xPortal on your phone and scan this QR code"
                : loading === 'walletconnect' 
                  ? "Approve the connection in xPortal then come back here"
                  : "Approve the connection in your wallet"
              }
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col items-center py-4 space-y-4">
            {qrCodeDataUrl ? (
              <>
                <div className="bg-white p-3 rounded-lg">
                  <img 
                    src={qrCodeDataUrl} 
                    alt="WalletConnect QR Code" 
                    className="w-64 h-64"
                    data-testid="img-qr-code"
                  />
                </div>
                {deepLinkUrl && (
                  <a
                    href={deepLinkUrl}
                    className="inline-flex items-center gap-2 text-sm text-primary hover:underline"
                    data-testid="link-open-xportal"
                  >
                    <ExternalLink className="h-4 w-4" />
                    Open in xPortal
                  </a>
                )}
                <p className="text-center text-sm text-muted-foreground">
                  Waiting for connection from xPortal...
                </p>
              </>
            ) : (
              <>
                <Loader2 className="h-12 w-12 animate-spin text-primary" />
                <p className="text-center text-muted-foreground">
                  Waiting for approval...
                </p>
              </>
            )}
            <Button variant="ghost" onClick={handleCancel} data-testid="button-cancel">
              <X className="h-4 w-4 mr-2" />
              Cancel
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
            Connect your wallet
          </DialogTitle>
          <DialogDescription>
            Choose your connection method
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
            <span>xPortal App</span>
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
          Secure authentication via cryptographic signature
        </p>
      </DialogContent>
    </Dialog>
  );
}

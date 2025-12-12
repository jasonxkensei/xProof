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
import { Shield, Wallet, QrCode, Loader2, X, Smartphone } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import QRCodeLib from 'qrcode';

const WALLETCONNECT_PROJECT_ID = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || 'b4c11c7335da6e3e77753a17d466e4e2';
const RELAY_URL = 'wss://relay.walletconnect.com';
const CHAIN_ID = '1';

interface WcAttempt {
  id: number;
  provider: WalletConnectV2Provider;
  abortController: AbortController;
}

interface WalletLoginModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function WalletLoginModal({ open, onOpenChange }: WalletLoginModalProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const [loginAttempted, setLoginAttempted] = useState(false);
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string | null>(null);
  const [wcConnectedAddress, setWcConnectedAddress] = useState<string | null>(null);
  const [isCancelling, setIsCancelling] = useState(false);
  const attemptRef = useRef<WcAttempt | null>(null);
  const attemptIdCounter = useRef(0);
  const { toast } = useToast();
  const isLoggedIn = useGetIsLoggedIn();
  const { address } = useGetAccount();

  useEffect(() => {
    const syncAndReload = async () => {
      if (isLoggedIn && address && open && loginAttempted) {
        console.log('Wallet connected via SDK hooks:', address);
        
        await new Promise(resolve => setTimeout(resolve, 500));
        
        const keys = Object.keys(localStorage);
        let nativeAuthToken: string | null = null;
        
        for (const key of keys) {
          const value = localStorage.getItem(key);
          if (value && value.length > 100) {
            if (value.includes('.') || key.toLowerCase().includes('auth') || key.toLowerCase().includes('token')) {
              nativeAuthToken = value;
              break;
            }
          }
        }
        
        const loginInfo = localStorage.getItem('loginInfo');
        if (loginInfo && !nativeAuthToken) {
          try {
            const parsed = JSON.parse(loginInfo);
            if (parsed.nativeAuthToken) {
              nativeAuthToken = parsed.nativeAuthToken;
            }
          } catch (e) {
            if (loginInfo.length > 100) {
              nativeAuthToken = loginInfo;
            }
          }
        }
        
        if (nativeAuthToken) {
          try {
            const syncResponse = await fetch('/api/auth/wallet/sync', {
              method: 'POST',
              headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${nativeAuthToken}`
              },
              credentials: 'include',
              body: JSON.stringify({ walletAddress: address }),
            });
            
            if (syncResponse.ok) {
              localStorage.setItem('walletAddress', address);
              window.location.reload();
              return;
            }
          } catch (error) {
            console.error('Error syncing with backend:', error);
          }
        }
        
        try {
          const simpleSync = await fetch('/api/auth/wallet/simple-sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ walletAddress: address }),
          });
          
          if (simpleSync.ok) {
            localStorage.setItem('walletAddress', address);
            window.location.reload();
            return;
          }
        } catch (error) {
          console.log('Simple sync not available');
        }
        
        localStorage.setItem('walletAddress', address);
        window.location.reload();
      }
    };
    
    syncAndReload();
  }, [isLoggedIn, address, open, loginAttempted]);

  useEffect(() => {
    if (wcConnectedAddress) {
      console.log('WalletConnect connected, syncing:', wcConnectedAddress);
      
      localStorage.setItem('walletAddress', wcConnectedAddress);
      
      fetch('/api/auth/wallet/simple-sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ walletAddress: wcConnectedAddress }),
      })
        .then(() => {
          toast({
            title: "Wallet Connected",
            description: `Connected: ${wcConnectedAddress.substring(0, 10)}...${wcConnectedAddress.substring(wcConnectedAddress.length - 6)}`,
          });
          window.location.reload();
        })
        .catch(() => {
          window.location.reload();
        });
    }
  }, [wcConnectedAddress, toast]);

  useEffect(() => {
    if (!open) {
      setLoginAttempted(false);
      setLoading(null);
      setQrCodeDataUrl(null);
      setWcConnectedAddress(null);
      setIsCancelling(false);
      
      const attempt = attemptRef.current;
      if (attempt) {
        attempt.abortController.abort();
        attemptRef.current = null;
        attempt.provider.logout().catch(() => {});
      }
    }
  }, [open]);

  const handleExtensionLogin = async () => {
    setLoading('extension');
    setLoginAttempted(true);
    try {
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.extension 
      });
      
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      const loginResult = await provider.login();
      console.log('Extension login completed:', loginResult);
      
      for (let i = 0; i < 20; i++) {
        await new Promise(resolve => setTimeout(resolve, 250));
        if (!document.querySelector('[data-testid="modal-wallet-login"]')) {
          return;
        }
      }
      
      const manualAddress = (provider as any).account?.address || 
                           sessionStorage.getItem('sdk-dapp-account-address') ||
                           sessionStorage.getItem('loginData');
      if (manualAddress) {
        localStorage.setItem('walletAddress', manualAddress);
        window.location.reload();
      }
    } catch (error: any) {
      console.error('Extension login error:', error);
      toast({
        title: "Extension Login Failed",
        description: error.message || "Please install MultiversX DeFi Wallet Extension",
        variant: "destructive"
      });
      setLoading(null);
      setLoginAttempted(false);
    }
  };

  const handleWebWalletLogin = async () => {
    setLoading('webwallet');
    setLoginAttempted(true);
    try {
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.crossWindow 
      });
      
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      await provider.login();
      console.log('Web Wallet login completed');
    } catch (error: any) {
      console.error('Web Wallet login error:', error);
      toast({
        title: "Web Wallet Login Failed",
        description: error.message || "Failed to connect to Web Wallet",
        variant: "destructive"
      });
      setLoading(null);
      setLoginAttempted(false);
    }
  };

  const handleWalletConnectLogin = async () => {
    if (isCancelling) {
      console.log('Cancel in progress, please wait...');
      return;
    }
    
    setLoading('walletconnect');
    setLoginAttempted(true);
    
    const attemptId = ++attemptIdCounter.current;
    const abortController = new AbortController();
    
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    console.log(`Starting WalletConnect attempt #${attemptId}, isMobile:`, isMobile);
    
    let wcProvider: WalletConnectV2Provider | null = null;
    
    try {
      const callbacks = {
        onClientLogin: async () => {
          console.log(`WalletConnect attempt #${attemptId}: Client logged in!`);
          if (attemptRef.current?.id === attemptId && wcProvider) {
            const addr = wcProvider.address;
            if (addr) {
              setWcConnectedAddress(addr);
              setQrCodeDataUrl(null);
              setLoading(null);
            }
          }
        },
        onClientLogout: async () => {
          console.log(`WalletConnect attempt #${attemptId}: Client logged out`);
          if (attemptRef.current?.id === attemptId) {
            setQrCodeDataUrl(null);
            setLoading(null);
          }
        },
        onClientEvent: async (event: any) => {
          console.log(`WalletConnect attempt #${attemptId} event:`, event);
        }
      };
      
      console.log('Creating WalletConnectV2Provider...');
      wcProvider = new WalletConnectV2Provider(
        callbacks,
        CHAIN_ID,
        RELAY_URL,
        WALLETCONNECT_PROJECT_ID
      );
      
      const attempt: WcAttempt = {
        id: attemptId,
        provider: wcProvider,
        abortController
      };
      attemptRef.current = attempt;
      
      console.log('Initializing WalletConnect provider...');
      await wcProvider.init();
      console.log('WalletConnect initialized');
      
      if (abortController.signal.aborted) {
        console.log(`Attempt #${attemptId} aborted before connect`);
        return;
      }
      
      console.log('Connecting to get URI...');
      const { uri, approval } = await wcProvider.connect();
      console.log('Got WalletConnect URI');
      
      if (abortController.signal.aborted) {
        console.log(`Attempt #${attemptId} aborted after connect`);
        await wcProvider.logout().catch(() => {});
        return;
      }
      
      if (uri) {
        const qrDataUrl = await QRCodeLib.toDataURL(uri, {
          width: 280,
          margin: 2,
          color: {
            dark: '#000000',
            light: '#ffffff'
          }
        });
        
        if (attemptRef.current?.id === attemptId) {
          setQrCodeDataUrl(qrDataUrl);
          console.log('QR code generated');
        }
        
        if (isMobile) {
          const xPortalUri = uri.replace('wc:', 'xportal:wc:');
          console.log('Opening xPortal deep link...');
          window.location.href = xPortalUri;
        }
      }
      
      console.log('Waiting for user approval and login...');
      await wcProvider.login({ approval });
      console.log(`WalletConnect attempt #${attemptId} login() completed`);
      
    } catch (error: any) {
      if (abortController.signal.aborted) {
        console.log(`WalletConnect attempt #${attemptId} was cancelled`);
        return;
      }
      
      console.error(`WalletConnect attempt #${attemptId} error:`, error);
      
      let errorMessage = error.message || "Failed to connect via WalletConnect";
      if (error.message?.includes("rejected") || error.message?.includes("cancelled") || error.message?.includes("Proposal")) {
        errorMessage = "Connection cancelled or rejected by wallet";
      }
      
      toast({
        title: "xPortal Connection Failed",
        description: errorMessage,
        variant: "destructive"
      });
      
      if (attemptRef.current?.id === attemptId) {
        setLoading(null);
        setQrCodeDataUrl(null);
        setLoginAttempted(false);
        attemptRef.current = null;
      }
    }
  };

  const handleCancelWalletConnect = async () => {
    const attempt = attemptRef.current;
    if (!attempt) {
      setQrCodeDataUrl(null);
      setLoading(null);
      setLoginAttempted(false);
      return;
    }
    
    console.log(`Cancelling WalletConnect attempt #${attempt.id}...`);
    setIsCancelling(true);
    
    attempt.abortController.abort();
    
    setQrCodeDataUrl(null);
    setLoading(null);
    setLoginAttempted(false);
    
    if (attemptRef.current?.id === attempt.id) {
      attemptRef.current = null;
    }
    
    try {
      await attempt.provider.logout();
      console.log(`WalletConnect attempt #${attempt.id} logged out`);
    } catch (e) {
      console.log(`Logout cleanup error for attempt #${attempt.id} (expected):`, e);
    }
    
    setIsCancelling(false);
  };

  if (qrCodeDataUrl) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-md" data-testid="modal-wallet-login">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Smartphone className="h-5 w-5 text-primary" />
              Scan with xPortal
            </DialogTitle>
            <DialogDescription>
              Scan this QR code with your xPortal mobile app to connect your wallet
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col items-center py-4 space-y-4">
            <div className="bg-white p-4 rounded-lg shadow-sm">
              <img 
                src={qrCodeDataUrl} 
                alt="WalletConnect QR Code"
                className="w-[280px] h-[280px]"
                data-testid="img-walletconnect-qr"
              />
            </div>
            
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span>Waiting for connection...</span>
            </div>
            
            <Button
              variant="outline"
              onClick={handleCancelWalletConnect}
              disabled={isCancelling}
              className="w-full"
              data-testid="button-cancel-walletconnect"
            >
              {isCancelling ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <X className="h-4 w-4 mr-2" />
              )}
              {isCancelling ? 'Cancelling...' : 'Cancel'}
            </Button>
          </div>

          <p className="text-xs text-muted-foreground text-center">
            Open xPortal app, tap the scan icon, and scan this code
          </p>
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
            Connect Your Wallet
          </DialogTitle>
          <DialogDescription>
            Choose your preferred wallet to authenticate securely with cryptographic signatures
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 py-4">
          <Button
            onClick={handleExtensionLogin}
            disabled={loading !== null || isCancelling}
            className="w-full justify-start gap-3"
            variant="default"
            data-testid="button-extension-login"
          >
            {loading === 'extension' ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Wallet className="h-5 w-5" />
            )}
            <span>MultiversX DeFi Wallet Extension</span>
          </Button>

          <Button
            onClick={handleWebWalletLogin}
            disabled={loading !== null || isCancelling}
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

          <Button
            onClick={handleWalletConnectLogin}
            disabled={loading !== null || isCancelling}
            className="w-full justify-start gap-3"
            variant="outline"
            data-testid="button-walletconnect-login"
          >
            {loading === 'walletconnect' ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <QrCode className="h-5 w-5" />
            )}
            <span>xPortal Mobile (WalletConnect)</span>
          </Button>
        </div>

        <p className="text-xs text-muted-foreground text-center">
          All authentication methods use cryptographic signatures to prevent wallet impersonation
        </p>
      </DialogContent>
    </Dialog>
  );
}

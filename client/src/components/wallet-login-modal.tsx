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
import { useGetIsLoggedIn } from '@multiversx/sdk-dapp/out/react/account/useGetIsLoggedIn';
import { useGetAccount } from '@multiversx/sdk-dapp/out/react/account/useGetAccount';
import { Shield, Wallet, Loader2, X, Smartphone, QrCode } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useLocation } from "wouter";
import { queryClient } from "@/lib/queryClient";
import { useXPortalRecovery, savePendingXPortalConnection, clearPendingXPortalConnection } from "@/hooks/useXPortalRecovery";
import { setActiveWcProvider } from "@/lib/walletConnectStore";
import QRCode from 'qrcode';

// WalletConnect configuration
const WALLETCONNECT_PROJECT_ID = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || 'b4c11c7335da6e3e77753a17d466e4e2';
const WALLETCONNECT_RELAY_URL = 'wss://relay.walletconnect.com';
const CHAIN_ID = '1'; // MultiversX Mainnet

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
  const [wcUri, setWcUri] = useState<string | null>(null);
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string | null>(null);
  const providerRef = useRef<any>(null);
  const wcProviderRef = useRef<WalletConnectV2Provider | null>(null);
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
      logger.log('🔄 Syncing wallet with backend:', walletAddress);
      
      const response = await fetch('/api/auth/wallet/simple-sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ walletAddress }),
      });
      
      if (response.ok) {
        const userData = await response.json();
        logger.log('✅ Backend sync successful:', userData);
        
        localStorage.setItem('walletAddress', walletAddress);
        
        queryClient.setQueryData(['/api/auth/me'], userData);
        await queryClient.invalidateQueries({ queryKey: ['/api/auth/me'] });
        
        toast({
          title: "Wallet connected",
          description: `Connected: ${walletAddress.substring(0, 10)}...${walletAddress.slice(-6)}`,
        });
        
        onOpenChange(false);
        navigate('/dashboard');
        
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
      logger.log('✅ SDK detected login:', address);
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
      logger.log('🔌 Creating extension provider...');
      logger.log('🌐 Current origin:', window.location.origin);
      logger.log('🔗 Current hostname:', window.location.hostname);
      
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.extension 
      });
      providerRef.current = provider;
      logger.log('✅ Extension provider created:', provider);
      
      if (typeof provider.init === 'function') {
        logger.log('📡 Initializing provider...');
        await provider.init();
        logger.log('✅ Provider initialized');
      }
      
      logger.log('🔐 Calling extension login...');
      const loginResult = await provider.login();
      logger.log('📋 Extension login result:', JSON.stringify(loginResult, null, 2));
      
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
          logger.log('getAddress failed:', e);
        }
      }
      
      if (!walletAddress && (provider as any).account?.address) {
        walletAddress = (provider as any).account.address;
      }
      
      logger.log('📍 Got wallet address:', walletAddress);
      
      if (walletAddress && walletAddress.startsWith('erd1')) {
        await syncAndRedirect(walletAddress);
      } else {
        logger.log('⏳ Address not immediately available, waiting for SDK...');
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
            setError('Connection timed out. Please try again.');
          }
        }, 500);
        addPollingInterval(intervalId);
      }
    } catch (err: any) {
      console.error('❌ Extension login error:', err);
      console.error('❌ Error name:', err?.name);
      console.error('❌ Error message:', err?.message);
      console.error('❌ Error stack:', err?.stack);
      
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
      logger.log('🌐 Creating web wallet provider...');
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.crossWindow 
      });
      
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      logger.log('🔐 Calling web wallet login...');
      await provider.login();
      logger.log('✅ Web Wallet login completed');
      
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
    syncAttempted.current = false;
    
    try {
      logger.log('📱 Creating WalletConnect provider directly...');
      logger.log('🌐 Current origin:', window.location.origin);
      logger.log('🔗 Current hostname:', window.location.hostname);
      logger.log('🔑 WalletConnect Project ID:', WALLETCONNECT_PROJECT_ID);
      
      // Create callbacks for the WalletConnect provider
      const callbacks = {
        onClientLogin: () => {
          logger.log('✅ WalletConnect: Client logged in');
        },
        onClientLogout: () => {
          logger.log('🚪 WalletConnect: Client logged out');
        },
        onClientEvent: (event: any) => {
          logger.log('📡 WalletConnect event:', event);
        }
      };
      
      // Create provider options with metadata
      const providerOptions = {
        metadata: {
          name: 'xproof',
          description: 'Blockchain Certification Platform - Create immutable proofs of file ownership',
          url: window.location.origin,
          icons: [`${window.location.origin}/favicon.ico`]
        }
      };
      
      logger.log('📋 WalletConnect options:', JSON.stringify(providerOptions, null, 2));
      
      // Create WalletConnect provider directly with explicit configuration
      const wcProvider = new WalletConnectV2Provider(
        callbacks,
        CHAIN_ID,
        WALLETCONNECT_RELAY_URL,
        WALLETCONNECT_PROJECT_ID,
        providerOptions
      );
      
      wcProviderRef.current = wcProvider;
      setActiveWcProvider(wcProvider);
      logger.log('✅ WalletConnect provider created directly');
      
      // Initialize the provider
      logger.log('🔄 Initializing WalletConnect provider...');
      await wcProvider.init();
      logger.log('✅ WalletConnect provider initialized');
      
      // Connect and get URI for QR code
      logger.log('🔗 Connecting to get pairing URI...');
      const { uri, approval } = await wcProvider.connect();
      
      if (uri) {
        logger.log('📱 WalletConnect URI obtained:', uri.substring(0, 50) + '...');
        setWcUri(uri);
        
        // Generate QR code
        const qrDataUrl = await QRCode.toDataURL(uri, {
          width: 280,
          margin: 2,
          color: {
            dark: '#000000',
            light: '#ffffff'
          }
        });
        setQrCodeDataUrl(qrDataUrl);
        logger.log('📸 QR code generated');
        
        if (isMobileDevice()) {
          savePendingXPortalConnection();
          logger.log('📱 Saved pending xPortal connection state for recovery');
          
          const encodedUri = encodeURIComponent(uri);

          const xportalDeepLink = `xportal://wc?uri=${encodedUri}`;
          const universalLink = `https://maiar.com/?wallet-connect=${encodedUri}`;

          toast({
            title: "xPortal",
            description: "Approve the connection in xPortal, then come back to this page.",
          });

          logger.log('📱 Trying xPortal deep link (xportal:// scheme)...');
          window.location.href = xportalDeepLink;

          setTimeout(() => {
            if (!document.hidden) {
              logger.log('📱 xportal:// scheme did not open app, trying universal link...');
              window.location.href = universalLink;
            }
          }, 2500);
        }
      }
      
      setWaitingForConnection(true);
      
      // Login with the approval callback - the provider handles the flow
      logger.log('⏳ Calling login with approval callback...');
      const loginResult = await wcProvider.login({ approval });
      logger.log('📋 WalletConnect login result:', loginResult);
      
      let walletAddress = wcProvider.getAddress();
      logger.log('📍 Got wallet address from WalletConnect:', walletAddress);
      
      if (walletAddress && walletAddress.startsWith('erd1')) {
        // Clear pending state on successful connection
        clearPendingXPortalConnection();
        setWaitingForConnection(false);
        setWcUri(null);
        setQrCodeDataUrl(null);
        await syncAndRedirect(walletAddress);
      } else {
        // Poll for address
        let attempts = 0;
        const maxAttempts = 60;
        const intervalId = setInterval(async () => {
          attempts++;
          
          const addr = wcProvider.getAddress();
          
          if (addr && addr.startsWith('erd1')) {
            removePollingInterval(intervalId);
            clearPendingXPortalConnection();
            setWaitingForConnection(false);
            setWcUri(null);
            setQrCodeDataUrl(null);
            await syncAndRedirect(addr);
          } else if (attempts >= maxAttempts) {
            removePollingInterval(intervalId);
            clearPendingXPortalConnection();
            setWaitingForConnection(false);
            setLoading(null);
            setWcUri(null);
            setQrCodeDataUrl(null);
            setError('Connection timed out. Please try again.');
          }
        }, 1000);
        addPollingInterval(intervalId);
      }
      
    } catch (err: any) {
      console.error('WalletConnect error:', err);
      clearPendingXPortalConnection();
      setWcUri(null);
      setQrCodeDataUrl(null);
      
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

  // Use xPortal recovery hook  
  const { needsRecovery, clearRecovery, pendingConnection } = useXPortalRecovery();
  const recoveryAttemptedRef = useRef(false);
  const shouldAutoStartRef = useRef(false);
  
  // Clear recovery state when user is successfully logged in
  useEffect(() => {
    if (isLoggedIn && address && needsRecovery) {
      logger.log('📱 xPortal recovery: User logged in, clearing recovery state');
      clearRecovery();
    }
  }, [isLoggedIn, address, needsRecovery, clearRecovery]);
  
  // Check for pending xPortal connection on component mount (recovery after deep link return)
  useEffect(() => {
    if (needsRecovery && !open && !recoveryAttemptedRef.current) {
      recoveryAttemptedRef.current = true;
      shouldAutoStartRef.current = true;
      logger.log('📱 xPortal recovery: Auto-opening modal for reconnection...');
      // Don't clear recovery until connection succeeds - it's cleared when isLoggedIn becomes true
      onOpenChange(true);
    }
  }, [needsRecovery, open, onOpenChange]);
  
  // Auto-start WalletConnect when modal opens for recovery (reuse existing handler)
  useEffect(() => {
    if (open && shouldAutoStartRef.current && !loading && !waitingForConnection) {
      shouldAutoStartRef.current = false;
      logger.log('📱 xPortal recovery: Starting WalletConnect login...');
      
      // Small delay to let modal fully render, then call the existing handler
      const timer = setTimeout(() => {
        handleWalletConnectLogin();
      }, 300);
      
      return () => clearTimeout(timer);
    }
  }, [open, loading, waitingForConnection]);
  
  // Reset state when modal closes
  useEffect(() => {
    if (!open) {
      recoveryAttemptedRef.current = false;
      // Clean up WalletConnect state on modal close
      setWcUri(null);
      setQrCodeDataUrl(null);
      // Cleanup WalletConnect provider if still active (but not if user is logged in - keep session alive)
      if (wcProviderRef.current && !isLoggedIn) {
        try { wcProviderRef.current.logout(); } catch (e) { }
        wcProviderRef.current = null;
        setActiveWcProvider(null);
      }
    }
  }, [open, isLoggedIn]);

  const handleCancel = () => {
    // Clean up extension/web wallet provider
    if (providerRef.current && typeof providerRef.current.logout === 'function') {
      try { providerRef.current.logout(); } catch (e) { }
    }
    // Clean up WalletConnect provider
    if (wcProviderRef.current && typeof wcProviderRef.current.logout === 'function') {
      try { wcProviderRef.current.logout(); } catch (e) { }
      wcProviderRef.current = null;
      setActiveWcProvider(null);
    }
    // Clear all state
    setLoading(null);
    setWaitingForConnection(false);
    setWcUri(null);
    setQrCodeDataUrl(null);
    clearPendingXPortalConnection();
  };

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
            {loading === 'walletconnect' && isMobileDevice() && !qrCodeDataUrl && (
              <p className="text-center text-sm text-muted-foreground">
                After approving in xPortal, come back to this page.
              </p>
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

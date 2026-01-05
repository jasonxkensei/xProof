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
  const [wcUri, setWcUri] = useState<string | null>(null);
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
            title: "Wallet connecté",
            description: `Connecté : ${wcConnectedAddress.substring(0, 10)}...${wcConnectedAddress.substring(wcConnectedAddress.length - 6)}`,
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
      setWcUri(null);
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
      
      // Wait for SDK hooks to detect the connection (they poll the provider state)
      // Don't navigate until we have a verified address from the SDK
      let verifiedAddress = '';
      for (let i = 0; i < 30; i++) {
        await new Promise(resolve => setTimeout(resolve, 200));
        
        // Try to get address from provider
        try {
          if (typeof (provider as any).getAddress === 'function') {
            const addr = await (provider as any).getAddress();
            if (addr && addr.startsWith('erd1')) {
              verifiedAddress = addr;
              break;
            }
          }
          if ((provider as any).account?.address) {
            const addr = (provider as any).account.address;
            if (addr && addr.startsWith('erd1')) {
              verifiedAddress = addr;
              break;
            }
          }
        } catch (e) {
          console.log('Waiting for address...', e);
        }
      }
      
      if (verifiedAddress) {
        console.log('Extension login verified with address:', verifiedAddress);
        localStorage.setItem('walletAddress', verifiedAddress);
        window.location.reload();
      } else {
        // Fallback: check if SDK hooks detected the login
        const sdkAddress = sessionStorage.getItem('sdk-dapp-account-address');
        if (sdkAddress) {
          localStorage.setItem('walletAddress', sdkAddress);
          window.location.reload();
        } else {
          throw new Error('Could not verify wallet connection');
        }
      }
    } catch (error: any) {
      console.error('Extension login error:', error);
      toast({
        title: "Échec de connexion Extension",
        description: error.message || "Veuillez installer l'extension MultiversX DeFi Wallet",
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
        title: "Échec de connexion Web Wallet",
        description: error.message || "Impossible de se connecter au Web Wallet",
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
            // Get address from provider's account or getAddress method
            let addr = '';
            try {
              if (typeof (wcProvider as any).getAddress === 'function') {
                addr = await (wcProvider as any).getAddress();
              } else if ((wcProvider as any).account?.address) {
                addr = (wcProvider as any).account.address;
              }
            } catch (e) {
              console.log('Could not get address from provider:', e);
            }
            if (addr) {
              setWcConnectedAddress(addr);
              setQrCodeDataUrl(null);
              setWcUri(null);
              setLoading(null);
            }
          }
        },
        onClientLogout: async () => {
          console.log(`WalletConnect attempt #${attemptId}: Client logged out`);
          if (attemptRef.current?.id === attemptId) {
            setQrCodeDataUrl(null);
            setWcUri(null);
            setLoading(null);
          }
        },
        onClientEvent: async (event: any) => {
          console.log(`WalletConnect attempt #${attemptId} event:`, event);
        }
      };
      
      console.log('Creating WalletConnectV2Provider with:', {
        chainId: CHAIN_ID,
        relayUrl: RELAY_URL,
        projectId: WALLETCONNECT_PROJECT_ID ? 'configured' : 'MISSING'
      });
      
      if (!WALLETCONNECT_PROJECT_ID) {
        throw new Error('WalletConnect Project ID is not configured');
      }
      
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
      try {
        await wcProvider.init();
        console.log('WalletConnect initialized successfully');
      } catch (initError: any) {
        console.error('WalletConnect init failed:', initError);
        throw new Error(`Initialization failed: ${initError.message || 'Unknown error'}`);
      }
      
      if (abortController.signal.aborted) {
        console.log(`Attempt #${attemptId} aborted before connect`);
        return;
      }
      
      console.log('Connecting to WalletConnect relay...');
      let connectResult;
      try {
        connectResult = await wcProvider.connect();
        console.log('WalletConnect connect() succeeded, uri:', connectResult.uri ? 'present' : 'missing');
      } catch (connectError: any) {
        console.error('WalletConnect connect failed:', connectError);
        throw new Error(`Connection failed: ${connectError.message || 'Unknown error'}`);
      }
      
      const { uri, approval } = connectResult;
      console.log('Got WalletConnect URI:', uri ? 'yes' : 'no');
      
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
          setWcUri(uri);
          console.log('QR code generated, URI stored');
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
      
      let errorMessage = error.message || "Impossible de se connecter via WalletConnect";
      if (error.message?.includes("rejected") || error.message?.includes("cancelled") || error.message?.includes("Proposal")) {
        errorMessage = "Connexion annulée ou refusée par le wallet";
      }
      
      toast({
        title: "Échec de connexion xPortal",
        description: errorMessage,
        variant: "destructive"
      });
      
      if (attemptRef.current?.id === attemptId) {
        setLoading(null);
        setQrCodeDataUrl(null);
        setWcUri(null);
        setLoginAttempted(false);
        attemptRef.current = null;
      }
    }
  };

  const handleCancelWalletConnect = async () => {
    const attempt = attemptRef.current;
    if (!attempt) {
      setQrCodeDataUrl(null);
      setWcUri(null);
      setLoading(null);
      setLoginAttempted(false);
      return;
    }
    
    console.log(`Cancelling WalletConnect attempt #${attempt.id}...`);
    setIsCancelling(true);
    
    attempt.abortController.abort();
    
    setQrCodeDataUrl(null);
    setWcUri(null);
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

  const isMobileDevice = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
    typeof navigator !== 'undefined' ? navigator.userAgent : ''
  );

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
                ? "Cliquez sur le bouton ci-dessous pour ouvrir xPortal et autoriser la connexion"
                : "Scannez ce QR code avec l'application xPortal pour connecter votre wallet"
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
                      
                      // Try multiple deep link formats for better compatibility
                      const isAndroid = /Android/i.test(navigator.userAgent);
                      const isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);
                      
                      // Universal link format (works best for xPortal)
                      const universalLink = `https://maiar.page.link/?apn=com.elrond.maiar.wallet&isi=1519405832&ibi=com.elrond.maiar.wallet&link=https://maiar.com/?wallet-connect=${encodedUri}`;
                      
                      // Alternative: direct xPortal web link
                      const xPortalWebLink = `https://xportal.com/wc?uri=${encodedUri}`;
                      
                      // Try to open the app
                      if (isIOS) {
                        // iOS: Use universal link first
                        window.location.href = universalLink;
                      } else if (isAndroid) {
                        // Android: Try intent URL for better app opening
                        const intentUrl = `intent://wc?uri=${encodedUri}#Intent;scheme=xportal;package=com.elrond.maiar.wallet;end`;
                        window.location.href = intentUrl;
                        
                        // Fallback to universal link after short delay
                        setTimeout(() => {
                          window.location.href = universalLink;
                        }, 2000);
                      } else {
                        // Fallback for other devices
                        window.location.href = xPortalWebLink;
                      }
                    }
                  }}
                  className="w-full"
                  size="lg"
                  disabled={!wcUri}
                  data-testid="button-open-xportal"
                >
                  {!wcUri ? (
                    <Loader2 className="h-5 w-5 mr-2 animate-spin" />
                  ) : (
                    <Smartphone className="h-5 w-5 mr-2" />
                  )}
                  {!wcUri ? 'Préparation...' : 'Ouvrir xPortal'}
                </Button>
                
                <div className="text-center text-sm text-muted-foreground space-y-2">
                  <div className="flex items-center justify-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>En attente de connexion...</span>
                  </div>
                  <p className="text-xs">
                    Après avoir autorisé dans xPortal, revenez ici. La connexion sera automatique.
                  </p>
                  <p className="text-xs text-muted-foreground/70">
                    Si l'app ne s'ouvre pas, assurez-vous que xPortal est installé depuis l'App Store ou Google Play
                  </p>
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
              disabled={isCancelling}
              className="w-full"
              data-testid="button-cancel-walletconnect"
            >
              {isCancelling ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <X className="h-4 w-4 mr-2" />
              )}
              {isCancelling ? 'Annulation...' : 'Annuler'}
            </Button>
          </div>

          <p className="text-xs text-muted-foreground text-center">
            {isMobileDevice 
              ? "Assurez-vous que xPortal est installé sur votre appareil"
              : "Ouvrez l'app xPortal, appuyez sur l'icône scan et scannez ce code"
            }
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
            Connectez votre wallet
          </DialogTitle>
          <DialogDescription>
            Choisissez votre méthode de connexion préférée pour vous authentifier de manière sécurisée
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 py-4">
          <Button
            onClick={handleWalletConnectLogin}
            disabled={loading !== null || isCancelling}
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
            disabled={loading !== null || isCancelling}
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
            <span>MultiversX Wallet</span>
          </Button>
        </div>

        <p className="text-xs text-muted-foreground text-center">
          Authentification sécurisée par signature cryptographique
        </p>
      </DialogContent>
    </Dialog>
  );
}

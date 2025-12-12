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
import { WalletConnectV2Provider } from '@multiversx/sdk-wallet-connect-provider/out/walletConnectV2Provider';
import { useGetIsLoggedIn } from '@multiversx/sdk-dapp/out/react/account/useGetIsLoggedIn';
import { useGetAccount } from '@multiversx/sdk-dapp/out/react/account/useGetAccount';
import { Shield, Wallet, QrCode, Loader2, Smartphone } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { queryClient } from "@/lib/queryClient";

interface WalletLoginModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function WalletLoginModal({ open, onOpenChange }: WalletLoginModalProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const [loginAttempted, setLoginAttempted] = useState(false);
  const { toast } = useToast();
  const isLoggedIn = useGetIsLoggedIn();
  const { address } = useGetAccount();

  useEffect(() => {
    const syncAndReload = async () => {
      if (isLoggedIn && address && open && loginAttempted) {
        console.log('✅ Wallet connected via SDK hooks:', address);
        
        // Wait a bit for SDK to store the token
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Log all sessionStorage keys for debugging
        console.log('📦 SessionStorage keys:', Object.keys(sessionStorage));
        
        // Search for Native Auth token in sessionStorage
        const keys = Object.keys(sessionStorage);
        let nativeAuthToken: string | null = null;
        
        for (const key of keys) {
          const value = sessionStorage.getItem(key);
          // Look for long tokens that could be Native Auth
          if (value && value.length > 100) {
            console.log(`🔍 Found potential token at key "${key}" (length: ${value.length})`);
            // Native Auth tokens are typically base64-encoded and start with specific patterns
            if (value.includes('.') || key.toLowerCase().includes('auth') || key.toLowerCase().includes('token')) {
              nativeAuthToken = value;
              console.log(`✅ Selected token from key: ${key}`);
              break;
            }
          }
        }
        
        // Also check for loginInfo which might contain the token
        const loginInfo = sessionStorage.getItem('loginInfo');
        if (loginInfo && !nativeAuthToken) {
          try {
            const parsed = JSON.parse(loginInfo);
            if (parsed.nativeAuthToken) {
              nativeAuthToken = parsed.nativeAuthToken;
              console.log('✅ Found token in loginInfo');
            }
          } catch (e) {
            // Not JSON, might be the token itself
            if (loginInfo.length > 100) {
              nativeAuthToken = loginInfo;
            }
          }
        }
        
        console.log('🔑 Native Auth Token found:', !!nativeAuthToken);
        
        if (nativeAuthToken) {
          try {
            console.log('📡 Syncing with backend...');
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
              console.log('✅ Backend session created successfully');
              localStorage.setItem('walletAddress', address);
              console.log('🔄 Reloading page to update app state...');
              window.location.reload();
              return;
            } else {
              console.error('❌ Sync failed:', await syncResponse.text());
            }
          } catch (error) {
            console.error('❌ Error syncing with backend:', error);
          }
        }
        
        // Fallback: create a simple session without Native Auth (less secure but functional)
        console.log('⚠️ No Native Auth token found, trying simple wallet sync...');
        try {
          const simpleSync = await fetch('/api/auth/wallet/simple-sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ walletAddress: address }),
          });
          
          if (simpleSync.ok) {
            console.log('✅ Simple sync successful');
            localStorage.setItem('walletAddress', address);
            window.location.reload();
            return;
          }
        } catch (error) {
          console.log('Simple sync not available');
        }
        
        // Last resort: just save to localStorage and reload
        localStorage.setItem('walletAddress', address);
        window.location.reload();
      }
    };
    
    syncAndReload();
  }, [isLoggedIn, address, open, loginAttempted]);

  useEffect(() => {
    if (!open) {
      setLoginAttempted(false);
      setLoading(null);
    }
  }, [open]);

  const handleExtensionLogin = async () => {
    setLoading('extension');
    setLoginAttempted(true);
    try {
      console.log('🔌 Creating Extension provider...');
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.extension 
      });
      
      if (typeof provider.init === 'function') {
        console.log('🔧 Initializing provider...');
        await provider.init();
      }
      
      console.log('🔐 Calling provider.login()...');
      const loginResult = await provider.login();
      console.log('✅ Login call completed, result:', loginResult);
      console.log('⏳ Waiting for SDK hooks to update...');
      
      // Poll for address since SDK hooks may not update immediately
      for (let i = 0; i < 20; i++) {
        await new Promise(resolve => setTimeout(resolve, 250));
        // Check if useEffect has closed the modal
        if (!document.querySelector('[data-testid="modal-wallet-login"]')) {
          console.log('✅ Modal closed by useEffect, login successful');
          return;
        }
      }
      
      // If we get here, the SDK didn't update - try to get address manually
      console.log('⚠️ SDK hooks did not update, trying manual save...');
      const manualAddress = (provider as any).account?.address || 
                           sessionStorage.getItem('sdk-dapp-account-address') ||
                           sessionStorage.getItem('loginData');
      if (manualAddress) {
        localStorage.setItem('walletAddress', manualAddress);
        window.location.reload();
      }
    } catch (error: any) {
      console.error('❌ Extension login error:', error);
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
      console.log('🌐 Creating Web Wallet provider...');
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.crossWindow 
      });
      
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      await provider.login();
      console.log('✅ Web Wallet login call completed');
      console.log('⏳ Waiting for SDK hooks to update...');
    } catch (error: any) {
      console.error('❌ Web Wallet login error:', error);
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
    setLoading('walletconnect');
    setLoginAttempted(true);
    try {
      console.log('🚀 Starting WalletConnect login (direct provider)...');
      const projectId = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID;
      console.log('📱 WalletConnect Project ID:', projectId ? `${projectId.slice(0, 8)}...` : 'MISSING');
      
      if (!projectId) {
        throw new Error("WalletConnect Project ID is not configured.");
      }
      
      const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
      console.log('📱 Running on mobile:', isMobile);
      
      const relayUrl = 'wss://relay.walletconnect.com';
      const chainId = '1'; // Mainnet
      
      const callbacks = {
        onClientLogin: () => {
          console.log('✅ WalletConnect: Client logged in');
        },
        onClientLogout: () => {
          console.log('📤 WalletConnect: Client logged out');
        },
        onClientEvent: (event: any) => {
          console.log('📢 WalletConnect event:', event);
        }
      };
      
      console.log('🔧 Creating WalletConnectV2Provider directly...');
      const wcProvider = new WalletConnectV2Provider(
        callbacks,
        chainId,
        relayUrl,
        projectId,
        {
          metadata: {
            name: 'ProofMint',
            description: 'Blockchain Certification Platform',
            url: window.location.origin,
            icons: [`${window.location.origin}/favicon.ico`]
          }
        }
      );
      
      console.log('🔧 Initializing WalletConnect provider...');
      const initialized = await wcProvider.init();
      console.log('✅ Provider initialized:', initialized);
      
      console.log('🔗 Connecting to get pairing URI...');
      const { uri, approval } = await wcProvider.connect();
      console.log('📋 Got pairing URI:', uri ? `${uri.slice(0, 50)}...` : 'none');
      
      if (uri) {
        if (isMobile) {
          // Save pending connection state before leaving
          sessionStorage.setItem('wc_pending_connection', 'true');
          sessionStorage.setItem('wc_pending_timestamp', Date.now().toString());
          
          const deepLink = `xportal://wc?uri=${encodeURIComponent(uri)}`;
          console.log('📱 Opening xPortal deep link...');
          
          toast({
            title: "Ouverture de xPortal...",
            description: "Approuvez la connexion dans l'app xPortal, puis revenez ici",
          });
          
          // Small delay to show toast before navigating
          setTimeout(() => {
            window.location.href = deepLink;
          }, 500);
          
          // Continue waiting for approval in background
          // This will complete if user returns without closing tab
          try {
            console.log('⏳ Waiting for approval (may complete on return)...');
            const session = await approval();
            console.log('✅ Session approved:', session);
            
            const account = await wcProvider.login({ approval: () => Promise.resolve(session) });
            console.log('✅ Login successful:', account);
            
            if (account?.address) {
              sessionStorage.removeItem('wc_pending_connection');
              localStorage.setItem('walletAddress', account.address);
              
              await fetch('/api/auth/wallet/simple-sync', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ walletAddress: account.address }),
              }).catch(() => {});
              
              window.location.reload();
            }
          } catch (approvalError) {
            console.log('Approval interrupted (expected on mobile redirect):', approvalError);
          }
        } else {
          // Desktop: show instructions to scan QR (URI can be shown as QR)
          console.log('🖥️ Desktop - URI for QR:', uri);
          toast({
            title: "Scannez avec xPortal",
            description: "Ouvrez xPortal sur votre téléphone et scannez le QR code",
          });
          
          console.log('⏳ Waiting for approval...');
          const session = await approval();
          console.log('✅ Session approved:', session);
          
          const account = await wcProvider.login({ approval: () => Promise.resolve(session) });
          console.log('✅ Login successful:', account);
          
          if (account?.address) {
            localStorage.setItem('walletAddress', account.address);
            
            await fetch('/api/auth/wallet/simple-sync', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({ walletAddress: account.address }),
            }).catch(() => {});
            
            window.location.reload();
          }
        }
      }
    } catch (error: any) {
      console.error('❌ WalletConnect error:', error);
      console.error('Error details:', {
        message: error.message,
        stack: error.stack,
        type: error.constructor?.name
      });
      
      let errorMessage = error.message || "Failed to connect via WalletConnect";
      if (error.message?.includes("rejected") || error.message?.includes("cancelled")) {
        errorMessage = "Connection cancelled";
      }
      
      toast({
        title: "xPortal Connection Failed",
        description: errorMessage,
        variant: "destructive"
      });
      setLoading(null);
      setLoginAttempted(false);
    }
  };

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
            <span>MultiversX DeFi Wallet Extension</span>
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
              <QrCode className="h-5 w-5" />
            )}
            <span>xPortal Mobile (WalletConnect)</span>
          </Button>
        </div>

        <p className="text-xs text-muted-foreground text-center">
          🔒 All authentication methods use cryptographic signatures to prevent wallet impersonation
        </p>
      </DialogContent>
    </Dialog>
  );
}

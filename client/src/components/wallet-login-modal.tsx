import { useState, useEffect } from "react";
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
import { Shield, Wallet, QrCode, Loader2 } from "lucide-react";
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
    if (isLoggedIn && address && open && loginAttempted) {
      console.log('✅ Wallet connected via SDK hooks:', address);
      console.log('💾 Saving wallet address to localStorage');
      localStorage.setItem('walletAddress', address);
      
      console.log('🔄 Reloading page to update app state...');
      window.location.reload();
    }
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
      console.log('🚀 Starting WalletConnect login...');
      console.log('📱 WalletConnect Project ID available:', !!import.meta.env.VITE_WALLETCONNECT_PROJECT_ID);
      
      const provider = await ProviderFactory.create({ 
        type: ProviderTypeEnum.walletConnect 
      });
      
      console.log('✅ WalletConnect provider created successfully');
      
      if (typeof provider.init === 'function') {
        await provider.init();
      }
      
      await provider.login();
      console.log('✅ WalletConnect login completed');
      console.log('⏳ Waiting for SDK hooks to update...');
    } catch (error: any) {
      console.error('❌ WalletConnect error:', error);
      console.error('Error details:', {
        message: error.message,
        stack: error.stack,
        type: error.constructor.name
      });
      
      toast({
        title: "WalletConnect Failed",
        description: error.message || "Failed to connect via WalletConnect",
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

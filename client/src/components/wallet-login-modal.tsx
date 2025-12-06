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
  const { toast } = useToast();
  const isLoggedIn = useGetIsLoggedIn();
  const { address } = useGetAccount();

  useEffect(() => {
    if (isLoggedIn && address && open) {
      console.log('✅ Wallet connected:', address);
      queryClient.invalidateQueries({ queryKey: ['/api/auth/me'] });
      onOpenChange(false);
      setLoading(null);
    }
  }, [isLoggedIn, address, open, onOpenChange]);

  const handleExtensionLogin = async () => {
    setLoading('extension');
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
      await provider.login();
      console.log('✅ Login call completed');
    } catch (error: any) {
      console.error('❌ Extension login error:', error);
      toast({
        title: "Extension Login Failed",
        description: error.message || "Please install MultiversX DeFi Wallet Extension",
        variant: "destructive"
      });
      setLoading(null);
    }
  };

  const handleWebWalletLogin = async () => {
    setLoading('webwallet');
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
    } catch (error: any) {
      console.error('❌ Web Wallet login error:', error);
      toast({
        title: "Web Wallet Login Failed",
        description: error.message || "Failed to connect to Web Wallet",
        variant: "destructive"
      });
      setLoading(null);
    }
  };

  const handleWalletConnectLogin = async () => {
    setLoading('walletconnect');
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

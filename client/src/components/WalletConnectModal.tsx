import { useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Wallet, Loader2, ExternalLink, Shield, CheckCircle2, Smartphone } from "lucide-react";
import { useSecureWalletAuth } from "@/hooks/useSecureWalletAuth";
import { Alert, AlertDescription } from "@/components/ui/alert";

interface WalletConnectModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function WalletConnectModal({ open, onOpenChange }: WalletConnectModalProps) {
  const { 
    connectExtension, 
    connectWalletConnect, 
    isConnecting, 
    isExtensionAvailable 
  } = useSecureWalletAuth();

  const handleExtensionConnect = async () => {
    const success = await connectExtension();
    if (success) {
      setTimeout(() => onOpenChange(false), 1000);
    }
  };

  const handleMobileConnect = async () => {
    const success = await connectWalletConnect();
    if (success) {
      setTimeout(() => onOpenChange(false), 1000);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md" data-testid="modal-wallet-connect">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            Connect Your Wallet
          </DialogTitle>
          <DialogDescription>
            Sign a message to securely authenticate with your MultiversX wallet
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Browser Extension Option */}
          <div className="space-y-3">
            <Button
              onClick={handleExtensionConnect}
              disabled={isConnecting || !isExtensionAvailable}
              className="w-full justify-start h-auto py-4"
              variant={isExtensionAvailable ? "default" : "outline"}
              data-testid="button-connect-extension"
            >
              <div className="flex items-center gap-3 w-full">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-background/10">
                  {isConnecting ? (
                    <Loader2 className="h-5 w-5 animate-spin" />
                  ) : (
                    <Wallet className="h-5 w-5" />
                  )}
                </div>
                <div className="flex-1 text-left">
                  <div className="font-semibold">Browser Extension</div>
                  <div className="text-xs opacity-90">
                    {isExtensionAvailable ? 'MultiversX DeFi Wallet detected' : 'Not installed'}
                  </div>
                </div>
                {isExtensionAvailable && (
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                )}
              </div>
            </Button>

            {!isExtensionAvailable && (
              <Alert>
                <AlertDescription className="text-sm">
                  Install the MultiversX DeFi Wallet extension to continue.
                  <a
                    href="https://chrome.google.com/webstore/detail/dngmlblcodfobpdpecaadgfbcggfjfnm"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="ml-1 inline-flex items-center gap-1 font-medium text-primary hover:underline"
                  >
                    Get Extension
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </AlertDescription>
              </Alert>
            )}
          </div>

          {/* Mobile WalletConnect Option */}
          <div className="space-y-3">
            <Button
              onClick={handleMobileConnect}
              disabled={isConnecting}
              className="w-full justify-start h-auto py-4"
              variant="outline"
              data-testid="button-connect-mobile"
            >
              <div className="flex items-center gap-3 w-full">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                  {isConnecting ? (
                    <Loader2 className="h-5 w-5 animate-spin text-primary" />
                  ) : (
                    <Smartphone className="h-5 w-5 text-primary" />
                  )}
                </div>
                <div className="flex-1 text-left">
                  <div className="font-semibold">xPortal Mobile</div>
                  <div className="text-xs opacity-90">
                    Scan QR code with your phone
                  </div>
                </div>
              </div>
            </Button>

            <Alert>
              <AlertDescription className="text-sm">
                Use the xPortal app on your phone to scan the QR code and connect.
              </AlertDescription>
            </Alert>
          </div>

          {/* Security Info */}
          <div className="rounded-lg border bg-muted/30 p-4">
            <div className="space-y-2 text-sm">
              <div className="flex items-start gap-2">
                <Shield className="mt-0.5 h-4 w-4 text-primary shrink-0" />
                <div className="space-y-1">
                  <div className="font-medium">Secure Authentication</div>
                  <div className="text-xs text-muted-foreground">
                    Your wallet signs a unique challenge to prove ownership. We never access your private keys.
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

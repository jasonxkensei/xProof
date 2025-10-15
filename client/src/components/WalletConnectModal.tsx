import { useEffect, useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Wallet, Loader2, ExternalLink, Shield, CheckCircle2 } from "lucide-react";
import { useSecureWalletAuth } from "@/hooks/useSecureWalletAuth";
import { Alert, AlertDescription } from "@/components/ui/alert";

interface WalletConnectModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function WalletConnectModal({ open, onOpenChange }: WalletConnectModalProps) {
  const { connectWallet, isConnecting, isXPortalAvailable, checkXPortalAvailability } = useSecureWalletAuth();
  const [connectionStep, setConnectionStep] = useState<
    'idle' | 'requesting' | 'signing' | 'verifying' | 'success'
  >('idle');

  useEffect(() => {
    if (open) {
      checkXPortalAvailability();
      setConnectionStep('idle');
    }
  }, [open]);

  const handleConnect = async () => {
    setConnectionStep('requesting');
    const success = await connectWallet();
    
    if (success) {
      setConnectionStep('success');
      setTimeout(() => {
        onOpenChange(false);
      }, 1000);
    } else {
      setConnectionStep('idle');
    }
  };

  const getStepMessage = () => {
    switch (connectionStep) {
      case 'requesting':
        return 'Requesting wallet access...';
      case 'signing':
        return 'Please sign the message in your wallet...';
      case 'verifying':
        return 'Verifying signature...';
      case 'success':
        return 'Authentication successful!';
      default:
        return '';
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
          {/* XPortal Option */}
          <div className="space-y-3">
            <Button
              onClick={handleConnect}
              disabled={isConnecting || !isXPortalAvailable}
              className="w-full justify-start h-auto py-4"
              variant={isXPortalAvailable ? "default" : "outline"}
              data-testid="button-connect-xportal"
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
                  <div className="font-semibold">XPortal Extension</div>
                  <div className="text-xs opacity-90">
                    {isXPortalAvailable ? 'Detected' : 'Not installed'}
                  </div>
                </div>
                {isXPortalAvailable && (
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                )}
              </div>
            </Button>

            {!isXPortalAvailable && (
              <Alert>
                <AlertDescription className="text-sm">
                  Install the XPortal browser extension to continue.
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

          {/* Connection Steps */}
          {isConnecting && (
            <div className="rounded-lg border bg-muted/50 p-4">
              <div className="flex items-center gap-3">
                <Loader2 className="h-4 w-4 animate-spin text-primary" />
                <div className="text-sm text-muted-foreground">
                  {getStepMessage()}
                </div>
              </div>
            </div>
          )}

          {connectionStep === 'success' && (
            <div className="rounded-lg border border-green-500/20 bg-green-500/10 p-4">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="h-4 w-4 text-green-500" />
                <div className="text-sm text-green-700 dark:text-green-400">
                  Wallet connected successfully!
                </div>
              </div>
            </div>
          )}

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

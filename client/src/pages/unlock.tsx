import { useEffect } from 'react';
import { useLocation } from 'wouter';
import { UnlockPanelManager } from '@multiversx/sdk-dapp/out/managers/UnlockPanelManager/UnlockPanelManager';
import { Shield, Wallet } from 'lucide-react';

export default function Unlock() {
  const [, navigate] = useLocation();

  useEffect(() => {
    const unlockPanelManager = UnlockPanelManager.init({
      loginHandler: () => {
        navigate('/dashboard');
      },
      onClose: () => {
        navigate('/');
      }
    });

    // Open the unlock panel immediately when the page loads
    unlockPanelManager.openUnlockPanel();
  }, [navigate]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-zinc-950 via-zinc-900 to-emerald-950 flex items-center justify-center p-4">
      <div className="max-w-md w-full space-y-8 text-center">
        <div className="flex justify-center">
          <Shield className="w-16 h-16 text-primary" />
        </div>
        <h1 className="text-4xl font-bold text-white">ProofMint</h1>
        <p className="text-zinc-400 text-lg">
          Connect your MultiversX wallet to continue
        </p>
        <div className="flex items-center justify-center gap-2 text-sm text-zinc-500">
          <Wallet className="w-4 h-4" />
          <span>Choose from xPortal, DeFi Wallet, Web Wallet, Ledger, or WalletConnect</span>
        </div>
      </div>
    </div>
  );
}

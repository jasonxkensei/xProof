import { ExtensionLoginButton } from '@multiversx/sdk-dapp/UI/extension/ExtensionLoginButton';
import { WebWalletLoginButton } from '@multiversx/sdk-dapp/UI/webWallet/WebWalletLoginButton';
import { WalletConnectLoginButton } from '@multiversx/sdk-dapp/UI/walletConnect/WalletConnectLoginButton';
import { LedgerLoginButton } from '@multiversx/sdk-dapp/UI/ledger/LedgerLoginButton';
import { Card } from '@/components/ui/card';
import { Shield, Wallet, QrCode, Usb, Chrome } from 'lucide-react';

export default function Unlock() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-zinc-950 via-zinc-900 to-emerald-950 flex items-center justify-center p-4">
      <div className="max-w-md w-full space-y-8">
        {/* Header */}
        <div className="text-center space-y-3">
          <div className="flex justify-center">
            <Shield className="w-16 h-16 text-primary" />
          </div>
          <h1 className="text-4xl font-bold text-white">ProofMint</h1>
          <p className="text-zinc-400 text-lg">
            Connect your MultiversX wallet to get started
          </p>
        </div>

        {/* Wallet Options */}
        <Card className="p-6 space-y-4 bg-zinc-900/50 border-zinc-800">
          <h2 className="text-xl font-semibold text-white mb-4">
            Choose Connection Method
          </h2>

          {/* Browser Extension */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm text-zinc-400 mb-1">
              <Chrome className="w-4 h-4" />
              <span>Browser Extension</span>
            </div>
            <ExtensionLoginButton
              callbackRoute="/dashboard"
              loginButtonText="xPortal / DeFi Wallet"
              data-testid="button-extension-login"
              className="w-full bg-primary hover:bg-primary/90 text-white font-medium py-3 px-4 rounded-lg transition-colors"
            />
          </div>

          {/* Web Wallet */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm text-zinc-400 mb-1">
              <Wallet className="w-4 h-4" />
              <span>Web Wallet</span>
            </div>
            <WebWalletLoginButton
              callbackRoute="/dashboard"
              loginButtonText="MultiversX Web Wallet"
              data-testid="button-web-wallet-login"
              className="w-full bg-zinc-800 hover:bg-zinc-700 text-white font-medium py-3 px-4 rounded-lg transition-colors"
            />
          </div>

          {/* WalletConnect (Mobile) */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm text-zinc-400 mb-1">
              <QrCode className="w-4 h-4" />
              <span>Mobile App</span>
            </div>
            <WalletConnectLoginButton
              callbackRoute="/dashboard"
              loginButtonText="xPortal Mobile App"
              data-testid="button-walletconnect-login"
              className="w-full bg-zinc-800 hover:bg-zinc-700 text-white font-medium py-3 px-4 rounded-lg transition-colors"
            />
          </div>

          {/* Ledger */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm text-zinc-400 mb-1">
              <Usb className="w-4 h-4" />
              <span>Hardware Wallet</span>
            </div>
            <LedgerLoginButton
              callbackRoute="/dashboard"
              loginButtonText="Ledger"
              data-testid="button-ledger-login"
              className="w-full bg-zinc-800 hover:bg-zinc-700 text-white font-medium py-3 px-4 rounded-lg transition-colors"
            />
          </div>
        </Card>

        {/* Footer */}
        <p className="text-center text-sm text-zinc-500">
          Your wallet will be used to sign transactions and prove file ownership on the MultiversX blockchain
        </p>
      </div>
    </div>
  );
}

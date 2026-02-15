import "./polyfills"; // MUST be first - fixes MultiversX SDK Node.js dependencies
import { createRoot } from "react-dom/client";
import { initApp } from '@multiversx/sdk-dapp/out/methods/initApp/initApp';
import type { InitAppType } from '@multiversx/sdk-dapp/out/methods/initApp/initApp.types';
import { EnvironmentsEnum } from '@multiversx/sdk-dapp/out/types/enums.types';
import App from "./App";
import "./index.css";
import { logger } from './lib/logger';

// Configure MultiversX SDK for MAINNET with Native Auth
// Use environment variable with fallback to ensure WalletConnect works in all environments
const walletConnectProjectId = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || 'b4c11c7335da6e3e77753a17d466e4e2';

logger.log('🔍 WalletConnect Project ID:', walletConnectProjectId ? 'Configured ✅' : 'Missing ❌');
logger.log('🌐 MultiversX Network: MAINNET');

// WalletConnect requires metadata for the dApp
const walletConnectV2Options = walletConnectProjectId ? {
  projectId: walletConnectProjectId,
  metadata: {
    name: 'xproof',
    description: 'Proof primitive for agents & humans on MultiversX',
    url: window.location.origin,
    icons: [`${window.location.origin}/favicon.ico`]
  },
  // WalletConnect relay configuration
  relayUrl: 'wss://relay.walletconnect.com'
} : undefined;

const config: InitAppType = {
  storage: {
    // Use localStorage for better persistence on mobile (survives page unload during deep links)
    getStorageCallback: () => localStorage
  },
  dAppConfig: {
    environment: EnvironmentsEnum.mainnet, // MAINNET for real transactions
    nativeAuth: {
      expirySeconds: 86400, // 24 hours
      tokenExpirationToastWarningSeconds: 300 // warn 5 min before expiration
    },
    // WalletConnect configuration with full options
    ...(walletConnectProjectId && {
      walletConnectV2ProjectId: walletConnectProjectId,
      walletConnectV2Options: walletConnectV2Options
    })
  }
};

logger.log('📋 MultiversX Config:', JSON.stringify(config, null, 2));
logger.log('🔗 WalletConnect Options:', JSON.stringify(walletConnectV2Options, null, 2));

initApp(config);

createRoot(document.getElementById("root")!).render(<App />);

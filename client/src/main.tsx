import "./polyfills"; // MUST be first - fixes MultiversX SDK Node.js dependencies
import { createRoot } from "react-dom/client";
import { initApp } from '@multiversx/sdk-dapp/out/methods/initApp/initApp';
import type { InitAppType } from '@multiversx/sdk-dapp/out/methods/initApp/initApp.types';
import { EnvironmentsEnum } from '@multiversx/sdk-dapp/out/types/enums.types';
import App from "./App";
import "./index.css";

// Configure MultiversX SDK for MAINNET with Native Auth
const walletConnectProjectId = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID;

console.log('🔍 WalletConnect Project ID:', walletConnectProjectId ? 'Configured ✅' : 'Missing ❌');
console.log('🌐 MultiversX Network: MAINNET');

const config: InitAppType = {
  storage: {
    getStorageCallback: () => sessionStorage
  },
  dAppConfig: {
    environment: EnvironmentsEnum.mainnet, // MAINNET for real transactions
    nativeAuth: {
      expirySeconds: 86400, // 24 hours
      tokenExpirationToastWarningSeconds: 300 // warn 5 min before expiration
    },
    // WalletConnect Project ID must be directly in dAppConfig for sdk-dapp v5+
    ...(walletConnectProjectId && {
      walletConnectV2ProjectId: walletConnectProjectId
    })
  }
};

console.log('📋 MultiversX Config:', JSON.stringify(config, null, 2));

initApp(config);

createRoot(document.getElementById("root")!).render(<App />);

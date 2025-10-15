import "./polyfills"; // MUST be first - fixes MultiversX SDK Node.js dependencies
import { createRoot } from "react-dom/client";
import { initApp } from '@multiversx/sdk-dapp/out/methods/initApp/initApp';
import type { InitAppType } from '@multiversx/sdk-dapp/out/methods/initApp/initApp.types';
import { EnvironmentsEnum } from '@multiversx/sdk-dapp/out/types/enums.types';
import App from "./App";
import "./index.css";

// Configure MultiversX SDK for devnet
const config: InitAppType = {
  storage: {
    getStorageCallback: () => sessionStorage
  },
  dAppConfig: {
    environment: EnvironmentsEnum.devnet,
    ...(import.meta.env.VITE_WALLETCONNECT_PROJECT_ID && {
      customNetworkConfig: {
        walletConnectV2ProjectId: import.meta.env.VITE_WALLETCONNECT_PROJECT_ID
      }
    })
  }
};

initApp(config);

createRoot(document.getElementById("root")!).render(<App />);

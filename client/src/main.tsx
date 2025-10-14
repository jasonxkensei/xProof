// Polyfills for MultiversX SDK browser compatibility
import { Buffer } from "buffer";
if (typeof window !== 'undefined') {
  window.global = window;
  window.Buffer = Buffer;
  window.process = { env: {} } as any;
}

import { createRoot } from "react-dom/client";
import { initApp } from "@multiversx/sdk-dapp/out/methods/initApp/initApp";
import type { InitAppType } from "@multiversx/sdk-dapp/out/methods/initApp/initApp.types";
import { EnvironmentsEnum } from "@multiversx/sdk-dapp/out/types/enums.types";
import App from "./App";
import "./index.css";

const config: InitAppType = {
  storage: {
    getStorageCallback: () => sessionStorage
  },
  dAppConfig: {
    environment: EnvironmentsEnum.devnet,
    nativeAuth: {
      expirySeconds: 86400, // 24 hours
      tokenExpirationToastWarningSeconds: 600 // 10 minutes warning
    },
    network: {
      walletAddress: "https://devnet-wallet.multiversx.com"
    }
  }
};

initApp(config).then(() => {
  createRoot(document.getElementById("root")!).render(<App />);
});

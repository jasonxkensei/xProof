import "./polyfills"; // MUST be first - fixes MultiversX SDK Node.js dependencies
import { createRoot } from "react-dom/client";
import { initApp } from '@multiversx/sdk-dapp/out/methods/initApp/initApp';
import type { InitAppType } from '@multiversx/sdk-dapp/out/methods/initApp/initApp.types';
import { EnvironmentsEnum } from '@multiversx/sdk-dapp/out/types/enums.types';
import App from "./App";
import "./index.css";
import { logger } from './lib/logger';

logger.log('MultiversX Network: MAINNET');

const config: InitAppType = {
  storage: {
    getStorageCallback: () => localStorage
  },
  dAppConfig: {
    environment: EnvironmentsEnum.mainnet,
    nativeAuth: {
      expirySeconds: 86400,
      tokenExpirationToastWarningSeconds: 300
    },
  }
};

logger.log('MultiversX Config:', JSON.stringify(config, null, 2));

initApp(config);

createRoot(document.getElementById("root")!).render(<App />);

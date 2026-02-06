import { WalletConnectV2Provider } from '@multiversx/sdk-wallet-connect-provider';

const WALLETCONNECT_PROJECT_ID = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || 'b4c11c7335da6e3e77753a17d466e4e2';
const WALLETCONNECT_RELAY_URL = 'wss://relay.walletconnect.com';
const CHAIN_ID = '1';

let activeWcProvider: WalletConnectV2Provider | null = null;

export function setActiveWcProvider(provider: WalletConnectV2Provider | null) {
  activeWcProvider = provider;
}

export function getActiveWcProvider(): WalletConnectV2Provider | null {
  return activeWcProvider;
}

export async function disconnectWcProvider(): Promise<void> {
  if (activeWcProvider) {
    try {
      await activeWcProvider.logout();
    } catch (e) {
    }
    activeWcProvider = null;
    return;
  }

  const hasWcSession = Object.keys(localStorage).some(
    key => key.startsWith('wc@') || key.includes('walletconnect')
  );

  if (hasWcSession) {
    try {
      const callbacks = {
        onClientLogin: () => {},
        onClientLogout: () => {},
        onClientEvent: () => {}
      };

      const provider = new WalletConnectV2Provider(
        callbacks,
        CHAIN_ID,
        WALLETCONNECT_RELAY_URL,
        WALLETCONNECT_PROJECT_ID
      );

      await provider.init();
      await provider.logout();
    } catch (e) {
    }
  }

  const keysToRemove: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && (key.startsWith('wc@') || key.includes('walletconnect'))) {
      keysToRemove.push(key);
    }
  }
  keysToRemove.forEach(key => localStorage.removeItem(key));
}

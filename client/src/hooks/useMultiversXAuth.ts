import { useGetAccount, useGetIsLoggedIn, useGetLoginInfo } from '@multiversx/sdk-dapp/hooks';
import { logout } from '@multiversx/sdk-dapp/utils';

/**
 * Hook to access MultiversX wallet authentication state
 * Uses official MultiversX SDK with support for:
 * - XPortal/DeFi Browser Extension
 * - MultiversX Web Wallet
 * - WalletConnect (mobile xPortal app)
 * - Ledger hardware wallet
 */
export function useMultiversXAuth() {
  const { address } = useGetAccount();
  const isLoggedIn = useGetIsLoggedIn();
  const { tokenLogin } = useGetLoginInfo();

  const disconnectWallet = async () => {
    await logout();
  };

  return {
    address,
    isAuthenticated: isLoggedIn,
    isLoading: false, // SDK handles loading internally
    nativeAuthToken: tokenLogin?.nativeAuthToken,
    disconnectWallet,
  };
}

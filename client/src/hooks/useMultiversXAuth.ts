import { useGetAccount } from '@multiversx/sdk-dapp/out/react/account/useGetAccount';
import { useGetIsLoggedIn } from '@multiversx/sdk-dapp/out/react/account/useGetIsLoggedIn';
import { useGetLoginInfo } from '@multiversx/sdk-dapp/out/react/loginInfo/useGetLoginInfo';
import { logout } from '@multiversx/sdk-dapp/out/utils';

/**
 * Hook to access MultiversX wallet authentication state
 * Uses official MultiversX SDK with support for:
 * - XPortal/DeFi Browser Extension
 * - MultiversX Web Wallet (no extension needed)
 * - WalletConnect (mobile xPortal app)
 * - Ledger hardware wallet
 * - xAlias
 * - Passkeys
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

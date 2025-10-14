/**
 * Simple MultiversX Web Wallet Authentication
 * Uses direct HTTP redirects - no heavy SDK needed
 */

const WALLET_URL = 'https://devnet-wallet.multiversx.com';
const CALLBACK_URL = `${window.location.origin}/wallet-callback`;

export interface WalletLoginInfo {
  address: string;
  signature: string;
  loginToken: string;
}

/**
 * Redirect user to MultiversX Web Wallet for login
 */
export function loginWithWallet() {
  const callbackUrl = encodeURIComponent(CALLBACK_URL);
  window.location.href = `${WALLET_URL}/hook/login?callbackUrl=${callbackUrl}`;
}

/**
 * Parse wallet callback URL parameters
 */
export function parseWalletCallback(): WalletLoginInfo | null {
  const params = new URLSearchParams(window.location.search);
  const address = params.get('address');
  const signature = params.get('signature');
  const loginToken = params.get('loginToken');

  if (!address || !signature || !loginToken) {
    return null;
  }

  return { address, signature, loginToken };
}

/**
 * Logout from wallet
 */
export function logoutWallet() {
  // Clear local session
  localStorage.removeItem('wallet_address');
  
  // Redirect to wallet logout
  const callbackUrl = encodeURIComponent(window.location.origin);
  window.location.href = `${WALLET_URL}/hook/logout?callbackUrl=${callbackUrl}`;
}

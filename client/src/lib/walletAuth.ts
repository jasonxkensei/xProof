/**
 * MultiversX Web Wallet Authentication
 * Simple webhook-based approach using official MultiversX documentation
 * https://docs.multiversx.com/wallet/webhooks/
 */

const WALLET_URL = 'https://wallet.multiversx.com';

/**
 * Redirect user to MultiversX Web Wallet for login
 * The wallet will redirect back with ?address=erd1...
 */
export function loginWithWallet() {
  const callbackUrl = encodeURIComponent(`${window.location.origin}/wallet-callback`);
  window.location.href = `${WALLET_URL}/hook/login?callbackUrl=${callbackUrl}`;
}

/**
 * Parse wallet callback URL to get the user's address
 * According to MultiversX docs, the callback includes ?address=erd1...
 */
export function parseWalletCallback(): string | null {
  const params = new URLSearchParams(window.location.search);
  const address = params.get('address');
  
  if (!address || !address.startsWith('erd1')) {
    return null;
  }
  
  return address;
}

/**
 * Logout from wallet
 */
export function logoutWallet() {
  // Clear any local data
  localStorage.clear();
  
  // Redirect to home
  window.location.href = '/';
}

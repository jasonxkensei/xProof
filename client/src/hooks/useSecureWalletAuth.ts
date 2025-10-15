import { useState, useEffect } from 'react';
import { useToast } from '@/hooks/use-toast';
import { apiRequest } from '@/lib/queryClient';
import { ExtensionProvider } from '@multiversx/sdk-extension-provider';
import { WalletConnectV2Provider } from '@multiversx/sdk-wallet-connect-provider';

type WalletMethod = 'extension' | 'walletconnect' | null;

/**
 * Hook for secure wallet authentication with signature verification
 * Supports both Extension (browser) and WalletConnect (mobile xPortal)
 */
export function useSecureWalletAuth() {
  const [isConnecting, setIsConnecting] = useState(false);
  const [isExtensionAvailable, setIsExtensionAvailable] = useState(false);
  const [walletMethod, setWalletMethod] = useState<WalletMethod>(null);
  const [wcProvider, setWcProvider] = useState<WalletConnectV2Provider | null>(null);
  const { toast } = useToast();

  // Check if Extension is available on mount
  useEffect(() => {
    const checkExtension = async () => {
      try {
        const provider = ExtensionProvider.getInstance();
        const initialized = await provider.init();
        setIsExtensionAvailable(initialized);
      } catch (error) {
        console.log('Extension not available:', error);
        setIsExtensionAvailable(false);
      }
    };
    checkExtension();
  }, []);

  /**
   * Initialize WalletConnect provider for mobile
   */
  const initWalletConnect = async (): Promise<WalletConnectV2Provider> => {
    // WalletConnect Project ID - get free at https://cloud.walletconnect.com
    const projectId = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || '9b1a9564f91cb6592d96d63c0a6c4d2c'; // Demo ID
    const relayUrl = 'wss://relay.walletconnect.com';
    const chainId = 'D'; // D = Devnet, T = Testnet, 1 = Mainnet

    const callbacks = {
      onClientLogin: async () => {
        console.log('WalletConnect client logged in');
      },
      onClientLogout: async () => {
        console.log('WalletConnect client logged out');
      },
      onClientEvent: async (event: any) => {
        console.log('WalletConnect event:', event);
      }
    };

    const provider = new WalletConnectV2Provider(
      callbacks,
      chainId,
      relayUrl,
      projectId
    );

    await provider.init();
    setWcProvider(provider);
    return provider;
  };

  /**
   * Connect with browser extension
   */
  const connectExtension = async (): Promise<boolean> => {
    setIsConnecting(true);
    setWalletMethod('extension');

    try {
      const provider = ExtensionProvider.getInstance();
      
      // Initialize if needed
      const initialized = await provider.init();
      if (!initialized) {
        throw new Error('Extension not available. Please install MultiversX DeFi Wallet.');
      }

      // Step 1: Login (get wallet address)
      await provider.login();
      const walletAddress = await provider.getAddress();
      console.log('Wallet address:', walletAddress);

      // Step 2: Request challenge from backend
      const challengeResponse = await apiRequest('POST', '/api/auth/challenge', {
        walletAddress,
      });
      const { nonce, message } = await challengeResponse.json();
      console.log('Challenge received:', nonce);

      // Step 3: Sign the challenge message with wallet
      const signedMessage = await provider.signMessage({
        message: message
      });
      const signature = signedMessage.signature;
      console.log('Message signed successfully');

      // Step 4: Verify signature on backend
      const verifyResponse = await apiRequest('POST', '/api/auth/verify', {
        walletAddress,
        signature,
        nonce,
      });

      const { user } = await verifyResponse.json();
      console.log('Authentication successful:', user);

      toast({
        title: "Connected Successfully!",
        description: `Wallet ${walletAddress.slice(0, 8)}...${walletAddress.slice(-6)} authenticated`,
      });

      // Redirect to dashboard
      window.location.href = '/dashboard';
      return true;
    } catch (error: any) {
      console.error('Extension connection error:', error);
      
      let errorMessage = 'Failed to connect wallet';
      if (error.message?.includes('not available')) {
        errorMessage = 'Please install MultiversX DeFi Wallet extension';
      } else if (error.message?.includes('User rejected')) {
        errorMessage = 'Connection cancelled by user';
      } else if (error.message) {
        errorMessage = error.message;
      }

      toast({
        title: "Connection Failed",
        description: errorMessage,
        variant: "destructive",
      });

      return false;
    } finally {
      setIsConnecting(false);
    }
  };

  /**
   * Connect with WalletConnect (xPortal mobile)
   */
  const connectWalletConnect = async (): Promise<boolean> => {
    setIsConnecting(true);
    setWalletMethod('walletconnect');

    try {
      // Initialize WalletConnect provider
      const provider = await initWalletConnect();

      // Step 1: Login (shows QR code modal)
      await provider.login();
      const walletAddress = await provider.getAddress();
      console.log('WalletConnect address:', walletAddress);

      // Step 2: Request challenge from backend
      const challengeResponse = await apiRequest('POST', '/api/auth/challenge', {
        walletAddress,
      });
      const { nonce, message } = await challengeResponse.json();
      console.log('Challenge received:', nonce);

      // Step 3: Sign the challenge message
      const signedMessage = await provider.signMessage({
        message: message
      });
      const signature = signedMessage.signature;
      console.log('Message signed via WalletConnect');

      // Step 4: Verify signature on backend
      const verifyResponse = await apiRequest('POST', '/api/auth/verify', {
        walletAddress,
        signature,
        nonce,
      });

      const { user } = await verifyResponse.json();
      console.log('Authentication successful:', user);

      toast({
        title: "Connected Successfully!",
        description: `Mobile wallet authenticated`,
      });

      // Redirect to dashboard
      window.location.href = '/dashboard';
      return true;
    } catch (error: any) {
      console.error('WalletConnect error:', error);
      
      let errorMessage = 'Failed to connect mobile wallet';
      if (error.message?.includes('User rejected')) {
        errorMessage = 'Connection cancelled';
      } else if (error.message) {
        errorMessage = error.message;
      }

      toast({
        title: "Connection Failed",
        description: errorMessage,
        variant: "destructive",
      });

      return false;
    } finally {
      setIsConnecting(false);
    }
  };

  /**
   * Logout and clear session
   */
  const disconnectWallet = async () => {
    try {
      // Logout from provider
      if (walletMethod === 'extension') {
        const provider = ExtensionProvider.getInstance();
        await provider.logout();
      } else if (walletMethod === 'walletconnect' && wcProvider) {
        await wcProvider.logout();
      }
      
      // Call backend logout
      await apiRequest('POST', '/api/auth/logout', {});

      // Redirect to home
      window.location.href = '/';
    } catch (error) {
      console.error('Logout error:', error);
      // Still redirect even if logout fails
      window.location.href = '/';
    }
  };

  return {
    connectExtension,
    connectWalletConnect,
    disconnectWallet,
    isConnecting,
    isExtensionAvailable,
    walletMethod,
  };
}

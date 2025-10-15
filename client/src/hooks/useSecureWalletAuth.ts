import { useState } from 'react';
import { useToast } from '@/hooks/use-toast';
import { apiRequest } from '@/lib/queryClient';

interface WalletProvider {
  init(): Promise<boolean>;
  login(): Promise<string>;
  signMessage(message: string): Promise<string>;
  getAddress(): Promise<string>;
  logout(): Promise<void>;
}

/**
 * XPortal (formerly Maiar DeFi Wallet) Extension Provider
 * Uses the injected window.elrondWallet object
 */
class XPortalProvider implements WalletProvider {
  async init(): Promise<boolean> {
    // Check if XPortal extension is installed
    return typeof (window as any).elrondWallet !== 'undefined';
  }

  async login(): Promise<string> {
    const elrondWallet = (window as any).elrondWallet;
    if (!elrondWallet) {
      throw new Error('XPortal extension not found');
    }

    // Request account from extension
    const address = await elrondWallet.requestAccounts();
    if (!address || address.length === 0) {
      throw new Error('No account selected');
    }

    return Array.isArray(address) ? address[0] : address;
  }

  async signMessage(message: string): Promise<string> {
    const elrondWallet = (window as any).elrondWallet;
    if (!elrondWallet) {
      throw new Error('XPortal extension not found');
    }

    // Sign the message with the wallet
    const signature = await elrondWallet.signMessage({
      message,
    });

    return signature.signature || signature;
  }

  async getAddress(): Promise<string> {
    const elrondWallet = (window as any).elrondWallet;
    if (!elrondWallet) {
      throw new Error('XPortal extension not found');
    }

    const address = await elrondWallet.getAddress();
    return address;
  }

  async logout(): Promise<void> {
    const elrondWallet = (window as any).elrondWallet;
    if (elrondWallet && elrondWallet.logout) {
      await elrondWallet.logout();
    }
  }
}

/**
 * Hook for secure wallet authentication with signature verification
 */
export function useSecureWalletAuth() {
  const [isConnecting, setIsConnecting] = useState(false);
  const [isXPortalAvailable, setIsXPortalAvailable] = useState(false);
  const { toast } = useToast();

  // Check if XPortal is available on mount
  const checkXPortalAvailability = async () => {
    const provider = new XPortalProvider();
    const available = await provider.init();
    setIsXPortalAvailable(available);
    return available;
  };

  /**
   * Connect and authenticate with wallet using signature verification
   */
  const connectWallet = async (): Promise<boolean> => {
    setIsConnecting(true);

    try {
      const provider = new XPortalProvider();

      // Step 1: Check if XPortal is available
      const isAvailable = await provider.init();
      if (!isAvailable) {
        toast({
          title: "XPortal Extension Not Found",
          description: "Please install the XPortal browser extension to continue",
          variant: "destructive",
        });
        return false;
      }

      // Step 2: Request wallet address
      const walletAddress = await provider.login();
      console.log('Wallet address:', walletAddress);

      // Step 3: Request challenge from backend
      const challengeResponse = await apiRequest('POST', '/api/auth/challenge', {
        walletAddress,
      });
      const { nonce, message } = await challengeResponse.json();
      console.log('Challenge received:', nonce);

      // Step 4: Sign the challenge message with wallet
      const signature = await provider.signMessage(message);
      console.log('Message signed successfully');

      // Step 5: Verify signature on backend
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
      console.error('Wallet connection error:', error);
      
      let errorMessage = 'Failed to connect wallet';
      if (error.message.includes('User rejected')) {
        errorMessage = 'Connection cancelled by user';
      } else if (error.message.includes('not found')) {
        errorMessage = 'Please install XPortal extension';
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
      const provider = new XPortalProvider();
      await provider.logout();
      
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
    connectWallet,
    disconnectWallet,
    isConnecting,
    isXPortalAvailable,
    checkXPortalAvailability,
  };
}

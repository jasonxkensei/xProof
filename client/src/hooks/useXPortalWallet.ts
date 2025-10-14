import { useState, useEffect } from "react";

// XPortal wallet interface (will be injected by XPortal extension)
interface XPortalWallet {
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  getAddress: () => string | null;
  signTransaction: (transaction: any) => Promise<any>;
  isConnected: () => boolean;
}

declare global {
  interface Window {
    elrondWallet?: XPortalWallet;
  }
}

export function useXPortalWallet() {
  const [address, setAddress] = useState<string | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isAvailable, setIsAvailable] = useState(false);

  useEffect(() => {
    // Check if XPortal wallet extension is available
    const checkWallet = () => {
      if (window.elrondWallet) {
        setIsAvailable(true);
        if (window.elrondWallet.isConnected()) {
          const addr = window.elrondWallet.getAddress();
          setAddress(addr);
          setIsConnected(!!addr);
        }
      }
    };

    checkWallet();
    // Retry a few times in case extension loads slowly
    const interval = setInterval(checkWallet, 1000);
    setTimeout(() => clearInterval(interval), 5000);

    return () => clearInterval(interval);
  }, []);

  const connect = async () => {
    if (!window.elrondWallet) {
      throw new Error("XPortal wallet extension not found. Please install it from the browser store.");
    }

    try {
      await window.elrondWallet.connect();
      const addr = window.elrondWallet.getAddress();
      setAddress(addr);
      setIsConnected(!!addr);
    } catch (error: any) {
      throw new Error(`Failed to connect wallet: ${error.message}`);
    }
  };

  const disconnect = async () => {
    if (!window.elrondWallet) return;

    try {
      await window.elrondWallet.disconnect();
      setAddress(null);
      setIsConnected(false);
    } catch (error: any) {
      throw new Error(`Failed to disconnect wallet: ${error.message}`);
    }
  };

  const signTransaction = async (transaction: any) => {
    if (!window.elrondWallet) {
      throw new Error("XPortal wallet not available");
    }

    if (!isConnected) {
      throw new Error("Wallet not connected");
    }

    try {
      const signedTx = await window.elrondWallet.signTransaction(transaction);
      return signedTx;
    } catch (error: any) {
      throw new Error(`Failed to sign transaction: ${error.message}`);
    }
  };

  return {
    address,
    isConnected,
    isAvailable,
    connect,
    disconnect,
    signTransaction,
  };
}

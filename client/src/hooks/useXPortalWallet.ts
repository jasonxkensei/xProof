import { useState, useEffect } from "react";

// XPortal wallet interface (will be injected by XPortal extension)
interface XPortalWallet {
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  getAddress: () => string | null;
  signMessage: (message: string) => Promise<string>;
  signTransaction: (transaction: any) => Promise<any>;
  isConnected: () => boolean;
}

declare global {
  interface Window {
    elrondWallet?: XPortalWallet;
  }
}

// Development mode: Create simulated wallet for testing
// In production, users would need the XPortal browser extension installed
const createSimulatedWallet = (): XPortalWallet => {
  let connected = false;
  let address: string | null = null;

  return {
    async connect() {
      // Simulate wallet connection
      address = "erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu";
      connected = true;
      console.log("🔗 Simulated wallet connected:", address);
    },
    async disconnect() {
      address = null;
      connected = false;
      console.log("❌ Simulated wallet disconnected");
    },
    getAddress() {
      return address;
    },
    async signMessage(message: string) {
      if (!connected) throw new Error("Wallet not connected");
      // Simulate signature (in production, this would be real ed25519 signature)
      const simSignature = Array.from({ length: 128 }, () => 
        Math.floor(Math.random() * 16).toString(16)
      ).join('');
      console.log("✍️ Simulated message signing:", message.substring(0, 50) + "...");
      return simSignature;
    },
    async signTransaction(transaction: any) {
      if (!connected) throw new Error("Wallet not connected");
      console.log("✍️ Simulated transaction signing:", transaction);
      return { ...transaction, signature: "simulated_signature" };
    },
    isConnected() {
      return connected;
    },
  };
};

// Check if in development mode and inject simulated wallet
if (import.meta.env.DEV && !window.elrondWallet) {
  console.log("🔧 Development mode: Using simulated XPortal wallet");
  window.elrondWallet = createSimulatedWallet();
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
        // Try to get current address (if already connected)
        try {
          const addr = window.elrondWallet.getAddress?.();
          if (addr) {
            setAddress(addr);
            setIsConnected(true);
          }
        } catch (e) {
          // Not connected yet, that's fine
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

  const signMessage = async (message: string) => {
    if (!window.elrondWallet) {
      throw new Error("XPortal wallet not available");
    }

    if (!isConnected) {
      throw new Error("Wallet not connected");
    }

    try {
      const signature = await window.elrondWallet.signMessage(message);
      return signature;
    } catch (error: any) {
      throw new Error(`Failed to sign message: ${error.message}`);
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
    signMessage,
    signTransaction,
  };
}

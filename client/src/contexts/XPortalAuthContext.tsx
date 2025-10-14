import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { useXPortalWallet } from "@/hooks/useXPortalWallet";
import { apiRequest } from "@/lib/queryClient";

interface User {
  walletAddress: string;
  subscriptionTier: string;
  subscriptionStatus: string;
  monthlyUsage: number;
  companyName: string | null;
  companyLogoUrl: string | null;
  firstName?: string | null;
  lastName?: string | null;
  email?: string | null;
  usageResetDate?: Date | null;
  createdAt?: Date | null;
}

interface AuthContextType {
  user: User | null;
  wallet: ReturnType<typeof useXPortalWallet>;
  isLoading: boolean;
  isAuthenticated: boolean;
  isConnecting: boolean;
  connectWallet: () => Promise<void>;
  disconnectWallet: () => Promise<void>;
}

const XPortalAuthContext = createContext<AuthContextType | undefined>(undefined);

export function XPortalAuthProvider({ children }: { children: ReactNode }) {
  const wallet = useXPortalWallet();
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Sync user data when wallet connects/disconnects
  useEffect(() => {
    async function syncUser() {
      if (wallet.isConnected && wallet.address) {
        try {
          setIsLoading(true);
          
          // Step 1: Request challenge from server
          const challengeResponse = await apiRequest("POST", "/api/auth/challenge", {
            walletAddress: wallet.address,
          }) as { nonce: string; message: string };
          
          // Step 2: Sign the message with wallet
          const signature = await wallet.signMessage(challengeResponse.message);
          
          if (!signature) {
            throw new Error("Failed to sign message");
          }
          
          // Step 3: Verify signature and create session
          const userData = await apiRequest("POST", "/api/auth/verify", {
            walletAddress: wallet.address,
            signature,
            nonce: challengeResponse.nonce,
          }) as { user: User; message: string };
          
          setUser(userData.user);
        } catch (error) {
          console.error("Error syncing user:", error);
          setUser(null);
          // Disconnect wallet if authentication fails
          await wallet.disconnect();
        } finally {
          setIsLoading(false);
        }
      } else {
        setUser(null);
        setIsLoading(false);
      }
    }

    syncUser();
  }, [wallet.isConnected, wallet.address]);

  const connectWallet = async () => {
    await wallet.connect();
  };

  const disconnectWallet = async () => {
    try {
      // Call logout endpoint to destroy server session
      await apiRequest("POST", "/api/auth/logout", {});
    } catch (error) {
      console.error("Error logging out:", error);
    } finally {
      await wallet.disconnect();
      setUser(null);
    }
  };

  return (
    <XPortalAuthContext.Provider
      value={{
        user,
        wallet,
        isLoading,
        isAuthenticated: wallet.isConnected && !!user,
        isConnecting: wallet.isConnecting,
        connectWallet,
        disconnectWallet,
      }}
    >
      {children}
    </XPortalAuthContext.Provider>
  );
}

export function useXPortalAuth() {
  const context = useContext(XPortalAuthContext);
  if (!context) {
    throw new Error("useXPortalAuth must be used within XPortalAuthProvider");
  }
  return context;
}

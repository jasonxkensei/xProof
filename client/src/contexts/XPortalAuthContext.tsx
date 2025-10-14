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
}

interface AuthContextType {
  user: User | null;
  wallet: ReturnType<typeof useXPortalWallet>;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: () => Promise<void>;
  logout: () => Promise<void>;
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
          // Register or fetch user by wallet address
          const response = await apiRequest("POST", "/api/auth/xportal", {
            walletAddress: wallet.address,
          });
          const userData = await response.json();
          setUser(userData);
        } catch (error) {
          console.error("Error syncing user:", error);
          setUser(null);
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

  const login = async () => {
    await wallet.connect();
  };

  const logout = async () => {
    await wallet.disconnect();
    setUser(null);
  };

  return (
    <XPortalAuthContext.Provider
      value={{
        user,
        wallet,
        isLoading,
        isAuthenticated: wallet.isConnected && !!user,
        login,
        logout,
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

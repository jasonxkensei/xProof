import { useQuery, useMutation } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import { useLocation } from 'wouter';
import { queryClient } from '@/lib/queryClient';
import { useGetAccount } from '@multiversx/sdk-dapp/out/react/account/useGetAccount';
import { useGetIsLoggedIn } from '@multiversx/sdk-dapp/out/react/account/useGetIsLoggedIn';
import { getAccountProvider } from '@multiversx/sdk-dapp/out/providers/helpers/accountProvider';

interface User {
  id: number;
  walletAddress: string;
  email?: string | null;
  subscriptionTier: string;
  subscriptionStatus: string;
  monthlyUsage: number;
  companyName?: string | null;
  companyLogoUrl?: string | null;
  firstName?: string | null;
  lastName?: string | null;
  usageResetDate?: Date | null;
  createdAt?: Date | null;
}

function getNativeAuthTokenFromStorage(): string | null {
  // SDK now uses localStorage for better persistence (mobile deep links)
  const keys = Object.keys(localStorage);
  for (const key of keys) {
    if (key.includes('nativeAuth') || key.includes('token')) {
      const value = localStorage.getItem(key);
      if (value && value.length > 50) {
        return value;
      }
    }
  }
  const directToken = localStorage.getItem('nativeAuthToken');
  if (directToken) return directToken;
  
  const loginToken = localStorage.getItem('loginToken');
  if (loginToken) return loginToken;
  
  // Fallback to sessionStorage for backward compatibility
  const sessionKeys = Object.keys(sessionStorage);
  for (const key of sessionKeys) {
    if (key.includes('nativeAuth') || key.includes('token')) {
      const value = sessionStorage.getItem(key);
      if (value && value.length > 50) {
        return value;
      }
    }
  }
  
  return null;
}

export function useWalletAuth() {
  const [, navigate] = useLocation();
  const prevLoggedIn = useRef(false);
  
  // Get wallet state from sdk-dapp
  const { address: sdkAddress } = useGetAccount();
  const isLoggedInSdk = useGetIsLoggedIn();
  
  // Fallback: check localStorage for saved wallet address (localStorage persists across page reloads)
  const savedAddress = typeof window !== 'undefined' ? localStorage.getItem('walletAddress') : null;
  const address = sdkAddress || savedAddress || '';
  const isLoggedIn = isLoggedInSdk || !!savedAddress;
  
  console.log('🔍 localStorage walletAddress:', savedAddress);

  console.log('👀 useWalletAuth state:', { 
    isLoggedInSdk, 
    sdkAddress: sdkAddress?.slice(0, 20), 
    savedAddress: savedAddress?.slice(0, 20),
    effectiveAddress: address?.slice(0, 20),
    isLoggedIn
  });

  useEffect(() => {
    if (isLoggedIn && address && !prevLoggedIn.current) {
      console.log('🔄 Wallet login detected, invalidating auth query...');
      prevLoggedIn.current = true;
      queryClient.invalidateQueries({ queryKey: ['/api/auth/me'] });
    } else if (!isLoggedIn && prevLoggedIn.current) {
      console.log('🔌 Wallet disconnected');
      prevLoggedIn.current = false;
      localStorage.removeItem('walletAddress');
    }
  }, [isLoggedIn, address]);

  // Fetch user data from backend when wallet is connected
  const { data: user, isLoading, refetch } = useQuery<User | null>({
    queryKey: ['/api/auth/me'],
    queryFn: async () => {
      if (!address) {
        return null;
      }

      console.log('📡 Checking auth status for wallet:', address);

      try {
        const response = await fetch('/api/auth/me', {
          credentials: 'include',
        });
        
        if (response.status === 401) {
          console.log('🔐 No backend session, syncing with Native Auth...');
          const nativeAuthToken = getNativeAuthTokenFromStorage();
          
          if (!nativeAuthToken) {
            console.error('No native auth token found - will retry...');
            await new Promise(resolve => setTimeout(resolve, 1000));
            const retryToken = getNativeAuthTokenFromStorage();
            if (!retryToken) {
              console.error('Still no token after retry');
              return null;
            }
          }

          const tokenToUse = nativeAuthToken || getNativeAuthTokenFromStorage();
          if (!tokenToUse) return null;

          const syncResponse = await fetch('/api/auth/wallet/sync', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${tokenToUse}`
            },
            credentials: 'include',
            body: JSON.stringify({ walletAddress: address }),
          });

          if (syncResponse.ok) {
            console.log('✅ Backend session created successfully');
            return syncResponse.json();
          }
          console.error('❌ Failed to sync with backend:', await syncResponse.text());
          return null;
        }
        
        if (!response.ok) {
          throw new Error('Failed to fetch user');
        }
        
        console.log('✅ User authenticated from existing session');
        return response.json();
      } catch (error) {
        console.error('Error checking auth status:', error);
        return null;
      }
    },
    enabled: isLoggedIn && !!address, // Only run query when wallet is connected
    retry: 2,
    retryDelay: 1000,
    staleTime: 1000 * 60 * 5, // 5 minutes
  });

  // Logout mutation
  const logoutMutation = useMutation({
    mutationFn: async () => {
      // Logout from sdk-dapp (clears wallet connection)
      try {
        const provider = getAccountProvider();
        if (provider && typeof provider.logout === 'function') {
          await provider.logout();
        }
      } catch (e) {
        console.log('Provider logout error (non-fatal):', e);
      }
      
      // Logout from backend (clears session)
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          credentials: 'include',
        });
      } catch (e) {
        console.log('Backend logout error (non-fatal):', e);
      }

      return { success: true };
    },
    onSuccess: () => {
      // Clear all storage
      localStorage.removeItem('walletAddress');
      localStorage.removeItem('loginInfo');
      localStorage.removeItem('nativeAuthToken');
      localStorage.removeItem('loginToken');
      
      // Clear all SDK-related keys
      const keysToRemove: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && (key.includes('sdk') || key.includes('wallet') || key.includes('auth') || key.includes('dapp'))) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach(key => localStorage.removeItem(key));
      
      sessionStorage.clear();
      queryClient.clear();
      
      // Force navigation with page reload to reset SDK state
      window.location.href = '/';
    },
    onError: (error) => {
      console.error('Logout error:', error);
      // Still clear everything and redirect on error
      localStorage.clear();
      sessionStorage.clear();
      queryClient.clear();
      window.location.href = '/';
    },
  });

  return {
    user,
    walletAddress: address,
    isAuthenticated: isLoggedIn && !!user,
    isWalletConnected: isLoggedInSdk, // SDK is actually connected (can sign transactions)
    isLoading: isLoading && isLoggedIn, // Loading only when fetching user data
    logout: logoutMutation.mutate,
    isLoggingOut: logoutMutation.isPending,
  };
}

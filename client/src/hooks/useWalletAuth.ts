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
  const keys = Object.keys(sessionStorage);
  for (const key of keys) {
    if (key.includes('nativeAuth') || key.includes('token')) {
      const value = sessionStorage.getItem(key);
      if (value && value.length > 50) {
        return value;
      }
    }
  }
  const directToken = sessionStorage.getItem('nativeAuthToken');
  if (directToken) return directToken;
  
  const loginToken = sessionStorage.getItem('loginToken');
  if (loginToken) return loginToken;
  
  return null;
}

export function useWalletAuth() {
  const [, navigate] = useLocation();
  const prevLoggedIn = useRef(false);
  
  // Get wallet state from sdk-dapp
  const { address: sdkAddress } = useGetAccount();
  const isLoggedInSdk = useGetIsLoggedIn();
  
  // Fallback: check sessionStorage for saved wallet address
  const savedAddress = sessionStorage.getItem('walletAddress');
  const address = sdkAddress || savedAddress || '';
  const isLoggedIn = isLoggedInSdk || !!savedAddress;

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
      sessionStorage.removeItem('walletAddress');
    }
  }, [isLoggedIn, address]);

  // Fetch user data from backend when wallet is connected
  const { data: user, isLoading, refetch } = useQuery<User | null>({
    queryKey: ['/api/auth/me'],
    queryFn: async () => {
      if (!address || !isLoggedInSdk) {
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
          
          console.log('🔑 Native Auth Token found:', !!nativeAuthToken);
          
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
      const provider = getAccountProvider();
      await provider.logout();
      
      // Logout from backend (clears session)
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Logout failed');
      }

      return response.json();
    },
    onSuccess: () => {
      queryClient.clear();
      navigate('/');
    },
  });

  return {
    user,
    walletAddress: address,
    isAuthenticated: isLoggedInSdk && !!user,
    isLoading: isLoading || (isLoggedInSdk && !user), // Loading if sdk says logged in but no user data yet
    logout: logoutMutation.mutate,
    isLoggingOut: logoutMutation.isPending,
  };
}

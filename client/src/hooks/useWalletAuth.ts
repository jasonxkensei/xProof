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
  const initialCheckDone = useRef(false);
  
  const { address: sdkAddress } = useGetAccount();
  const isLoggedInSdk = useGetIsLoggedIn();
  
  const savedAddress = typeof window !== 'undefined' ? localStorage.getItem('walletAddress') : null;
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
      localStorage.removeItem('walletAddress');
    }
  }, [isLoggedIn, address]);

  const { data: user, isLoading } = useQuery<User | null>({
    queryKey: ['/api/auth/me'],
    queryFn: async () => {
      console.log('📡 Checking auth status...');
      
      try {
        const response = await fetch('/api/auth/me', {
          credentials: 'include',
        });
        
        if (response.ok) {
          const userData = await response.json();
          console.log('✅ User authenticated from existing session:', userData.walletAddress?.slice(0, 15));
          
          if (userData.walletAddress && !localStorage.getItem('walletAddress')) {
            localStorage.setItem('walletAddress', userData.walletAddress);
          }
          
          initialCheckDone.current = true;
          return userData;
        }
        
        if (response.status === 401) {
          console.log('🔐 No backend session...');
          
          if (address) {
            console.log('📤 Attempting to sync wallet:', address.slice(0, 15));
            const nativeAuthToken = getNativeAuthTokenFromStorage();
            
            if (nativeAuthToken) {
              const syncResponse = await fetch('/api/auth/wallet/sync', {
                method: 'POST',
                headers: { 
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${nativeAuthToken}`
                },
                credentials: 'include',
                body: JSON.stringify({ walletAddress: address }),
              });

              if (syncResponse.ok) {
                console.log('✅ Backend session created via native auth');
                initialCheckDone.current = true;
                return syncResponse.json();
              }
            }
            
            const simpleSyncResponse = await fetch('/api/auth/wallet/simple-sync', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({ walletAddress: address }),
            });

            if (simpleSyncResponse.ok) {
              console.log('✅ Backend session created via simple sync');
              initialCheckDone.current = true;
              return simpleSyncResponse.json();
            }
            
            console.log('❌ Could not establish backend session');
          }
          
          initialCheckDone.current = true;
          return null;
        }
        
        initialCheckDone.current = true;
        return null;
      } catch (error) {
        console.error('Error checking auth status:', error);
        initialCheckDone.current = true;
        return null;
      }
    },
    enabled: true,
    retry: 1,
    retryDelay: 500,
    staleTime: 1000 * 60 * 5,
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      try {
        const provider = getAccountProvider();
        if (provider && typeof provider.logout === 'function') {
          await provider.logout();
        }
      } catch (e) {
        console.log('Provider logout error (non-fatal):', e);
      }
      
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
      localStorage.removeItem('walletAddress');
      localStorage.removeItem('loginInfo');
      localStorage.removeItem('nativeAuthToken');
      localStorage.removeItem('loginToken');
      
      const keysToRemove: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && (key.includes('sdk') || key.includes('wallet') || key.includes('auth') || key.includes('dapp') || key.includes('wc@'))) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach(key => localStorage.removeItem(key));
      
      sessionStorage.clear();
      queryClient.clear();
      
      window.location.href = '/';
    },
    onError: (error) => {
      console.error('Logout error:', error);
      localStorage.clear();
      sessionStorage.clear();
      queryClient.clear();
      window.location.href = '/';
    },
  });

  const isAuthenticated = !!user;

  return {
    user,
    walletAddress: user?.walletAddress || address,
    isAuthenticated,
    isWalletConnected: isLoggedInSdk,
    isLoading,
    logout: logoutMutation.mutate,
    isLoggingOut: logoutMutation.isPending,
  };
}

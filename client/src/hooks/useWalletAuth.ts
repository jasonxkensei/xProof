import { useQuery, useMutation } from '@tanstack/react-query';
import { logger } from '@/lib/logger';
import { useEffect, useRef, useState, useCallback } from 'react';
import { useLocation } from 'wouter';
import { queryClient } from '@/lib/queryClient';
import { useGetAccount } from '@multiversx/sdk-dapp/out/react/account/useGetAccount';
import { useGetIsLoggedIn } from '@multiversx/sdk-dapp/out/react/account/useGetIsLoggedIn';
import { getAccountProvider } from '@multiversx/sdk-dapp/out/providers/helpers/accountProvider';
import { disconnectWcProvider } from '@/lib/walletConnectStore';

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

// Global sync state - shared promise ensures all hook instances wait for the same sync
let syncPromise: Promise<User | null> | null = null;
let lastSyncedAddress: string | null = null;

export function useWalletAuth() {
  const [, navigate] = useLocation();
  const prevLoggedIn = useRef(false);
  const prevAddress = useRef<string | null>(null);
  const [sessionReady, setSessionReady] = useState(false);
  const [syncFailed, setSyncFailed] = useState(false);
  
  const { address: sdkAddress } = useGetAccount();
  const isLoggedInSdk = useGetIsLoggedIn();
  
  const savedAddress = typeof window !== 'undefined' ? localStorage.getItem('walletAddress') : null;
  const address = sdkAddress || savedAddress || '';
  const isLoggedIn = isLoggedInSdk || !!savedAddress;
  
  // Query should only run when:
  // 1. No wallet connected (check for existing session)
  // 2. Wallet connected AND sync completed successfully
  const shouldQueryAuth = !isLoggedIn || (sessionReady && !syncFailed);
  
  logger.log('👀 useWalletAuth state:', { 
    isLoggedInSdk, 
    sdkAddress: sdkAddress?.slice(0, 20), 
    savedAddress: savedAddress?.slice(0, 20),
    effectiveAddress: address?.slice(0, 20),
    isLoggedIn,
    sessionReady,
    syncFailed,
    shouldQueryAuth
  });

  // Sync wallet with backend when wallet is connected
  // Uses shared promise so all hook instances wait for the same sync
  const syncWalletSession = useCallback(async (walletAddress: string): Promise<User | null> => {
    // If sync already in progress for this address, await the existing promise
    if (syncPromise && lastSyncedAddress === walletAddress) {
      logger.log('⏳ Sync already in progress, waiting...');
      return syncPromise;
    }
    
    // Start new sync
    logger.log('📤 Syncing wallet session:', walletAddress.slice(0, 15));
    lastSyncedAddress = walletAddress;
    
    syncPromise = (async () => {
      try {
        // Try native auth first
        const nativeAuthToken = getNativeAuthTokenFromStorage();
        if (nativeAuthToken) {
          const syncResponse = await fetch('/api/auth/wallet/sync', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${nativeAuthToken}`
            },
            credentials: 'include',
            body: JSON.stringify({ walletAddress }),
          });
          
          if (syncResponse.ok) {
            logger.log('✅ Backend session created via native auth');
            const userData = await syncResponse.json();
            return userData;
          }
        }
        
        // Fallback to simple sync
        const simpleSyncResponse = await fetch('/api/auth/wallet/simple-sync', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ walletAddress }),
        });
        
        if (simpleSyncResponse.ok) {
          logger.log('✅ Backend session created via simple sync');
          const userData = await simpleSyncResponse.json();
          return userData;
        }
        
        logger.log('❌ Could not establish backend session');
        return null;
      } catch (error) {
        console.error('Sync error:', error);
        return null;
      } finally {
        syncPromise = null;
      }
    })();
    
    return syncPromise;
  }, []);

  useEffect(() => {
    // Handle wallet connection - sync with backend
    const addressChanged = address && address !== prevAddress.current;
    const needsSync = isLoggedIn && address && (!sessionReady || addressChanged);
    
    if (needsSync) {
      logger.log('🔄 Wallet detected, syncing session...', addressChanged ? '(address changed)' : '');
      prevLoggedIn.current = true;
      prevAddress.current = address;
      setSyncFailed(false);
      
      // Sync first, then enable queries
      syncWalletSession(address).then((user) => {
        if (user) {
          logger.log('✅ Session ready, enabling queries');
          setSessionReady(true);
          setSyncFailed(false);
          localStorage.setItem('walletAddress', address);
          // Invalidate queries so they refetch with the new session
          queryClient.invalidateQueries({ queryKey: ['/api/auth/me'] });
          queryClient.invalidateQueries({ queryKey: ['/api/certifications'] });
        } else {
          // Sync failed - enable queries anyway to check existing session
          // This prevents permanent stall on transient failures
          logger.log('⚠️ Sync failed, enabling queries anyway for fallback');
          setSessionReady(true);
          setSyncFailed(false); // Allow queries to run
        }
      });
    } else if (!isLoggedIn && prevLoggedIn.current) {
      logger.log('🔌 Wallet disconnected');
      prevLoggedIn.current = false;
      prevAddress.current = null;
      lastSyncedAddress = null;
      setSessionReady(false);
      setSyncFailed(false);
      localStorage.removeItem('walletAddress');
    }
  }, [isLoggedIn, address, sessionReady, syncWalletSession]);

  const { data: user, isLoading } = useQuery<User | null>({
    queryKey: ['/api/auth/me'],
    queryFn: async () => {
      logger.log('📡 Checking auth status...');
      
      try {
        const response = await fetch('/api/auth/me', {
          credentials: 'include',
        });
        
        if (response.ok) {
          const userData = await response.json();
          logger.log('✅ User authenticated from existing session:', userData.walletAddress?.slice(0, 15));
          
          if (userData.walletAddress && !localStorage.getItem('walletAddress')) {
            localStorage.setItem('walletAddress', userData.walletAddress);
          }
          
          return userData;
        }
        
        if (response.status === 401) {
          logger.log('🔐 No backend session, waiting for sync...');
          return null;
        }
        
        return null;
      } catch (error) {
        console.error('Error checking auth status:', error);
        return null;
      }
    },
    // Only query when no wallet OR when sync is complete
    enabled: shouldQueryAuth,
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
        logger.log('Provider logout error (non-fatal):', e);
      }
      
      try {
        await disconnectWcProvider();
        logger.log('WalletConnect provider disconnected');
      } catch (e) {
        logger.log('WalletConnect disconnect error (non-fatal):', e);
      }
      
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          credentials: 'include',
        });
      } catch (e) {
        logger.log('Backend logout error (non-fatal):', e);
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

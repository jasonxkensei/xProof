import { useQuery, useMutation } from '@tanstack/react-query';
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

export function useWalletAuth() {
  const [, navigate] = useLocation();
  
  // Get wallet state from sdk-dapp
  const { address } = useGetAccount();
  const isLoggedInSdk = useGetIsLoggedIn();

  // Fetch user data from backend when wallet is connected
  const { data: user, isLoading } = useQuery<User | null>({
    queryKey: ['/api/auth/me'],
    queryFn: async () => {
      if (!address || !isLoggedInSdk) {
        return null;
      }

      try {
        const response = await fetch('/api/auth/me', {
          credentials: 'include',
        });
        
        if (response.status === 401) {
          // If backend session doesn't exist, create it with Native Auth token
          const nativeAuthToken = sessionStorage.getItem('nativeAuthToken');
          
          if (!nativeAuthToken) {
            console.error('No native auth token found - authentication failed');
            return null;
          }

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
            return syncResponse.json();
          }
          return null;
        }
        
        if (!response.ok) {
          throw new Error('Failed to fetch user');
        }
        
        return response.json();
      } catch (error) {
        console.error('Error checking auth status:', error);
        return null;
      }
    },
    enabled: isLoggedInSdk && !!address, // Only run query when wallet is connected
    retry: false,
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

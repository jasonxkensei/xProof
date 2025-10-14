import { useQuery, useMutation } from '@tanstack/react-query';
import { useLocation } from 'wouter';
import { apiRequest, queryClient } from '@/lib/queryClient';

interface User {
  id: number;
  walletAddress: string;
  email?: string;
  tier: string;
  subscriptionStatus: string;
}

export function useWalletAuth() {
  const [, navigate] = useLocation();

  // Check if user is authenticated - handle 401 as "not logged in" not error
  const { data: user, isLoading } = useQuery<User | null>({
    queryKey: ['/api/auth/me'],
    queryFn: async () => {
      try {
        const response = await fetch('/api/auth/me', {
          credentials: 'include', // Important: include cookies
        });
        
        if (response.status === 401) {
          // Not authenticated is not an error - just return null
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
    retry: false,
    staleTime: 1000 * 60 * 5, // 5 minutes
  });

  // Login mutation
  const loginMutation = useMutation({
    mutationFn: async ({ address, signature, loginToken }: { 
      address: string; 
      signature: string; 
      loginToken: string;
    }) => {
      const response = await fetch('/api/auth/wallet/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include', // Important: include cookies
        body: JSON.stringify({
          walletAddress: address,
          signature,
          loginToken
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Login failed');
      }

      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/auth/me'] });
      navigate('/dashboard');
    },
  });

  // Logout mutation
  const logoutMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include', // Important: include cookies
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
    isAuthenticated: !!user && user !== null,
    isLoading,
    loginAsync: loginMutation.mutateAsync, // Use mutateAsync for promise-based calls
    logout: logoutMutation.mutate,
    isLoggingIn: loginMutation.isPending,
  };
}

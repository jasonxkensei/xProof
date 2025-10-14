import { useEffect } from 'react';
import { useLocation } from 'wouter';
import { parseWalletCallback } from '@/lib/walletAuth';
import { useWalletAuth } from '@/hooks/useWalletAuth';
import { Shield } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

export default function WalletCallback() {
  const [, navigate] = useLocation();
  const { loginAsync } = useWalletAuth();
  const { toast } = useToast();

  useEffect(() => {
    const processLogin = async () => {
      const walletInfo = parseWalletCallback();
      
      if (walletInfo) {
        try {
          // Login with wallet credentials
          await loginAsync({
            address: walletInfo.address,
            signature: walletInfo.signature,
            loginToken: walletInfo.loginToken
          });
          
          // Success toast
          toast({
            title: "Connected!",
            description: "Your wallet has been connected successfully.",
          });
        } catch (error: any) {
          console.error('Login failed:', error);
          toast({
            variant: "destructive",
            title: "Connection Failed",
            description: error.message || "Failed to connect your wallet. Please try again.",
          });
          navigate('/');
        }
      } else {
        // No valid callback data, redirect to home
        navigate('/');
      }
    };

    processLogin();
  }, [loginAsync, navigate, toast]);

  return (
    <div className="flex h-screen items-center justify-center bg-gradient-to-br from-zinc-950 via-zinc-900 to-emerald-950">
      <div className="text-center space-y-4">
        <Shield className="w-16 h-16 text-primary mx-auto animate-pulse" />
        <h2 className="text-2xl font-bold text-white">Authenticating...</h2>
        <p className="text-zinc-400">Please wait while we verify your wallet</p>
      </div>
    </div>
  );
}

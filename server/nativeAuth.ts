import { NativeAuthServer } from '@multiversx/sdk-native-auth-server';

// Initialize Native Auth server for token verification
const nativeAuthServer = new NativeAuthServer({
  apiUrl: 'https://api.multiversx.com', // Mainnet API
  maxExpirySeconds: 86400, // 24 hours (must match client config)
  acceptedOrigins: [
    process.env.REPL_ID ? `https://${process.env.REPL_ID}.replit.dev` : 'http://localhost:5000',
    process.env.REPL_DOMAINS ? `https://${process.env.REPL_DOMAINS}` : undefined,
    'https://xproof.app',
    'https://www.xproof.app',
  ].filter(Boolean) as string[]
});

export interface DecodedNativeAuthToken {
  address: string;
  body: string;
  signature: string;
  origin: string;
  blockHash: string;
  ttl: number;
  extraInfo?: {
    timestamp: number;
  };
}

/**
 * Verify MultiversX Native Auth token
 * Returns the decoded token with wallet address if valid, throws if invalid
 */
export async function verifyNativeAuthToken(
  token: string
): Promise<DecodedNativeAuthToken> {
  try {
    // Decode the token to extract data
    const decoded = nativeAuthServer.decode(token);
    
    // Validate the token (checks signature, expiration, origin)
    await nativeAuthServer.validate(token);
    
    return decoded;
  } catch (error: any) {
    throw new Error(`Invalid Native Auth token: ${error.message}`);
  }
}

/**
 * Extract Bearer token from Authorization header
 */
export function extractBearerToken(authHeader: string | undefined): string | null {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.replace('Bearer ', '');
}

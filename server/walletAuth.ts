import { RequestHandler } from "express";
import crypto from "crypto";
import { Address } from "@multiversx/sdk-core";
import { UserVerifier } from "@multiversx/sdk-wallet/out/userVerifier";

// Store challenges temporarily (in production, use Redis)
const challenges = new Map<string, { nonce: string; timestamp: number }>();

// Clean up expired challenges every 5 minutes
setInterval(() => {
  const now = Date.now();
  const entries = Array.from(challenges.entries());
  for (const [key, value] of entries) {
    if (now - value.timestamp > 5 * 60 * 1000) { // 5 minutes
      challenges.delete(key);
    }
  }
}, 5 * 60 * 1000);

export interface WalletSession {
  walletAddress: string;
}

// Middleware to check if user is authenticated with wallet
export const isWalletAuthenticated: RequestHandler = (req: any, res, next) => {
  if (!req.session || !req.session.walletAddress) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  
  // Attach wallet address to request for easy access
  req.walletAddress = req.session.walletAddress;
  next();
};

// Generate a challenge for wallet signature
export function generateChallenge(walletAddress: string): string {
  const nonce = crypto.randomBytes(32).toString('hex');
  challenges.set(walletAddress, {
    nonce,
    timestamp: Date.now(),
  });
  return nonce;
}

// Verify wallet signature
export function verifyWalletSignature(
  walletAddress: string,
  signature: string,
  nonce: string
): boolean {
  try {
    // Check if challenge exists and is not expired
    const challenge = challenges.get(walletAddress);
    if (!challenge || challenge.nonce !== nonce) {
      return false;
    }

    // Check if challenge is expired (5 minutes)
    if (Date.now() - challenge.timestamp > 5 * 60 * 1000) {
      challenges.delete(walletAddress);
      return false;
    }

    // Verify wallet address format
    let address: Address;
    try {
      address = Address.newFromBech32(walletAddress);
    } catch {
      return false;
    }
    
    // Verify signature is present and non-empty
    if (!signature || signature.length === 0) {
      return false;
    }
    
    // Construct the exact message that was signed
    const messageToSign = `ProofMint Login\n\nSign this message to authenticate.\n\nNonce: ${nonce}`;
    
    // Verify signature using MultiversX SDK
    try {
      const signatureBuffer = Buffer.from(signature, 'hex');
      const verifier = UserVerifier.fromAddress(address);
      const isValid = verifier.verify(
        Buffer.from(messageToSign, 'utf8'),
        signatureBuffer
      );
      
      if (!isValid) {
        return false;
      }
    } catch (error) {
      console.error("Signature verification failed:", error);
      return false;
    }

    // Clean up used challenge after successful verification
    challenges.delete(walletAddress);
    return true;
  } catch (error) {
    console.error("Error verifying wallet signature:", error);
    return false;
  }
}

// Create wallet session
export function createWalletSession(req: any, walletAddress: string): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.walletAddress = walletAddress;
    req.session.save((err: any) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

// Destroy wallet session
export function destroyWalletSession(req: any): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.destroy((err: any) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

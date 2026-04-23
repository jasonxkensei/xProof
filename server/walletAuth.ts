import { RequestHandler } from "express";

export interface WalletSession {
  walletAddress: string;
}

export const isWalletAuthenticated: RequestHandler = (req: any, res, next) => {
  if (!req.session || !req.session.walletAddress) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  req.walletAddress = req.session.walletAddress;
  next();
};

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

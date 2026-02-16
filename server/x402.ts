import { x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import type { Request, Response } from "express";
import { logger } from "./logger";

const X402_PAY_TO = process.env.X402_PAY_TO || "";
const X402_NETWORK = process.env.X402_NETWORK || "eip155:8453";
const X402_FACILITATOR_URL = process.env.X402_FACILITATOR_URL || "https://www.x402.org/facilitator";
const X402_PRICE_PROOF = process.env.X402_PRICE_PROOF || "$0.05";
const X402_PRICE_BATCH = process.env.X402_PRICE_BATCH || "$0.05";

let resourceServer: any = null;

function getResourceServer() {
  if (!resourceServer) {
    const facilitatorClient = new HTTPFacilitatorClient({
      url: X402_FACILITATOR_URL,
    });
    resourceServer = new x402ResourceServer(facilitatorClient)
      .register(X402_NETWORK as `${string}:${string}`, new ExactEvmScheme());
  }
  return resourceServer;
}

export function isX402Configured(): boolean {
  return !!X402_PAY_TO;
}

export function getPaymentRequirements(route: "proof" | "batch") {
  const price = route === "batch" ? X402_PRICE_BATCH : X402_PRICE_PROOF;
  return {
    scheme: "exact",
    price,
    network: X402_NETWORK,
    payTo: X402_PAY_TO,
    maxTimeoutSeconds: 60,
    description: route === "batch"
      ? "xproof batch certification — per file in batch"
      : "xproof single file certification",
  };
}

export function build402Response(req: Request, route: "proof" | "batch") {
  const requirements = getPaymentRequirements(route);
  const resource = `https://${req.get('host')}/api/${route === "batch" ? "batch" : "proof"}`;

  return {
    x402Version: 1,
    accepts: [requirements],
    resource,
    description: requirements.description,
    mimeType: "application/json",
  };
}

export async function verifyX402Payment(req: Request, route: "proof" | "batch"): Promise<{ valid: boolean; error?: string }> {
  if (!isX402Configured()) {
    return { valid: false, error: "x402 not configured" };
  }

  const paymentHeader = req.headers["x-payment"] as string;
  if (!paymentHeader) {
    return { valid: false, error: "No X-PAYMENT header" };
  }

  try {
    const server = getResourceServer();
    const requirements = getPaymentRequirements(route);
    const resource = `https://${req.get('host')}/api/${route === "batch" ? "batch" : "proof"}`;

    const paymentPayload = JSON.parse(
      Buffer.from(paymentHeader, "base64").toString("utf-8")
    );

    const result = await server.verify(paymentPayload, {
      ...requirements,
      resource,
      asset: "USDC",
    });

    if (result?.isValid) {
      try {
        await server.settle(paymentPayload, {
          ...requirements,
          resource,
          asset: "USDC",
        });
      } catch (settleErr: any) {
        logger.error("Settlement error (non-blocking)", { component: "x402", error: settleErr.message });
      }
      return { valid: true };
    }

    return { valid: false, error: "Payment verification failed" };
  } catch (err: any) {
    logger.error("Verification error", { component: "x402", error: err.message });
    return { valid: false, error: `Payment verification error: ${err.message}` };
  }
}

export function send402Response(res: Response, req: Request, route: "proof" | "batch") {
  const body = build402Response(req, route);
  res.status(402).json(body);
}

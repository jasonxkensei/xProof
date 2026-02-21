import { getUncachableStripeClient, getStripePublishableKey } from "./stripeClient";
import { logger } from "./logger";
import { getCertificationPriceUsd } from "./pricing";

export async function isStripeConfigured(): Promise<boolean> {
  try {
    await getStripePublishableKey();
    return true;
  } catch {
    return false;
  }
}

interface CheckoutParams {
  quantity?: number;
  successUrl: string;
  cancelUrl: string;
  metadata?: Record<string, string>;
}

export async function createCertificationCheckout(params: CheckoutParams) {
  const { quantity = 1, successUrl, cancelUrl, metadata = {} } = params;

  const priceUsd = await getCertificationPriceUsd();
  const unitAmountCents = Math.round(priceUsd * 100);

  const stripe = await getUncachableStripeClient();

  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items: [
      {
        price_data: {
          currency: "usd",
          unit_amount: unitAmountCents,
          product_data: {
            name: "xProof Certification",
            description: "Blockchain proof-of-existence on MultiversX",
          },
        },
        quantity,
      },
    ],
    success_url: successUrl,
    cancel_url: cancelUrl,
    metadata,
  });

  return {
    sessionId: session.id,
    url: session.url,
  };
}

export async function getStripePublishableKeyForClient(): Promise<string> {
  return await getStripePublishableKey();
}

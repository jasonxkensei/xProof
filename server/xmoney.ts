import crypto from "crypto";

// xMoney API Configuration
const XMONEY_BASE_URL = process.env.NODE_ENV === "production" 
  ? "https://merchant.xmoney.com"
  : "https://merchant-stage.xmoney.com";

const XMONEY_API_KEY = process.env.XMONEY_API_KEY;
const XMONEY_SITE_ID = process.env.XMONEY_SITE_ID;
const XMONEY_WEBHOOK_SECRET = process.env.XMONEY_WEBHOOK_SECRET;

// Check if xMoney is configured
export function isXMoneyConfigured(): boolean {
  return Boolean(XMONEY_API_KEY && XMONEY_SITE_ID);
}

// Throw error if xMoney is not configured
function ensureConfigured() {
  if (!XMONEY_API_KEY || !XMONEY_SITE_ID) {
    throw new Error("xMoney is not configured. Please set XMONEY_API_KEY and XMONEY_SITE_ID environment variables.");
  }
}

interface CreateOrderParams {
  amount: number;
  currency: string;
  orderDescription: string;
  customerEmail?: string;
  returnUrl?: string;
  cancelUrl?: string;
}

interface XMoneyOrder {
  orderId: string;
  transactionId?: string;
  paymentUrl?: string;
  status: string;
}

interface XMoneyOrderStatus {
  orderId: string;
  transactionId?: string;
  amount: number;
  currency: string;
  status: string;
  createdAt?: string;
  updatedAt?: string;
}

interface XMoneyRefundResponse {
  refundId: string;
  transactionId: string;
  amount: number;
  status: string;
  message?: string;
}

/**
 * Create a payment order with xMoney
 */
export async function createXMoneyOrder(params: CreateOrderParams): Promise<XMoneyOrder> {
  ensureConfigured();

  const formData = new URLSearchParams({
    siteId: XMONEY_SITE_ID!,
    apiKey: XMONEY_API_KEY!,
    amount: params.amount.toFixed(2),
    currency: params.currency,
    orderDescription: params.orderDescription,
    ...(params.customerEmail && { customerEmail: params.customerEmail }),
    ...(params.returnUrl && { returnUrl: params.returnUrl }),
    ...(params.cancelUrl && { cancelUrl: params.cancelUrl }),
  });

  const response = await fetch(`${XMONEY_BASE_URL}/api/order`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: formData.toString(),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`xMoney API error: ${error}`);
  }

  const data = await response.json();

  // Handle redirect for 3D Secure
  if (data.isRedirect && data.redirect?.url) {
    return {
      orderId: data.orderId?.toString() || "",
      transactionId: data.transactionId?.toString(),
      paymentUrl: data.redirect.url,
      status: "pending_redirect",
    };
  }

  return {
    orderId: data.orderId?.toString() || "",
    transactionId: data.transactionId?.toString(),
    paymentUrl: data.paymentUrl,
    status: data.status || "created",
  };
}

/**
 * Get order status
 */
export async function getXMoneyOrderStatus(orderId: string): Promise<XMoneyOrderStatus> {
  ensureConfigured();

  const response = await fetch(
    `${XMONEY_BASE_URL}/api/order/${orderId}?siteId=${XMONEY_SITE_ID}&apiKey=${XMONEY_API_KEY}`
  );

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`xMoney API error: ${error}`);
  }

  const data = await response.json();
  return {
    orderId: data.orderId?.toString() || orderId,
    transactionId: data.transactionId?.toString(),
    amount: parseFloat(data.amount) || 0,
    currency: data.currency || "USD",
    status: data.status || "unknown",
    createdAt: data.createdAt,
    updatedAt: data.updatedAt,
  };
}

/**
 * Verify webhook signature using constant-time comparison
 */
export function verifyXMoneyWebhook(payload: string, signature: string): boolean {
  if (!XMONEY_WEBHOOK_SECRET) {
    console.warn("xMoney webhook secret not configured");
    return false;
  }

  const expectedSignature = crypto
    .createHmac("sha256", XMONEY_WEBHOOK_SECRET)
    .update(payload)
    .digest("hex");

  // Use constant-time comparison to prevent timing attacks
  const expectedBuffer = Buffer.from(expectedSignature);
  const signatureBuffer = Buffer.from(signature);

  // Ensure both buffers have the same length to prevent timing leaks
  if (expectedBuffer.length !== signatureBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, signatureBuffer);
}

/**
 * Issue a refund for a transaction
 */
export async function refundXMoneyTransaction(
  transactionId: string,
  amount?: number
): Promise<XMoneyRefundResponse> {
  ensureConfigured();

  const formData = new URLSearchParams({
    siteId: XMONEY_SITE_ID!,
    apiKey: XMONEY_API_KEY!,
    transactionId,
    ...(amount && { amount: amount.toFixed(2) }),
  });

  const response = await fetch(`${XMONEY_BASE_URL}/api/refund`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: formData.toString(),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`xMoney refund error: ${error}`);
  }

  const data = await response.json();
  return {
    refundId: data.refundId?.toString() || "",
    transactionId: data.transactionId?.toString() || transactionId,
    amount: parseFloat(data.amount) || 0,
    status: data.status || "unknown",
    message: data.message,
  };
}

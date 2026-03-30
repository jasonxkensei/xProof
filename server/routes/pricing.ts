import { type Express } from "express";
import { getCertificationPriceEgld, getPricingInfo } from "../pricing";

export function registerPricingRoutes(app: Express) {
  // Get pricing information (public endpoint)
  app.get("/api/pricing", async (req, res) => {
    try {
      const wallet = (req.query.wallet as string || "").trim().toLowerCase();
      const ADMIN_WALLETS = (process.env.ADMIN_WALLETS || "").split(",").map(w => w.trim().toLowerCase()).filter(Boolean);
      const isAdmin = wallet && ADMIN_WALLETS.includes(wallet);
      const receiverAddress = process.env.MULTIVERSX_RECEIVER_ADDRESS || process.env.XPROOF_WALLET_ADDRESS || process.env.MULTIVERSX_SENDER_ADDRESS || "";

      const pricing = await getPricingInfo();

      if (isAdmin) {
        return res.json({
          protocol: "xproof",
          version: "1.0",
          ...pricing,
          price_usd: 0,
          price_egld: "0",
          egld_usd_rate: 0,
          receiver_address: receiverAddress,
          payment_methods: [
            { method: "EGLD", description: "Pay in EGLD at current exchange rate on MultiversX" },
            { method: "USDC", description: "Pay in USDC on Base via x402 protocol" },
          ],
        });
      }

      const { priceUsd, priceEgld, egldUsdRate } = await getCertificationPriceEgld();

      res.json({
        protocol: "xproof",
        version: "1.0",
        ...pricing,
        price_usd: priceUsd,
        price_egld: priceEgld,
        egld_usd_rate: egldUsdRate,
        receiver_address: receiverAddress,
        payment_methods: [
          { method: "EGLD", description: "Pay in EGLD at current exchange rate on MultiversX" },
          { method: "USDC", description: "Pay in USDC on Base via x402 protocol" },
        ],
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to retrieve pricing information" });
    }
  });

  // Deprecated — use /api/pricing instead
  app.get("/api/certification-price", (req, res) => {
    const wallet = req.query.wallet ? `?wallet=${req.query.wallet}` : "";
    res.redirect(301, `/api/pricing${wallet}`);
  });
}

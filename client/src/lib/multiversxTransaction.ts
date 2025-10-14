export interface MultiversXTransactionResult {
  txHash: string;
  explorerUrl: string;
}

export async function sendProofTransaction(
  userAddress: string, 
  fileHash: string,
  fileName: string
): Promise<MultiversXTransactionResult> {
  const chainId = import.meta.env.VITE_MULTIVERSX_CHAIN_ID || "D";
  const gatewayUrl = import.meta.env.VITE_MULTIVERSX_GATEWAY_URL || "https://devnet-gateway.multiversx.com";
  
  const txData = `certify:${fileHash}:${fileName}`;
  const encoder = new TextEncoder();
  const dataBytes = encoder.encode(txData);
  const base64Data = btoa(String.fromCharCode(...Array.from(dataBytes)));

  const accountResponse = await fetch(`${gatewayUrl}/address/${userAddress}`);
  const accountData = await accountResponse.json();
  
  const transaction = {
    nonce: accountData.data.account.nonce,
    value: "0",
    receiver: userAddress,
    sender: userAddress,
    gasPrice: 1000000000,
    gasLimit: 500000,
    data: base64Data,
    chainID: chainId,
    version: 1,
  };

  const response = await fetch(`${gatewayUrl}/transaction/send`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(transaction),
  });

  const result = await response.json();
  
  if (result.error) {
    throw new Error(result.error);
  }

  const explorerBaseUrl = chainId === "1" 
    ? "https://explorer.multiversx.com"
    : "https://devnet-explorer.multiversx.com";

  return {
    txHash: result.data.txHash,
    explorerUrl: `${explorerBaseUrl}/transactions/${result.data.txHash}`,
  };
}

import { Transaction, Address, TransactionComputer } from "@multiversx/sdk-core";
import { getAccountProvider } from "@multiversx/sdk-dapp/out/providers/helpers/accountProvider";

export interface MultiversXTransactionResult {
  txHash: string;
  explorerUrl: string;
}

export interface TransactionParams {
  userAddress: string;
  fileHash: string;
  fileName: string;
  authorName?: string;
}

const MAINNET_API = "https://api.multiversx.com";
const MAINNET_GATEWAY = "https://gateway.multiversx.com";
const MAINNET_EXPLORER = "https://explorer.multiversx.com";
const CHAIN_ID = "1"; // Mainnet

async function getAccountNonce(address: string): Promise<number> {
  const response = await fetch(`${MAINNET_API}/accounts/${address}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch account: ${response.statusText}`);
  }
  const data = await response.json();
  return data.nonce || 0;
}

export async function createCertificationTransaction(params: TransactionParams): Promise<Transaction> {
  const { userAddress, fileHash, fileName, authorName } = params;
  
  const payloadText = `certify:${fileHash}|filename:${fileName}${authorName ? `|author:${authorName}` : ""}`;
  const encoder = new TextEncoder();
  const dataPayload = encoder.encode(payloadText);
  
  const nonce = await getAccountNonce(userAddress);
  
  const gasLimit = BigInt(50000 + dataPayload.length * 1500);
  
  const transaction = new Transaction({
    nonce: BigInt(nonce),
    value: BigInt(0),
    sender: Address.newFromBech32(userAddress),
    receiver: Address.newFromBech32(userAddress),
    gasLimit: gasLimit,
    data: dataPayload,
    chainID: CHAIN_ID,
  });
  
  return transaction;
}

export async function signAndSendTransaction(transaction: Transaction): Promise<MultiversXTransactionResult> {
  let provider = getAccountProvider();
  
  if (!provider) {
    console.log("🔌 No provider found, creating new Extension provider...");
    const { ProviderFactory } = await import('@multiversx/sdk-dapp/out/providers/ProviderFactory');
    const { ProviderTypeEnum } = await import('@multiversx/sdk-dapp/out/providers/types/providerFactory.types');
    
    provider = await ProviderFactory.create({ 
      type: ProviderTypeEnum.extension 
    });
    
    if (!provider) {
      throw new Error("No wallet provider found. Please connect your wallet first.");
    }
  }
  
  try {
    if (typeof provider.init === 'function') {
      console.log("🔧 Initializing provider for transaction signing...");
      await provider.init();
    }
    
    console.log("✍️ Requesting signature from wallet extension...");
    console.log("📝 Please check your wallet extension and complete any 2FA verification");
    
    const signedTransactions = await provider.signTransactions([transaction]);
    
    if (!signedTransactions || signedTransactions.length === 0) {
      throw new Error("Transaction signing was cancelled or failed");
    }
    
    const signedTx = signedTransactions[0];
    
    const response = await fetch(`${MAINNET_GATEWAY}/transaction/send`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(signedTx.toSendable()),
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Gateway error: ${response.statusText} - ${errorText}`);
    }
    
    const result = await response.json();
    
    if (result.error) {
      throw new Error(`Transaction error: ${result.error}`);
    }
    
    if (!result.data?.txHash) {
      throw new Error(`Invalid gateway response: ${JSON.stringify(result)}`);
    }
    
    return {
      txHash: result.data.txHash,
      explorerUrl: `${MAINNET_EXPLORER}/transactions/${result.data.txHash}`,
    };
  } catch (error: any) {
    if (error.message?.includes("cancelled") || error.message?.includes("denied")) {
      throw new Error("Transaction was cancelled by user");
    }
    throw error;
  }
}

export async function sendCertificationTransaction(params: TransactionParams): Promise<MultiversXTransactionResult> {
  console.log("🔐 Creating certification transaction for Mainnet...");
  console.log("📄 File hash:", params.fileHash);
  console.log("👤 User:", params.userAddress);
  
  const transaction = await createCertificationTransaction(params);
  console.log("📝 Transaction created, requesting signature from wallet...");
  
  const result = await signAndSendTransaction(transaction);
  console.log("✅ Transaction sent successfully!");
  console.log("🔗 Explorer:", result.explorerUrl);
  
  return result;
}

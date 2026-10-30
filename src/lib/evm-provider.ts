import { ethers, JsonRpcProvider, Network } from "ethers";
import { EvmChainConfig, EvmChainId } from "@/types/evm-security";

export const EVM_CHAINS: Record<EvmChainId, EvmChainConfig> = {
  ethereum: {
    id: "ethereum",
    name: "Ethereum",
    symbol: "ETH",
    chainId: 1,
    rpcUrls: [
      "https://ethereum-rpc.publicnode.com",
      "https://1rpc.io/eth",
      "https://rpc.ankr.com/eth",
    ],
    explorerUrl: "https://etherscan.io",
    badgeColor: "emerald",
  },
  base: {
    id: "base",
    name: "Base",
    symbol: "ETH",
    chainId: 8453,
    rpcUrls: [
      "https://mainnet.base.org",
      "https://base-rpc.publicnode.com",
      "https://1rpc.io/base",
    ],
    explorerUrl: "https://basescan.org",
    badgeColor: "cyan",
  },
  bnb: {
    id: "bnb",
    name: "BNB Chain",
    symbol: "BNB",
    chainId: 56,
    rpcUrls: [
      "https://bsc-rpc.publicnode.com",
      "https://1rpc.io/bnb",
      "https://rpc.ankr.com/bsc",
    ],
    explorerUrl: "https://bscscan.com",
    badgeColor: "amber",
  },
};

/**
 * Executes an RPC call across fallback URLs with a strict timeout
 */
async function callWithFallback<T>(
  rpcUrls: string[],
  chainId: number,
  chainName: string,
  fn: (provider: JsonRpcProvider) => Promise<T>
): Promise<T | null> {
  const network = new Network(chainName, chainId);

  for (const url of rpcUrls) {
    try {
      const provider = new JsonRpcProvider(url, network, {
        staticNetwork: network,
      });

      // Wrap in a 4-second timeout to avoid long hanging requests
      const result = await Promise.race([
        fn(provider),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("RPC Timeout")), 4500)
        ),
      ]);

      return result;
    } catch {
      // Try next fallback URL silently
      continue;
    }
  }

  return null;
}

export interface OnChainWalletData {
  balanceWei: string | null;
  balanceFormatted: string | null;
  transactionCount: number | null;
  isContract: boolean | null;
  blockNumber: number | null;
}

/**
 * Fetches real on-chain parameters for an EVM address
 */
export async function fetchOnChainWalletData(
  address: string,
  chain: EvmChainId
): Promise<OnChainWalletData> {
  const config = EVM_CHAINS[chain];
  if (!config) {
    throw new Error(`Unsupported EVM chain: ${chain}`);
  }

  const [balanceRes, countRes, codeRes, blockRes] = await Promise.all([
    callWithFallback(config.rpcUrls, config.chainId, config.name, (p) =>
      p.getBalance(address)
    ),
    callWithFallback(config.rpcUrls, config.chainId, config.name, (p) =>
      p.getTransactionCount(address)
    ),
    callWithFallback(config.rpcUrls, config.chainId, config.name, (p) =>
      p.getCode(address)
    ),
    callWithFallback(config.rpcUrls, config.chainId, config.name, (p) =>
      p.getBlockNumber()
    ),
  ]);

  const balanceFormatted =
    balanceRes !== null ? ethers.formatEther(balanceRes) : null;

  const isContract =
    codeRes !== null ? codeRes.length > 2 && codeRes !== "0x" : null;

  return {
    balanceWei: balanceRes !== null ? balanceRes.toString() : null,
    balanceFormatted,
    transactionCount: countRes,
    isContract,
    blockNumber: blockRes,
  };
}

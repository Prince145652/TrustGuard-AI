/**
 * Standalone NEAR Protocol Configuration
 * Decoupled to eliminate circular dependencies between client and cache modules.
 */

export interface NearConfig {
  networkId: "testnet" | "mainnet";
  nodeUrl: string;
  contractId: string;
  explorerBaseUrl: string;
}

export const NEAR_CONFIG: NearConfig = {
  networkId: "testnet",
  nodeUrl: process.env.NEAR_NODE_URL || "https://rpc.testnet.near.org",
  contractId: process.env.NEAR_CONTRACT_ID || "tg-auditor-2026.testnet",
  explorerBaseUrl: "https://testnet.nearblocks.io/txns",
};

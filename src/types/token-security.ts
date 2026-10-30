import { EvmChainId } from "@/types/evm-security";

export type TokenRiskLevel = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

export interface TokenSecurityIndicator {
  id: string;
  name: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  detected: boolean;
  description: string;
  whySuspicious: string;
  evidence: string;
}

export interface TokenSecurityScanResult {
  address: string;
  chain: EvmChainId;
  chainName: string;
  tokenName: string;
  tokenSymbol: string;
  decimals: number | "UNKNOWN";
  totalSupply: string;
  formattedSupply: string;
  isContract: boolean;
  isOpenSource: "VERIFIED" | "UNVERIFIED" | "UNKNOWN";
  isProxy: boolean | "UNKNOWN";
  proxyImplementation?: string;
  ownerAddress?: string;
  isOwnershipRenounced: boolean | "UNKNOWN";
  canMint: boolean | "UNKNOWN";
  canPause: boolean | "UNKNOWN";
  hasBlacklist: boolean | "UNKNOWN";
  isHoneypot: boolean | "UNKNOWN";
  buyTax: number | "UNKNOWN";
  sellTax: number | "UNKNOWN";
  cannotSellAll: boolean | "UNKNOWN";
  holderCount?: number | "UNKNOWN";
  isInDex: boolean | "UNKNOWN";
  riskScore: number; // 0 - 100
  riskLevel: TokenRiskLevel;
  verdict: "HONEYPOT_MALICIOUS" | "HIGH_RISK" | "MEDIUM_RISK" | "LOW_RISK" | "STANDARD_SAFE" | "UNKNOWN";
  summary: string;
  indicators: TokenSecurityIndicator[];
  evidence: {
    category: string;
    finding: string;
    status: "SAFE" | "WARNING" | "CRITICAL" | "UNKNOWN";
  }[];
  recommendations: string[];
  timestamp: string;
  disclaimer: string;
}

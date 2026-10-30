export type EvmChainId = "ethereum" | "base" | "bnb";

export interface EvmChainConfig {
  id: EvmChainId;
  name: string;
  symbol: string;
  chainId: number;
  rpcUrls: string[];
  explorerUrl: string;
  badgeColor: string;
}

export type EvmRiskLevel = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

export interface ThreatIntelligenceMatch {
  isMalicious: boolean;
  category?: "Phishing Drainer" | "Sanctioned Entity" | "Honeypot Deployer" | "Exploit Contract" | "None";
  threatName?: string;
  evidenceSource?: string;
  details?: string;
}

export interface EvmThreatFactor {
  id: string;
  name: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  detected: boolean;
  impactScore: number;
  evidence: string;
}

export interface EvmWalletScanResult {
  address: string;
  chain: EvmChainId;
  chainName: string;
  riskScore: number; // 0 - 100
  riskLevel: EvmRiskLevel;
  accountType: "Externally Owned Account (EOA)" | "Smart Contract" | "Unknown";
  balance: {
    raw: string;
    formatted: string;
    symbol: string;
    status: "CONFIRMED" | "UNKNOWN";
  };
  transactionCount: {
    nonce: number;
    status: "CONFIRMED" | "UNKNOWN";
  };
  threats: string[];
  evidence: {
    category: string;
    finding: string;
    status: "SAFE" | "WARNING" | "CRITICAL" | "UNKNOWN";
  }[];
  recommendations: string[];
  timestamp: string;
  scannedAtBlock?: number;
  isThreatDatabaseHit: boolean;
  disclaimer: string;
}

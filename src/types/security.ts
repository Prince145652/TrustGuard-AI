export type ScanType = "wallet" | "token" | "phishing" | "contract" | "website";

export type RiskLevel = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

export type NavTab = "overview" | "wallet" | "website" | "token" | "analyst" | "reports" | "settings";

export type NearNetwork = "NEAR Mainnet" | "NEAR Testnet" | "Aurora Engine";

export interface SecurityFactor {
  id: string;
  category: "Access Control" | "Smart Contract Logic" | "Phishing & Domain" | "Liquidity & Honeypot" | "Transaction History";
  name: string;
  description: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  passed: boolean;
  impactScore: number;
}

export interface ScanResult {
  id: string;
  target: string;
  type: ScanType;
  riskScore: number; // 0 (Safest) to 100 (Critical Danger)
  riskLevel: RiskLevel;
  timestamp: string;
  summary: string;
  factors: SecurityFactor[];
  blockchainVerified: boolean;
  nearTxHash?: string;
  nearContractId?: string;
  verifiedAt?: string;
  metadata?: Record<string, unknown>;
}

export interface SecurityStats {
  totalScans: number;
  threatsDetected: number;
  protectedWallets: number;
  securityScore: number;
  isSampleData: boolean;
}

export interface RecentSecurityActivity {
  id: string;
  target: string;
  scanType: "Wallet Scanner" | "Website Scanner" | "Token Scanner";
  riskLevel: RiskLevel;
  date: string;
  status: "Safe" | "Threat Blocked" | "High Risk" | "Verified On-Chain";
  nearTxHash?: string;
  isSample: boolean;
}

export interface RecentAudit {
  id: string;
  target: string;
  type: ScanType;
  riskLevel: RiskLevel;
  riskScore: number;
  nearTxHash?: string;
  timestamp: string;
  status: "VERIFIED_ON_NEAR" | "PENDING_BLOCKCHAIN" | "OFF_CHAIN_ONLY";
}

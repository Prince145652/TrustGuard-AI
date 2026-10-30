export type VerificationStatus =
  | "VERIFIED_ON_NEAR"
  | "OFFCHAIN_REGISTERED_PENDING_DEPLOYMENT"
  | "PENDING_FINALITY"
  | "HASH_MISMATCH"
  | "NOT_REGISTERED";

export interface NearVerificationRecord {
  reportId: string;
  reportHash: string; // 64-character SHA-256
  target: string;
  scanType: "WALLET" | "WEBSITE" | "TOKEN";
  riskScore: number;
  riskLevel: string;
  contractId: string;
  network: "NEAR Testnet" | "NEAR Mainnet";
  nearTxHash?: string; // Only present when real confirmed on-chain transaction exists
  blockHeight: number;
  anchoredAt: string;
  status: VerificationStatus;
  statusLabel?: string;
  isContractDeployed?: boolean;
  explorerUrl?: string; // Only present when real confirmed transaction hash exists
  metadata?: {
    totalFindings: number;
    sealedBy: string;
    canonicalJsonSchemaVersion: string;
    note?: string;
  };
}

export interface RegisterReportRequest {
  target: string;
  scanType: "WALLET" | "WEBSITE" | "TOKEN";
  riskScore: number;
  riskLevel: string;
  threats?: string[];
  evidence?: Array<{ category: string; finding: string; status: string }>;
  indicators?: Array<{ name: string; description: string; detected: boolean }>;
}

export interface RegisterReportResponse {
  success: boolean;
  record: NearVerificationRecord;
  message: string;
}

export interface VerifyReportQueryResponse {
  isVerified: boolean;
  status: VerificationStatus;
  record?: NearVerificationRecord;
  queriedAtBlock: number;
  message: string;
}

import { JsonRpcProvider } from "near-api-js";
import {
  NearVerificationRecord,
  VerificationStatus,
} from "@/types/near-verification";
import { isValidSha256 } from "@/lib/near-hashing";

export const NEAR_CONFIG = {
  networkId: "testnet" as const,
  nodeUrl: process.env.NEAR_NODE_URL || "https://rpc.testnet.near.org",
  contractId:
    process.env.NEAR_CONTRACT_ID || "tg-auditor-2026.testnet",
  explorerBaseUrl: "https://testnet.nearblocks.io/txns",
};

function getProvider() {
  return new JsonRpcProvider({
    url: NEAR_CONFIG.nodeUrl,
  });
}

/**
 * Gets the latest NEAR Testnet block status.
 */
export async function getNearTestnetStatus(): Promise<{
  blockHeight: number;
  synced: boolean;
}> {
  const provider = getProvider();
  const status = await provider.viewNodeStatus();

  return {
    blockHeight: status.sync_info.latest_block_height,
    synced: !status.sync_info.syncing,
  };
}

/**
 * Converts an on-chain TrustGuard report into the app's
 * NearVerificationRecord format.
 */
function mapOnChainRecord(
  record: Record<string, unknown>
): NearVerificationRecord {
  const timestampNs = record.timestamp_ns;

  let anchoredAt = new Date().toISOString();

  if (typeof timestampNs === "number" || typeof timestampNs === "string") {
    try {
      const milliseconds = Number(BigInt(timestampNs) / BigInt(1_000_000));
      if (Number.isFinite(milliseconds)) {
        anchoredAt = new Date(milliseconds).toISOString();
      }
    } catch {
      // Keep current timestamp only as a display fallback.
    }
  }

  return {
    reportId: String(record.report_id || ""),
    reportHash: String(record.report_hash || "").toLowerCase(),
    target: String(record.target || ""),
    scanType: "WALLET",
    riskScore: Number(record.risk_score || 0),
    riskLevel: "ON-CHAIN VERIFIED",
    contractId: NEAR_CONFIG.contractId,
    network: "NEAR Testnet",
    blockHeight: Number(record.block_height || 0),
    anchoredAt,
    status: "VERIFIED_ON_NEAR",
    statusLabel: "Verified live on NEAR Testnet",
    isContractDeployed: true,
    metadata: {
      totalFindings: 0,
      sealedBy: String(record.registrar || NEAR_CONFIG.contractId),
      canonicalJsonSchemaVersion: "1.0.0",
      note: "Verified via live read-only NEAR RPC",
    },
  };
}

/**
 * This function is retained for compatibility with the existing API.
 *
 * IMPORTANT: It does not claim to anchor a report unless a real signed
 * transaction is broadcast to the deployed contract.
 */
export async function anchorReportOnNear(): Promise<NearVerificationRecord> {
  throw new Error(
    "Live report anchoring is not configured in this server instance. " +
      "Use the authorized NEAR relayer to broadcast register_report before " +
      "claiming on-chain verification."
  );
}

/**
 * Verifies a report hash or report ID against the live NEAR Testnet contract.
 */
export async function verifyReportOnNear(
  hashOrId: string
): Promise<{
  isVerified: boolean;
  status: VerificationStatus;
  record?: NearVerificationRecord;
  queriedAtBlock: number;
  message?: string;
}> {
  const query = hashOrId.trim();

  if (!query) {
    throw new Error("Please provide a report hash or report ID.");
  }

  const provider = getProvider();
  const testnetState = await getNearTestnetStatus();

  try {
    // SHA-256 hashes are verified directly with verify_report.
    if (isValidSha256(query)) {
      const normalizedHash = query.toLowerCase();

      const exists = await provider.callFunction({
        contractId: NEAR_CONFIG.contractId,
        method: "verify_report",
        args: {
          report_hash: normalizedHash,
        },
      });

      if (!exists) {
        return {
          isVerified: false,
          status: "NOT_REGISTERED",
          queriedAtBlock: testnetState.blockHeight,
          message:
            "This report hash is not registered on the TrustGuard NEAR Testnet contract.",
        };
      }

      const onChainRecord = await provider.callFunction({
        contractId: NEAR_CONFIG.contractId,
        method: "get_report",
        args: {
          report_hash: normalizedHash,
        },
      });

      return {
        isVerified: true,
        status: "VERIFIED_ON_NEAR",
        record: mapOnChainRecord(onChainRecord as Record<string, unknown>),
        queriedAtBlock: testnetState.blockHeight,
        message:
          "Cryptographic report hash verified via live NEAR Testnet RPC.",
      };
    }

    // Otherwise, treat the input as a human-readable Report ID.
    const onChainRecord = await provider.callFunction({
      contractId: NEAR_CONFIG.contractId,
      method: "get_report_by_id",
      args: {
        report_id: query,
      },
    });

    if (!onChainRecord) {
      return {
        isVerified: false,
        status: "NOT_REGISTERED",
        queriedAtBlock: testnetState.blockHeight,
        message:
          "No report with this Report ID is registered on the TrustGuard NEAR Testnet contract.",
      };
    }

    return {
      isVerified: true,
      status: "VERIFIED_ON_NEAR",
      record: mapOnChainRecord(onChainRecord as Record<string, unknown>),
      queriedAtBlock: testnetState.blockHeight,
      message: "Report ID verified via live NEAR Testnet RPC.",
    };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown NEAR RPC error.";

    throw new Error(
      `Unable to verify the report against NEAR Testnet: ${message}`
    );
  }
}

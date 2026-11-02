import {
  JsonRpcProvider,
  Account,
  KeyPairSigner,
  KeyPair,
} from "near-api-js";
import fs from "fs";
import path from "path";
import os from "os";
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

export interface AnchorReportInput {
  reportId: string;
  reportHash: string;
  target: string;
  scanType: "WALLET" | "WEBSITE" | "TOKEN";
  riskScore: number;
  riskLevel: string;
  totalFindings?: number;
}

function getProvider(): JsonRpcProvider {
  return new JsonRpcProvider({
    url: NEAR_CONFIG.nodeUrl,
  });
}

/**
 * Loads the authorized server-side NEAR account for signing.
 * Reads credentials strictly from ~/.near-credentials/testnet on the server.
 * Never exposes or logs the private key.
 */
function getSignerAccount(): Account {
  const accountId = NEAR_CONFIG.contractId;
  const credPath = path.join(
    os.homedir(),
    ".near-credentials",
    "testnet",
    `${accountId}.json`
  );

  if (!fs.existsSync(credPath)) {
    throw new Error(
      `NEAR Testnet signer credential for "${accountId}" not found in ~/.near-credentials/testnet. ` +
        `Live anchoring cannot be signed.`
    );
  }

  let cred: { private_key?: string; secret_key?: string };
  try {
    cred = JSON.parse(fs.readFileSync(credPath, "utf8"));
  } catch (err: unknown) {
    throw new Error(
      `Failed to parse NEAR credential file for "${accountId}": ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }

  const privateKey = cred.private_key || cred.secret_key;
  if (!privateKey || typeof privateKey !== "string") {
    throw new Error(
      `Signing private key is missing or invalid in credential file for "${accountId}".`
    );
  }

  // The KeyPair is kept in memory within this function scope and never exposed
  const keyPair = KeyPair.fromString(
    privateKey as Parameters<typeof KeyPair.fromString>[0]
  );
  const signer = new KeyPairSigner(keyPair);
  const provider = getProvider();

  return new Account(accountId, provider, signer);
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
  record: Record<string, unknown>,
  txHash?: string
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

  const result: NearVerificationRecord = {
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

  if (txHash) {
    result.nearTxHash = txHash;
    result.explorerUrl = `${NEAR_CONFIG.explorerBaseUrl}/${txHash}`;
  }

  return result;
}

/**
 * Anchors a security report on NEAR Testnet using the authorized server-side account.
 *
 * Flow:
 * 1. Checks whether the report_hash is already registered on-chain (pre-flight check).
 * 2. If already registered, retrieves the existing on-chain record and returns it as VERIFIED_ON_NEAR
 *    without broadcasting another transaction.
 * 3. If not registered and broadcasting is not paused, normalizes risk_score to 0-100,
 *    loads server-side credentials, and broadcasts register_report.
 * 4. Waits for transaction confirmation, queries the confirmed record, and returns
 *    NearVerificationRecord with real blockHeight, nearTxHash, and explorerUrl.
 */
export async function anchorReportOnNear(
  data: AnchorReportInput
): Promise<NearVerificationRecord> {
  const normalizedHash = data.reportHash.toLowerCase().trim();

  if (!isValidSha256(normalizedHash)) {
    throw new Error(
      "Invalid report hash format. Must be a 64-character hexadecimal SHA-256 string."
    );
  }

  const provider = getProvider();

  // 1. Pre-flight check: is this hash already registered on-chain?
  const alreadyRegistered = await provider.callFunction({
    contractId: NEAR_CONFIG.contractId,
    method: "verify_report",
    args: {
      report_hash: normalizedHash,
    },
  });

  if (alreadyRegistered) {
    const existing = await provider.callFunction({
      contractId: NEAR_CONFIG.contractId,
      method: "get_report",
      args: {
        report_hash: normalizedHash,
      },
    });

    const record = mapOnChainRecord(existing as Record<string, unknown>);
    record.scanType = data.scanType;
    record.riskLevel = data.riskLevel;
    if (data.totalFindings !== undefined && record.metadata) {
      record.metadata.totalFindings = data.totalFindings;
    }
    return record;
  }

  // Safety guard: if transaction broadcasting is explicitly disabled
  if (process.env.NEAR_NO_BROADCAST === "true") {
    throw new Error(
      `Report hash ${normalizedHash} is not registered on NEAR Testnet and transaction broadcasting is paused (NEAR_NO_BROADCAST=true).`
    );
  }

  // 2. Normalize arguments for the smart contract (0-100 integer)
  const normalizedRiskScore = Math.min(
    100,
    Math.max(0, Math.round(data.riskScore))
  );

  // 3. Obtain server-side signer (fails honestly if credential is missing)
  const signerAccount = getSignerAccount();

  // 4. Sign and broadcast register_report transaction
  const outcome = await signerAccount.callFunctionRaw({
    contractId: NEAR_CONFIG.contractId,
    methodName: "register_report",
    args: {
      report_id: data.reportId,
      report_hash: normalizedHash,
      target: data.target,
      risk_score: normalizedRiskScore,
    },
    gas: BigInt("30000000000000"), // 30 TGas
    deposit: BigInt("0"),
  });

  const txHash = outcome.transaction.hash;

  // 5. Query newly confirmed record to obtain block height and timestamp
  const onChainRecord = await provider.callFunction({
    contractId: NEAR_CONFIG.contractId,
    method: "get_report",
    args: {
      report_hash: normalizedHash,
    },
  });

  const record = mapOnChainRecord(
    onChainRecord as Record<string, unknown>,
    txHash
  );
  record.scanType = data.scanType;
  record.riskLevel = data.riskLevel;
  if (data.totalFindings !== undefined && record.metadata) {
    record.metadata.totalFindings = data.totalFindings;
  }

  return record;
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

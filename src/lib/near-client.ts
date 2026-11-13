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
import { NEAR_CONFIG } from "@/lib/near-config";
import { cacheAnchoredTx, getCachedTx, isValidNearTxHash } from "@/lib/tx-cache";

export { NEAR_CONFIG };

export interface AnchorReportInput {
  reportId: string;
  reportHash: string;
  target: string;
  scanType: "WALLET" | "WEBSITE" | "TOKEN";
  riskScore: number;
  riskLevel: string;
  totalFindings?: number;
}

export type NearProviderMock = {
  callFunction?: (params: { contractId: string; method: string; args: Record<string, unknown> }) => Promise<unknown>;
  viewNodeStatus?: () => Promise<{ sync_info: { latest_block_height: number; syncing?: boolean } }>;
};

let testMockProvider: NearProviderMock | null = null;

function isTestEnvironment(): boolean {
  return process.env.NODE_ENV === "test" || Boolean(process.env.NODE_TEST_CONTEXT);
}

export function setNearTestMocks(mock: NearProviderMock | null): void {
  if (!isTestEnvironment()) {
    throw new Error("setNearTestMocks is strictly permitted in test environments.");
  }
  testMockProvider = mock;
}

function getProvider(): JsonRpcProvider {
  return new JsonRpcProvider({
    url: NEAR_CONFIG.nodeUrl,
  });
}

async function callContractMethod(method: string, args: Record<string, unknown>): Promise<unknown> {
  if (isTestEnvironment() && testMockProvider?.callFunction) {
    return testMockProvider.callFunction({
      contractId: NEAR_CONFIG.contractId,
      method,
      args,
    });
  }
  const provider = getProvider();
  return provider.callFunction({
    contractId: NEAR_CONFIG.contractId,
    method,
    args,
  });
}

/**
 * Loads the authorized server-side NEAR account for signing.
 * Sources credentials in priority order:
 * 1. process.env.NEAR_SIGNER_PRIVATE_KEY (raw ed25519:... string)
 * 2. process.env.NEAR_CREDENTIALS_JSON (raw JSON string or base64 encoded JSON)
 * 3. Filesystem fallback: ~/.near-credentials/testnet/${accountId}.json
 * Never logs or exposes the private key.
 * Safely validates malformed inputs.
 */
export function getSignerAccount(): Account {
  const accountId = NEAR_CONFIG.contractId;
  let rawPrivateKey: string | undefined;

  // 1. Direct environment variable: NEAR_SIGNER_PRIVATE_KEY
  if (process.env.NEAR_SIGNER_PRIVATE_KEY) {
    const candidate = process.env.NEAR_SIGNER_PRIVATE_KEY.trim();
    if (candidate) {
      rawPrivateKey = candidate;
    }
  }

  // 2. Structured environment variable: NEAR_CREDENTIALS_JSON
  if (!rawPrivateKey && process.env.NEAR_CREDENTIALS_JSON) {
    const raw = process.env.NEAR_CREDENTIALS_JSON.trim();
    if (raw) {
      let parsed: { private_key?: string; secret_key?: string; account_id?: string } | null = null;
      try {
        if (raw.startsWith("{")) {
          parsed = JSON.parse(raw);
        } else {
          // Attempt base64 decode if not plain JSON
          const decoded = Buffer.from(raw, "base64").toString("utf8");
          parsed = JSON.parse(decoded);
        }
      } catch {
        throw new Error(
          `Invalid NEAR_CREDENTIALS_JSON configuration for "${accountId}": malformed JSON format.`
        );
      }

      if (!parsed || typeof parsed !== "object") {
        throw new Error(
          `Invalid NEAR_CREDENTIALS_JSON configuration for "${accountId}": expected JSON object.`
        );
      }

      const keyFromEnvJson = parsed.private_key || parsed.secret_key;
      if (!keyFromEnvJson || typeof keyFromEnvJson !== "string") {
        throw new Error(
          `Signing private key is missing or invalid in NEAR_CREDENTIALS_JSON for "${accountId}".`
        );
      }
      rawPrivateKey = keyFromEnvJson.trim();
    }
  }

  // 3. Filesystem fallback (~/.near-credentials/testnet/${accountId}.json)
  if (!rawPrivateKey) {
    const credPath = path.join(
      os.homedir(),
      ".near-credentials",
      "testnet",
      `${accountId}.json`
    );

    if (!fs.existsSync(credPath)) {
      throw new Error(
        `NEAR Testnet signer credential for "${accountId}" not found. ` +
        `Please set NEAR_SIGNER_PRIVATE_KEY or NEAR_CREDENTIALS_JSON environment variable, ` +
        `or configure credentials in ~/.near-credentials/testnet.`
      );
    }

    let cred: { private_key?: string; secret_key?: string };
    try {
      cred = JSON.parse(fs.readFileSync(credPath, "utf8"));
    } catch (err: unknown) {
      throw new Error(
        `Failed to parse NEAR credential file for "${accountId}": ${
          err instanceof Error ? err.message : "Malformed credential file"
        }`
      );
    }

    const keyFromFile = cred.private_key || cred.secret_key;
    if (!keyFromFile || typeof keyFromFile !== "string") {
      throw new Error(
        `Signing private key is missing or invalid in credential file for "${accountId}".`
      );
    }
    rawPrivateKey = keyFromFile.trim();
  }

  // Validate and parse the private key safely
  let keyPair: KeyPair;
  try {
    keyPair = KeyPair.fromString(
      rawPrivateKey as Parameters<typeof KeyPair.fromString>[0]
    );
  } catch {
    throw new Error(
      `Invalid NEAR signer private key for "${accountId}": malformed key format.`
    );
  }

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
  if (isTestEnvironment() && testMockProvider?.viewNodeStatus) {
    const status = await testMockProvider.viewNodeStatus();
    return {
      blockHeight: status.sync_info.latest_block_height,
      synced: !status.sync_info.syncing,
    };
  }

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
  const alreadyRegistered = await callContractMethod("verify_report", {
    report_hash: normalizedHash,
  });

  if (alreadyRegistered) {
    const existing = await callContractMethod("get_report", {
      report_hash: normalizedHash,
    });

    // Priority 3: Hydrate genuine transaction hash from cache if available
    const cached = getCachedTx(normalizedHash) || getCachedTx(data.reportId);
    const cachedTxHash = cached?.nearTxHash;

    const record = mapOnChainRecord(existing as Record<string, unknown>, cachedTxHash);
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

  // Priority 3: Cache genuine transaction hash upon broadcast confirmation
  if (txHash && isValidNearTxHash(txHash)) {
    try {
      cacheAnchoredTx({
        reportHash: normalizedHash,
        reportId: data.reportId,
        nearTxHash: txHash,
        contractId: NEAR_CONFIG.contractId,
        network: NEAR_CONFIG.networkId,
        timestamp: Date.now(),
      });
    } catch (cacheErr) {
      console.warn("[near-client] Failed to cache anchored transaction hash:", cacheErr);
    }
  }

  // 5. Query newly confirmed record to obtain block height and timestamp
  const onChainRecord = await callContractMethod("get_report", {
    report_hash: normalizedHash,
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

      const exists = await callContractMethod("verify_report", {
        report_hash: normalizedHash,
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

      const onChainRecord = await callContractMethod("get_report", {
        report_hash: normalizedHash,
      });

      // Priority 3: Hydrate genuine transaction hash from cache if available
      const cached = getCachedTx(normalizedHash);
      const cachedTxHash = cached?.nearTxHash;

      return {
        isVerified: true,
        status: "VERIFIED_ON_NEAR",
        record: mapOnChainRecord(onChainRecord as Record<string, unknown>, cachedTxHash),
        queriedAtBlock: testnetState.blockHeight,
        message:
          "Cryptographic report hash verified via live NEAR Testnet RPC.",
      };
    }

    // Otherwise, treat the input as a human-readable Report ID.
    const onChainRecord = await callContractMethod("get_report_by_id", {
      report_id: query,
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

    // Priority 3: Hydrate genuine transaction hash from cache if available
    const cached = getCachedTx(query);
    const cachedTxHash = cached?.nearTxHash;

    return {
      isVerified: true,
      status: "VERIFIED_ON_NEAR",
      record: mapOnChainRecord(onChainRecord as Record<string, unknown>, cachedTxHash),
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

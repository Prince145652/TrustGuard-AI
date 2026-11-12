import "server-only";

import fs from "fs";
import path from "path";
import { baseDecode } from "near-api-js";
import { isValidSha256 } from "./near-hashing";
import { NEAR_CONFIG } from "./near-config";

if (typeof window !== "undefined") {
  throw new Error("Transaction cache is server-only and cannot be executed in browser environments.");
}

export interface CachedTxRecord {
  reportHash: string;
  reportId: string;
  nearTxHash: string;
  contractId: string;
  network: "testnet" | "mainnet";
  timestamp: number;
  blockHeight?: number;
}

export interface CacheAnchoredTxParams {
  reportHash: string;
  reportId: string;
  nearTxHash: string;
  contractId?: string;
  network?: "testnet" | "mainnet";
  blockHeight?: number;
  timestamp?: number;
}

// In-memory indexes
const hashIndex = new Map<string, CachedTxRecord>();
const idIndex = new Map<string, CachedTxRecord>();

// Persistence configuration
let customCacheFilePath: string | null = null;
let simulateFailure = false;
let isInitialized = false;

function getCacheFilePath(): string {
  if (customCacheFilePath) {
    return customCacheFilePath;
  }
  return path.join(process.cwd(), ".cache", "near-tx-cache.json");
}

/**
 * Validates whether a given string is a genuine Base58 32-byte NEAR transaction hash.
 * Returns true strictly if Base58 decoding succeeds and yields exactly 32 bytes.
 */
export function isValidNearTxHash(hash: unknown): hash is string {
  if (typeof hash !== "string") return false;
  const trimmed = hash.trim();
  if (trimmed.length < 32 || trimmed.length > 64) return false;
  try {
    const decoded = baseDecode(trimmed);
    return decoded.length === 32;
  } catch {
    return false;
  }
}

/**
 * Loads cached records from disk into memory.
 * Gracefully ignores corrupted files or invalid records.
 */
function initializeCacheIfNeeded(): void {
  if (isInitialized) return;
  isInitialized = true;

  const filePath = getCacheFilePath();
  try {
    if (!fs.existsSync(/*turbopackIgnore: true*/ filePath)) return;

    const raw = fs.readFileSync(/*turbopackIgnore: true*/ filePath, "utf8");
    const parsed = JSON.parse(raw);

    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        if (
          item &&
          typeof item === "object" &&
          typeof item.reportHash === "string" &&
          typeof item.reportId === "string" &&
          typeof item.nearTxHash === "string"
        ) {
          const normHash = item.reportHash.toLowerCase().trim();
          const normId = item.reportId.toUpperCase().trim();
          const txHash = item.nearTxHash.trim();

          if (isValidSha256(normHash) && isValidNearTxHash(txHash)) {
            const record: CachedTxRecord = {
              reportHash: normHash,
              reportId: normId,
              nearTxHash: txHash,
              contractId: typeof item.contractId === "string" ? item.contractId : NEAR_CONFIG.contractId,
              network: item.network === "mainnet" ? "mainnet" : "testnet",
              timestamp: typeof item.timestamp === "number" ? item.timestamp : Date.now(),
              blockHeight: typeof item.blockHeight === "number" ? item.blockHeight : undefined,
            };

            // Only load records matching the active contract and network
            if (
              record.contractId === NEAR_CONFIG.contractId &&
              record.network === NEAR_CONFIG.networkId
            ) {
              hashIndex.set(normHash, record);
              idIndex.set(normId, record);
            }
          }
        }
      }
    }
  } catch (err) {
    // Non-fatal: if file read fails, keep empty in-memory cache
    console.warn("[NearTxCache] Unable to load transaction cache from disk:", err instanceof Error ? err.message : String(err));
  }
}

/**
 * Safely and atomically persists the in-memory cache to disk.
 * Uses atomic rename to prevent half-written or corrupted JSON files.
 * Degrades gracefully if disk write fails.
 */
function persistCacheToDisk(): boolean {
  if (simulateFailure) {
    console.warn("[NearTxCache] Simulated cache write failure triggered.");
    return false;
  }

  const filePath = getCacheFilePath();
  const dir = path.dirname(filePath);

  try {
    if (!fs.existsSync(/*turbopackIgnore: true*/ dir)) {
      fs.mkdirSync(/*turbopackIgnore: true*/ dir, { recursive: true });
    }

    const records = Array.from(hashIndex.values());
    const payload = JSON.stringify(records, null, 2);
    const tempPath = `${filePath}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(36).substring(2, 7)}`;

    fs.writeFileSync(/*turbopackIgnore: true*/ tempPath, payload, "utf8");
    fs.renameSync(/*turbopackIgnore: true*/ tempPath, filePath);
    return true;
  } catch (err) {
    console.warn("[NearTxCache] Failed to persist cache to disk (graceful degradation):", err instanceof Error ? err.message : String(err));
    return false;
  }
}

/**
 * Stores an anchored transaction record into the dual-layer cache.
 * Validates inputs: reportHash must be valid SHA-256 and nearTxHash must be valid Base58 32-byte.
 * Returns true if successfully validated and cached; false otherwise.
 */
export function cacheAnchoredTx(params: CacheAnchoredTxParams): boolean {
  initializeCacheIfNeeded();

  if (!params.reportHash || !params.nearTxHash) return false;

  const normHash = params.reportHash.toLowerCase().trim();
  const normId = (params.reportId || "").toUpperCase().trim();
  const txHash = params.nearTxHash.trim();

  if (!isValidSha256(normHash)) return false;
  if (!isValidNearTxHash(txHash)) return false;

  const record: CachedTxRecord = {
    reportHash: normHash,
    reportId: normId,
    nearTxHash: txHash,
    contractId: params.contractId || NEAR_CONFIG.contractId,
    network: params.network || NEAR_CONFIG.networkId,
    timestamp: typeof params.timestamp === "number" ? params.timestamp : Date.now(),
    blockHeight: typeof params.blockHeight === "number" ? params.blockHeight : undefined,
  };

  hashIndex.set(normHash, record);
  if (normId) {
    idIndex.set(normId, record);
  }

  persistCacheToDisk();
  return true;
}

/**
 * Retrieves a cached transaction record by reportHash (lowercase SHA-256).
 */
export function getCachedTxByReportHash(reportHash: string): CachedTxRecord | undefined {
  initializeCacheIfNeeded();
  if (!reportHash) return undefined;
  return hashIndex.get(reportHash.toLowerCase().trim());
}

/**
 * Retrieves a cached transaction record by reportId (uppercase).
 */
export function getCachedTxByReportId(reportId: string): CachedTxRecord | undefined {
  initializeCacheIfNeeded();
  if (!reportId) return undefined;
  return idIndex.get(reportId.toUpperCase().trim());
}

/**
 * Bidirectional lookup by either SHA-256 report hash or report ID.
 */
export function getCachedTx(hashOrId: string): CachedTxRecord | undefined {
  initializeCacheIfNeeded();
  if (!hashOrId) return undefined;
  const trimmed = hashOrId.trim();

  if (isValidSha256(trimmed)) {
    return hashIndex.get(trimmed.toLowerCase());
  }

  // Check by reportId first
  const byId = idIndex.get(trimmed.toUpperCase());
  if (byId) return byId;

  // Fallback to checking hash index
  return hashIndex.get(trimmed.toLowerCase());
}

/**
 * Retrieves all currently cached records.
 */
export function getAllCachedTxRecords(): CachedTxRecord[] {
  initializeCacheIfNeeded();
  return Array.from(hashIndex.values());
}

/* =========================================================================
 * Test Support Utilities (for deterministic unit tests)
 * ========================================================================= */

export function clearTxCacheForTesting(): void {
  hashIndex.clear();
  idIndex.clear();
  isInitialized = true;
  simulateFailure = false;

  const filePath = getCacheFilePath();
  try {
    if (fs.existsSync(/*turbopackIgnore: true*/ filePath)) {
      fs.unlinkSync(/*turbopackIgnore: true*/ filePath);
    }
  } catch {}
}

export function setTxCacheFilePathForTesting(filePath: string | null): void {
  customCacheFilePath = filePath;
  isInitialized = false;
  hashIndex.clear();
  idIndex.clear();
}

export function simulateTxCacheFailureForTesting(fail: boolean): void {
  simulateFailure = fail;
}

export function getTxCacheStatsForTesting(): { count: number; initialized: boolean } {
  return {
    count: hashIndex.size,
    initialized: isInitialized,
  };
}

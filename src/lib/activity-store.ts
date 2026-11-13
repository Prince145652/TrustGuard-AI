"use client";

import { useEffect, useState, useCallback } from "react";
import { RecentSecurityActivity, RiskLevel, SecurityStats } from "@/types/security";
import { SAMPLE_RECENT_ACTIVITIES, SAMPLE_SECURITY_STATS } from "@/lib/constants";
import { getRiskLevelFromScore } from "@/lib/utils";
import { looksLikeSecret, redactSecrets } from "@/lib/validators";

export const STORAGE_KEY_ACTIVITIES = "trustguard_live_activities_v1";
export const ACTIVITY_EVENT_NAME = "trustguard:activity-updated";
export const MAX_LIVE_ACTIVITIES = 25;

export type SupportedScanTypeInput =
  | "wallet"
  | "website"
  | "token"
  | "WALLET"
  | "WEBSITE"
  | "TOKEN"
  | "Wallet Scanner"
  | "Website Scanner"
  | "Token Scanner";

export function normalizeScanType(
  rawType: string
): "Wallet Scanner" | "Website Scanner" | "Token Scanner" {
  const lower = (rawType || "").toLowerCase();
  if (lower.includes("wallet")) return "Wallet Scanner";
  if (lower.includes("web") || lower.includes("url") || lower.includes("phishing"))
    return "Website Scanner";
  return "Token Scanner";
}

export function deriveActivityStatus(
  riskLevel: RiskLevel
): RecentSecurityActivity["status"] {
  if (riskLevel === "UNKNOWN") return "Inconclusive";
  if (riskLevel === "CRITICAL") return "Threat Blocked";
  if (riskLevel === "HIGH") return "High Risk";
  return "Safe";
}

function getFormattedNow(): string {
  const d = new Date();
  const hours = String(d.getHours()).padStart(2, "0");
  const mins = String(d.getMinutes()).padStart(2, "0");
  return `Today, ${hours}:${mins}`;
}

export function getLiveActivities(): RecentSecurityActivity[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY_ACTIVITIES);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.slice(0, MAX_LIVE_ACTIVITIES);
    }
    return [];
  } catch {
    return [];
  }
}

export function saveLiveActivities(activities: RecentSecurityActivity[]): void {
  if (typeof window === "undefined") return;
  try {
    const trimmed = activities.slice(0, MAX_LIVE_ACTIVITIES);
    window.localStorage.setItem(STORAGE_KEY_ACTIVITIES, JSON.stringify(trimmed));
    window.dispatchEvent(new CustomEvent(ACTIVITY_EVENT_NAME));
  } catch {
    // Fail gracefully on storage quota or access issues
  }
}

export function clearLiveActivities(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(STORAGE_KEY_ACTIVITIES);
    window.dispatchEvent(new CustomEvent(ACTIVITY_EVENT_NAME));
  } catch {
    // Fail gracefully
  }
}

export interface RecordScanParams {
  target: string;
  scanType: SupportedScanTypeInput;
  riskScore?: number;
  riskLevel: RiskLevel | string;
  nearTxHash?: string;
}

/**
 * Record or update a live scan in the activity store with FIFO eviction (max 25)
 * and target + scanType deduplication.
 */
export function recordScanActivity(params: RecordScanParams): RecentSecurityActivity {
  if (looksLikeSecret(params.target)) {
    throw new Error("SECURITY VIOLATION: Private keys, recovery phrases, and secrets can never be recorded in client storage.");
  }
  const target = redactSecrets(params.target.trim());
  const scanType = normalizeScanType(params.scanType);
  const normalizedRiskLevel = (
    params.riskLevel === "UNKNOWN"
      ? "UNKNOWN"
      : ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(
          params.riskLevel as RiskLevel
        )
      ? params.riskLevel
      : params.riskScore !== undefined
      ? getRiskLevelFromScore(params.riskScore)
      : "UNKNOWN"
  ) as RiskLevel;

  const defaultStatus = deriveActivityStatus(normalizedRiskLevel);
  const existingList = getLiveActivities();

  // Deduplicate: check if this target + scanType is already in live activities
  const existingIndex = existingList.findIndex(
    (item) =>
      item.scanType === scanType &&
      item.target.toLowerCase() === target.toLowerCase()
  );

  let updatedActivity: RecentSecurityActivity;

  if (existingIndex >= 0) {
    const existing = existingList[existingIndex];
    // Rule: Only preserve Verified On-Chain if ALREADY verified on-chain via recordNearRegistration
    const isAlreadyVerified = existing.status === "Verified On-Chain" && Boolean(existing.nearTxHash);
    const confirmedTxHash = isAlreadyVerified ? existing.nearTxHash : undefined;

    // Rule 4: UNKNOWN must always remain Inconclusive, regardless of transaction hash
    // Requirement 1 & 2: recordScanActivity can NEVER assign or promote to "Verified On-Chain"
    const status: RecentSecurityActivity["status"] =
      normalizedRiskLevel === "UNKNOWN"
        ? "Inconclusive"
        : isAlreadyVerified
        ? "Verified On-Chain"
        : defaultStatus;

    updatedActivity = {
      ...existing,
      target, // preserve latest capitalization
      riskLevel: normalizedRiskLevel,
      status,
      nearTxHash: confirmedTxHash,
      date: getFormattedNow(),
      isSample: false,
    };
    // Remove old occurrence and prepend updated to the top
    const remaining = existingList.filter((_, idx) => idx !== existingIndex);
    const nextList = [updatedActivity, ...remaining].slice(0, MAX_LIVE_ACTIVITIES);
    saveLiveActivities(nextList);
  } else {
    // Requirement 1 & 2: Normal scanner activity is strictly off-chain.
    // recordScanActivity() can NEVER assign "Verified On-Chain", even if nearTxHash is supplied.
    const status: RecentSecurityActivity["status"] =
      normalizedRiskLevel === "UNKNOWN"
        ? "Inconclusive"
        : defaultStatus;

    updatedActivity = {
      id: `live-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      target,
      scanType,
      riskLevel: normalizedRiskLevel,
      date: getFormattedNow(),
      status,
      nearTxHash: undefined,
      isSample: false,
    };
    const nextList = [updatedActivity, ...existingList].slice(0, MAX_LIVE_ACTIVITIES);
    saveLiveActivities(nextList);
  }

  return updatedActivity;
}

export interface RecordNearParams {
  target: string;
  scanType: SupportedScanTypeInput;
  nearTxHash?: string; // Genuine confirmed NEAR transaction hash only (undefined if off-chain)
  riskScore?: number;
  riskLevel?: RiskLevel | string;
  reportId?: string;
}

/**
 * Promotes an existing activity to "Verified On-Chain" and binds the transaction hash.
 * If not already present in live activities, adds it as a verified record.
 * Enforces that records without genuine nearTxHash receive off-chain status, never "Verified On-Chain".
 */
export function recordNearRegistration(params: RecordNearParams): RecentSecurityActivity {
  const target = params.target.trim();
  const scanType = normalizeScanType(params.scanType);
  const existingList = getLiveActivities();

  const existingIndex = existingList.findIndex(
    (item) =>
      item.scanType === scanType &&
      item.target.toLowerCase() === target.toLowerCase()
  );

  let updatedActivity: RecentSecurityActivity;

  if (existingIndex >= 0) {
    const existing = existingList[existingIndex];
    // Rule 5: Canonical risk level using getRiskLevelFromScore when score available
    const riskLevel: RiskLevel =
      params.riskLevel === "UNKNOWN"
        ? "UNKNOWN"
        : params.riskScore !== undefined
        ? getRiskLevelFromScore(params.riskScore)
        : params.riskLevel && ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(params.riskLevel as RiskLevel)
        ? (params.riskLevel as RiskLevel)
        : existing.riskLevel;

    // Rule 3: Preserve confirmed tx hash if already anchored
    const confirmedTxHash = (params.nearTxHash && params.nearTxHash.trim()) || existing.nearTxHash;

    // Rule 4: UNKNOWN must always remain Inconclusive, regardless of transaction hash
    // Rule 1 & 2: Without a genuine nearTxHash, never assign "Verified On-Chain"; preserve off-chain status
    const status: RecentSecurityActivity["status"] =
      riskLevel === "UNKNOWN"
        ? "Inconclusive"
        : confirmedTxHash
        ? "Verified On-Chain"
        : deriveActivityStatus(riskLevel);

    updatedActivity = {
      ...existing,
      riskLevel,
      status,
      nearTxHash: confirmedTxHash,
      date: getFormattedNow(),
      isSample: false,
    };
    const remaining = existingList.filter((_, idx) => idx !== existingIndex);
    const nextList = [updatedActivity, ...remaining].slice(0, MAX_LIVE_ACTIVITIES);
    saveLiveActivities(nextList);
  } else {
    // Rule 5: Canonical risk level; fallback to UNKNOWN, never "SAFE"
    const normalizedRiskLevel: RiskLevel =
      params.riskLevel === "UNKNOWN"
        ? "UNKNOWN"
        : params.riskScore !== undefined
        ? getRiskLevelFromScore(params.riskScore)
        : params.riskLevel && ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(params.riskLevel as RiskLevel)
        ? (params.riskLevel as RiskLevel)
        : "UNKNOWN";

    const confirmedTxHash = params.nearTxHash && params.nearTxHash.trim() ? params.nearTxHash.trim() : undefined;

    // Rule 4: UNKNOWN must always map to Inconclusive
    // Rule 1 & 2: Without a genuine nearTxHash, never assign "Verified On-Chain"; use off-chain status
    const status: RecentSecurityActivity["status"] =
      normalizedRiskLevel === "UNKNOWN"
        ? "Inconclusive"
        : confirmedTxHash
        ? "Verified On-Chain"
        : deriveActivityStatus(normalizedRiskLevel);

    updatedActivity = {
      id: `live-near-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      target,
      scanType,
      riskLevel: normalizedRiskLevel,
      date: getFormattedNow(),
      status,
      nearTxHash: confirmedTxHash,
      isSample: false,
    };
    const nextList = [updatedActivity, ...existingList].slice(0, MAX_LIVE_ACTIVITIES);
    saveLiveActivities(nextList);
  }

  return updatedActivity;
}

/**
 * Merges live activity items with static sample activities.
 * Live activities always precede sample activities, and duplicate targets
 * in the sample list are shadowed by live scans.
 */
export function mergeAndDeduplicateActivities(
  liveActivities: RecentSecurityActivity[],
  sampleActivities: RecentSecurityActivity[] = SAMPLE_RECENT_ACTIVITIES,
  maxLive = MAX_LIVE_ACTIVITIES
): RecentSecurityActivity[] {
  const validLive = (liveActivities || []).slice(0, maxLive);
  const liveTargetKeys = new Set(
    validLive.map((a) => `${a.scanType}:${a.target.toLowerCase().trim()}`)
  );

  // Filter out any sample activity shadowed by a real scan on the same target & type
  const unshadowedSamples = sampleActivities.filter(
    (s) => !liveTargetKeys.has(`${s.scanType}:${s.target.toLowerCase().trim()}`)
  );

  return [...validLive, ...unshadowedSamples];
}

/**
 * Checks whether an activity record possesses explicit verified on-chain provenance.
 * True strictly when:
 * 1. The activity is genuine live data (isSample === false).
 * 2. The activity has explicit on-chain verified status (status === "Verified On-Chain").
 * 3. A genuine non-empty NEAR transaction hash is present.
 */
export function hasVerifiedOnChainProvenance(
  activity: Pick<RecentSecurityActivity, "isSample" | "status" | "nearTxHash">
): boolean {
  return (
    activity.isSample === false &&
    activity.status === "Verified On-Chain" &&
    typeof activity.nearTxHash === "string" &&
    activity.nearTxHash.trim().length > 0
  );
}

/**
 * Resolves the NearBlocks testnet explorer URL ONLY for activities with explicit verified on-chain provenance.
 * Returns null for sample data, unverified off-chain scans, or missing hashes, preventing 404 explorer errors.
 */
export function getActivityExplorerUrl(
  activity: Pick<RecentSecurityActivity, "isSample" | "status" | "nearTxHash">
): string | null {
  if (!hasVerifiedOnChainProvenance(activity)) {
    return null;
  }
  return `https://testnet.nearblocks.io/txns/${activity.nearTxHash!.trim()}`;
}

export interface DynamicSecurityStats {
  // Provenance indicator: true when showing simulated benchmark data, false when displaying real live session telemetry
  isSampleData: boolean;
  // Displayed metrics for the active view
  totalScans: number;
  threatsDetected: number;
  protectedWallets: number;
  securityScore: number;
  // Pure live session telemetry (strictly non-sample provenance)
  liveCount: number;
  liveThreats: number;
  liveWallets: number;
  liveSafeWallets: number;
  liveVerified: number;
  sessionCleanRate: number | null;
  // Sample platform baseline retained separately for demo reference only (never blended into live telemetry)
  sampleBaseline: SecurityStats;
}

/**
 * Computes dynamic ecosystem telemetry from live session activities without conflating
 * sample baseline numbers into real live metrics.
 * Preserves platform-wide securityScore semantics while providing session-specific metrics.
 */
export function computeSecurityStats(
  liveActivities: RecentSecurityActivity[] = [],
  baseline: SecurityStats = SAMPLE_SECURITY_STATS,
  options?: { viewMode?: "live" | "sample" }
): DynamicSecurityStats {
  const validLive = Array.isArray(liveActivities)
    ? liveActivities.filter((a) => a.isSample === false)
    : [];

  const liveCount = validLive.length;
  const liveThreats = validLive.filter(
    (a) => a.riskLevel === "CRITICAL" || a.riskLevel === "HIGH"
  ).length;
  const liveWallets = validLive.filter(
    (a) => a.scanType === "Wallet Scanner"
  ).length;
  const liveSafeWallets = validLive.filter(
    (a) =>
      a.scanType === "Wallet Scanner" &&
      a.riskLevel !== "CRITICAL" &&
      a.riskLevel !== "HIGH"
  ).length;
  const liveVerified = validLive.filter((a) => hasVerifiedOnChainProvenance(a)).length;

  const liveClean = liveCount - liveThreats;
  const sessionCleanRate = liveCount > 0 ? Number(((liveClean / liveCount) * 100).toFixed(1)) : null;

  const forceSampleView = options?.viewMode === "sample";

  if (liveCount > 0 && !forceSampleView) {
    // Truth-in-Advertising: Report pure live session telemetry for counts.
    // Preserve platform-wide security score semantics from baseline while recording sessionCleanRate.
    return {
      isSampleData: false,
      totalScans: liveCount,
      threatsDetected: liveThreats,
      protectedWallets: liveSafeWallets,
      securityScore: baseline.securityScore,
      liveCount,
      liveThreats,
      liveWallets,
      liveSafeWallets,
      liveVerified,
      sessionCleanRate,
      sampleBaseline: baseline,
    };
  }

  // Baseline demonstration mode: metrics are explicitly marked as simulated sample data
  return {
    isSampleData: true,
    totalScans: baseline.totalScans,
    threatsDetected: baseline.threatsDetected,
    protectedWallets: baseline.protectedWallets,
    securityScore: baseline.securityScore,
    liveCount,
    liveThreats,
    liveWallets,
    liveSafeWallets,
    liveVerified,
    sessionCleanRate,
    sampleBaseline: baseline,
  };
}

/**
 * React hook to subscribe to live activities with SSR hydration safety.
 */
export function useRecentActivities() {
  const [liveActivities, setLiveActivities] = useState<RecentSecurityActivity[]>([]);
  const [isHydrated, setIsHydrated] = useState(false);

  const refreshActivities = useCallback(() => {
    setLiveActivities(getLiveActivities());
  }, []);

  useEffect(() => {
    // Hydrate from localStorage once mounted on client
    refreshActivities();
    setIsHydrated(true);

    const handleUpdate = () => refreshActivities();
    const handleStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY_ACTIVITIES || e.key === null) {
        refreshActivities();
      }
    };

    window.addEventListener(ACTIVITY_EVENT_NAME, handleUpdate);
    window.addEventListener("storage", handleStorage);

    return () => {
      window.removeEventListener(ACTIVITY_EVENT_NAME, handleUpdate);
      window.removeEventListener("storage", handleStorage);
    };
  }, [refreshActivities]);

  // Before hydration, return static sample data to guarantee DOM match with SSR
  const activities = isHydrated
    ? mergeAndDeduplicateActivities(liveActivities, SAMPLE_RECENT_ACTIVITIES)
    : SAMPLE_RECENT_ACTIVITIES;

  return {
    activities,
    liveActivities: isHydrated ? liveActivities : [],
    liveCount: isHydrated ? liveActivities.length : 0,
    isHydrated,
    clearActivities: clearLiveActivities,
  };
}

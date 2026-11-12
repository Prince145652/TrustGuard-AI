"use client";

import { useEffect, useState, useCallback } from "react";
import { RecentSecurityActivity, RiskLevel } from "@/types/security";
import { SAMPLE_RECENT_ACTIVITIES } from "@/lib/constants";
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
    // Rule 3: Preserve existing confirmed tx hash if not overridden with a new one
    const confirmedTxHash = params.nearTxHash || existing.nearTxHash;

    // Rule 4: UNKNOWN must always remain Inconclusive, regardless of transaction hash
    // Rule 1 & 3: Only retain Verified On-Chain if genuine tx hash exists; otherwise use off-chain status
    const status: RecentSecurityActivity["status"] =
      normalizedRiskLevel === "UNKNOWN"
        ? "Inconclusive"
        : confirmedTxHash && (existing.status === "Verified On-Chain" || params.nearTxHash)
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
    const confirmedTxHash = params.nearTxHash || undefined;
    const status: RecentSecurityActivity["status"] =
      normalizedRiskLevel === "UNKNOWN"
        ? "Inconclusive"
        : confirmedTxHash
        ? "Verified On-Chain"
        : defaultStatus;

    updatedActivity = {
      id: `live-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
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
    liveCount: isHydrated ? liveActivities.length : 0,
    isHydrated,
    clearActivities: clearLiveActivities,
  };
}

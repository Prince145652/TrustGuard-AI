import crypto from "crypto";

/**
 * Canonical JSON serialization:
 * Recursively sorts all object keys in lexicographical order.
 * Ensures identical data structures produce byte-identical UTF-8 strings.
 */
export function canonicalStringify(obj: unknown): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalStringify).join(",") + "]";
  }

  const record = obj as Record<string, unknown>;
  const sortedKeys = Object.keys(record).sort();
  const serializedEntries = sortedKeys
    .filter((key) => record[key] !== undefined) // Omit undefined keys
    .map((key) => JSON.stringify(key) + ":" + canonicalStringify(record[key]));

  return "{" + serializedEntries.join(",") + "}";
}

/**
 * Generates deterministic SHA-256 digest of security audit report data.
 * Filters out non-deterministic ephemeral timestamps to ensure reproducibility.
 */
export function generateReportHash(reportData: Record<string, unknown>): string {
  // Extract strictly deterministic core report fields
  const deterministicData = {
    target: reportData.target,
    scanType: reportData.scanType,
    riskScore: reportData.riskScore,
    riskLevel: reportData.riskLevel,
    threats: reportData.threats || [],
    evidence: reportData.evidence || [],
    indicators: reportData.indicators || [],
  };

  const canonicalJson = canonicalStringify(deterministicData);
  return crypto.createHash("sha256").update(canonicalJson, "utf8").digest("hex");
}

/**
 * Validates whether an input string is a valid 64-character SHA-256 hex string
 */
export function isValidSha256(hash: string): boolean {
  return /^[a-fA-F0-9]{64}$/.test(hash.trim());
}

/**
 * Generates an immutable, human-readable Report ID
 */
export function generateReportId(scanType: string, target: string): string {
  const shortTarget = target.replace(/[^a-zA-Z0-9]/g, "").slice(0, 8).toUpperCase();
  const randSuffix = crypto.randomBytes(4).toString("hex").toUpperCase();
  return `TG-${scanType.toUpperCase()}-${shortTarget}-${randSuffix}`;
}

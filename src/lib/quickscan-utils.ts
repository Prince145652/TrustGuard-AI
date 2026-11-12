import { EvmChainId } from "@/types/evm-security";
import { RiskLevel, SecurityFactor } from "@/types/security";
import { ScanContext } from "@/types/ai-analyst";

export const SUPPORTED_EVM_CHAINS: readonly EvmChainId[] = ["ethereum", "base", "bnb"] as const;

export function isEvmChainId(chain: unknown): chain is EvmChainId {
  return typeof chain === "string" && SUPPORTED_EVM_CHAINS.includes(chain as EvmChainId);
}

export function isEvmAddress(target: string): boolean {
  if (!target) return false;
  return /^0x[a-fA-F0-9]{40}$/.test(target.trim());
}

export function isNearTarget(target: string): boolean {
  if (!target) return false;
  const t = target.trim().toLowerCase();
  return t.endsWith(".near") || t.endsWith(".testnet") || (!t.startsWith("0x") && !t.includes("://") && !t.includes("."));
}

export interface PrefillTargets {
  wallet?: string;
  website?: string;
  token?: string;
}

export interface PrefillChains {
  wallet?: EvmChainId;
  token?: EvmChainId;
}

export interface PrefillTransitionResult {
  nextTargets: PrefillTargets;
  nextChains: PrefillChains;
  allowed: boolean;
  reason?: string;
}

export function computePrefillTransition(
  tab: "wallet" | "website" | "token",
  target: string,
  chain: unknown,
  currentTargets: PrefillTargets,
  currentChains: PrefillChains
): PrefillTransitionResult {
  const trimmed = target ? target.trim() : "";

  if (!trimmed) {
    const { [tab]: _t, ...restTargets } = currentTargets;
    const { [tab as "wallet" | "token"]: _c, ...restChains } = currentChains;
    return {
      nextTargets: restTargets,
      nextChains: restChains,
      allowed: false,
      reason: "Empty target provided.",
    };
  }

  // Strict EVM validation for wallet and token scanners
  if (tab === "wallet" || tab === "token") {
    if (!isEvmAddress(trimmed)) {
      return {
        nextTargets: currentTargets,
        nextChains: currentChains,
        allowed: false,
        reason: `Target "${trimmed}" is not a valid 0x EVM address. Dedicated ${tab} scanner requires an EVM address.`,
      };
    }
  }

  const nextTargets: PrefillTargets = {
    ...currentTargets,
    [tab]: trimmed,
  };

  const nextChains: PrefillChains = { ...currentChains };
  if (tab === "wallet" || tab === "token") {
    if (isEvmChainId(chain)) {
      nextChains[tab] = chain;
    } else {
      delete nextChains[tab];
    }
  }

  return {
    nextTargets,
    nextChains,
    allowed: true,
  };
}

export interface QuickScanCardResult {
  target: string;
  riskScore: number;
  riskLevel: RiskLevel;
  summary: string;
  factors: SecurityFactor[];
  verifiedOnNear: boolean;
  nearTxHash?: string;
  threats?: string[];
  detectedChain?: EvmChainId;
}

export function buildQuickScanContext(
  scanType: "wallet" | "website" | "token",
  result: QuickScanCardResult
): ScanContext {
  const chain = isEvmChainId(result.detectedChain) ? result.detectedChain : undefined;

  // Deduplicate threats while preserving severity
  const threats: string[] = [];
  const seenThreatKeys = new Set<string>();

  if (result.threats && result.threats.length > 0) {
    for (const t of result.threats) {
      const clean = t.trim();
      const norm = clean.toLowerCase();
      if (clean && !seenThreatKeys.has(norm)) {
        seenThreatKeys.add(norm);
        threats.push(clean);
      }
    }
  }

  const failedFactors = (result.factors || []).filter(
    (f) => !f.passed && (f.severity === "CRITICAL" || f.severity === "HIGH" || f.severity === "MEDIUM")
  );

  for (const f of failedFactors) {
    const threatText = `[${f.severity}] ${f.name}: ${f.description}`;
    const nameNorm = f.name.toLowerCase();
    const alreadyCovered = Array.from(seenThreatKeys).some((seen) => {
      if (seen.includes(nameNorm) || nameNorm.includes(seen) || seen === threatText.toLowerCase()) {
        return true;
      }
      // Check significant keywords (length >= 4) from factor name
      const nameWords = nameNorm.split(/[^a-z0-9]+/).filter((w) => w.length >= 4);
      return nameWords.length > 0 && nameWords.some((w) => seen.includes(w));
    });

    if (!alreadyCovered) {
      seenThreatKeys.add(threatText.toLowerCase());
      threats.push(threatText);
    }
  }

  if (threats.length === 0 && result.riskScore >= 75) {
    threats.push(`High risk indicator identified during quick scan on ${result.target}`);
  }

  // Evidence: preserve native severity in finding text; status respects schema enum
  const evidence = (result.factors || []).map((f) => ({
    category: f.category || "Security Inspection",
    finding: f.passed
      ? `[SAFE] ${f.name}: ${f.description}`
      : `[${f.severity} Severity] ${f.name}: ${f.description}`,
    status: f.passed
      ? ("SAFE" as const)
      : f.severity === "CRITICAL"
      ? ("CRITICAL" as const)
      : ("WARNING" as const),
  }));

  const indicators = failedFactors.map((f) => ({
    name: f.name,
    description: f.description,
    detected: true,
    severity: f.severity,
    whySuspicious: `Flagged during quick scan: ${f.name} (${f.severity} severity)`,
  }));

  return {
    scanType,
    target: result.target,
    chain,
    riskScore: result.riskScore,
    riskLevel: result.riskLevel,
    threats,
    evidence,
    indicators,
  };
}

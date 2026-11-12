"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  ShieldCheck,
  Lightbulb,
  SearchCheck,
  ExternalLink,
} from "lucide-react";
import { StructuredSecurityReport } from "@/types/ai-analyst";

interface EvidenceFirstVerdictProps {
  report: StructuredSecurityReport;
}

function getConfidence(report: StructuredSecurityReport): number {
  const evidenceCount = report.evidence.length;
  const threatCount = report.detectedThreats.length;

  // Transparent heuristic confidence — not an AI probability.
  return Math.min(95, 55 + evidenceCount * 8 + threatCount * 5);
}

function getRiskStyles(riskScore: number, riskLevel?: string) {
  if (riskLevel === "UNKNOWN") {
    return {
      label: "INCONCLUSIVE (TELEMETRY TIMEOUT)",
      badge: "bg-amber-500/15 text-amber-300 border-amber-500/40",
      icon: "text-amber-400",
    };
  }

  if (riskScore >= 75) {
    return {
      label: "HIGH RISK",
      badge: "bg-rose-500/15 text-rose-300 border-rose-500/40",
      icon: "text-rose-400",
    };
  }

  if (riskScore >= 35) {
    return {
      label: "MEDIUM RISK",
      badge: "bg-yellow-500/15 text-yellow-300 border-yellow-500/40",
      icon: "text-yellow-400",
    };
  }

  return {
    label: "LOW RISK",
    badge: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
    icon: "text-emerald-400",
  };
}

export function EvidenceFirstVerdict({
  report,
}: EvidenceFirstVerdictProps) {
  const nearRecord = report.nearRecord;
  const isAnchored = nearRecord?.status === "VERIFIED_ON_NEAR";
  const confidence = getConfidence(report);
  const risk = getRiskStyles(report.riskScore, report.riskLevel);

  const suspiciousSignals =
    report.detectedThreats.length > 0
      ? report.detectedThreats.length
      : report.evidence.length;

  return (
    <div className="mt-4 rounded-xl border border-cyan-500/20 bg-gradient-to-b from-slate-900 to-slate-950 p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-300">
            AI Security Verdict
          </span>
        </div>

        <span className="text-[10px] font-mono text-slate-500">
          Evidence-backed
        </span>
      </div>

      {/* Judge-Friendly Proof Summary (Real on-chain verification only) */}
      {isAnchored && nearRecord && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-[11px] font-mono text-emerald-300">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          <span className="font-semibold">
            Evidence-backed analysis • Cryptographically anchored on NEAR
          </span>
        </div>
      )}

      {/* Risk & Confidence */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className={`rounded-lg border p-3 ${risk.badge}`}>
          <div className="text-[10px] uppercase font-mono opacity-70">
            Risk Assessment
          </div>
          <div className="mt-1 flex items-center gap-2">
            <AlertTriangle className={`w-4 h-4 ${risk.icon}`} />
            <span className="font-bold text-sm">
              {risk.label}
            </span>
          </div>
        </div>

        <div className="rounded-lg border border-slate-700 bg-slate-950/70 p-3">
          <div className="text-[10px] uppercase font-mono text-slate-500">
            Evidence Confidence
          </div>
          <div className="mt-1 flex items-center gap-2">
            <SearchCheck className="w-4 h-4 text-cyan-400" />
            <span className="font-bold text-sm text-slate-200">
              {confidence}%
            </span>
          </div>
        </div>
      </div>

      {/* Why */}
      <div className="rounded-lg bg-slate-950/60 border border-slate-800 p-3">
        <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
          <Lightbulb className="w-4 h-4 text-yellow-400" />
          Why was this flagged?
        </div>

        <p className="mt-2 text-xs text-slate-400 leading-relaxed">
          {suspiciousSignals > 0
            ? `${suspiciousSignals} security signal${
                suspiciousSignals === 1 ? "" : "s"
              } contributed to this assessment.`
            : "No high-confidence suspicious signals were detected in the available scanner data."}
        </p>
      </div>

      {/* Evidence */}
      {report.evidence.length > 0 && (
        <div className="space-y-2">
          <div className="text-[10px] font-bold uppercase tracking-wider text-cyan-400">
            Security Evidence
          </div>

          <div className="space-y-2">
            {report.evidence.slice(0, 5).map((evidence, index) => (
              <div
                key={`${evidence}-${index}`}
                className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-950/50 p-2.5"
              >
                <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <span className="text-xs text-slate-300 leading-relaxed">
                  {evidence}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Real NEAR Report Integrity (Only when verified on-chain) */}
      {isAnchored && nearRecord && (
        <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/20 p-3 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-xs font-bold text-cyan-300">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span>Report Integrity Verified on NEAR</span>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-bold">
              Anchored on NEAR Testnet
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono pt-1 text-slate-300">
            {nearRecord.blockHeight > 0 && (
              <div>
                <span className="text-slate-500">Block Height: </span>
                <span className="text-slate-200">#{nearRecord.blockHeight.toLocaleString()}</span>
              </div>
            )}
            {nearRecord.contractId && (
              <div>
                <span className="text-slate-500">Contract: </span>
                <span className="text-slate-200">{nearRecord.contractId}</span>
              </div>
            )}
            {nearRecord.reportHash && (
              <div className="sm:col-span-2 truncate">
                <span className="text-slate-500">SHA-256 Digest: </span>
                <span className="text-slate-300">{nearRecord.reportHash}</span>
              </div>
            )}
          </div>

          {nearRecord.explorerUrl && nearRecord.nearTxHash && (
            <div className="pt-1 border-t border-cyan-500/20 flex items-center justify-between">
              <span className="text-[10px] font-mono text-slate-400">
                Tx: {nearRecord.nearTxHash.slice(0, 10)}...{nearRecord.nearTxHash.slice(-8)}
              </span>
              <a
                href={nearRecord.explorerUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
              >
                <span>View on Explorer</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          )}
        </div>
      )}

      {/* Recommended Action */}
      {report.recommendedActions.length > 0 && (
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3">
          <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-400">
            Recommended Action
          </div>

          <ul className="mt-2 space-y-1.5">
            {report.recommendedActions.slice(0, 3).map((action, index) => (
              <li
                key={`${action}-${index}`}
                className="text-xs text-slate-300 flex gap-2"
              >
                <span className="text-emerald-400">•</span>
                {action}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Responsible AI limitation */}
      <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3">
        <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-yellow-300">
          <AlertTriangle className="w-3.5 h-3.5" />
          AI Analysis Limitation
        </div>

        <p className="mt-1.5 text-[11px] text-slate-400 leading-relaxed">
          {report.uncertaintyNotes ||
            "This analysis is based on available scanner evidence and is not a guarantee of safety. Always verify important transactions independently."}
        </p>
      </div>
    </div>
  );
}

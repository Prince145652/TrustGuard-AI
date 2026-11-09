"use client";

import React, { useState } from "react";
import {
  Brain,
  FileCheck2,
  Copy,
  Check,
  RefreshCw,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  Clock,
  Layers,
} from "lucide-react";
import { ScanContext } from "@/types/ai-analyst";
import { NearVerificationRecord } from "@/types/near-verification";

export interface ScannerReportPayload {
  target: string;
  scanType: "wallet" | "website" | "token";
  riskScore: number;
  riskLevel: string;
  threats?: string[];
  evidence?: Array<{
    category: string;
    finding: string;
    status: "SAFE" | "WARNING" | "CRITICAL" | "UNKNOWN";
  }>;
  indicators?: Array<{
    name: string;
    description: string;
    detected: boolean;
    severity?: string;
    whySuspicious?: string;
  }>;
  recommendations?: string[];
  chain?: string;
}

interface ScannerActionButtonsProps {
  report: ScannerReportPayload;
  onAnalyzeWithAi?: (context: ScanContext) => void;
}

export function ScannerActionButtons({
  report,
  onAnalyzeWithAi,
}: ScannerActionButtonsProps) {
  const [isRegistering, setIsRegistering] = useState(false);
  const [registerError, setRegisterError] = useState<string | null>(null);
  const [registrationRecord, setRegistrationRecord] =
    useState<NearVerificationRecord | null>(null);
  const [copiedField, setCopiedField] = useState<"id" | "hash" | null>(null);

  const handleCopy = (text: string, field: "id" | "hash") => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleAnalyzeClick = () => {
    if (!onAnalyzeWithAi) return;

    const context: ScanContext = {
      scanType: report.scanType,
      target: report.target,
      chain: report.chain,
      riskScore: report.riskScore,
      riskLevel: report.riskLevel,
      threats: report.threats,
      evidence: report.evidence,
      indicators: report.indicators,
      nearRecord: registrationRecord || undefined,
    };

    onAnalyzeWithAi(context);
  };

  const handleRegisterOnNear = async () => {
    if (isRegistering || registrationRecord) return;

    setIsRegistering(true);
    setRegisterError(null);

    try {
      const res = await fetch("/api/near/register-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: report.target,
          scanType: report.scanType.toUpperCase(),
          riskScore: report.riskScore,
          riskLevel: report.riskLevel,
          threats: report.threats || [],
          evidence: report.evidence || [],
          indicators: report.indicators || [],
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.details?.[0] || data.error || "Failed to register report");
      }

      setRegistrationRecord(data.record);
    } catch (err: unknown) {
      setRegisterError(
        err instanceof Error ? err.message : "Error submitting report to NEAR registry"
      );
    } finally {
      setIsRegistering(false);
    }
  };

  return (
    <div className="space-y-4 pt-2">
      {/* Action Buttons Row */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        {/* 1. Analyze with AI Analyst */}
        {onAnalyzeWithAi && (
          <button
            type="button"
            onClick={handleAnalyzeClick}
            className="flex-1 px-4 py-3 bg-gradient-to-r from-cyan-500/20 to-emerald-500/20 hover:from-cyan-500/30 hover:to-emerald-500/30 border border-cyan-500/40 hover:border-cyan-400 text-cyan-200 hover:text-white rounded-xl text-xs sm:text-sm font-bold font-mono transition-all flex items-center justify-center space-x-2 shadow-md shadow-cyan-950/40"
          >
            <Brain className="w-4 h-4 text-cyan-400" />
            <span>Analyze with AI Analyst</span>
            <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
          </button>
        )}

        {/* 2. Register Report on NEAR */}
        <button
          type="button"
          onClick={handleRegisterOnNear}
          disabled={isRegistering || Boolean(registrationRecord)}
          className={`flex-1 px-4 py-3 rounded-xl text-xs sm:text-sm font-bold font-mono transition-all flex items-center justify-center space-x-2 border ${
            registrationRecord
              ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300 cursor-default"
              : isRegistering
              ? "bg-slate-900 border-slate-700 text-slate-400 cursor-wait"
              : "bg-slate-900 hover:bg-slate-800 border-slate-700 hover:border-emerald-500/50 text-slate-200 hover:text-emerald-300 shadow-md shadow-slate-950"
          }`}
        >
          {isRegistering ? (
            <>
              <RefreshCw className="w-4 h-4 text-emerald-400 animate-spin" />
              <span>Generating SHA-256 &amp; Registering...</span>
            </>
          ) : registrationRecord ? (
            <>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Report Registered in Registry</span>
            </>
          ) : (
            <>
              <FileCheck2 className="w-4 h-4 text-emerald-400" />
              <span>Register Report on NEAR</span>
            </>
          )}
        </button>
      </div>

      {/* Error Message */}
      {registerError && (
        <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center space-x-2 animate-in fade-in duration-200">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{registerError}</span>
        </div>
      )}

      {/* Registration Details Card */}
      {registrationRecord && (
        <div className="p-4 sm:p-5 rounded-xl bg-slate-950/90 border border-emerald-500/30 space-y-3.5 text-xs font-mono animate-in fade-in duration-200">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              <span className="font-bold text-slate-200">
                Cryptographic Fingerprint Generated
              </span>
            </div>

            {/* HONEST STATUS LABEL */}
            <span
              className={`px-2.5 py-1 rounded-md text-[10px] font-bold border ${
                registrationRecord.status === "VERIFIED_ON_NEAR"
                  ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300"
                  : "bg-amber-500/15 border-amber-500/30 text-amber-300"
              }`}
            >
              {registrationRecord.statusLabel ||
                (registrationRecord.status === "VERIFIED_ON_NEAR"
                  ? "Verified live on NEAR Testnet"
                  : "Off-chain registration — Testnet contract deployment pending")}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
            <div>
              <span className="text-slate-500 uppercase text-[10px] block">Report ID:</span>
              <div className="flex items-center justify-between bg-slate-900/80 px-2.5 py-1.5 rounded-lg border border-slate-800 mt-1">
                <span className="text-slate-200 font-bold truncate mr-2">
                  {registrationRecord.reportId}
                </span>
                <button
                  type="button"
                  onClick={() => handleCopy(registrationRecord.reportId, "id")}
                  className="text-slate-400 hover:text-slate-200 shrink-0"
                  title="Copy Report ID"
                >
                  {copiedField === "id" ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <span className="text-slate-500 uppercase text-[10px] block">Network &amp; Block:</span>
              <div className="flex items-center space-x-1.5 bg-slate-900/80 px-2.5 py-1.5 rounded-lg border border-slate-800 mt-1 text-slate-300">
                <Clock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>
                  {registrationRecord.network} • Block #{registrationRecord.blockHeight.toLocaleString()}
                </span>
              </div>
            </div>
          </div>

          {/* SHA-256 Digest Box */}
          <div className="space-y-1">
            <span className="text-slate-500 uppercase text-[10px] block">
              Canonical JSON SHA-256 Digest:
            </span>
            <div className="flex items-center justify-between bg-slate-900/90 p-2.5 rounded-lg border border-slate-800 text-[11px] text-cyan-300 break-all">
              <span>{registrationRecord.reportHash}</span>
              <button
                type="button"
                onClick={() => handleCopy(registrationRecord.reportHash, "hash")}
                className="ml-2 text-slate-400 hover:text-slate-200 shrink-0 p-1"
                title="Copy SHA-256 Hash"
              >
                {copiedField === "hash" ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
          </div>

          {/* Honest Explanation & Conditional Explorer Link */}
          <div className="pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[10px] text-slate-400">
            <div className="flex items-start space-x-1.5">
              {registrationRecord.status === "VERIFIED_ON_NEAR" ? (
                <>
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <span className="text-slate-300">
                    Cryptographically anchored and verified on NEAR Testnet via contract {registrationRecord.contractId}.
                  </span>
                </>
              ) : (
                <>
                  <Layers className="w-3.5 h-3.5 text-slate-500 shrink-0 mt-0.5" />
                  <span>
                    Report registered off-chain in TrustGuard ledger. On-chain transaction broadcast will activate once NEAR Testnet contract deployment is finalized.
                  </span>
                </>
              )}
            </div>

            {/* Only show explorer link if an actual transaction hash exists */}
            {registrationRecord.nearTxHash && registrationRecord.explorerUrl && (
              <a
                href={registrationRecord.explorerUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:text-cyan-300 inline-flex items-center space-x-1 font-bold shrink-0"
              >
                <span>View on Explorer</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

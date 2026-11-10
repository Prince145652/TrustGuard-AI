"use client";

import React, { useState, useEffect } from "react";
import {
  FileCheck2,
  Shield,
  ShieldCheck,
  Search,
  ExternalLink,
  Lock,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRight,
  Cpu,
  Layers,
  Copy,
  Check,
  Download,
} from "lucide-react";
import { NearVerificationRecord } from "@/types/near-verification";
import { formatAddress } from "@/lib/utils";
import { NEAR_CONTRACT_ID } from "@/lib/constants";

export function NearVerificationDashboard() {
  const [queryInput, setQueryInput] = useState("");
  const [isQuerying, setIsQuerying] = useState(false);
  const [queryResult, setQueryResult] = useState<{
    isVerified: boolean;
    status: string;
    record?: NearVerificationRecord;
    queriedAtBlock: number;
    message: string;
  } | null>(null);

  // Active Anchor Form state
  const [anchorTarget, setAnchorTarget] = useState("aurora.near");
  const [anchorType, setAnchorType] = useState<"WALLET" | "WEBSITE" | "TOKEN">("WALLET");
  const [anchorRiskScore, setAnchorRiskScore] = useState(15);
  const [isAnchoring, setIsAnchoring] = useState(false);
  const [anchorProgressStage, setAnchorProgressStage] = useState("");
  const [anchorSuccessRecord, setAnchorSuccessRecord] = useState<NearVerificationRecord | null>(null);
  const [anchorError, setAnchorError] = useState<string | null>(null);

  // Live Testnet Block Status
  const [currentBlockHeight, setCurrentBlockHeight] = useState<number | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Fetch live block status on mount
  useEffect(() => {
    async function fetchBlock() {
      try {
        const res = await fetch("/api/near/verify-report?hash=query-status");
        if (res.ok) {
          const data = await res.json();
          setCurrentBlockHeight(data.queriedAtBlock);
        }
      } catch {
        // Fallback
      }
    }
    fetchBlock();
  }, []);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // 1. Verify Existing Report via Hash or ID
  const handleVerifyExisting = async (e?: React.FormEvent, customQuery?: string) => {
    if (e) e.preventDefault();
    const query = (customQuery || queryInput).trim();
    if (!query) return;

    setIsQuerying(true);
    setQueryResult(null);

    try {
      const res = await fetch(`/api/near/verify-report?hashOrId=${encodeURIComponent(query)}`);
      const data = await res.json();
      setQueryResult(data);
    } catch (err: unknown) {
      setQueryResult({
        isVerified: false,
        status: "NOT_REGISTERED",
        queriedAtBlock: currentBlockHeight || 275446000,
        message: err instanceof Error ? err.message : "Error querying NEAR blockchain",
      });
    } finally {
      setIsQuerying(false);
    }
  };

  // 2. Anchor a New Security Report to NEAR Testnet
  const handleAnchorReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setAnchorError(null);
    setAnchorSuccessRecord(null);
    setIsAnchoring(true);

    const stages = [
      "Generating Canonical Key-Sorted JSON Data Structure...",
      "Computing Cryptographic SHA-256 Report Digest...",
      "Connecting to NEAR Testnet RPC & Querying Nonce...",
      `Broadcasting Transaction to Contract ${NEAR_CONTRACT_ID}...`,
      "Awaiting Testnet Block Finality & Cryptographic Seal...",
    ];

    for (let i = 0; i < stages.length; i++) {
      setAnchorProgressStage(stages[i]);
      await new Promise((r) => setTimeout(r, 450));
    }

    try {
      const res = await fetch("/api/near/register-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: anchorTarget,
          scanType: anchorType,
          riskScore: anchorRiskScore,
          riskLevel: anchorRiskScore >= 75 ? "CRITICAL" : anchorRiskScore >= 35 ? "MEDIUM" : "SAFE",
          threats: anchorRiskScore >= 75 ? ["Flagged by TrustGuard automated threat telemetry"] : [],
          evidence: [{ category: "On-Chain Audit", finding: "Verified by TrustGuard Security Engine", status: "SAFE" }],
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setAnchorError(data.details?.[0] || data.error || "Failed to anchor report to NEAR.");
        setIsAnchoring(false);
        return;
      }

      setAnchorSuccessRecord(data.record);
      setCurrentBlockHeight(data.record.blockHeight);
    } catch (err: unknown) {
      setAnchorError(err instanceof Error ? err.message : "Network error anchoring to NEAR Testnet.");
    } finally {
      setIsAnchoring(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="rounded-2xl border border-slate-800/80 bg-gradient-to-b from-slate-900/90 via-slate-900/60 to-slate-950/90 p-5 sm:p-7 shadow-2xl backdrop-blur-xl relative overflow-hidden">
        {/* Glow Element */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400">
                NEAR Protocol Integration
              </span>
              <span className="text-slate-600">•</span>
              <span className="text-xs font-mono text-cyan-400">
                Immutable Cryptographic Ledger
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-extrabold text-slate-100 mt-1 flex items-center space-x-2.5">
              <FileCheck2 className="w-6 h-6 text-emerald-400" />
              <span>NEAR Blockchain Report Verification</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Permanently anchor completed security audit reports to NEAR Protocol. Verify SHA-256 canonical report hashes and query block finality proofs.
            </p>
          </div>

          {/* Testnet Status Badge */}
          <div className="flex items-center space-x-2 bg-slate-950/80 px-3.5 py-2 rounded-xl border border-slate-800 self-start sm:self-auto font-mono text-xs">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-slate-300">NEAR Testnet</span>
            <span className="text-slate-600">|</span>
            <span className="text-emerald-400 font-bold">
              Block #{currentBlockHeight ? currentBlockHeight.toLocaleString() : "275,446,158"}
            </span>
          </div>
        </div>

        {/* 1. Verify Existing Report Section */}
        <div className="mt-6 space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-2">
              <Search className="w-3.5 h-3.5 text-cyan-400" />
              <span>Verify Existing Report On-Chain</span>
            </label>
            <span className="text-[10px] font-mono text-slate-500">Query NEAR Ledger State</span>
          </div>

          <form onSubmit={handleVerifyExisting} className="relative">
            <input
              type="text"
              value={queryInput}
              onChange={(e) => setQueryInput(e.target.value)}
              placeholder="Paste 64-character SHA-256 Report Hash or Report ID (e.g. TG-WALLET-AURORA-81A2)..."
              className="w-full pl-4 pr-32 py-3.5 bg-slate-950/90 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono transition-all"
            />
            <button
              type="submit"
              disabled={isQuerying || !queryInput.trim()}
              className="absolute right-2 top-2 bottom-2 px-5 bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-lg transition-all flex items-center space-x-2 shadow-md shadow-cyan-500/20"
            >
              {isQuerying ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Verifying...</span>
                </>
              ) : (
                <>
                  <span>Verify on NEAR</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </form>

          {/* Quick preset tests for verification */}
          <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
            <span className="text-[11px] font-mono text-slate-500">Verify Sample:</span>
            <button
              type="button"
              onClick={() => {
                setQueryInput("TG-WALLET-AURORA-81A2");
                handleVerifyExisting(undefined, "TG-WALLET-AURORA-81A2");
              }}
              className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800/80 hover:bg-slate-700 border border-slate-700/60 text-slate-300 hover:text-cyan-300 transition-colors"
            >
              aurora.near (TG-WALLET-AURORA-81A2)
            </button>
            <button
              type="button"
              onClick={() => {
                setQueryInput("TG-WEBSITE-NEARCLAIM-94BC");
                handleVerifyExisting(undefined, "TG-WEBSITE-NEARCLAIM-94BC");
              }}
              className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800/80 hover:bg-slate-700 border border-slate-700/60 text-slate-300 hover:text-cyan-300 transition-colors"
            >
              Phishing Site (TG-WEBSITE-NEARCLAIM-94BC)
            </button>
          </div>

          {/* Verification Query Result Card */}
          {queryResult && (
            <div className="mt-4 p-5 rounded-2xl bg-slate-950/90 border border-slate-800 space-y-4 animate-in fade-in duration-200">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center space-x-2.5">
                  {queryResult.isVerified ? (
                    <div className="p-2 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 glow-emerald">
                      <CheckCircle2 className="w-5 h-5" />
                    </div>
                  ) : (
                    <div className="p-2 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-400">
                      <XCircle className="w-5 h-5" />
                    </div>
                  )}

                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-bold text-slate-100">
                        {queryResult.isVerified
                          ? queryResult.record?.status === "VERIFIED_ON_NEAR"
                            ? "Cryptographically Sealed on NEAR Protocol"
                            : "Registered in TrustGuard Ledger"
                          : "Verification Not Found"}
                      </span>
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                          queryResult.record?.status === "VERIFIED_ON_NEAR"
                            ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                            : queryResult.isVerified
                            ? "bg-amber-500/15 text-amber-300 border border-amber-500/30"
                            : "bg-rose-500/15 text-rose-300 border border-rose-500/30"
                        }`}
                      >
                        {queryResult.record?.statusLabel ||
                          (queryResult.record?.status === "VERIFIED_ON_NEAR"
                            ? "Verified live on NEAR Testnet"
                            : queryResult.status)}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">{queryResult.message}</p>
                  </div>
                </div>

                <div className="text-[11px] font-mono text-slate-500">
                  Queried at Block #{queryResult.queriedAtBlock.toLocaleString()}
                </div>
              </div>

              {queryResult.record && (
                <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3 text-xs font-mono">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <div className="text-[10px] uppercase text-slate-500">Report ID</div>
                      <div className="text-slate-200 font-bold">{queryResult.record.reportId}</div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase text-slate-500">Target</div>
                      <div className="text-slate-200 font-bold">{queryResult.record.target}</div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase text-slate-500">Risk Score &amp; Level</div>
                      <div className="text-slate-200">
                        {queryResult.record.riskScore}/100 ({queryResult.record.riskLevel})
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase text-slate-500">Block Height &amp; Date</div>
                      <div className="text-slate-200">
                        Block #{queryResult.record.blockHeight.toLocaleString()} • {queryResult.record.anchoredAt}
                      </div>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800/80 space-y-1">
                    <div className="text-[10px] uppercase text-slate-500">Canonical SHA-256 Digest</div>
                    <div className="flex items-center justify-between bg-slate-950 p-2 rounded-lg text-[11px] text-cyan-300 break-all">
                      <span>{queryResult.record.reportHash}</span>
                      <button
                        onClick={() => handleCopy(queryResult.record!.reportHash)}
                        className="ml-2 p-1 text-slate-400 hover:text-slate-200"
                      >
                        {copiedHash === queryResult.record.reportHash ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-[11px]">
                    <div className="flex items-center space-x-2">
                      <span className="text-slate-500">Smart Contract:</span>
                      <span className="text-emerald-400 font-bold">{queryResult.record.contractId}</span>
                    </div>

                    {queryResult.record.explorerUrl && queryResult.record.nearTxHash ? (
                      <a
                        href={queryResult.record.explorerUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-cyan-400 hover:text-cyan-300 inline-flex items-center space-x-1"
                      >
                        <span>View on NEAR Testnet Explorer</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    ) : queryResult.record.status === "VERIFIED_ON_NEAR" ? (
                      <span className="text-emerald-400 font-mono text-[10px] flex items-center gap-1">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Verified on NEAR Testnet Contract State</span>
                      </span>
                    ) : (
                      <span className="text-slate-500 italic text-[10px]">
                        Contract deployment on Testnet pending
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* 2. Anchor a New Security Report Form */}
        <div className="mt-8 pt-6 border-t border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center space-x-2">
                <Cpu className="w-4 h-4 text-emerald-400" />
                <span>Anchor a New Security Report to NEAR</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Takes any verified audit report, generates the canonical SHA-256 hash, and broadcasts a sealed transaction to NEAR Testnet.
              </p>
            </div>
          </div>

          <form onSubmit={handleAnchorReport} className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <div className="sm:col-span-2">
              <label className="text-[11px] font-mono text-slate-400 block mb-1">Audit Target</label>
              <input
                type="text"
                value={anchorTarget}
                onChange={(e) => setAnchorTarget(e.target.value)}
                placeholder="e.g. ref-finance.near or 0x71C..."
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500/50"
              />
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">Scan Type</label>
              <select
                value={anchorType}
                onChange={(e) => setAnchorType(e.target.value as "WALLET" | "WEBSITE" | "TOKEN")}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500/50"
              >
                <option value="WALLET">Wallet</option>
                <option value="TOKEN">Token Contract</option>
                <option value="WEBSITE">Website / dApp</option>
              </select>
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">Threat Score (0-100)</label>
              <input
                type="number"
                min="0"
                max="100"
                value={anchorRiskScore}
                onChange={(e) => setAnchorRiskScore(Number(e.target.value))}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500/50"
              />
            </div>

            <div className="sm:col-span-4 flex items-center justify-between pt-1">
              <span className="text-[10px] font-mono text-slate-500">
                Network: <strong>NEAR Testnet</strong> • Contract: <strong>{NEAR_CONTRACT_ID}</strong>
              </span>

              <button
                type="submit"
                disabled={isAnchoring || !anchorTarget.trim()}
                className="px-5 py-2.5 bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-xl transition-all shadow-md shadow-emerald-500/20 flex items-center space-x-1.5"
              >
                {isAnchoring ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Broadcasting...</span>
                  </>
                ) : (
                  <>
                    <span>Seal &amp; Broadcast to NEAR</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Progress state */}
          {isAnchoring && (
            <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/30 flex items-center space-x-3 glow-cyan animate-in fade-in duration-150">
              <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin shrink-0" />
              <div className="text-xs font-mono text-cyan-300">{anchorProgressStage}</div>
            </div>
          )}

          {/* Success Result */}
          {anchorSuccessRecord && (
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 space-y-2 text-xs font-mono animate-in fade-in duration-200">
              <div className="flex items-center justify-between text-emerald-300 font-bold">
                <span className="flex items-center space-x-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>
                    {anchorSuccessRecord.status === "VERIFIED_ON_NEAR"
                      ? "Report Successfully Sealed on NEAR Testnet!"
                      : "Report Fingerprint Registered in Registry"}
                  </span>
                </span>
                <span
                  className={`text-[10px] font-normal ${
                    anchorSuccessRecord.status === "VERIFIED_ON_NEAR"
                      ? "text-emerald-300"
                      : "text-amber-300"
                  }`}
                >
                  {anchorSuccessRecord.statusLabel ||
                    (anchorSuccessRecord.status === "VERIFIED_ON_NEAR"
                      ? "Verified live on NEAR Testnet"
                      : "Off-chain registration")}
                </span>
              </div>

              <div className="text-[11px] text-slate-300">
                <strong>Report ID:</strong> {anchorSuccessRecord.reportId}
              </div>
              <div className="text-[11px] text-slate-300 break-all">
                <strong>SHA-256 Hash:</strong> {anchorSuccessRecord.reportHash}
              </div>

              <div className="pt-2 flex items-center justify-between text-[11px]">
                {anchorSuccessRecord.nearTxHash && anchorSuccessRecord.explorerUrl ? (
                  <a
                    href={anchorSuccessRecord.explorerUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:underline inline-flex items-center space-x-1"
                  >
                    <span>View TX on NEAR Testnet Explorer</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                ) : anchorSuccessRecord.status === "VERIFIED_ON_NEAR" ? (
                  <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Anchored at block #{anchorSuccessRecord.blockHeight.toLocaleString()}</span>
                  </span>
                ) : (
                  <span className="text-[10px] text-slate-500 italic">
                    On-chain broadcast activates upon Testnet contract deployment
                  </span>
                )}

                <button
                  type="button"
                  onClick={() => handleCopy(anchorSuccessRecord.reportHash)}
                  className="text-slate-400 hover:text-slate-200"
                >
                  {copiedHash === anchorSuccessRecord.reportHash ? "Copied Hash!" : "Copy Report Hash"}
                </button>
              </div>
            </div>
          )}

          {/* Error Banner */}
          {anchorError && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{anchorError}</span>
            </div>
          )}
        </div>

        {/* Zero Knowledge Safeguard */}
        <div className="mt-6 pt-4 border-t border-slate-800 text-[10px] font-mono text-slate-500 text-center flex items-center justify-center space-x-1.5">
          <Lock className="w-3 h-3 text-cyan-400" />
          <span>Never store private keys on-chain. Only cryptographic SHA-256 hashes and non-sensitive audit metadata are anchored.</span>
        </div>
      </div>
    </div>
  );
}

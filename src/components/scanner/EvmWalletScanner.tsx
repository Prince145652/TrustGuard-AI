"use client";

import React, { useState } from "react";
import {
  Shield,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Search,
  ExternalLink,
  Cpu,
  Layers,
  ArrowRight,
  Info,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Lock,
  AlertOctagon,
} from "lucide-react";
import { EvmChainId, EvmWalletScanResult } from "@/types/evm-security";
import { EVM_CHAINS } from "@/lib/evm-provider";
import { looksLikeSecret } from "@/lib/validators";
import { ScannerActionButtons } from "@/components/scanner/ScannerActionButtons";
import { ScanContext } from "@/types/ai-analyst";

interface EvmWalletScannerProps {
  onAnalyzeWithAi?: (context: ScanContext) => void;
}

export function EvmWalletScanner({ onAnalyzeWithAi }: EvmWalletScannerProps = {}) {
  const [selectedChain, setSelectedChain] = useState<EvmChainId>("ethereum");
  const [walletAddress, setWalletAddress] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState("");
  const [scanResult, setScanResult] = useState<EvmWalletScanResult | null>(null);

  // Test presets
  const presets = [
    {
      label: "Vitalik (Clean EOA)",
      address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      chain: "ethereum" as EvmChainId,
      type: "SAFE",
    },
    {
      label: "Tornado Router (Sanctioned)",
      address: "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",
      chain: "ethereum" as EvmChainId,
      type: "MALICIOUS",
    },
    {
      label: "PinkDrainer (Flagged)",
      address: "0x00000000ae347930bd1e7b0f35588b92280f9e75",
      chain: "ethereum" as EvmChainId,
      type: "MALICIOUS",
    },
    {
      label: "Binance Wallet (High Tx)",
      address: "0x28C6c06298d514Db089934071355E5743bf21d60",
      chain: "bnb" as EvmChainId,
      type: "SAFE",
    },
    {
      label: "Base Ecosystem Wallet",
      address: "0x4200000000000000000000000000000000000006",
      chain: "base" as EvmChainId,
      type: "SAFE",
    },
  ];

  const handleApplyPreset = (address: string, chain: EvmChainId) => {
    setWalletAddress(address);
    setSelectedChain(chain);
    setValidationError(null);
  };

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setValidationError(null);

    const input = walletAddress.trim();

    if (!input) {
      setValidationError("Please enter an Ethereum-compatible wallet address.");
      return;
    }

    // Defensive check: Catch accidental private key or seed phrase paste
    if (looksLikeSecret(input)) {
      setValidationError(
        "CRITICAL SECURITY ALERT: You entered what appears to be a private key or recovery seed phrase! TrustGuard never asks for secrets. Please enter a public 0x wallet address only."
      );
      return;
    }

    // Validate 0x + 40 hex chars
    if (!/^0x[a-fA-F0-9]{40}$/.test(input)) {
      setValidationError(
        "Invalid address format. EVM wallet addresses must begin with '0x' followed by 40 hexadecimal characters (42 characters in total)."
      );
      return;
    }

    setIsScanning(true);
    setScanResult(null);

    // Multi-stage progress indicator
    const stages = [
      "Validating EVM Checksum & Secret Leak Pre-Checks...",
      "Querying OFAC Sanctions & Web3 Drainer Registries...",
      `Connecting to ${EVM_CHAINS[selectedChain].name} RPC nodes for Balance & Nonce...`,
      "Analyzing Contract Bytecode & Calculating Transparent Risk Score...",
    ];

    for (let i = 0; i < stages.length; i++) {
      setScanStage(stages[i]);
      await new Promise((r) => setTimeout(r, 450));
    }

    try {
      const res = await fetch("/api/scan/evm-wallet", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: input, chain: selectedChain }),
      });

      const data = await res.json();

      if (!res.ok) {
        setValidationError(data.details?.[0] || data.error || "Failed to complete on-chain scan.");
        setIsScanning(false);
        return;
      }

      setScanResult(data);
    } catch (err: unknown) {
      setValidationError(
        err instanceof Error ? err.message : "Network error connecting to scanner API."
      );
    } finally {
      setIsScanning(false);
    }
  };

  // Helper for risk color styling
  const getRiskStyle = (score: number, level: string) => {
    if (level === "UNKNOWN") {
      return {
        badge: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
        bar: "bg-zinc-500",
        text: "text-zinc-400",
        border: "border-zinc-800",
        glow: "",
      };
    }
    if (score < 15) {
      return {
        badge: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
        bar: "bg-emerald-500",
        text: "text-emerald-400",
        border: "border-emerald-500/40",
        glow: "shadow-[0_0_20px_rgba(16,185,129,0.15)]",
      };
    }
    if (score < 35) {
      return {
        badge: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
        bar: "bg-cyan-500",
        text: "text-cyan-400",
        border: "border-cyan-500/40",
        glow: "shadow-[0_0_20px_rgba(6,182,212,0.15)]",
      };
    }
    if (score < 65) {
      return {
        badge: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
        bar: "bg-yellow-500",
        text: "text-yellow-400",
        border: "border-yellow-500/40",
        glow: "shadow-[0_0_20px_rgba(234,179,8,0.15)]",
      };
    }
    if (score < 85) {
      return {
        badge: "bg-orange-500/10 text-orange-400 border-orange-500/30",
        bar: "bg-orange-500",
        text: "text-orange-400",
        border: "border-orange-500/40",
        glow: "shadow-[0_0_20px_rgba(249,115,22,0.15)]",
      };
    }
    return {
      badge: "bg-rose-500/10 text-rose-400 border-rose-500/30",
      bar: "bg-rose-500",
      text: "text-rose-400",
      border: "border-rose-500/40",
      glow: "shadow-[0_0_25px_rgba(244,63,94,0.25)]",
    };
  };

  return (
    <div className="space-y-6">
      {/* Scanner Card */}
      <div className="rounded-2xl border border-slate-800/80 bg-gradient-to-b from-slate-900/90 via-slate-900/60 to-slate-950/90 p-5 sm:p-7 shadow-2xl backdrop-blur-xl relative overflow-hidden">
        {/* Ambient Top Glow */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400">
                EVM Security Engine
              </span>
              <span className="text-slate-600">•</span>
              <span className="text-xs font-mono text-cyan-400">
                Real-Time RPC &amp; Threat Intelligence
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-extrabold text-slate-100 mt-1 flex items-center space-x-2.5">
              <Shield className="w-6 h-6 text-emerald-400" />
              <span>EVM Wallet Security Scanner</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Inspect any Ethereum, Base, or BNB Chain wallet address for drainer signatures, OFAC sanctions, contract bytecode, and on-chain balance.
            </p>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400 bg-slate-950/80 px-3 py-1.5 rounded-xl border border-slate-800 self-start sm:self-auto">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Secret Protection: Public Data Only</span>
          </div>
        </div>

        {/* 1. Blockchain Selection */}
        <div className="mt-5 space-y-2">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-2">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>1. Select Blockchain Network</span>
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {(["ethereum", "base", "bnb"] as EvmChainId[]).map((cId) => {
              const chain = EVM_CHAINS[cId];
              const isSelected = selectedChain === cId;
              return (
                <button
                  key={cId}
                  type="button"
                  onClick={() => {
                    setSelectedChain(cId);
                    setScanResult(null);
                  }}
                  className={`p-3 rounded-xl border text-left transition-all flex items-center justify-between group ${
                    isSelected
                      ? "border-emerald-500/50 bg-emerald-500/15 text-emerald-300 shadow-[0_0_15px_rgba(16,185,129,0.15)]"
                      : "border-slate-800 bg-slate-950/70 text-slate-400 hover:text-slate-200 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center space-x-2.5">
                    <span
                      className={`w-2.5 h-2.5 rounded-full ${
                        cId === "ethereum"
                          ? "bg-emerald-400"
                          : cId === "base"
                          ? "bg-cyan-400"
                          : "bg-amber-400"
                      }`}
                    />
                    <div>
                      <div className="text-xs font-bold text-slate-100">{chain.name}</div>
                      <div className="text-[10px] font-mono text-slate-400">
                        Chain ID: {chain.chainId} • {chain.symbol}
                      </div>
                    </div>
                  </div>
                  {isSelected && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
                </button>
              );
            })}
          </div>
        </div>

        {/* 2. Wallet Input & Form */}
        <form onSubmit={handleScan} className="mt-5 space-y-3">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-2">
            <Search className="w-3.5 h-3.5 text-emerald-400" />
            <span>2. Enter Ethereum-Compatible Address</span>
          </label>

          <div className="relative">
            <input
              type="text"
              value={walletAddress}
              onChange={(e) => {
                setWalletAddress(e.target.value);
                setValidationError(null);
              }}
              placeholder="e.g. 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
              className="w-full pl-4 pr-32 py-3.5 bg-slate-950/90 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono transition-all"
            />
            <button
              type="submit"
              disabled={isScanning || !walletAddress.trim()}
              className="absolute right-2 top-2 bottom-2 px-5 bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-lg transition-all flex items-center space-x-2 shadow-lg shadow-emerald-500/20"
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Auditing...</span>
                </>
              ) : (
                <>
                  <span>Audit Wallet</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>

          {/* Preset Buttons for Immediate Testing */}
          <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
            <span className="text-[11px] font-mono text-slate-500">Test Cases:</span>
            {presets.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleApplyPreset(p.address, p.chain)}
                className={`px-2 py-0.5 rounded text-[11px] font-mono border transition-all ${
                  p.type === "MALICIOUS"
                    ? "bg-rose-500/10 border-rose-500/30 text-rose-300 hover:bg-rose-500/20"
                    : "bg-slate-800/80 border-slate-700/60 text-slate-300 hover:text-cyan-300"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* Validation Error Message */}
          {validationError && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start space-x-2 animate-in fade-in duration-150">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{validationError}</span>
            </div>
          )}
        </form>

        {/* 3. Loading Indicator */}
        {isScanning && (
          <div className="mt-6 p-6 rounded-2xl bg-slate-950/80 border border-cyan-500/30 flex flex-col items-center justify-center space-y-3 glow-cyan animate-in fade-in duration-200">
            <div className="relative">
              <div className="w-12 h-12 rounded-full border-2 border-cyan-500/20 border-t-cyan-400 animate-spin" />
              <Cpu className="w-5 h-5 text-cyan-400 absolute inset-0 m-auto" />
            </div>
            <div className="text-center space-y-1">
              <div className="text-xs font-mono text-cyan-300 font-semibold">{scanStage}</div>
              <div className="text-[11px] text-slate-500">
                Correlating real RPC block headers with threat registries
              </div>
            </div>
          </div>
        )}

        {/* 4. Complete Audit Report Results */}
        {scanResult && !isScanning && (
          <div className="mt-6 space-y-6 animate-in fade-in duration-300">
            {/* Top Score Banner */}
            {(() => {
              const styles = getRiskStyle(scanResult.riskScore, scanResult.riskLevel);
              return (
                <div
                  className={`p-6 rounded-2xl border ${styles.border} bg-slate-950/80 ${styles.glow} space-y-4`}
                >
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    <div className="space-y-1.5">
                      <div className="flex items-center space-x-2">
                        <span className="text-[11px] font-mono uppercase text-slate-400">
                          Audited Address ({scanResult.chainName}):
                        </span>
                        <a
                          href={`${EVM_CHAINS[scanResult.chain].explorerUrl}/address/${scanResult.address}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs font-mono font-bold text-slate-100 hover:text-cyan-300 inline-flex items-center space-x-1"
                        >
                          <span>{scanResult.address}</span>
                          <ExternalLink className="w-3 h-3 text-cyan-400" />
                        </a>
                      </div>

                      <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
                          {scanResult.accountType}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
                          Balance:{" "}
                          {scanResult.balance.status === "CONFIRMED"
                            ? `${scanResult.balance.formatted} ${scanResult.balance.symbol}`
                            : "Unknown (RPC Timeout)"}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
                          Lifetime Txs:{" "}
                          {scanResult.transactionCount.status === "CONFIRMED" &&
                          scanResult.transactionCount.nonce >= 0
                            ? scanResult.transactionCount.nonce
                            : "Unknown"}
                        </span>
                      </div>
                    </div>

                    {/* Risk Score Gauge */}
                    <div className="flex items-center space-x-4 bg-slate-900/90 p-4 rounded-xl border border-slate-800 shrink-0">
                      <div className="text-right">
                        <div className="text-[10px] font-mono uppercase text-slate-400">
                          Risk Score
                        </div>
                        <div className={`text-3xl font-extrabold font-mono ${styles.text}`}>
                          {scanResult.riskScore}
                          <span className="text-xs text-slate-400">/100</span>
                        </div>
                      </div>
                      <div
                        className={`px-3 py-1.5 rounded-lg text-xs font-bold font-mono border ${styles.badge}`}
                      >
                        {scanResult.riskLevel}
                      </div>
                    </div>
                  </div>

                  {/* Progress Bar */}
                  <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden border border-slate-800">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${styles.bar}`}
                      style={{ width: `${Math.max(scanResult.riskScore, 5)}%` }}
                    />
                  </div>
                </div>
              );
            })()}

            {/* Detected Threats (If Any) */}
            {scanResult.threats.length > 0 ? (
              <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 space-y-2">
                <div className="flex items-center space-x-2 text-rose-300 font-bold text-xs uppercase font-mono">
                  <AlertOctagon className="w-4 h-4 text-rose-400" />
                  <span>Active Threats Identified ({scanResult.threats.length})</span>
                </div>
                <ul className="space-y-1.5 pl-5 list-disc text-xs text-rose-200">
                  {scanResult.threats.map((t, idx) => (
                    <li key={idx} className="leading-relaxed">
                      {t}
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-300 flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>
                  No direct matches in threat intelligence drainer or sanctions registries.
                </span>
              </div>
            )}

            {/* Evidence Breakdown Grid */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                <span>Transparent Evidence ({scanResult.evidence.length} Parameters)</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {scanResult.evidence.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start space-x-3"
                  >
                    <div className="mt-0.5 shrink-0">
                      {item.status === "SAFE" ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : item.status === "WARNING" ? (
                        <AlertTriangle className="w-4 h-4 text-yellow-400" />
                      ) : item.status === "CRITICAL" ? (
                        <XCircle className="w-4 h-4 text-rose-400" />
                      ) : (
                        <HelpCircle className="w-4 h-4 text-zinc-400" />
                      )}
                    </div>
                    <div className="space-y-0.5">
                      <div className="text-[10px] font-mono uppercase text-slate-400">
                        {item.category}
                      </div>
                      <p className="text-xs text-slate-200 leading-snug">{item.finding}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommended Actions */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <h4 className="text-xs font-semibold text-slate-200 uppercase font-mono flex items-center space-x-2">
                <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                <span>Recommended Actions:</span>
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-300 pl-4 list-disc">
                {scanResult.recommendations.map((rec, idx) => (
                  <li key={idx} className="leading-relaxed">
                    {rec}
                  </li>
                ))}
              </ul>
            </div>

            {/* Action Buttons: AI Analyst & NEAR Registry */}
            <ScannerActionButtons
              report={{
                target: scanResult.address,
                scanType: "wallet",
                chain: scanResult.chainName,
                riskScore: scanResult.riskScore,
                riskLevel: scanResult.riskLevel,
                threats: scanResult.threats,
                evidence: scanResult.evidence,
                recommendations: scanResult.recommendations,
              }}
              onAnalyzeWithAi={onAnalyzeWithAi}
            />

            {/* Mandatory Disclaimer */}
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 text-[11px] text-slate-400 leading-relaxed flex items-start space-x-2">
              <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <span>{scanResult.disclaimer}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

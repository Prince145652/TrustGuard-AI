"use client";

import React, { useState } from "react";
import {
  Coins,
  Shield,
  AlertTriangle,
  RefreshCw,
  Search,
  ExternalLink,
  Lock,
  CheckCircle2,
  XCircle,
  Info,
  Layers,
  ArrowRight,
  FileCode2,
} from "lucide-react";
import { EvmChainId } from "@/types/evm-security";
import { EVM_CHAINS } from "@/lib/evm-provider";
import { TokenSecurityScanResult, TokenRiskLevel } from "@/types/token-security";
import { looksLikeSecret } from "@/lib/validators";
import { ScannerActionButtons } from "@/components/scanner/ScannerActionButtons";
import { ScanContext } from "@/types/ai-analyst";

interface TokenSecurityScannerProps {
  onAnalyzeWithAi?: (context: ScanContext) => void;
}

export function TokenSecurityScanner({ onAnalyzeWithAi }: TokenSecurityScannerProps = {}) {
  const [selectedChain, setSelectedChain] = useState<EvmChainId>("ethereum");
  const [contractInput, setContractInput] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState("");
  const [scanResult, setScanResult] = useState<TokenSecurityScanResult | null>(null);

  // Test Presets
  const presets = [
    {
      label: "Tether (USDT - Ethereum)",
      address: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
      chain: "ethereum" as EvmChainId,
      type: "SAFE",
    },
    {
      label: "Wrapped BNB (WBNB - BSC)",
      address: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
      chain: "bnb" as EvmChainId,
      type: "SAFE",
    },
    {
      label: "USD Base Coin (Base)",
      address: "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA",
      chain: "base" as EvmChainId,
      type: "SAFE",
    },
    {
      label: "Personal EOA Wallet (Rejection Test)",
      address: "0x000000000000000000000000000000000000dEaD",
      chain: "ethereum" as EvmChainId,
      type: "REJECT",
    },
  ];

  const handleApplyPreset = (address: string, chain: EvmChainId) => {
    setContractInput(address);
    setSelectedChain(chain);
    setValidationError(null);
  };

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setValidationError(null);

    const input = contractInput.trim();

    if (!input) {
      setValidationError("Please enter an ERC-20 token contract address.");
      return;
    }

    // Defensive zero-knowledge check
    if (looksLikeSecret(input)) {
      setValidationError(
        "CRITICAL SECURITY ALERT: You entered what appears to be a private key or recovery seed phrase! TrustGuard never asks for secrets. Please enter a public token contract address only."
      );
      return;
    }

    // Format validation
    if (!/^0x[a-fA-F0-9]{40}$/.test(input)) {
      setValidationError(
        "Invalid contract address format. Contract addresses must begin with '0x' followed by 40 hexadecimal characters (42 characters in total)."
      );
      return;
    }

    setIsScanning(true);
    setScanResult(null);

    // Multi-phase progress indicator
    const stages = [
      `Connecting to ${EVM_CHAINS[selectedChain].name} RPC provider & verifying bytecode...`,
      "Reading on-chain ERC-20 standard metadata (name, symbol, supply)...",
      "Simulating live DEX liquidity, buy/sell taxes & honeypot traps...",
      "Auditing administrator privileges, blacklist & proxy slots...",
    ];

    for (let i = 0; i < stages.length; i++) {
      setScanStage(stages[i]);
      await new Promise((r) => setTimeout(r, 450));
    }

    try {
      const res = await fetch("/api/scan/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: input, chain: selectedChain }),
      });

      const data = await res.json();

      if (!res.ok) {
        setValidationError(data.details?.[0] || data.error || "Failed to analyze token contract.");
        setIsScanning(false);
        return;
      }

      setScanResult(data);
    } catch (err: unknown) {
      setValidationError(
        err instanceof Error ? err.message : "Network error connecting to token security API."
      );
    } finally {
      setIsScanning(false);
    }
  };

  // Helper for risk color styling
  const getRiskStyle = (score: number, level: TokenRiskLevel) => {
    if (level === "UNKNOWN") {
      return {
        badge: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
        bar: "bg-zinc-500",
        text: "text-zinc-400",
        border: "border-zinc-800",
        glow: "",
      };
    }
    if (score < 20) {
      return {
        badge: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
        bar: "bg-emerald-500",
        text: "text-emerald-400",
        border: "border-emerald-500/40",
        glow: "shadow-[0_0_20px_rgba(16,185,129,0.15)]",
      };
    }
    if (score < 40) {
      return {
        badge: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
        bar: "bg-cyan-500",
        text: "text-cyan-400",
        border: "border-cyan-500/40",
        glow: "shadow-[0_0_20px_rgba(6,182,212,0.15)]",
      };
    }
    if (score < 75) {
      return {
        badge: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
        bar: "bg-yellow-500",
        text: "text-yellow-400",
        border: "border-yellow-500/40",
        glow: "shadow-[0_0_20px_rgba(234,179,8,0.15)]",
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
        {/* Ambient Glow */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />

        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400">
                Multi-Chain Token Auditor
              </span>
              <span className="text-slate-600">•</span>
              <span className="text-xs font-mono text-cyan-400">
                Honeypot, Mint &amp; Tax Analyzer
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-extrabold text-slate-100 mt-1 flex items-center space-x-2.5">
              <Coins className="w-6 h-6 text-emerald-400" />
              <span>Token &amp; Smart Contract Security Scanner</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Inspect ERC-20 token contracts for honeypot traps, hidden buy/sell taxes, blacklist functions, unlimited minting rights, and upgradeable proxies.
            </p>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400 bg-slate-950/80 px-3 py-1.5 rounded-xl border border-slate-800 self-start sm:self-auto">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Read-Only Simulation: Zero Risk</span>
          </div>
        </div>

        {/* 1. Blockchain Selection */}
        <div className="mt-5 space-y-2">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-2">
            <Layers className="w-3.5 h-3.5 text-emerald-400" />
            <span>1. Select Network</span>
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

        {/* 2. Contract Address Form */}
        <form onSubmit={handleScan} className="mt-5 space-y-3">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-2">
            <Search className="w-3.5 h-3.5 text-cyan-400" />
            <span>2. Enter Token Contract Address</span>
          </label>

          <div className="relative">
            <input
              type="text"
              value={contractInput}
              onChange={(e) => {
                setContractInput(e.target.value);
                setValidationError(null);
              }}
              placeholder="e.g. 0xdAC17F958D2ee523a2206206994597C13D831ec7"
              className="w-full pl-4 pr-32 py-3.5 bg-slate-950/90 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500/60 font-mono transition-all"
            />
            <button
              type="submit"
              disabled={isScanning || !contractInput.trim()}
              className="absolute right-2 top-2 bottom-2 px-5 bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-lg transition-all flex items-center space-x-2 shadow-lg shadow-emerald-500/20"
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Auditing...</span>
                </>
              ) : (
                <>
                  <span>Audit Token</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>

          {/* Test Presets */}
          <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
            <span className="text-[11px] font-mono text-slate-500">Test Cases:</span>
            {presets.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleApplyPreset(p.address, p.chain)}
                className={`px-2 py-0.5 rounded text-[11px] font-mono border transition-all ${
                  p.type === "REJECT"
                    ? "bg-purple-500/10 border-purple-500/30 text-purple-300 hover:bg-purple-500/20"
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

        {/* Loading Indicator */}
        {isScanning && (
          <div className="mt-6 p-6 rounded-2xl bg-slate-950/80 border border-emerald-500/30 flex flex-col items-center justify-center space-y-3 glow-emerald animate-in fade-in duration-200">
            <div className="relative">
              <div className="w-12 h-12 rounded-full border-2 border-emerald-500/20 border-t-emerald-400 animate-spin" />
              <Coins className="w-5 h-5 text-emerald-400 absolute inset-0 m-auto" />
            </div>
            <div className="text-center space-y-1">
              <div className="text-xs font-mono text-emerald-300 font-semibold">{scanStage}</div>
              <div className="text-[11px] text-slate-500">
                Decompiling bytecode slots • Simulating DEX honeypot tax
              </div>
            </div>
          </div>
        )}

        {/* Complete Token Security Report Results */}
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
                          Audited Token ({scanResult.chainName}):
                        </span>
                        <a
                          href={`${EVM_CHAINS[scanResult.chain].explorerUrl}/token/${scanResult.address}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs font-mono font-bold text-slate-100 hover:text-cyan-300 inline-flex items-center space-x-1"
                        >
                          <span>{scanResult.address}</span>
                          <ExternalLink className="w-3 h-3 text-cyan-400" />
                        </a>
                      </div>

                      <div className="flex items-center space-x-2">
                        <span className="text-lg font-extrabold text-slate-100">
                          {scanResult.tokenName}
                        </span>
                        <span className="text-sm font-mono text-cyan-400">
                          ({scanResult.tokenSymbol})
                        </span>
                      </div>

                      <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
                          Decimals: {scanResult.decimals}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
                          Total Supply: {scanResult.formattedSupply}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold ${
                            scanResult.verdict === "HONEYPOT_MALICIOUS"
                              ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                              : scanResult.verdict === "HIGH_RISK"
                              ? "bg-orange-500/20 text-orange-300 border border-orange-500/40"
                              : scanResult.verdict === "STANDARD_SAFE"
                              ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                              : "bg-slate-800 text-slate-300"
                          }`}
                        >
                          Verdict: {scanResult.verdict}
                        </span>
                      </div>

                      <p className="text-xs text-slate-300 max-w-2xl pt-1">
                        {scanResult.summary}
                      </p>
                    </div>

                    {/* Risk Score Gauge */}
                    <div className="flex items-center space-x-4 bg-slate-900/90 p-4 rounded-xl border border-slate-800 shrink-0">
                      <div className="text-right">
                        <div className="text-[10px] font-mono uppercase text-slate-400">
                          Threat Score
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

            {/* 4 Feature Cards Matrix */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Card 1: Honeypot */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1">
                <div className="text-[10px] font-mono uppercase text-slate-400">Honeypot Status</div>
                <div className="text-sm font-bold flex items-center space-x-1.5">
                  {scanResult.isHoneypot === true ? (
                    <span className="text-rose-400 flex items-center space-x-1">
                      <XCircle className="w-4 h-4" />
                      <span>Honeypot Trap Detected</span>
                    </span>
                  ) : scanResult.isHoneypot === false ? (
                    <span className="text-emerald-400 flex items-center space-x-1">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>No Honeypot Trap</span>
                    </span>
                  ) : (
                    <span className="text-zinc-400">Unknown (Simulation N/A)</span>
                  )}
                </div>
                <div className="text-[11px] text-slate-500">
                  Cannot Sell All: {String(scanResult.cannotSellAll)}
                </div>
              </div>

              {/* Card 2: Trading Taxes */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1">
                <div className="text-[10px] font-mono uppercase text-slate-400">Trading Taxes</div>
                <div className="text-sm font-bold font-mono text-slate-200">
                  Buy: {scanResult.buyTax !== "UNKNOWN" ? `${scanResult.buyTax}%` : "Unknown"} • Sell:{" "}
                  {scanResult.sellTax !== "UNKNOWN" ? `${scanResult.sellTax}%` : "Unknown"}
                </div>
                <div className="text-[11px] text-slate-500">
                  {typeof scanResult.sellTax === "number" && scanResult.sellTax > 10
                    ? "Warning: Excessive Tax"
                    : "Standard Fee Range"}
                </div>
              </div>

              {/* Card 3: Source Code */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1">
                <div className="text-[10px] font-mono uppercase text-slate-400">Contract Verification</div>
                <div className="text-sm font-bold text-slate-200 flex items-center space-x-1.5">
                  <FileCode2 className="w-4 h-4 text-cyan-400" />
                  <span>{scanResult.isOpenSource}</span>
                </div>
                <div className="text-[11px] text-slate-500">
                  Proxy Architecture: {String(scanResult.isProxy)}
                </div>
              </div>

              {/* Card 4: Privileges */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1">
                <div className="text-[10px] font-mono uppercase text-slate-400">Admin Privileges</div>
                <div className="text-xs font-mono text-slate-200">
                  Mint: {String(scanResult.canMint)} • Blacklist: {String(scanResult.hasBlacklist)}
                </div>
                <div className="text-[11px] text-slate-500">
                  Ownership Renounced: {String(scanResult.isOwnershipRenounced)}
                </div>
              </div>
            </div>

            {/* Security Indicators & Why Suspicious */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                <span>Security Indicators &amp; Threat Breakdown ({scanResult.indicators.length} Tests)</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {scanResult.indicators.map((ind) => (
                  <div
                    key={ind.id}
                    className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start space-x-3"
                  >
                    <div className="mt-0.5 shrink-0">
                      {ind.detected ? (
                        ind.severity === "CRITICAL" ? (
                          <XCircle className="w-4 h-4 text-rose-400" />
                        ) : ind.severity === "HIGH" ? (
                          <AlertTriangle className="w-4 h-4 text-orange-400" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-yellow-400" />
                        )
                      ) : (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      )}
                    </div>
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-semibold text-slate-200">{ind.name}</span>
                        {ind.detected && (
                          <span className="text-[9px] font-mono uppercase px-1 py-0.2 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                            {ind.severity}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-300 leading-snug">{ind.description}</p>
                      <div className="text-[11px] text-slate-400 italic bg-slate-900/60 p-2 rounded-lg border border-slate-800/80">
                        <strong className="text-slate-300 not-italic">Risk Context:</strong> {ind.whySuspicious}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommended Actions */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <h4 className="text-xs font-semibold text-slate-200 uppercase font-mono flex items-center space-x-2">
                <Shield className="w-3.5 h-3.5 text-emerald-400" />
                <span>Recommended Security Actions:</span>
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
                scanType: "token",
                chain: scanResult.chainName,
                riskScore: scanResult.riskScore,
                riskLevel: scanResult.riskLevel,
                threats:
                  scanResult.isHoneypot === true
                    ? ["Honeypot Detected: Token transfers or sells restricted"]
                    : [],
                evidence: scanResult.evidence,
                indicators: scanResult.indicators.map((i) => ({
                  name: i.name,
                  description: i.description,
                  detected: i.detected,
                  severity: i.severity,
                  whySuspicious: i.whySuspicious,
                })),
                recommendations: scanResult.recommendations,
              }}
              onAnalyzeWithAi={onAnalyzeWithAi}
            />

            {/* Mandatory Security Disclaimer */}
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

"use client";

import React, { useState, useEffect } from "react";
import {
  Globe,
  Shield,
  AlertTriangle,
  RefreshCw,
  Search,
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
  Info,
  Layers,
  ArrowRight,
  Database,
  Radio,
} from "lucide-react";
import { WebsiteScanResult, WebsiteRiskLevel } from "@/types/website-security";
import { looksLikeSecret } from "@/lib/validators";
import { ScannerActionButtons } from "@/components/scanner/ScannerActionButtons";
import { ScanContext } from "@/types/ai-analyst";
import { recordScanActivity } from "@/lib/activity-store";

interface WebsiteScamDetectorProps {
  onAnalyzeWithAi?: (context: ScanContext) => void;
  initialTarget?: string;
  onClearPrefill?: () => void;
}

export function WebsiteScamDetector({
  onAnalyzeWithAi,
  initialTarget,
  onClearPrefill,
}: WebsiteScamDetectorProps = {}) {
  const [urlInput, setUrlInput] = useState(initialTarget || "");
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState("");
  const [scanResult, setScanResult] = useState<WebsiteScanResult | null>(null);

  // Synchronize prefilled target during render without triggering cascading renders
  const [prevTarget, setPrevTarget] = useState<string | undefined>(initialTarget);

  if (initialTarget !== undefined && initialTarget !== prevTarget) {
    setPrevTarget(initialTarget);
    setUrlInput(initialTarget);
    setScanResult(null);
    setValidationError(null);
  } else if (initialTarget === undefined && prevTarget !== undefined) {
    setPrevTarget(undefined);
  }

  useEffect(() => {
    if (initialTarget !== undefined) {
      onClearPrefill?.();
    }
  }, [initialTarget, onClearPrefill]);

  // Test Presets
  const presets = [
    {
      label: "Official dApp (ref.finance)",
      url: "https://app.ref.finance",
      type: "SAFE",
    },
    {
      label: "NEAR Phishing Drainer",
      url: "https://claim-free-near-gift.xyz",
      type: "MALICIOUS",
    },
    {
      label: "Fake Airdrop Clone",
      url: "https://near-airdrop-claim.fake.xyz",
      type: "MALICIOUS",
    },
    {
      label: "Insecure HTTP Site",
      url: "http://uniswap-claim.top",
      type: "WARNING",
    },
    {
      label: "SSRF Test (Private IP)",
      url: "http://192.168.1.1/admin",
      type: "SSRF",
    },
    {
      label: "Dangerous Scheme Test",
      url: "javascript:alert('phish')",
      type: "DANGEROUS",
    },
  ];

  const handleApplyPreset = (url: string) => {
    setUrlInput(url);
    setValidationError(null);
  };

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setValidationError(null);

    const input = urlInput.trim();

    if (!input) {
      setValidationError("Please enter a website URL or domain name to scan.");
      return;
    }

    // Defensive zero-knowledge check
    if (looksLikeSecret(input)) {
      setValidationError(
        "CRITICAL SECURITY ALERT: You entered what appears to be a private key or recovery seed phrase! TrustGuard never asks for secrets. Please enter a public website URL only."
      );
      return;
    }

    // Fast client-side check for dangerous schemes
    if (input.toLowerCase().startsWith("javascript:") || input.toLowerCase().startsWith("data:")) {
      setValidationError("SECURITY VIOLATION: Dangerous script or data URI schemes are blocked.");
      return;
    }

    setIsScanning(true);
    setScanResult(null);

    // Multi-phase progress indicator
    const stages = [
      "Validating URL syntax & executing anti-SSRF protections...",
      "Inspecting domain structure, SSL protocol & homograph indicators...",
      "Querying Web3 anti-phishing threat feeds & URLhaus/Google registries...",
      "Computing 0-100 Phishing Probability Score & compiling report...",
    ];

    for (let i = 0; i < stages.length; i++) {
      setScanStage(stages[i]);
      await new Promise((r) => setTimeout(r, 450));
    }

    try {
      const res = await fetch("/api/scan/website", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: input }),
      });

      const data = await res.json();

      if (!res.ok) {
        setValidationError(data.details?.[0] || data.error || "Failed to scan website.");
        setIsScanning(false);
        return;
      }

      setScanResult(data);
      recordScanActivity({
        target: data.domain || input,
        scanType: "Website Scanner",
        riskScore: data.riskScore,
        riskLevel: data.riskLevel,
      });
    } catch (err: unknown) {
      setValidationError(
        err instanceof Error ? err.message : "Network error connecting to scanner API."
      );
    } finally {
      setIsScanning(false);
    }
  };

  // Helper for risk color styling
  const getRiskStyle = (score: number, level: WebsiteRiskLevel) => {
    if (level === "UNKNOWN") {
      return {
        badge: "bg-amber-500/10 text-amber-400 border-amber-500/30",
        bar: "bg-amber-500",
        text: "text-amber-400",
        border: "border-amber-500/30",
        glow: "shadow-[0_0_15px_rgba(245,158,11,0.15)]",
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
      {/* Main Scanner Container */}
      <div className="rounded-2xl border border-slate-800/80 bg-gradient-to-b from-slate-900/90 via-slate-900/60 to-slate-950/90 p-5 sm:p-7 shadow-2xl backdrop-blur-xl relative overflow-hidden">
        {/* Glow Element */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400">
                Phishing Defense System
              </span>
              <span className="text-slate-600">•</span>
              <span className="text-xs font-mono text-emerald-400">
                Heuristics &amp; Threat Intelligence
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-extrabold text-slate-100 mt-1 flex items-center space-x-2.5">
              <Globe className="w-6 h-6 text-cyan-400" />
              <span>Website Scam &amp; Phishing Detector</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Inspect dApp domains, fake token claim websites, and malicious clones for typosquatting, SSL status, and known phishing indicators.
            </p>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400 bg-slate-950/80 px-3 py-1.5 rounded-xl border border-slate-800 self-start sm:self-auto">
            <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            <span>Isolated Safe Analysis: Zero Execution</span>
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={handleScan} className="mt-5 space-y-3">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-2">
            <Search className="w-3.5 h-3.5 text-cyan-400" />
            <span>Enter Website URL or Domain Name</span>
          </label>

          <div className="relative">
            <input
              type="text"
              value={urlInput}
              onChange={(e) => {
                setUrlInput(e.target.value);
                setValidationError(null);
              }}
              placeholder="e.g. https://app.ref.finance or claim-free-near-gift.xyz"
              className="w-full pl-4 pr-32 py-3.5 bg-slate-950/90 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono transition-all"
            />
            <button
              type="submit"
              disabled={isScanning || !urlInput.trim()}
              className="absolute right-2 top-2 bottom-2 px-5 bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-lg transition-all flex items-center space-x-2 shadow-lg shadow-cyan-500/20"
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <span>Analyze Domain</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>

          {/* Quick Preset Buttons */}
          <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
            <span className="text-[11px] font-mono text-slate-500">Test Cases:</span>
            {presets.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleApplyPreset(p.url)}
                className={`px-2 py-0.5 rounded text-[11px] font-mono border transition-all ${
                  p.type === "MALICIOUS"
                    ? "bg-rose-500/10 border-rose-500/30 text-rose-300 hover:bg-rose-500/20"
                    : p.type === "WARNING"
                    ? "bg-yellow-500/10 border-yellow-500/30 text-yellow-300 hover:bg-yellow-500/20"
                    : p.type === "SSRF" || p.type === "DANGEROUS"
                    ? "bg-purple-500/10 border-purple-500/30 text-purple-300 hover:bg-purple-500/20"
                    : "bg-slate-800/80 border-slate-700/60 text-slate-300 hover:text-cyan-300"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* Validation Error Banner */}
          {validationError && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start space-x-2 animate-in fade-in duration-150">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{validationError}</span>
            </div>
          )}
        </form>

        {/* Loading Indicator */}
        {isScanning && (
          <div className="mt-6 p-6 rounded-2xl bg-slate-950/80 border border-cyan-500/30 flex flex-col items-center justify-center space-y-3 glow-cyan animate-in fade-in duration-200">
            <div className="relative">
              <div className="w-12 h-12 rounded-full border-2 border-cyan-500/20 border-t-cyan-400 animate-spin" />
              <Globe className="w-5 h-5 text-cyan-400 absolute inset-0 m-auto" />
            </div>
            <div className="text-center space-y-1">
              <div className="text-xs font-mono text-cyan-300 font-semibold">{scanStage}</div>
              <div className="text-[11px] text-slate-500">
                Static heuristic parsing • Zero network payloads downloaded
              </div>
            </div>
          </div>
        )}

        {/* Security Report Results */}
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
                          Audited Domain:
                        </span>
                        <span className="text-sm font-mono font-bold text-slate-100">
                          {scanResult.domain}
                        </span>
                      </div>

                      <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[11px] flex items-center space-x-1 border ${
                            scanResult.isHttps
                              ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                              : "bg-rose-500/10 text-rose-300 border-rose-500/30"
                          }`}
                        >
                          {scanResult.isHttps ? (
                            <>
                              <Lock className="w-3 h-3 text-emerald-400" />
                              <span>HTTPS Enforced</span>
                            </>
                          ) : (
                            <>
                              <Unlock className="w-3 h-3 text-rose-400" />
                              <span>Insecure HTTP</span>
                            </>
                          )}
                        </span>

                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px] break-all">
                          Target: {scanResult.normalizedUrl}
                        </span>

                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold ${
                            scanResult.verdict === "MALICIOUS"
                              ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                              : scanResult.verdict === "SUSPICIOUS"
                              ? "bg-yellow-500/20 text-yellow-300 border border-yellow-500/40"
                              : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
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
                          Phishing Risk
                        </div>
                        <div className={`text-3xl font-extrabold font-mono ${styles.text}`}>
                          {scanResult.riskLevel === "UNKNOWN" ? (
                            <span className="text-xl font-bold tracking-tight">INCONCLUSIVE</span>
                          ) : (
                            <>
                              {scanResult.riskScore}
                              <span className="text-xs text-slate-400">/100</span>
                            </>
                          )}
                        </div>
                      </div>
                      <div
                        className={`px-3 py-1.5 rounded-lg text-xs font-bold font-mono border ${styles.badge}`}
                      >
                        {scanResult.riskLevel === "UNKNOWN" ? "TELEMETRY TIMEOUT" : scanResult.riskLevel}
                      </div>
                    </div>
                  </div>

                  {/* Progress Bar */}
                  <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden border border-slate-800">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${styles.bar}`}
                      style={{
                        width: scanResult.riskLevel === "UNKNOWN" ? "100%" : `${Math.max(scanResult.riskScore, 5)}%`,
                        opacity: scanResult.riskLevel === "UNKNOWN" ? 0.35 : 1,
                      }}
                    />
                  </div>
                </div>
              );
            })()}

            {/* Threat Intelligence Sources Panel */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                <Database className="w-3.5 h-3.5 text-cyan-400" />
                <span>Threat Intelligence Repositories</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {scanResult.threatIntelligence.map((source, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-200">{source.source}</span>
                      <span
                        className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border ${
                          source.status === "FLAGGED"
                            ? "bg-rose-500/15 text-rose-300 border-rose-500/40 font-bold"
                            : source.status === "CLEAN"
                            ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/40"
                            : "bg-slate-800 text-slate-400 border-slate-700/60"
                        }`}
                      >
                        {source.status}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-snug">{source.details}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Heuristic Indicators Breakdown */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                <Layers className="w-3.5 h-3.5 text-emerald-400" />
                <span>Heuristic Inspection Breakdown ({scanResult.indicators.length} Tests)</span>
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
                        ) : ind.severity === "MEDIUM" ? (
                          <AlertTriangle className="w-4 h-4 text-yellow-400" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-cyan-400" />
                        )
                      ) : (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      )}
                    </div>
                    <div className="space-y-0.5">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-semibold text-slate-200">{ind.name}</span>
                        {ind.detected && (
                          <span className="text-[9px] font-mono uppercase px-1 py-0.2 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                            {ind.severity}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-300 leading-snug">{ind.description}</p>
                      <div className="text-[10px] font-mono text-slate-500 pt-0.5">
                        {ind.evidence}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommended Actions */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <h4 className="text-xs font-semibold text-slate-200 uppercase font-mono flex items-center space-x-2">
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
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
                target: scanResult.url,
                scanType: "website",
                riskScore: scanResult.riskScore,
                riskLevel: scanResult.riskLevel,
                threats:
                  scanResult.verdict === "MALICIOUS" ? [scanResult.summary] : [],
                evidence: scanResult.threatIntelligence.map((t) => ({
                  category: t.source,
                  finding: t.details,
                  status:
                    t.status === "FLAGGED"
                      ? "CRITICAL"
                      : t.status === "CLEAN"
                      ? "SAFE"
                      : "UNKNOWN",
                })),
                indicators: scanResult.indicators.map((i) => ({
                  name: i.name,
                  description: i.description,
                  detected: i.detected,
                  severity: i.severity,
                  whySuspicious: i.evidence,
                })),
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

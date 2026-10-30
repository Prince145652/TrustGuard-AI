"use client";

import React, { useState } from "react";
import { FileCheck, Shield, Download, ExternalLink, Filter, CheckCircle2, AlertTriangle, ArrowRight } from "lucide-react";
import { SAMPLE_RECENT_ACTIVITIES } from "@/lib/constants";
import { formatAddress, getRiskColor } from "@/lib/utils";

export function SecurityReportsView() {
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

  const handleDownload = (id: string, target: string) => {
    setDownloadSuccess(id);
    setTimeout(() => setDownloadSuccess(null), 2500);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-gradient-to-r from-emerald-500/10 via-cyan-500/10 to-slate-900 border border-emerald-500/20">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono font-bold uppercase text-emerald-400">
              On-Chain Audit Repository
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              Sample Reports
            </span>
          </div>
          <h2 className="text-xl sm:text-2xl font-extrabold text-slate-100 mt-1">
            NEAR Blockchain Security Reports
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-xl">
            Cryptographically sealed audit records published to the TrustGuard smart contract registry on NEAR Protocol.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-center font-mono">
            <div className="text-xs text-slate-400">Registry Contract</div>
            <div className="text-xs text-emerald-400 font-bold">trustguard-v1.near</div>
          </div>
        </div>
      </div>

      {/* Reports List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {SAMPLE_RECENT_ACTIVITIES.map((report) => {
          const risk = getRiskColor(report.riskLevel);
          return (
            <div
              key={report.id}
              className="p-5 rounded-2xl border border-slate-800 bg-gradient-to-b from-slate-900/80 to-slate-950/90 hover:border-slate-700/80 transition-all space-y-4"
            >
              <div className="flex items-start justify-between">
                <div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                    {report.scanType}
                  </span>
                  <h4 className="text-sm font-bold font-mono text-slate-100 mt-2">
                    {report.target}
                  </h4>
                  <div className="text-[11px] text-slate-500 mt-0.5">{report.date}</div>
                </div>

                <div
                  className={`px-2.5 py-1 rounded-lg text-xs font-bold font-mono border ${risk.border} ${risk.bg} ${risk.text}`}
                >
                  {report.riskLevel}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-xs text-slate-300 space-y-1">
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <span>Cryptographic Proof:</span>
                  <span className="text-emerald-400 font-semibold">{report.status}</span>
                </div>
                {report.nearTxHash && (
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="text-slate-500">TX Hash:</span>
                    <a
                      href={`https://explorer.near.org/transactions/${report.nearTxHash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:underline inline-flex items-center space-x-1"
                    >
                      <span>{formatAddress(report.nearTxHash, 14)}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between pt-1">
                <button
                  onClick={() => handleDownload(report.id, report.target)}
                  className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800/80 hover:bg-slate-700/80 text-slate-200 transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{downloadSuccess === report.id ? "Exported!" : "Export JSON"}</span>
                </button>

                <a
                  href="https://explorer.near.org"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-slate-400 hover:text-emerald-300 inline-flex items-center space-x-1"
                >
                  <span>Verify on Explorer</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </a>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

"use client";

import React, { useState } from "react";
import { FileCheck, ExternalLink, Search, ShieldCheck, ShieldAlert, Cpu } from "lucide-react";
import { RECENT_AUDITS } from "@/lib/constants";
import { formatAddress, getRiskColor } from "@/lib/utils";
import { RecentAudit, ScanType } from "@/types/security";

export function RecentAuditsTable() {
  const [filterType, setFilterType] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const filtered = RECENT_AUDITS.filter((item) => {
    const matchesType = filterType === "ALL" || item.type === filterType.toLowerCase();
    const matchesSearch =
      item.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.nearTxHash && item.nearTxHash.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesType && matchesSearch;
  });

  return (
    <div className="rounded-2xl border border-slate-800 bg-gradient-to-b from-slate-900/90 to-[#07090e] p-5 sm:p-6 shadow-xl space-y-4">
      {/* Table Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <FileCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100">NEAR Verified Audit Ledger</h3>
            <p className="text-xs text-slate-400">
              Immutable audit reports cryptographically sealed on NEAR Protocol
            </p>
          </div>
        </div>

        {/* Filter buttons */}
        <div className="flex items-center space-x-2 text-xs">
          {["ALL", "WALLET", "TOKEN", "PHISHING"].map((type) => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              className={`px-2.5 py-1 rounded-lg font-mono transition-all ${
                filterType === type
                  ? "bg-slate-800 text-cyan-300 border border-cyan-500/30"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {type}
            </button>
          ))}
        </div>
      </div>

      {/* Search Bar */}
      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
          <Search className="w-3.5 h-3.5" />
        </div>
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search by target or NEAR transaction hash..."
          className="w-full pl-9 pr-4 py-2 bg-slate-950/80 border border-slate-800/80 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500/50 font-mono"
        />
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
              <th className="pb-3 font-medium">Target</th>
              <th className="pb-3 font-medium">Type</th>
              <th className="pb-3 font-medium">Risk Score</th>
              <th className="pb-3 font-medium">NEAR TX Hash</th>
              <th className="pb-3 font-medium">Status</th>
              <th className="pb-3 font-medium text-right">Scanned</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {filtered.map((audit) => {
              const riskColors = getRiskColor(audit.riskLevel);
              return (
                <tr key={audit.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 font-medium text-slate-200">
                    <span className="text-slate-100">{audit.target}</span>
                  </td>
                  <td className="py-3">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase text-[10px]">
                      {audit.type}
                    </span>
                  </td>
                  <td className="py-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${riskColors.border} ${riskColors.bg} ${riskColors.text}`}
                    >
                      {audit.riskScore}/100 ({audit.riskLevel})
                    </span>
                  </td>
                  <td className="py-3">
                    {audit.nearTxHash ? (
                      <a
                        href={`https://explorer.near.org/transactions/${audit.nearTxHash}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-cyan-400 hover:text-cyan-300 inline-flex items-center space-x-1"
                      >
                        <span>{formatAddress(audit.nearTxHash, 12)}</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    ) : (
                      <span className="text-slate-400">Off-chain scan</span>
                    )}
                  </td>
                  <td className="py-3">
                    {audit.status === "VERIFIED_ON_NEAR" ? (
                      <span className="inline-flex items-center space-x-1 text-emerald-400 text-[11px]">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Verified</span>
                      </span>
                    ) : (
                      <span className="text-slate-400 text-[11px]">Local Only</span>
                    )}
                  </td>
                  <td className="py-3 text-right text-slate-400 text-[11px] font-sans">
                    {audit.timestamp}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

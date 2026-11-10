"use client";

import React, { useState } from "react";
import {
  FileCheck,
  Search,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  AlertOctagon,
  Info,
  Filter,
} from "lucide-react";
import { SAMPLE_RECENT_ACTIVITIES } from "@/lib/constants";
import { getRiskColor, formatAddress } from "@/lib/utils";

export function RecentActivityTable() {
  const [filterType, setFilterType] = useState<string>("ALL");
  const [searchTerm, setSearchTerm] = useState("");

  const filtered = SAMPLE_RECENT_ACTIVITIES.filter((item) => {
    const matchesFilter =
      filterType === "ALL" ||
      (filterType === "WALLET" && item.scanType === "Wallet Scanner") ||
      (filterType === "WEBSITE" && item.scanType === "Website Scanner") ||
      (filterType === "TOKEN" && item.scanType === "Token Scanner");

    const matchesSearch =
      item.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.status.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (item.nearTxHash && item.nearTxHash.toLowerCase().includes(searchTerm.toLowerCase()));

    return matchesFilter && matchesSearch;
  });

  return (
    <div className="rounded-2xl border border-slate-800/80 bg-gradient-to-b from-slate-900/80 via-slate-900/50 to-slate-950/90 p-5 sm:p-6 shadow-xl backdrop-blur-md space-y-4">
      {/* Table Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 glow-emerald">
            <FileCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-base font-bold text-slate-100">Recent Security Activity</h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                Sample Data
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Audit log of recently analyzed accounts, dApps, and token contracts.
            </p>
          </div>
        </div>

        {/* Filter buttons */}
        <div className="flex items-center space-x-1.5 p-1 bg-slate-950 rounded-xl border border-slate-800 text-xs font-mono">
          {["ALL", "WALLET", "WEBSITE", "TOKEN"].map((btn) => (
            <button
              key={btn}
              onClick={() => setFilterType(btn)}
              className={`px-2.5 py-1 rounded-lg transition-all ${
                filterType === btn
                  ? "bg-slate-800 text-emerald-300 border border-emerald-500/30"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {btn}
            </button>
          ))}
        </div>
      </div>

      {/* Search Input */}
      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
          <Search className="w-3.5 h-3.5" />
        </div>
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Filter recent activity by target, status, or transaction hash..."
          className="w-full pl-9 pr-4 py-2 bg-slate-950/70 border border-slate-800/80 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 font-mono transition-all"
        />
      </div>

      {/* Table Content */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800/80 text-slate-400 font-mono text-[11px]">
              <th className="pb-3 font-semibold">Target</th>
              <th className="pb-3 font-semibold">Scan Type</th>
              <th className="pb-3 font-semibold">Risk Level</th>
              <th className="pb-3 font-semibold">Date</th>
              <th className="pb-3 font-semibold">Status</th>
              <th className="pb-3 font-semibold text-right">Blockchain Hash</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50 font-mono">
            {filtered.map((activity) => {
              const riskColors = getRiskColor(activity.riskLevel);
              return (
                <tr
                  key={activity.id}
                  className="hover:bg-slate-800/30 transition-colors group"
                >
                  {/* Target */}
                  <td className="py-3 font-semibold text-slate-200">
                    <span className="group-hover:text-cyan-300 transition-colors">
                      {activity.target}
                    </span>
                  </td>

                  {/* Scan Type */}
                  <td className="py-3">
                    <span className="px-2 py-0.5 rounded bg-slate-800/90 text-slate-300 text-[10px] border border-slate-700/40">
                      {activity.scanType}
                    </span>
                  </td>

                  {/* Risk Level */}
                  <td className="py-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${riskColors.border} ${riskColors.bg} ${riskColors.text}`}
                    >
                      {activity.riskLevel}
                    </span>
                  </td>

                  {/* Date */}
                  <td className="py-3 text-slate-400 text-[11px] font-sans">
                    {activity.date}
                  </td>

                  {/* Status */}
                  <td className="py-3">
                    {activity.status === "Verified On-Chain" ? (
                      <span className="inline-flex items-center space-x-1 text-emerald-400 text-[11px]">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Verified On-Chain</span>
                      </span>
                    ) : activity.status === "Threat Blocked" ? (
                      <span className="inline-flex items-center space-x-1 text-rose-400 text-[11px]">
                        <AlertOctagon className="w-3.5 h-3.5" />
                        <span>Threat Blocked</span>
                      </span>
                    ) : activity.status === "High Risk" ? (
                      <span className="inline-flex items-center space-x-1 text-orange-400 text-[11px]">
                        <ShieldAlert className="w-3.5 h-3.5" />
                        <span>High Risk</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center space-x-1 text-cyan-400 text-[11px]">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Safe</span>
                      </span>
                    )}
                  </td>

                  {/* Blockchain Hash */}
                  <td className="py-3 text-right">
                    {activity.nearTxHash ? (
                      <a
                        href={`https://testnet.nearblocks.io/txns/${activity.nearTxHash}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 text-[11px] hover:underline"
                      >
                        <span>{formatAddress(activity.nearTxHash, 10)}</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    ) : (
                      <span className="text-slate-400 text-[11px]">Off-Chain</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="pt-2 text-right">
        <span className="text-[10px] font-mono text-slate-400">
          * Activity entries above are demonstration samples for UI testing.
        </span>
      </div>
    </div>
  );
}

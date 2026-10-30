"use client";

import React from "react";
import { Activity, ShieldAlert, ShieldCheck, Award, Info, Lock } from "lucide-react";
import { SAMPLE_SECURITY_STATS } from "@/lib/constants";

export function OverviewStats() {
  const cards = [
    {
      title: "Total Scans",
      value: SAMPLE_SECURITY_STATS.totalScans.toLocaleString(),
      change: "+184 in last 24h",
      icon: Activity,
      color: "cyan",
      description: "Aggregated wallet, website & token checks",
    },
    {
      title: "Threats Detected",
      value: SAMPLE_SECURITY_STATS.threatsDetected.toLocaleString(),
      change: "Drainers, Honeypots & Clones",
      icon: ShieldAlert,
      color: "rose",
      description: "Identified malicious vectors neutralized",
    },
    {
      title: "Protected Wallets",
      value: SAMPLE_SECURITY_STATS.protectedWallets.toLocaleString(),
      change: "Active NEAR & EVM accounts",
      icon: Lock,
      color: "emerald",
      description: "Accounts scanned without key exposure",
    },
    {
      title: "Security Score",
      value: `${SAMPLE_SECURITY_STATS.securityScore}%`,
      change: "System Trust Rating",
      icon: Award,
      color: "emerald",
      description: "Overall ecosystem integrity rating",
    },
  ];

  return (
    <div className="space-y-3">
      {/* Sample Data Disclaimer Badge */}
      <div className="flex items-center justify-between px-3 py-1.5 rounded-xl bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400">
        <div className="flex items-center space-x-1.5">
          <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span>
            <strong className="text-slate-200">Demonstration Mode:</strong> The metrics below reflect simulated platform telemetry for testing. Real on-chain data is pulled on demand during live scans.
          </span>
        </div>
        <span className="hidden sm:inline-block font-mono text-[10px] text-cyan-400/90 uppercase px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
          Sample Data
        </span>
      </div>

      {/* 4 Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card, idx) => {
          const Icon = card.icon;
          return (
            <div
              key={idx}
              className="relative overflow-hidden rounded-2xl bg-gradient-to-b from-slate-900/80 via-slate-900/50 to-slate-950/80 border border-slate-800/80 p-5 hover:border-slate-700/80 transition-all duration-300 group hover:-translate-y-0.5 shadow-lg backdrop-blur-md"
            >
              {/* Header row */}
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  {card.title}
                </span>
                <div
                  className={`p-2.5 rounded-xl border transition-all ${
                    card.color === "emerald"
                      ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400 group-hover:glow-emerald"
                      : card.color === "cyan"
                      ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400 group-hover:glow-cyan"
                      : "bg-rose-500/10 border-rose-500/30 text-rose-400"
                  }`}
                >
                  <Icon className="w-4 h-4" />
                </div>
              </div>

              {/* Metric Value */}
              <div className="text-2xl sm:text-3xl font-extrabold font-mono text-slate-100 tracking-tight mb-1">
                {card.value}
              </div>

              {/* Subtitle / change */}
              <div className="text-[11px] font-mono text-emerald-400 flex items-center space-x-1">
                <span>{card.change}</span>
              </div>

              <div className="text-[11px] text-slate-500 mt-2 line-clamp-1">
                {card.description}
              </div>

              {/* Ambient Glow */}
              <div className="absolute -bottom-10 -right-10 w-28 h-28 bg-gradient-to-br from-emerald-500/5 to-cyan-500/5 rounded-full blur-2xl group-hover:opacity-100 opacity-40 transition-opacity pointer-events-none" />
            </div>
          );
        })}
      </div>
    </div>
  );
}

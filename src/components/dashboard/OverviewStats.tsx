"use client";

import React, { useState } from "react";
import { Activity, ShieldAlert, Award, Info, Lock } from "lucide-react";
import { SAMPLE_SECURITY_STATS } from "@/lib/constants";
import { useRecentActivities, computeSecurityStats } from "@/lib/activity-store";

export function OverviewStats() {
  const { liveActivities, liveCount } = useRecentActivities();
  const [viewMode, setViewMode] = useState<"live" | "sample">("live");

  const effectiveViewMode = liveCount > 0 ? viewMode : "sample";
  const stats = computeSecurityStats(liveActivities, SAMPLE_SECURITY_STATS, {
    viewMode: effectiveViewMode,
  });

  const cards = [
    {
      title: "Total Scans",
      value: stats.totalScans.toLocaleString(),
      change:
        !stats.isSampleData
          ? `${stats.liveCount} live scan${stats.liveCount === 1 ? "" : "s"} recorded`
          : "+184 in last 24h",
      icon: Activity,
      color: "cyan",
      description: !stats.isSampleData
        ? "Audited in current browser session"
        : "Aggregated wallet, website & token checks",
    },
    {
      title: "Threats Detected",
      value: stats.threatsDetected.toLocaleString(),
      change:
        !stats.isSampleData
          ? stats.liveThreats > 0
            ? `${stats.liveThreats} flagged in session`
            : "0 threats in session"
          : "Drainers, Honeypots & Clones",
      icon: ShieldAlert,
      color: "rose",
      description: !stats.isSampleData
        ? "Identified malicious vectors in session"
        : "Identified malicious vectors neutralized",
    },
    {
      title: "Protected Wallets",
      value: stats.protectedWallets.toLocaleString(),
      change:
        !stats.isSampleData
          ? `${stats.liveWallets} account${stats.liveWallets === 1 ? "" : "s"} audited`
          : "Active NEAR & EVM accounts",
      icon: Lock,
      color: "emerald",
      description: "Accounts scanned without key exposure",
    },
    {
      title: "Security Score",
      value: `${stats.securityScore}%`,
      change:
        !stats.isSampleData && stats.liveVerified > 0
          ? `System Trust Rating • ${stats.liveVerified} verified on NEAR`
          : "System Trust Rating",
      icon: Award,
      color: "emerald",
      description: "Overall ecosystem integrity rating",
    },
  ];

  return (
    <div className="space-y-3">
      {/* Telemetry Status / Mode Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-3 py-2 rounded-xl bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400">
        <div className="flex items-center space-x-1.5">
          <Info
            className={`w-3.5 h-3.5 shrink-0 ${
              !stats.isSampleData ? "text-emerald-400" : "text-cyan-400"
            }`}
          />
          <span>
            {!stats.isSampleData ? (
              <>
                <strong className="text-emerald-300">Live Session Active:</strong> Displaying telemetry from {stats.liveCount} genuine scan{stats.liveCount === 1 ? "" : "s"} ({stats.liveThreats} threat{stats.liveThreats === 1 ? "" : "s"}, {stats.liveVerified} anchored on NEAR).
              </>
            ) : (
              <>
                <strong className="text-slate-200">Demonstration Mode:</strong> The metrics below reflect simulated platform telemetry for testing. Run a live scan to populate genuine session telemetry.
              </>
            )}
          </span>
        </div>

        {/* Mode indicator and toggle when live scans exist */}
        <div className="flex items-center space-x-2 shrink-0">
          {liveCount > 0 ? (
            <div className="flex items-center space-x-1 p-0.5 bg-slate-950 rounded-lg border border-slate-800 font-mono text-[10px]">
              <button
                onClick={() => setViewMode("live")}
                className={`px-2 py-0.5 rounded transition-colors ${
                  viewMode === "live"
                    ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Session ({liveCount})
              </button>
              <button
                onClick={() => setViewMode("sample")}
                className={`px-2 py-0.5 rounded transition-colors ${
                  viewMode === "sample"
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Benchmark
              </button>
            </div>
          ) : (
            <span className="font-mono text-[10px] text-cyan-400/90 uppercase px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
              Sample Data
            </span>
          )}
        </div>
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
              <div
                className={`text-[11px] font-mono flex items-center space-x-1 ${
                  !stats.isSampleData ? "text-cyan-400" : "text-emerald-400"
                }`}
              >
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

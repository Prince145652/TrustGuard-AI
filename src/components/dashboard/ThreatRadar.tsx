"use client";

import React from "react";
import { Radar, AlertOctagon, Flame, ShieldAlert, CheckCircle, Zap } from "lucide-react";

export function ThreatRadar() {
  const threatCategories = [
    { name: "Wallet Drainer Scripts", count: 328, risk: "CRITICAL", percentage: 88, color: "rose" },
    { name: "Honeypot Buy/Sell Tax", count: 215, risk: "HIGH", percentage: 65, color: "orange" },
    { name: "Phishing Domain Clones", count: 184, risk: "CRITICAL", percentage: 82, color: "rose" },
    { name: "Infinite Allowance Exploits", count: 74, risk: "MEDIUM", percentage: 42, color: "yellow" },
    { name: "Fake AirDrop Contracts", count: 42, risk: "HIGH", percentage: 55, color: "orange" },
  ];

  return (
    <div className="rounded-2xl border border-slate-800 bg-gradient-to-b from-slate-900/90 to-[#07090e] p-5 sm:p-6 shadow-xl space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
            <Radar className="w-5 h-5 text-rose-400 animate-spin-slow" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100">Live Threat Radar</h3>
            <p className="text-xs text-slate-400">Real-time threat vectors detected across Web3 &amp; NEAR</p>
          </div>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center space-x-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span>SHIELD ONLINE</span>
        </span>
      </div>

      {/* Threat Bars */}
      <div className="space-y-3.5">
        {threatCategories.map((cat, idx) => (
          <div key={idx} className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300 font-medium">{cat.name}</span>
              <div className="flex items-center space-x-2">
                <span className="text-[11px] font-mono text-slate-400">{cat.count} attacks blocked</span>
                <span
                  className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border ${
                    cat.risk === "CRITICAL"
                      ? "text-rose-400 bg-rose-500/10 border-rose-500/30"
                      : cat.risk === "HIGH"
                      ? "text-orange-400 bg-orange-500/10 border-orange-500/30"
                      : "text-yellow-400 bg-yellow-500/10 border-yellow-500/30"
                  }`}
                >
                  {cat.risk}
                </span>
              </div>
            </div>

            {/* Progress Bar */}
            <div className="w-full h-2 rounded-full bg-slate-950 overflow-hidden border border-slate-800">
              <div
                className={`h-full rounded-full transition-all duration-700 ${
                  cat.risk === "CRITICAL"
                    ? "bg-gradient-to-r from-rose-500 to-rose-400"
                    : cat.risk === "HIGH"
                    ? "bg-gradient-to-r from-orange-500 to-amber-400"
                    : "bg-gradient-to-r from-yellow-500 to-emerald-400"
                }`}
                style={{ width: `${cat.percentage}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Advisory tip */}
      <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start space-x-3 text-xs text-slate-400">
        <Zap className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-slate-200">Security Rule:</strong> Always verify contract addresses before signing transactions with full access keys on NEAR Protocol. TrustGuard scans smart contract bytecode instantly.
        </p>
      </div>
    </div>
  );
}

"use client";

import React, { useState } from "react";
import { Brain, Sparkles, Send, Bot, Shield, Lightbulb, ChevronRight } from "lucide-react";

export function AiAnalystCard() {
  const [query, setQuery] = useState("");
  const [selectedTopic, setSelectedTopic] = useState<string | null>(null);

  const sampleAdvisories = [
    {
      title: "NEAR Function-Call Keys vs Full Access Keys",
      category: "Access Control",
      summary:
        "Never grant FullAccess permission to untrusted dApps. FullAccess keys allow arbitrary NEAR transfers. Legitimate dApps only request FunctionCall keys scoped to specific contract methods and spending allowances.",
    },
    {
      title: "NEP-141 Token Honeypot Mechanics",
      category: "Smart Contracts",
      summary:
        "Malicious tokens implement custom ft_transfer logic that blocks transfers when recipient is not the contract owner or applies a 99% fee. Always verify the contract WASM bytecode hash against known open-source builds.",
    },
    {
      title: "Zero-Knowledge & Safe Auditing Architecture",
      category: "Protocol Safety",
      summary:
        "TrustGuard AI operates strictly on public on-chain blockchain state and RPC endpoints. User private keys or recovery seeds are never required, requested, or transmitted.",
    },
  ];

  return (
    <div className="rounded-2xl border border-slate-800 bg-gradient-to-b from-slate-900/90 to-[#07090e] p-5 sm:p-6 shadow-xl space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Brain className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100 flex items-center space-x-2">
              <span>Gemini AI Security Analyst</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                Active Reasoning
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Autonomous Web3 threat modeling and contract vulnerability explanations
            </p>
          </div>
        </div>
      </div>

      {/* Advisory Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
        {sampleAdvisories.map((adv, idx) => (
          <div
            key={idx}
            onClick={() => setSelectedTopic(adv.title)}
            className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 hover:border-cyan-500/30 transition-all cursor-pointer group space-y-2"
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase text-cyan-400 px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
                {adv.category}
              </span>
              <Sparkles className="w-3.5 h-3.5 text-slate-400 group-hover:text-cyan-400 transition-colors" />
            </div>
            <h4 className="text-xs font-semibold text-slate-200 group-hover:text-cyan-200 transition-colors">
              {adv.title}
            </h4>
            <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-3">
              {adv.summary}
            </p>
          </div>
        ))}
      </div>

      {/* Analyst Console */}
      <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3">
        <div className="flex items-center space-x-2 text-xs font-mono text-emerald-400">
          <Bot className="w-4 h-4 text-emerald-400" />
          <span>Security Analyst Briefing:</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          {selectedTopic
            ? `Deep Dive on "${selectedTopic}": TrustGuard continuously parses NEAR contract ASTs and simulated transaction calls to detect unverified privilege escalation patterns before sign-off.`
            : "Select any security briefing above or initiate a scan to generate context-aware AI risk mitigation recommendations."}
        </p>
      </div>
    </div>
  );
}

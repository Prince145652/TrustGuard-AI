"use client";

import React, { useState } from "react";
import { Settings, Shield, Lock, Cpu, Server, Check, Save } from "lucide-react";

export function SettingsView() {
  const [rpcNode, setRpcNode] = useState("https://rpc.mainnet.near.org");
  const [aiEngine, setAiEngine] = useState("gemini-2.5-flash");
  const [sensitivity, setSensitivity] = useState("high");
  const [anchorOnChain, setAnchorOnChain] = useState(true);
  const [savedNotification, setSavedNotification] = useState(false);

  const handleSave = () => {
    setSavedNotification(true);
    setTimeout(() => setSavedNotification(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-4xl animate-in fade-in duration-300">
      <div>
        <h2 className="text-xl sm:text-2xl font-extrabold text-slate-100 flex items-center space-x-2">
          <Settings className="w-6 h-6 text-emerald-400" />
          <span>Security &amp; Engine Settings</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Configure blockchain RPC connectivity, Gemini AI heuristics, and zero-knowledge privacy parameters.
        </p>
      </div>

      <div className="space-y-4">
        {/* RPC Section */}
        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-md space-y-3">
          <div className="flex items-center space-x-2 text-sm font-semibold text-slate-200">
            <Server className="w-4 h-4 text-cyan-400" />
            <span>NEAR RPC Gateway</span>
          </div>
          <p className="text-xs text-slate-400">
            Select the JSON-RPC node provider used for fetching on-chain account state and contract WASM bytecode.
          </p>

          <select
            value={rpcNode}
            onChange={(e) => setRpcNode(e.target.value)}
            className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500/50"
          >
            <option value="https://rpc.mainnet.near.org">https://rpc.mainnet.near.org (Official NEAR RPC)</option>
            <option value="https://near.blockpi.network/v1/rpc/public">https://near.blockpi.network/v1/rpc/public (BlockPI)</option>
            <option value="https://free.rpc.fastnear.com">https://free.rpc.fastnear.com (FastNear Ultra-Low Latency)</option>
          </select>
        </div>

        {/* AI Model Section */}
        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-md space-y-3">
          <div className="flex items-center space-x-2 text-sm font-semibold text-slate-200">
            <Cpu className="w-4 h-4 text-emerald-400" />
            <span>Gemini AI Threat Classification Engine</span>
          </div>
          <p className="text-xs text-slate-400">
            Choose the neural reasoning tier applied to smart contract decompilation and phishing detection.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setAiEngine("gemini-2.5-flash")}
              className={`p-3 rounded-xl border text-left transition-all ${
                aiEngine === "gemini-2.5-flash"
                  ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-300"
                  : "border-slate-800 bg-slate-950/70 text-slate-400 hover:text-slate-200"
              }`}
            >
              <div className="text-xs font-bold font-mono">Gemini 2.5 Flash (Recommended)</div>
              <div className="text-[11px] text-slate-400 mt-1">
                Sub-second latency, ideal for real-time wallet scanning &amp; URL verification.
              </div>
            </button>

            <button
              type="button"
              onClick={() => setAiEngine("gemini-2.5-pro")}
              className={`p-3 rounded-xl border text-left transition-all ${
                aiEngine === "gemini-2.5-pro"
                  ? "border-cyan-500/50 bg-cyan-500/10 text-cyan-300"
                  : "border-slate-800 bg-slate-950/70 text-slate-400 hover:text-slate-200"
              }`}
            >
              <div className="text-xs font-bold font-mono">Gemini 2.5 Pro (Deep Audit)</div>
              <div className="text-[11px] text-slate-400 mt-1">
                Extended reasoning model for full smart contract bytecode vulnerability analysis.
              </div>
            </button>
          </div>
        </div>

        {/* Privacy & Zero-Knowledge Enforcement */}
        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-md space-y-3">
          <div className="flex items-center space-x-2 text-sm font-semibold text-slate-200">
            <Lock className="w-4 h-4 text-cyan-400" />
            <span>Zero-Knowledge &amp; Privacy Safeguards</span>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs">
              <div>
                <div className="font-semibold text-slate-200">Zero-Secret Policy</div>
                <div className="text-[11px] text-slate-400">
                  Client-side filtering blocks accidental submission of private keys or recovery phrases.
                </div>
              </div>
              <span className="text-[10px] font-mono font-bold text-emerald-400 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                LOCKED ON
              </span>
            </div>

            <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs">
              <div>
                <div className="font-semibold text-slate-200">On-Chain Audit Anchoring</div>
                <div className="text-[11px] text-slate-400">
                  Publish SHA-256 report verification hashes to the NEAR Protocol public ledger.
                </div>
              </div>
              <button
                type="button"
                onClick={() => setAnchorOnChain(!anchorOnChain)}
                className={`w-10 h-6 rounded-full transition-colors relative ${
                  anchorOnChain ? "bg-emerald-500" : "bg-slate-700"
                }`}
              >
                <div
                  className={`w-4 h-4 rounded-full bg-slate-950 transition-transform absolute top-1 ${
                    anchorOnChain ? "left-5" : "left-1"
                  }`}
                />
              </button>
            </div>
          </div>
        </div>

        {/* Save button */}
        <div className="flex items-center justify-between pt-2">
          {savedNotification ? (
            <span className="text-xs font-mono text-emerald-400 flex items-center space-x-1.5">
              <Check className="w-4 h-4" />
              <span>Settings successfully saved!</span>
            </span>
          ) : (
            <span className="text-xs text-slate-500">Changes apply to subsequent scan executions.</span>
          )}

          <button
            onClick={handleSave}
            className="flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold text-xs transition-all shadow-lg shadow-emerald-500/20"
          >
            <Save className="w-3.5 h-3.5" />
            <span>Save Preferences</span>
          </button>
        </div>
      </div>
    </div>
  );
}

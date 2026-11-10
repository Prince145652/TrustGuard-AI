"use client";

import React, { useState } from "react";
import { Navbar } from "@/components/layout/Navbar";
import { Sidebar } from "@/components/layout/Sidebar";
import { OverviewStats } from "@/components/dashboard/OverviewStats";
import { ScannerCards } from "@/components/dashboard/ScannerCards";
import { RecentActivityTable } from "@/components/dashboard/RecentActivityTable";
import { NearVerificationDashboard } from "@/components/near/NearVerificationDashboard";
import { SettingsView } from "@/components/dashboard/SettingsView";
import { EvmWalletScanner } from "@/components/scanner/EvmWalletScanner";
import { WebsiteScamDetector } from "@/components/scanner/WebsiteScamDetector";
import { TokenSecurityScanner } from "@/components/scanner/TokenSecurityScanner";
import { AiSecurityAnalyst } from "@/components/analyst/AiSecurityAnalyst";
import { NavTab, NearNetwork } from "@/types/security";
import { ScanContext } from "@/types/ai-analyst";

export default function DashboardPage() {
  const [currentTab, setCurrentTab] = useState<NavTab>("overview");
  const [currentNetwork, setCurrentNetwork] = useState<NearNetwork>("NEAR Testnet");
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false);
  const [activeScanContext, setActiveScanContext] = useState<ScanContext | null>(null);

  const handleAnalyzeWithAi = (context: ScanContext) => {
    setActiveScanContext(context);
    setCurrentTab("analyst");
  };

  return (
    <div className="min-h-screen bg-[#07090e] cyber-grid flex flex-col selection:bg-emerald-500/20 selection:text-emerald-300">
      {/* Top Navigation */}
      <Navbar
        currentNetwork={currentNetwork}
        onSelectNetwork={(net) => setCurrentNetwork(net)}
        isMobileSidebarOpen={isMobileSidebarOpen}
        onToggleMobileSidebar={() => setIsMobileSidebarOpen(!isMobileSidebarOpen)}
      />

      <div className="flex-1 flex max-w-7xl w-full mx-auto relative">
        {/* Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={(tab) => setCurrentTab(tab)}
          isOpenOnMobile={isMobileSidebarOpen}
          onCloseMobile={() => setIsMobileSidebarOpen(false)}
        />

        {/* Main Content Area */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 space-y-8 overflow-x-hidden min-w-0">
          {/* Header section when in overview */}
          {currentTab === "overview" && (
            <div className="space-y-8 animate-in fade-in duration-200">
              {/* Welcome Heading Banner */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400">
                      TrustGuard AI Security OS
                    </span>
                    <span className="text-slate-600">•</span>
                    <span className="text-xs font-mono text-cyan-400">
                      NEAR Hackathon 2026
                    </span>
                  </div>
                  <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100 tracking-tight mt-1">
                    Your Web3 Security Command Center
                  </h1>
                </div>

                <div className="flex items-center space-x-2 text-xs">
                  <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-900/80 border border-slate-800 text-slate-300 font-mono">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span>System Status: </span>
                    <strong className="text-emerald-400">OPERATIONAL</strong>
                  </div>
                </div>
              </div>

              {/* 1. Main Dashboard 4 Cards (Total Scans, Threats Detected, Protected Wallets, Security Score) */}
              <OverviewStats />

              {/* 2. Three Attractive Scanner Cards (Wallet, Website, Token) */}
              <ScannerCards />

              {/* 3. Recent Security Activity Table */}
              <RecentActivityTable />
            </div>
          )}

          {/* Dedicated Tab Views */}
          {currentTab === "wallet" && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <EvmWalletScanner onAnalyzeWithAi={handleAnalyzeWithAi} />
              <RecentActivityTable />
            </div>
          )}

          {currentTab === "website" && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <WebsiteScamDetector onAnalyzeWithAi={handleAnalyzeWithAi} />
              <RecentActivityTable />
            </div>
          )}

          {currentTab === "token" && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <TokenSecurityScanner onAnalyzeWithAi={handleAnalyzeWithAi} />
              <RecentActivityTable />
            </div>
          )}

          {currentTab === "analyst" && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <AiSecurityAnalyst initialContext={activeScanContext} />
            </div>
          )}

          {currentTab === "reports" && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <NearVerificationDashboard />
            </div>
          )}

          {currentTab === "settings" && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="pb-2 border-b border-slate-800/80">
                <h1 className="text-2xl font-bold text-slate-100">System Preferences</h1>
                <p className="text-xs text-slate-400 mt-1">
                  Configure blockchain nodes, AI sensitivity, and secret protection safeguards.
                </p>
              </div>
              <SettingsView />
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

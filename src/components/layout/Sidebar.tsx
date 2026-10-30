"use client";

import React from "react";
import {
  LayoutDashboard,
  Wallet,
  Globe,
  Coins,
  Brain,
  FileCheck2,
  Settings,
  Shield,
  Radio,
  ChevronRight,
} from "lucide-react";
import { NavTab } from "@/types/security";

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  isOpenOnMobile?: boolean;
  onCloseMobile?: () => void;
}

export function Sidebar({
  currentTab,
  onSelectTab,
  isOpenOnMobile = false,
  onCloseMobile,
}: SidebarProps) {
  const menuItems: { id: NavTab; label: string; icon: React.ElementType; badge?: string }[] = [
    { id: "overview", label: "Overview", icon: LayoutDashboard },
    { id: "wallet", label: "Wallet Scanner", icon: Wallet },
    { id: "website", label: "Website Scanner", icon: Globe },
    { id: "token", label: "Token Scanner", icon: Coins },
    { id: "analyst", label: "AI Security Analyst", icon: Brain, badge: "Gemini" },
    { id: "reports", label: "Security Reports", icon: FileCheck2, badge: "NEAR" },
    { id: "settings", label: "Settings", icon: Settings },
  ];

  const handleItemClick = (id: NavTab) => {
    onSelectTab(id);
    if (onCloseMobile) onCloseMobile();
  };

  return (
    <>
      {/* Mobile backdrop */}
      {isOpenOnMobile && (
        <div
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 md:hidden"
          onClick={onCloseMobile}
        />
      )}

      <aside
        className={`fixed md:static inset-y-0 left-0 z-40 w-64 shrink-0 flex flex-col justify-between border-r border-slate-800/80 bg-[#07090e]/95 backdrop-blur-xl p-4 transition-transform duration-300 ease-in-out md:translate-x-0 ${
          isOpenOnMobile ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        }`}
      >
        <div className="space-y-6">
          {/* Logo in sidebar */}
          <div className="flex items-center space-x-3 px-2 py-1">
            <div className="flex items-center justify-center w-9 h-9 rounded-xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 border border-emerald-500/40 text-emerald-400 glow-emerald">
              <Shield className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <div className="text-base font-bold tracking-wider text-slate-100">
                TRUSTGUARD<span className="text-cyan-400">.AI</span>
              </div>
              <div className="text-[10px] font-mono text-emerald-400 uppercase tracking-widest">
                NEAR Security Suite
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <div className="space-y-1">
            <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 mb-2 flex items-center justify-between">
              <span>Main Navigation</span>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            </div>

            <nav className="space-y-1.5">
              {menuItems.map((item) => {
                const Icon = item.icon;
                const isActive = currentTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => handleItemClick(item.id)}
                    className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all group ${
                      isActive
                        ? "bg-gradient-to-r from-emerald-500/15 via-emerald-500/10 to-cyan-500/10 text-emerald-300 border border-emerald-500/30 shadow-[0_0_15px_rgba(16,185,129,0.15)] font-semibold"
                        : "text-slate-400 hover:text-slate-100 hover:bg-slate-900/60 border border-transparent"
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      <Icon
                        className={`w-4 h-4 transition-colors ${
                          isActive
                            ? "text-emerald-400"
                            : "text-slate-400 group-hover:text-emerald-400"
                        }`}
                      />
                      <span>{item.label}</span>
                    </div>

                    <div className="flex items-center space-x-1.5">
                      {item.badge && (
                        <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                          {item.badge}
                        </span>
                      )}
                      {isActive && <ChevronRight className="w-3.5 h-3.5 text-emerald-400" />}
                    </div>
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Real-Time Defense Monitor Status */}
          <div className="p-3.5 rounded-2xl bg-gradient-to-b from-slate-900/80 to-slate-950/80 border border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-200 flex items-center space-x-1.5">
                <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
                <span>Heuristic Defense</span>
              </span>
              <span className="text-[9px] font-mono uppercase text-emerald-400 px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                Active
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Monitoring NEAR contract calls, drainer routers &amp; phishing clusters.
            </p>
          </div>
        </div>

        {/* Footer info */}
        <div className="pt-4 border-t border-slate-800/80 space-y-2">
          <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
            <span>NEAR 2026 Hackathon</span>
            <span className="text-cyan-400 font-bold">Beta v1.0</span>
          </div>
        </div>
      </aside>
    </>
  );
}

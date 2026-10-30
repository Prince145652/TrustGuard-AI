"use client";

import React, { useState } from "react";
import {
  Shield,
  Bell,
  ChevronDown,
  Globe,
  CheckCircle2,
  ExternalLink,
  Lock,
  Menu,
  X,
  AlertTriangle,
  User,
} from "lucide-react";
import { NETWORKS } from "@/lib/constants";
import { NearNetwork } from "@/types/security";

interface NavbarProps {
  currentNetwork: NearNetwork;
  onSelectNetwork: (net: NearNetwork) => void;
  onToggleMobileSidebar: () => void;
  isMobileSidebarOpen: boolean;
}

export function Navbar({
  currentNetwork,
  onSelectNetwork,
  onToggleMobileSidebar,
  isMobileSidebarOpen,
}: NavbarProps) {
  const [networkDropdownOpen, setNetworkDropdownOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);

  const notifications = [
    {
      id: "n-1",
      title: "Malicious Phishing Blocked",
      desc: "Deceptive domain claim-free-near-gift.xyz neutralized.",
      time: "10m ago",
      type: "threat",
    },
    {
      id: "n-2",
      title: "Contract Audited & Verified",
      desc: "aurora.near verified on NEAR Mainnet block #138,420,119.",
      time: "45m ago",
      type: "success",
    },
    {
      id: "n-3",
      title: "Heuristic Engine Updated",
      desc: "Gemini AI Threat model weights updated for NEP-141 honeypots.",
      time: "2h ago",
      type: "info",
    },
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-[#07090e]/90 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Left: Mobile hamburger + Brand */}
        <div className="flex items-center space-x-3">
          <button
            onClick={onToggleMobileSidebar}
            className="md:hidden p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 hover:text-emerald-400 focus:outline-none"
            aria-label="Toggle menu"
          >
            {isMobileSidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>

          <div className="flex items-center space-x-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500/20 via-cyan-500/20 to-emerald-500/10 border border-emerald-500/40 text-emerald-400 glow-emerald">
              <Shield className="w-5 h-5 text-emerald-400" />
              <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-400"></span>
              </span>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-base sm:text-lg font-bold tracking-wider text-slate-100">
                  TRUSTGUARD<span className="text-cyan-400 font-extrabold">.AI</span>
                </span>
                <span className="hidden sm:inline-block text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  v1.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Web3 Security Operations Center
              </p>
            </div>
          </div>
        </div>

        {/* Center: Zero Knowledge indicator */}
        <div className="hidden lg:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-slate-900/80 border border-slate-800 text-xs text-slate-400">
          <Lock className="w-3.5 h-3.5 text-cyan-400" />
          <span>Zero-Knowledge Engine: No Keys or Seed Phrases Stored</span>
        </div>

        {/* Right Section: Network selector, Notifications, User Profile */}
        <div className="flex items-center space-x-3">
          {/* Network Selector */}
          <div className="relative">
            <button
              onClick={() => {
                setNetworkDropdownOpen(!networkDropdownOpen);
                setNotificationsOpen(false);
              }}
              className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-slate-800 text-xs font-mono text-slate-200 transition-all focus:outline-none"
            >
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span className="hidden sm:inline">{currentNetwork}</span>
              <span className="sm:hidden font-mono text-[11px]">NEAR</span>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            </button>

            {networkDropdownOpen && (
              <div className="absolute right-0 mt-2 w-52 rounded-xl bg-[#090d16] border border-slate-800 shadow-2xl p-1.5 z-50 animate-in fade-in zoom-in-95 duration-150">
                <div className="px-2.5 py-1.5 text-[10px] font-mono uppercase text-slate-500 border-b border-slate-800/60 mb-1">
                  Active Blockchain Network
                </div>
                {NETWORKS.map((net) => (
                  <button
                    key={net.id}
                    onClick={() => {
                      onSelectNetwork(net.id);
                      setNetworkDropdownOpen(false);
                    }}
                    className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs font-mono transition-colors text-left ${
                      currentNetwork === net.id
                        ? "bg-emerald-500/15 text-emerald-300 font-semibold"
                        : "text-slate-300 hover:bg-slate-800/60"
                    }`}
                  >
                    <span>{net.label}</span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                      {net.badge}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Notification Icon */}
          <div className="relative">
            <button
              onClick={() => {
                setNotificationsOpen(!notificationsOpen);
                setNetworkDropdownOpen(false);
              }}
              className="relative p-2 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-slate-800 text-slate-300 hover:text-cyan-400 transition-colors focus:outline-none"
              aria-label="Notifications"
            >
              <Bell className="w-4 h-4" />
              <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#06b6d4]"></span>
            </button>

            {notificationsOpen && (
              <div className="absolute right-0 mt-2 w-80 rounded-2xl bg-[#090d16] border border-slate-800 shadow-2xl p-3 z-50 animate-in fade-in zoom-in-95 duration-150">
                <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 mb-2">
                  <span className="text-xs font-bold text-slate-200">Security Alerts</span>
                  <span className="text-[10px] font-mono text-cyan-400">3 New</span>
                </div>
                <div className="space-y-2">
                  {notifications.map((item) => (
                    <div
                      key={item.id}
                      className="p-2 rounded-xl bg-slate-950/70 border border-slate-800/60 hover:border-slate-700/80 transition-colors"
                    >
                      <div className="flex items-center justify-between text-xs font-medium text-slate-200">
                        <span>{item.title}</span>
                        <span className="text-[10px] font-mono text-slate-500">{item.time}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">{item.desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* User Profile */}
          <div className="flex items-center space-x-2.5 pl-1 sm:pl-2 border-l border-slate-800">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 p-[1px]">
              <div className="w-full h-full rounded-[11px] bg-slate-950 flex items-center justify-center text-slate-200">
                <User className="w-4 h-4 text-emerald-400" />
              </div>
            </div>
            <div className="hidden sm:block text-left">
              <div className="text-xs font-mono font-semibold text-slate-200 flex items-center space-x-1">
                <span>prince.near</span>
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
              </div>
              <div className="text-[10px] font-mono text-emerald-400">Shield Active</div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}

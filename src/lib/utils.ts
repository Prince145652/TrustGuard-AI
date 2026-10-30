import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { RiskLevel } from "@/types/security";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatAddress(address: string, maxLen = 14): string {
  if (!address) return "";
  if (address.endsWith(".near") || address.endsWith(".testnet")) {
    return address;
  }
  if (address.length <= maxLen) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

export function getRiskLevelFromScore(score: number): RiskLevel {
  if (score < 15) return "SAFE";
  if (score < 35) return "LOW";
  if (score < 65) return "MEDIUM";
  if (score < 85) return "HIGH";
  return "CRITICAL";
}

export function getRiskColor(level: RiskLevel): {
  text: string;
  bg: string;
  border: string;
  glow: string;
} {
  switch (level) {
    case "SAFE":
      return {
        text: "text-emerald-400",
        bg: "bg-emerald-500/10",
        border: "border-emerald-500/30",
        glow: "shadow-[0_0_15px_rgba(16,185,129,0.2)]",
      };
    case "LOW":
      return {
        text: "text-cyan-400",
        bg: "bg-cyan-500/10",
        border: "border-cyan-500/30",
        glow: "shadow-[0_0_15px_rgba(6,182,212,0.2)]",
      };
    case "MEDIUM":
      return {
        text: "text-yellow-400",
        bg: "bg-yellow-500/10",
        border: "border-yellow-500/30",
        glow: "shadow-[0_0_15px_rgba(234,179,8,0.2)]",
      };
    case "HIGH":
      return {
        text: "text-orange-400",
        bg: "bg-orange-500/10",
        border: "border-orange-500/30",
        glow: "shadow-[0_0_15px_rgba(249,115,22,0.2)]",
      };
    case "CRITICAL":
      return {
        text: "text-rose-400",
        bg: "bg-rose-500/10",
        border: "border-rose-500/30",
        glow: "shadow-[0_0_15px_rgba(244,63,94,0.3)]",
      };
    default:
      return {
        text: "text-zinc-400",
        bg: "bg-zinc-500/10",
        border: "border-zinc-500/30",
        glow: "shadow-none",
      };
  }
}

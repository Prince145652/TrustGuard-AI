"use client";

import React, { useState, useRef, useEffect } from "react";
import {
  Brain,
  Sparkles,
  Send,
  Bot,
  AlertTriangle,
  RefreshCw,
  Layers,
  Lock,
  User,
} from "lucide-react";
import {
  ScanContext,
  ChatMessage,
  AnalystLanguage,
} from "@/types/ai-analyst";
import { looksLikeSecret } from "@/lib/validators";
import { EvidenceFirstVerdict } from "../EvidenceFirstVerdict";

// Sequential message generator outside component render lifecycle
let messageSequence = 0;

function createChatMessage(
  sender: "user" | "analyst",
  content: string,
  extra?: Partial<ChatMessage>
): ChatMessage {
  messageSequence += 1;
  const now = new Date();
  const timeString = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return {
    id: `${sender}-${now.getTime()}-${messageSequence}`,
    sender,
    content,
    timestamp: timeString,
    ...extra,
  };
}

function formatEngineLabel(engineUsed?: string): { name: string; isGemini: boolean } {
  if (!engineUsed) return { name: "Security Analyst", isGemini: false };
  if (engineUsed === "gemini-2.5-flash" || engineUsed.startsWith("gemini")) {
    return { name: `Gemini (${engineUsed})`, isGemini: true };
  }
  if (
    engineUsed === "autonomous-local-heuristics" ||
    engineUsed.includes("heuristics") ||
    engineUsed.includes("deterministic")
  ) {
    return { name: "Deterministic Security Analysis", isGemini: false };
  }
  return { name: engineUsed, isGemini: false };
}

function renderInlineMarkdown(text: string): React.ReactNode {
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return (
        <strong key={i} className="font-bold text-slate-100">
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code
          key={i}
          className="px-1 py-0.5 rounded bg-slate-900 text-cyan-300 font-mono text-[11px] border border-slate-800"
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
}

function renderFormattedMarkdown(text: string): React.ReactNode {
  const lines = text.split("\n");
  let listCounter = 0;

  return lines.map((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed) {
      listCounter = 0;
      return <div key={idx} className="h-1.5" />;
    }
    // Specific heading checks: #### before ###
    if (trimmed.startsWith("#### ")) {
      listCounter = 0;
      return (
        <h4 key={idx} className="text-xs font-bold text-slate-200 mt-2.5 mb-1 flex items-center gap-1.5">
          {renderInlineMarkdown(trimmed.replace("#### ", ""))}
        </h4>
      );
    }
    if (trimmed.startsWith("### ")) {
      listCounter = 0;
      return (
        <h3 key={idx} className="text-sm font-bold text-cyan-300 mt-3 mb-1.5 flex items-center gap-1.5">
          {renderInlineMarkdown(trimmed.replace("### ", ""))}
        </h3>
      );
    }
    if (trimmed.startsWith("> ")) {
      listCounter = 0;
      return (
        <blockquote key={idx} className="border-l-2 border-cyan-500/50 pl-2.5 py-1 text-slate-400 italic text-[11px] bg-slate-900/40 rounded-r my-1.5">
          {renderInlineMarkdown(trimmed.replace("> ", ""))}
        </blockquote>
      );
    }
    if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
      listCounter = 0;
      return (
        <div key={idx} className="flex items-start gap-1.5 pl-1 text-slate-300 text-xs my-0.5">
          <span className="text-cyan-400 mt-0.5 select-none">•</span>
          <span>{renderInlineMarkdown(trimmed.substring(2))}</span>
        </div>
      );
    }
    if (/^\d+\.\s/.test(trimmed)) {
      const numMatch = trimmed.match(/^(\d+)\.\s(.*)$/);
      if (numMatch) {
        listCounter += 1;
        return (
          <div key={idx} className="flex items-start gap-1.5 pl-1 text-slate-300 text-xs my-0.5">
            <span className="text-emerald-400 font-mono text-[11px] font-bold mt-0.5 select-none">
              {listCounter}.
            </span>
            <span>{renderInlineMarkdown(numMatch[2])}</span>
          </div>
        );
      }
    }
    listCounter = 0;
    return (
      <p key={idx} className="text-xs text-slate-300 leading-relaxed my-0.5">
        {renderInlineMarkdown(trimmed)}
      </p>
    );
  });
}

// Presets for instant context loading
const CONTEXT_PRESETS: { label: string; context: ScanContext }[] = [
  {
    label: "Tornado Cash Router (Sanctioned Wallet)",
    context: {
      scanType: "wallet",
      target: "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",
      chain: "Ethereum",
      riskScore: 95,
      riskLevel: "CRITICAL",
      threats: [
        "Tornado.Cash Router: US Treasury OFAC Sanctioned mixer router linked to protocol exploits.",
      ],
      evidence: [
        { category: "Threat Intelligence", finding: "FLAGGED in OFAC SDN List & Etherscan Blacklist", status: "CRITICAL" },
        { category: "Bytecode Architecture", finding: "Smart contract router with unverified withdrawal delegate", status: "WARNING" },
      ],
    },
  },
  {
    label: "claim-free-near-gift.xyz (Phishing Site)",
    context: {
      scanType: "website",
      target: "https://claim-free-near-gift.xyz",
      riskScore: 95,
      riskLevel: "CRITICAL",
      threats: [
        "NEAR Phishing Airdrop Drainer: Deceptive lookalike domain requesting FullAccess keys.",
      ],
      evidence: [
        { category: "Brand Impersonation", finding: "Combines 'near' brand with triggers 'claim' and 'gift'", status: "CRITICAL" },
        { category: "Domain Reputation", finding: "Uses .xyz TLD, heavily abused by transient phishing kits", status: "WARNING" },
      ],
    },
  },
  {
    label: "Tether USD (Token Privileges)",
    context: {
      scanType: "token",
      target: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
      chain: "Ethereum",
      riskScore: 45,
      riskLevel: "MEDIUM",
      threats: [],
      evidence: [
        { category: "Admin Privileges", finding: "Contract contains active blacklist function to freeze holder addresses", status: "WARNING" },
        { category: "Supply Control", finding: "Privileged accounts retain unlimited minting capabilities", status: "WARNING" },
        { category: "Trading Fees", finding: "0% Buy / 0% Sell taxes verified", status: "SAFE" },
      ],
      indicators: [
        {
          name: "Blacklist Function",
          description: "Admin can freeze addresses",
          detected: true,
          whySuspicious: "Centralized blacklists can prevent token holders from transferring assets.",
        },
        {
          name: "Minting Privileges",
          description: "Unlimited supply minting capability",
          detected: true,
          whySuspicious: "Unchecked minting can dilute token valuation.",
        },
      ],
    },
  },
];

interface AiSecurityAnalystProps {
  initialContext?: ScanContext | null;
}

export function AiSecurityAnalyst({ initialContext }: AiSecurityAnalystProps = {}) {
  const [selectedLanguage, setSelectedLanguage] = useState<AnalystLanguage>("en");
  const [prevInitialContext, setPrevInitialContext] = useState<ScanContext | null | undefined>(
    initialContext
  );
  const [manualContext, setManualContext] = useState<ScanContext | undefined | null>(undefined);

  // When initialContext prop changes from a scanner, adjust context during render without an effect
  if (initialContext !== prevInitialContext) {
    setPrevInitialContext(initialContext);
    setManualContext(undefined);
  }

  const currentContext =
    manualContext === null
      ? undefined // General security mode explicitly chosen
      : manualContext ?? (initialContext || CONTEXT_PRESETS[0].context);

  const [inputMessage, setInputMessage] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "msg-welcome",
      sender: "analyst",
      content: `Hello! I am your **TrustGuard AI Security Analyst**, powered by real-time blockchain heuristics and multi-layer neural security models.

I can explain why a target is flagged, interpret smart contract bytecode, and provide step-by-step risk mitigation strategies. 

Select a context preset above or ask any Web3 security question below!`,
      timestamp: "Just now",
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isAnalyzing]);

  const handleSendMessage = async (customPrompt?: string) => {
    const textToSend = (customPrompt || inputMessage).trim();
    if (!textToSend) return;

    if (looksLikeSecret(textToSend)) {
      setErrorMessage("SECURITY VIOLATION: Never send private keys or seed phrases to the AI!");
      return;
    }

    setErrorMessage(null);

    const userMsg = createChatMessage("user", textToSend);

    setMessages((prev) => [...prev, userMsg]);
    if (!customPrompt) setInputMessage("");
    setIsAnalyzing(true);

    try {
      const history = messages
        .filter((m) => m.id !== "msg-welcome")
        .slice(-4)
        .map((m) => ({
          role: m.sender === "user" ? ("user" as const) : ("model" as const),
          content: m.content,
        }));

      const res = await fetch("/api/analyst/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: textToSend,
          language: selectedLanguage,
          context: currentContext,
          history,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setErrorMessage(data.details?.[0] || data.error || "Failed to generate AI analysis.");
        setIsAnalyzing(false);
        return;
      }

      const analystMsg = createChatMessage("analyst", data.response, {
        structuredReport: data.structuredReport,
        contextTarget: currentContext?.target,
        engineUsed: data.engineUsed,
      });

      setMessages((prev) => [...prev, analystMsg]);
    } catch (err: unknown) {
      setErrorMessage(
        err instanceof Error ? err.message : "Network error connecting to AI analyst."
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleQuickQuestion = (q: string) => {
    handleSendMessage(q);
  };

  return (
    <div className="space-y-6">
      {/* Container Card */}
      <div className="rounded-2xl border border-slate-800/80 bg-gradient-to-b from-slate-900/90 via-slate-900/60 to-slate-950/90 p-5 sm:p-7 shadow-2xl backdrop-blur-xl relative overflow-hidden flex flex-col">
        {/* Ambient Top Glow */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        {/* Top Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400">
                AI Security Reasoner
              </span>
              <span className="text-slate-600">•</span>
              <span className="text-xs font-mono text-emerald-400">
                Natural Language Threat Analyst
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-extrabold text-slate-100 mt-1 flex items-center space-x-2.5">
              <Brain className="w-6 h-6 text-cyan-400" />
              <span>AI-Powered Security Analyst</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Ask questions about scanned wallets, tokens, or websites. Get transparent vulnerability explanations and protection guides in English, Hindi, or Hinglish.
            </p>
          </div>

          {/* Language Switcher */}
          <div className="flex items-center space-x-1.5 p-1 bg-slate-950 rounded-xl border border-slate-800 text-xs font-mono self-start sm:self-auto">
            <button
              onClick={() => setSelectedLanguage("en")}
              className={`px-3 py-1.5 rounded-lg transition-all ${
                selectedLanguage === "en"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              🇬🇧 English
            </button>
            <button
              onClick={() => setSelectedLanguage("hi")}
              className={`px-3 py-1.5 rounded-lg transition-all ${
                selectedLanguage === "hi"
                  ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              🇮🇳 हिन्दी (Hindi)
            </button>
            <button
              onClick={() => setSelectedLanguage("hinglish")}
              className={`px-3 py-1.5 rounded-lg transition-all ${
                selectedLanguage === "hinglish"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              💬 Hinglish
            </button>
          </div>
        </div>

        {/* Loaded Context Selector Bar */}
        <div className="mt-4 p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2.5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span className="text-xs font-semibold uppercase font-mono text-slate-400 flex items-center space-x-2">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              <span>Loaded Security Context:</span>
            </span>

            {/* Presets dropdown / chips */}
            <div className="flex flex-wrap items-center gap-1.5">
              {initialContext && (
                <button
                  type="button"
                  onClick={() => setManualContext(undefined)}
                  className={`text-[11px] font-mono px-2.5 py-1 rounded-lg border transition-all ${
                    currentContext?.target === initialContext.target
                      ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-300 font-bold"
                      : "bg-slate-900 border-slate-800 text-slate-300 hover:text-white"
                  }`}
                >
                  Active Scan: {initialContext.target.slice(0, 16)}...
                </button>
              )}
              {CONTEXT_PRESETS.map((p, idx) => (
                <button
                  key={idx}
                  onClick={() => setManualContext(p.context)}
                  className={`text-[11px] font-mono px-2.5 py-1 rounded-lg border transition-all ${
                    currentContext?.target === p.context.target
                      ? "bg-cyan-500/15 border-cyan-500/40 text-cyan-300 font-bold"
                      : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {p.label}
                </button>
              ))}
              <button
                onClick={() => setManualContext(null)}
                className={`text-[11px] font-mono px-2.5 py-1 rounded-lg border transition-all ${
                  !currentContext
                    ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-bold"
                    : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
                }`}
              >
                General Security Mode
              </button>
            </div>
          </div>

          {currentContext && (
            <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/60 text-xs">
              <div className="flex items-center space-x-2 font-mono">
                <span className="text-slate-400 uppercase text-[10px] px-1.5 py-0.5 rounded bg-slate-800">
                  {currentContext.scanType}
                </span>
                <span className="text-slate-200 font-bold">{currentContext.target}</span>
              </div>
              <div className="flex items-center space-x-2 font-mono text-xs">
                <span className="text-slate-400">Threat Score:</span>
                <span
                  className={`px-2 py-0.5 rounded font-bold ${
                    currentContext.riskScore >= 75
                      ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                      : currentContext.riskScore >= 35
                      ? "bg-yellow-500/20 text-yellow-300 border border-yellow-500/40"
                      : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                  }`}
                >
                  {currentContext.riskScore}/100 ({currentContext.riskLevel})
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Quick Question Chips */}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-mono text-slate-500">Quick Analysis Queries:</span>
          {[
            "Why is this wallet risky?",
            "Is this token suspicious?",
            "Why is this website flagged?",
            "How can I protect my assets?",
          ].map((q, idx) => (
            <button
              key={idx}
              onClick={() => handleQuickQuestion(q)}
              className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-slate-900/80 hover:bg-slate-850 border border-slate-800/80 text-slate-300 hover:text-cyan-300 transition-colors"
            >
              &ldquo;{q}&rdquo;
            </button>
          ))}
        </div>

        {/* Chat Thread */}
        <div className="mt-5 flex-1 min-h-[350px] max-h-[500px] overflow-y-auto space-y-4 pr-1">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex items-start space-x-3 ${
                msg.sender === "user" ? "justify-end" : "justify-start"
              }`}
            >
              {msg.sender === "analyst" && (
                <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 border border-cyan-500/40 flex items-center justify-center shrink-0 mt-1 glow-cyan">
                  <Bot className="w-4 h-4 text-cyan-400" />
                </div>
              )}

              <div
                className={`p-4 rounded-2xl max-w-2xl text-xs sm:text-sm leading-relaxed space-y-3 ${
                  msg.sender === "user"
                    ? "bg-gradient-to-r from-emerald-500/20 to-cyan-500/20 border border-cyan-500/30 text-slate-100 rounded-tr-none"
                    : "bg-slate-950/90 border border-slate-800 text-slate-200 rounded-tl-none shadow-lg"
                }`}
              >
                {/* Engine Badge */}
                {msg.engineUsed && (() => {
                  const engine = formatEngineLabel(msg.engineUsed);
                  return (
                    <div className="flex items-center justify-between text-[10px] font-mono pb-1 border-b border-slate-800/80 text-slate-400">
                      <span className="flex items-center space-x-1.5">
                        <Sparkles
                          className={`w-3 h-3 ${engine.isGemini ? "text-cyan-400" : "text-emerald-400"}`}
                        />
                        <span className="text-slate-300 font-medium">{engine.name}</span>
                      </span>
                      <span>{msg.timestamp}</span>
                    </div>
                  );
                })()}

                {/* 1. Evidence-First Security Verdict (Renders BEFORE detailed explanation) */}
                {msg.structuredReport && (
                  <EvidenceFirstVerdict report={msg.structuredReport} />
                )}

                {/* 2. Formatted Markdown Detailed AI Response */}
                <div className="prose-invert text-xs sm:text-sm font-sans space-y-1 pt-1">
                  {renderFormattedMarkdown(msg.content)}
                </div>
              </div>

              {msg.sender === "user" && (
                <div className="w-8 h-8 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0 mt-1 text-slate-300">
                  <User className="w-4 h-4 text-emerald-400" />
                </div>
              )}
            </div>
          ))}

          {isAnalyzing && (
            <div className="flex items-start space-x-3">
              <div className="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center shrink-0 mt-1 animate-pulse">
                <Bot className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="p-4 rounded-2xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-cyan-300 flex items-center space-x-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Evaluating on-chain evidence &amp; threat telemetry...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Error Alert */}
        {errorMessage && (
          <div className="mt-3 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Input Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="mt-4 pt-3 border-t border-slate-800 flex items-center space-x-2"
        >
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => {
              setInputMessage(e.target.value);
              setErrorMessage(null);
            }}
            placeholder={
              selectedLanguage === "hi"
                ? "सुरक्षा से जुड़ा कोई भी सवाल पूछें (उदा. क्या यह टोकन सुरक्षित है?)..."
                : selectedLanguage === "hinglish"
                ? "Security question puchein (e.g. Yeh website risky kyun hai?)..."
                : "Ask about risk indicators, drainers, honeypots, or safety best practices..."
            }
            className="flex-1 py-3 px-4 bg-slate-950 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 transition-all font-sans"
          />

          <button
            type="submit"
            disabled={isAnalyzing || !inputMessage.trim()}
            className="p-3 bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 disabled:opacity-40 text-slate-950 font-bold rounded-xl transition-all shadow-md shadow-cyan-500/20"
            aria-label="Send message"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>

        {/* Footer Secret Protection Rule */}
        <div className="mt-3 text-[10px] font-mono text-slate-500 text-center flex items-center justify-center space-x-1.5">
          <Lock className="w-3.5 h-3.5 text-cyan-400" />
          <span>Secret Protection Architecture: We never request, store, or accept private keys or recovery seed phrases.</span>
        </div>
      </div>
    </div>
  );
}

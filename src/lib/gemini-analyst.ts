import { GoogleGenAI } from "@google/genai";
import {
  ScanContext,
  AnalystLanguage,
  AnalystApiResponse,
  StructuredSecurityReport,
} from "@/types/ai-analyst";

const SYSTEM_INSTRUCTION = `
You are the TRUSTGUARD AI Senior Web3 Cybersecurity Analyst for the NEAR Hackathon 2026.
Your purpose is to explain blockchain vulnerabilities, wallet drainers, token honeypots, and phishing attacks to Web3 users in simple, actionable terms.

MANDATORY SAFETY RULES:
1. ONLY analyze the verified evidence and scanner results provided in the prompt. NEVER invent blockchain transactions, balances, or security findings that were not provided.
2. NEVER override the scanner's risk score or verdict. If a target is marked HIGH or CRITICAL, warn the user explicitly.
3. NEVER guarantee that any wallet, token, or website is 100% safe. Always clarify that absence of threat indicators does not guarantee immunity from zero-day exploits.
4. Clearly explain UNCERTAINTY when data points are marked "UNKNOWN" or missing.
5. NEVER ask for, accept, or store private keys, recovery seed phrases, or credentials. Always emphasize zero-knowledge architecture.
6. LANGUAGE:
   - When language is 'hi': Respond in clear, accessible Hindi (हिंदी). Use standard Devanagari script.
   - When language is 'hinglish': Respond in conversational Hindi written in the Latin alphabet (e.g., "Yeh token risky lag raha hai kyunki isme 99% sell tax paya gaya hai...").
   - When language is 'en': Respond in professional, simple English.
7. Always provide actionable, practical security recommendations (e.g., using Revoke.cash, checking explorers, moving funds).
`;

/**
 * Deterministic Fallback Engine when Gemini API key is not configured
 * Generates an accurate, evidence-backed security breakdown directly from scanner telemetry.
 */
function generateDeterministicAnalysis(
  context: ScanContext | undefined,
  userQuestion: string,
  language: AnalystLanguage
): AnalystApiResponse {
  const now = new Date().toISOString();

  // If no specific scan context was passed, answer general Web3 security queries
  if (!context) {
    if (language === "hi") {
      return {
        response: `### TrustGuard AI सुरक्षा सलाहकार (सामान्य दिशानिर्देश) 🛡️

**सुरक्षा नियम:**
1. **सीड फ्रेज (Seed Phrase) कभी शेयर न करें:** कोई भी वास्तविक dApp या सपोर्ट एजेंट आपसे आपकी 12 या 24-शब्दों की रिकवरी कीज़ नहीं मांगता।
2. **अनलिमिटेड अप्रूवल (Unlimited Approvals) से बचें:** नए टोकन या dApps के साथ इंटरैक्ट करते समय हमेशा सीमित टोकन अनुमति दें और नियमित रूप से **Revoke.cash** का उपयोग करके पुरानी परमिशन हटाएं।
3. **हनीपॉट और फिशिंग से सावधान रहें:** टोकन खरीदने से पहले TrustGuard Token Scanner पर बाय/सेल टैक्स और ट्रांसफर पाबंदी जांचें।

*कोई विशिष्ट वॉलेट, वेबसाइट या टोकन का विश्लेषण करने के लिए उसे ऊपर स्कैनर में लोड करें।*`,
        engineUsed: "autonomous-local-heuristics",
        disclaimer: "TrustGuard AI Heuristic Engine. Operates strictly on deterministic security heuristics.",
      };
    } else if (language === "hinglish") {
      return {
        response: `### TrustGuard AI Security Advisor (General Security) 🛡️

**Zaroori Security Rules:**
1. **Seed Phrase Kabhi Share Na Karein:** Koi bhi legitimate dApp ya admin aapse aapki 12 ya 24-word recovery phrase nahi mangta.
2. **Unlimited Approvals Revoke Karein:** Kisi bhi dApp ko full token access dene se bachein. **Revoke.cash** use karke purane approvals regularly cancel karein.
3. **Phishing & Honeypots Se Bachein:** Airdrop ya free rewards claim karne wale kisi bhi link par wallet connect karne se pehle TrustGuard Scanner se verify karein.

*Kisi specific wallet, website ya token ka analysis dekhne ke liye use pehle scan karein.*`,
        engineUsed: "autonomous-local-heuristics",
        disclaimer: "TrustGuard AI Heuristic Engine. Operates strictly on deterministic security heuristics.",
      };
    }

    return {
      response: `### TrustGuard AI Security Advisor (General Guidance) 🛡️

**Core Web3 Defense Rules:**
1. **Zero-Knowledge Principle:** Never disclose your 12 or 24-word recovery phrase. TrustGuard and authentic dApps will never request your private keys.
2. **Manage Token Allowances:** Periodically audit and revoke unlimited token allowances using tools like **Revoke.cash** or blockchain explorer approval checkers.
3. **Verify Contract Addresses:** Always copy contract addresses directly from verified sources like CoinMarketCap or project documentation, never from search ads or Telegram DMs.

*To analyze a specific target, enter a wallet address, token contract, or dApp URL into the scanners above.*`,
      engineUsed: "autonomous-local-heuristics",
      disclaimer: "TrustGuard AI Heuristic Engine. Operates strictly on deterministic security heuristics.",
    };
  }

  // Construct Structured Report from verified context
  const detectedThreats = context.threats || [];
  const evidenceList = (context.evidence || []).map((e) => `${e.category}: ${e.finding}`);
  if (context.indicators) {
    context.indicators
      .filter((i) => i.detected)
      .forEach((i) => evidenceList.push(`${i.name} (${i.severity || "FLAG"}): ${i.description}`));
  }

  const recommendedActions: string[] = [];
  if (context.riskScore >= 75) {
    recommendedActions.push(
      "DO NOT INTERACT: Disconnect wallets immediately and do not approve signatures.",
      "If you already interacted, revoke all allowances using Revoke.cash and transfer assets to a fresh wallet.",
      "Report the malicious target to decentralized scam registries."
    );
  } else if (context.riskScore >= 35) {
    recommendedActions.push(
      "Exercise heightened caution. Verify all transaction parameters and gas fees before signing.",
      "Check the target's on-chain history and ensure source code is verified on the explorer."
    );
  } else {
    recommendedActions.push(
      "Baseline security checks passed. Standard caution is still recommended.",
      "Never approve unlimited spending limits unless interacting with audited, battle-tested protocols."
    );
  }

  const structuredReport: StructuredSecurityReport = {
    target: context.target,
    scanType: context.scanType.toUpperCase(),
    riskScore: context.riskScore,
    riskLevel: context.riskLevel,
    detectedThreats,
    evidence: evidenceList,
    recommendedActions,
    analysisTimestamp: now,
    uncertaintyNotes:
      "This analysis is strictly based on public on-chain heuristics and threat registries. Absence of detection does not guarantee absolute safety.",
  };

  // Generate language-specific narrative
  let narrative = "";

  if (language === "hi") {
    narrative = `### AI सुरक्षा विश्लेषण रिपोर्ट: ${context.target} 🔍

**जोखिम स्तर:** **${context.riskLevel}** (स्कोर: **${context.riskScore}/100**)  
**स्कैन प्रकार:** ${context.scanType === "wallet" ? "वॉलेट सुरक्षा" : context.scanType === "token" ? "टोकन व स्मार्ट कॉन्ट्रैक्ट" : "वेबसाइट / dApp"}

#### मुख्य निष्कर्ष (Findings):
${
  detectedThreats.length > 0
    ? detectedThreats.map((t) => `- ⚠️ **चेतावनी:** ${t}`).join("\n")
    : `- कोई प्रत्यक्ष ब्लैकलिस्ट या ड्रेनर खतरा दर्ज नहीं है।`
}

#### साक्ष्य विवरण (Evidence):
${evidenceList.slice(0, 4).map((e) => `- **प्रमाण:** ${e}`).join("\n")}

#### अनुशंसित सुरक्षा उपाय (Recommended Actions):
${recommendedActions.map((a) => `1. ${a}`).join("\n")}

> **सुरक्षा नोट:** TrustGuard AI किसी भी परिस्थिति में 100% सुरक्षा की गारंटी नहीं देता। अज्ञात या नए कॉन्ट्रैक्ट्स के साथ लेनदेन करते समय हमेशा सतर्क रहें।`;
  } else if (language === "hinglish") {
    narrative = `### AI Security Analyst Report: ${context.target} 🔍

**Risk Level:** **${context.riskLevel}** (Score: **${context.riskScore}/100**)  
**Category:** ${context.scanType === "wallet" ? "EVM Wallet" : context.scanType === "token" ? "Token Contract" : "Website Domain"}

#### Key Findings & Alerts:
${
  detectedThreats.length > 0
    ? detectedThreats.map((t) => `- ⚠️ **Alert:** ${t}`).join("\n")
    : `- Scanner ko koi direct drainer ya honeypot blacklist match nahi mila.`
}

#### Verification Evidence:
${evidenceList.slice(0, 4).map((e) => `- **Evidence:** ${e}`).join("\n")}

#### Zaroori Actions (Kya Karein):
${recommendedActions.map((a) => `1. ${a}`).join("\n")}

> **Safety Reminder:** Zero threat detection ka matlab 100% safe hona nahi hota. Unknown contracts ke sath interact karte waqt hamesha cautious rahein.`;
  } else {
    narrative = `### AI Security Analyst Report: ${context.target} 🔍

**Threat Assessment:** **${context.riskLevel}** (Risk Score: **${context.riskScore}/100**)  
**Scan Target Type:** ${context.scanType.toUpperCase()}

#### Key Threat Findings:
${
  detectedThreats.length > 0
    ? detectedThreats.map((t) => `- 🚨 **Threat Identified:** ${t}`).join("\n")
    : `- No direct blacklist matches or known drainer signatures were found in active threat feeds.`
}

#### Transparent Evidence Log:
${evidenceList.slice(0, 4).map((e) => `- **Evidence:** ${e}`).join("\n")}

#### Recommended Actions:
${recommendedActions.map((a) => `1. ${a}`).join("\n")}

> **Security Disclaimer:** TrustGuard AI operates on deterministic heuristics and public blockchain state. Absence of recorded flags does not eliminate zero-day risks.`;
  }

  return {
    response: narrative,
    structuredReport,
    engineUsed: "autonomous-local-heuristics",
    disclaimer: "TrustGuard AI Deterministic Security Engine. Based on scanner telemetry.",
  };
}

/**
 * Primary entry point: Queries Gemini API if key is present,
 * or gracefully falls back to deterministic local analyst engine.
 */
export async function analyzeWithGemini(
  context: ScanContext | undefined,
  userMessage: string,
  language: AnalystLanguage = "en",
  chatHistory: Array<{ role: "user" | "model"; content: string }> = []
): Promise<AnalystApiResponse> {
  const apiKey = process.env.GEMINI_API_KEY;

  // If no Gemini API key is configured, use local engine
  if (!apiKey) {
    return generateDeterministicAnalysis(context, userMessage, language);
  }

  try {
    const ai = new GoogleGenAI({ apiKey });

    // Format context into a strict prompt
    let prompt = `User Question: "${userMessage}"\nLanguage: "${language}"\n\n`;

    if (context) {
      prompt += `SCANNER CONTEXT PROVIDED (Strictly stick to this evidence):\n`;
      prompt += `- Target: ${context.target}\n`;
      prompt += `- Scan Type: ${context.scanType}\n`;
      prompt += `- Risk Score: ${context.riskScore}/100 (${context.riskLevel})\n`;
      if (context.chain) prompt += `- Blockchain: ${context.chain}\n`;
      if (context.threats && context.threats.length > 0) {
        prompt += `- Detected Threats: ${JSON.stringify(context.threats)}\n`;
      }
      if (context.evidence && context.evidence.length > 0) {
        prompt += `- Verified Evidence: ${JSON.stringify(context.evidence)}\n`;
      }
      if (context.indicators && context.indicators.length > 0) {
        prompt += `- Security Indicators: ${JSON.stringify(context.indicators.filter((i) => i.detected))}\n`;
      }
    } else {
      prompt += `No specific scanner context was supplied. Answer general Web3 security questions accurately.\n`;
    }

    const contents = [
      ...chatHistory.map((h) => ({
        role: h.role,
        parts: [{ text: h.content }],
      })),
      {
        role: "user" as const,
        parts: [{ text: prompt }],
      },
    ];

    const modelResponse = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents,
      config: {
        systemInstruction: SYSTEM_INSTRUCTION,
        temperature: 0.2, // Low temperature for factual security consistency
      },
    });

    const text = modelResponse.text || "No response generated by Gemini model.";

    // Generate matching structured report
    const fallbackData = generateDeterministicAnalysis(context, userMessage, language);

    return {
      response: text,
      structuredReport: fallbackData.structuredReport,
      engineUsed: "gemini-2.5-flash",
      disclaimer: "AI-generated reasoning based on verified scanner telemetry.",
    };
  } catch (err: unknown) {
    console.warn("Gemini API call failed, falling back to local heuristic engine:", err);
    return generateDeterministicAnalysis(context, userMessage, language);
  }
}

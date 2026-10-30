import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { validateAndSanitizeUrl } from "@/lib/url-security";
import {
  analyzeDomainHeuristics,
  checkThreatIntelligenceSources,
} from "@/lib/website-threat-intel";
import {
  WebsiteRiskLevel,
  WebsiteScanResult,
} from "@/types/website-security";

const requestSchema = z.object({
  url: z.string().trim().min(1, "URL cannot be empty"),
});

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const parsedInput = requestSchema.safeParse(body);

    if (!parsedInput.success) {
      return NextResponse.json(
        {
          error: "Validation failed",
          details: parsedInput.error.issues.map((i) => i.message),
        },
        { status: 400 }
      );
    }

    // 1. URL & SSRF Validation
    const validation = validateAndSanitizeUrl(parsedInput.data.url);
    if (!validation.valid || !validation.url) {
      return NextResponse.json(
        {
          error: "URL Validation Error",
          details: [validation.error || "Invalid URL provided."],
        },
        { status: 400 }
      );
    }

    const targetUrl = validation.url;
    const domain = targetUrl.hostname.toLowerCase();

    // 2. Heuristic Domain Analysis (Pure static evaluation, no web crawling or file execution)
    const indicators = analyzeDomainHeuristics(targetUrl);

    // 3. Threat Intelligence Cross-Referencing
    const threatIntel = await checkThreatIntelligenceSources(targetUrl);

    // 4. Evidence-Based 0-100 Risk Scoring
    let riskScore = 0;
    const recommendations: string[] = [];

    // Indicator impacts
    const isDirectIp = indicators.find((i) => i.id === "ind-direct-ip")?.detected;
    const isHomograph = indicators.find((i) => i.id === "ind-homograph")?.detected;
    const isImpersonating = indicators.find((i) => i.id === "ind-impersonation")?.detected;
    const hasSubdomains = indicators.find((i) => i.id === "ind-subdomains")?.detected;
    const isHttp = indicators.find((i) => i.id === "ind-protocol")?.detected;
    const isHighRiskTld = indicators.find((i) => i.id === "ind-high-risk-tld")?.detected;

    if (threatIntel.isBlacklisted) {
      riskScore = 95;
      recommendations.push(
        "CRITICAL: Do NOT visit this domain or connect your Web3 wallet.",
        "If you already interacted, immediately revoke active approvals via Revoke.cash and move assets to a fresh wallet.",
        "Report this phishing URL to community scam aggregators."
      );
    } else if (isImpersonating) {
      riskScore = 85;
      recommendations.push(
        "CRITICAL: High probability of phishing lookalike targeting trusted Web3 brands.",
        "Do NOT approve signature requests, permit approvals, or seed phrase requests.",
        "Verify the official domain from verified social media or CoinMarketCap."
      );
    } else {
      // Aggregate heuristic indicators
      if (isHomograph) riskScore += 35;
      if (isDirectIp) riskScore += 30;
      if (hasSubdomains) riskScore += 20;
      if (isHttp) riskScore += 15;
      if (isHighRiskTld) riskScore += 15;

      riskScore = Math.min(Math.max(riskScore, 5), 100);

      if (riskScore >= 65) {
        recommendations.push(
          "Multiple suspicious indicators detected. Exercise extreme caution before connecting wallets.",
          "Verify SSL certificate authority and check domain registration date before interacting."
        );
      } else if (riskScore >= 35) {
        recommendations.push(
          "Some unusual domain traits identified. Ensure you arrived here from an authentic official bookmark.",
          "Check smart contract permissions carefully before confirming transactions."
        );
      } else {
        // Enforce rule: Do not claim safe simply because no threats were detected
        recommendations.push(
          "No known phishing indicators detected in current threat databases.",
          "Always verify recipient contract addresses and never enter private keys or recovery seed phrases."
        );
      }
    }

    // Determine Risk Level & Verdict
    let riskLevel: WebsiteRiskLevel = "SAFE";
    let verdict: WebsiteScanResult["verdict"] = "NO_THREATS_DETECTED";

    if (threatIntel.isBlacklisted || isImpersonating) {
      riskLevel = "CRITICAL";
      verdict = "MALICIOUS";
    } else if (riskScore >= 65) {
      riskLevel = "HIGH";
      verdict = "SUSPICIOUS";
    } else if (riskScore >= 35) {
      riskLevel = "MEDIUM";
      verdict = "SUSPICIOUS";
    } else if (riskScore >= 15) {
      riskLevel = "LOW";
      verdict = "LOW_RISK";
    } else {
      riskLevel = "SAFE";
      verdict = "NO_THREATS_DETECTED";
    }

    const summary =
      verdict === "MALICIOUS"
        ? `HIGH RISK PHISHING DETECTED: '${domain}' exhibits verified deceptive characteristics or threat intelligence blacklisting. Do not connect Web3 wallets.`
        : verdict === "SUSPICIOUS"
        ? `CAUTION ADVISED: '${domain}' displays anomalous domain patterns (e.g., suspicious subdomains, high-risk TLD, or protocol issues).`
        : `NO THREATS DETECTED: '${domain}' passed baseline phishing heuristics. Note: Absence of detection in threat databases is not a guarantee of safety.`;

    const responsePayload: WebsiteScanResult = {
      url: parsedInput.data.url,
      normalizedUrl: targetUrl.toString(),
      domain,
      protocol: targetUrl.protocol as "https:" | "http:",
      isHttps: targetUrl.protocol === "https:",
      riskScore,
      riskLevel,
      verdict,
      summary,
      indicators,
      threatIntelligence: threatIntel.results,
      recommendations,
      timestamp: new Date().toISOString(),
      disclaimer:
        "TrustGuard AI Phishing & Domain Report. Evaluates domain patterns, SSL protocols, and threat intelligence. Does not guarantee safety; zero detected threats does not eliminate zero-day risks.",
    };

    return NextResponse.json(responsePayload);
  } catch (err: unknown) {
    console.error("Website Scanner Error:", err);
    return NextResponse.json(
      {
        error: "Internal website analysis error",
        message: err instanceof Error ? err.message : "Unexpected error during domain scan",
      },
      { status: 500 }
    );
  }
}

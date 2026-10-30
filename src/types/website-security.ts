export type WebsiteRiskLevel = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

export interface PhishingIndicator {
  id: string;
  name: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  detected: boolean;
  description: string;
  evidence: string;
}

export interface ThreatIntelligenceSourceResult {
  source: string;
  status: "CLEAN" | "FLAGGED" | "UNAVAILABLE" | "SKIPPED";
  threatType?: string;
  details: string;
}

export interface WebsiteScanResult {
  url: string;
  normalizedUrl: string;
  domain: string;
  protocol: "https:" | "http:";
  isHttps: boolean;
  riskScore: number; // 0 - 100
  riskLevel: WebsiteRiskLevel;
  verdict: "MALICIOUS" | "SUSPICIOUS" | "LOW_RISK" | "NO_THREATS_DETECTED" | "UNKNOWN";
  summary: string;
  indicators: PhishingIndicator[];
  threatIntelligence: ThreatIntelligenceSourceResult[];
  recommendations: string[];
  timestamp: string;
  disclaimer: string;
}

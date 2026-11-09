import { NearVerificationRecord } from "@/types/near-verification";

export type AnalystLanguage = "en" | "hi" | "hinglish";

export interface ScanContext {
  scanType: "wallet" | "website" | "token";
  target: string;
  chain?: string;
  riskScore: number;
  riskLevel: string;
  threats?: string[];
  evidence?: Array<{
    category: string;
    finding: string;
    status: "SAFE" | "WARNING" | "CRITICAL" | "UNKNOWN";
  }>;
  indicators?: Array<{
    name: string;
    description: string;
    detected: boolean;
    severity?: string;
    whySuspicious?: string;
  }>;
  nearRecord?: NearVerificationRecord;
}

export interface ChatMessage {
  id: string;
  sender: "user" | "analyst";
  content: string;
  timestamp: string;
  contextTarget?: string;
  structuredReport?: StructuredSecurityReport;
  engineUsed?: "gemini-2.5-flash" | "autonomous-local-heuristics";
}

export interface StructuredSecurityReport {
  target: string;
  scanType: string;
  riskScore: number;
  riskLevel: string;
  detectedThreats: string[];
  evidence: string[];
  recommendedActions: string[];
  analysisTimestamp: string;
  uncertaintyNotes?: string;
  nearRecord?: NearVerificationRecord;
}

export interface AnalystApiResponse {
  response: string;
  structuredReport?: StructuredSecurityReport;
  engineUsed: "gemini-2.5-flash" | "autonomous-local-heuristics";
  disclaimer: string;
}

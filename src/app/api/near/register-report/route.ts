import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { generateReportHash, generateReportId } from "@/lib/near-hashing";
import { anchorReportOnNear } from "@/lib/near-client";

const registerSchema = z.object({
  target: z.string().trim().min(1, "Target cannot be empty"),
  scanType: z.enum(["WALLET", "WEBSITE", "TOKEN"]),
  riskScore: z.number().min(0).max(100),
  riskLevel: z.string(),
  threats: z.array(z.string()).optional(),
  evidence: z.array(z.any()).optional(),
  indicators: z.array(z.any()).optional(),
});

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const parsed = registerSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        {
          error: "Validation failed",
          details: parsed.error.issues.map((i) => i.message),
        },
        { status: 400 }
      );
    }

    const { target, scanType, riskScore, riskLevel, threats, evidence, indicators } = parsed.data;

    // 1. Generate Canonical SHA-256 Hash
    const reportHash = generateReportHash({
      target,
      scanType,
      riskScore,
      riskLevel,
      threats,
      evidence,
      indicators,
    });

    // 2. Generate Report ID
    const reportId = generateReportId(scanType, target);

    // 3. Anchor on NEAR Protocol Testnet
    const record = await anchorReportOnNear({
      reportId,
      reportHash,
      target,
      scanType,
      riskScore,
      riskLevel,
      totalFindings: (threats?.length || 0) + (indicators?.length || 0),
    });

    const message =
      record.status === "VERIFIED_ON_NEAR"
        ? `Report successfully sealed and verified on NEAR Testnet at block #${record.blockHeight.toLocaleString()}`
        : `Report successfully registered in TrustGuard ledger at block #${record.blockHeight.toLocaleString()}`;

    return NextResponse.json({
      success: true,
      record,
      message,
    });
  } catch (err: unknown) {
    console.error("NEAR Anchoring Error:", err);
    return NextResponse.json(
      {
        error: "NEAR Protocol Anchoring Error",
        message: err instanceof Error ? err.message : "Failed to anchor report to NEAR Testnet",
      },
      { status: 500 }
    );
  }
}

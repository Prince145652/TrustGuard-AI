import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { verifyReportOnNear } from "@/lib/near-client";
import { checkRateLimit, createRateLimitResponse } from "@/lib/rate-limiter";

const querySchema = z.object({
  hashOrId: z.string().trim().min(2, "Report Hash or Report ID is required"),
});

export async function GET(req: NextRequest) {
  try {
    const rateLimit = checkRateLimit(req, { max: 60, windowMs: 60000 });
    if (!rateLimit.success) {
      return createRateLimitResponse(rateLimit.reset);
    }

    const { searchParams } = new URL(req.url);
    const hashOrId =
      searchParams.get("hashOrId") ||
      searchParams.get("hash") ||
      searchParams.get("reportId") ||
      searchParams.get("id");

    const parsed = querySchema.safeParse({ hashOrId });
    if (!parsed.success) {
      return NextResponse.json(
        {
          error: "Validation failed",
          details: parsed.error.issues.map((i) => i.message),
        },
        { status: 400 }
      );
    }

    const result = await verifyReportOnNear(parsed.data.hashOrId);

    return NextResponse.json({
      isVerified: result.isVerified,
      status: result.status,
      record: result.record,
      queriedAtBlock: result.queriedAtBlock,
      message:
        result.message ||
        (result.isVerified
          ? `Report verified in TrustGuard registry at block #${result.record?.blockHeight.toLocaleString()}`
          : "No registered security report matching this hash or ID was found in the NEAR Protocol ledger."),
    });
  } catch (err: unknown) {
    console.error("NEAR Verification Error:", err instanceof Error ? err.stack || err.message : String(err));
    return NextResponse.json(
      {
        error: "Verification Error",
        message: "Failed to query NEAR Testnet state. Please try again later.",
      },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    const rateLimit = checkRateLimit(req, { max: 60, windowMs: 60000 });
    if (!rateLimit.success) {
      return createRateLimitResponse(rateLimit.reset);
    }

    const body = await req.json();
    const parsed = querySchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        {
          error: "Validation failed",
          details: parsed.error.issues.map((i) => i.message),
        },
        { status: 400 }
      );
    }

    const result = await verifyReportOnNear(parsed.data.hashOrId);

    return NextResponse.json({
      isVerified: result.isVerified,
      status: result.status,
      record: result.record,
      queriedAtBlock: result.queriedAtBlock,
      message:
        result.message ||
        (result.isVerified
          ? `Report verified in TrustGuard registry at block #${result.record?.blockHeight.toLocaleString()}`
          : "No registered security report matching this hash or ID was found in the NEAR Protocol ledger."),
    });
  } catch (err: unknown) {
    console.error("NEAR Verification Error:", err instanceof Error ? err.stack || err.message : String(err));
    return NextResponse.json(
      {
        error: "Verification Error",
        message: "Failed to query NEAR Testnet state. Please try again later.",
      },
      { status: 500 }
    );
  }
}

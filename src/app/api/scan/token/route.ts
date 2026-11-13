import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { ethers } from "ethers";
import { looksLikeSecret } from "@/lib/validators";
import { analyzeTokenContract } from "@/lib/token-analyzer";
import { checkRateLimit, createRateLimitResponse } from "@/lib/rate-limiter";

const tokenScanSchema = z.object({
  address: z
    .string()
    .trim()
    .refine((val) => !looksLikeSecret(val), {
      message: "SECURITY VIOLATION: Private keys and recovery seed phrases are strictly forbidden!",
    })
    .refine((val) => /^0x[a-fA-F0-9]{40}$/.test(val) && ethers.isAddress(val), {
      message: "Invalid contract address format. Must be a valid 42-character 0x-prefixed hex address.",
    }),
  chain: z.enum(["ethereum", "base", "bnb"]),
});

export async function POST(req: NextRequest) {
  try {
    const rateLimit = checkRateLimit(req, { max: 30, windowMs: 60000 });
    if (!rateLimit.success) {
      return createRateLimitResponse(rateLimit.reset);
    }

    const body = await req.json();
    const parseResult = tokenScanSchema.safeParse(body);

    if (!parseResult.success) {
      return NextResponse.json(
        {
          error: "Validation failed",
          details: parseResult.error.issues.map((i) => i.message),
        },
        { status: 400 }
      );
    }

    const { address, chain } = parseResult.data;
    const result = await analyzeTokenContract(address, chain);

    return NextResponse.json(result);
  } catch (err: unknown) {
    console.error("Token Scanner Error:", err instanceof Error ? err.stack || err.message : String(err));
    const message = err instanceof Error ? err.message : "Error analyzing token contract";
    const isClientError = message.includes("not a deployed contract") || message.includes("Invalid");

    return NextResponse.json(
      {
        error: isClientError ? "Contract Validation Error" : "Token Analysis Error",
        details: [isClientError ? message : "An unexpected error occurred during token contract analysis. Please try again later."],
      },
      { status: isClientError ? 400 : 500 }
    );
  }
}

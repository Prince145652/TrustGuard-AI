import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { looksLikeSecret } from "@/lib/validators";
import { analyzeWithGemini } from "@/lib/gemini-analyst";

const analystRequestSchema = z.object({
  message: z.string().trim().min(1, "Message cannot be empty"),
  language: z.enum(["en", "hi", "hinglish"]).default("en"),
  context: z
    .object({
      scanType: z.enum(["wallet", "website", "token"]),
      target: z.string().min(1),
      chain: z.string().optional(),
      riskScore: z.number().min(0).max(100),
      riskLevel: z.string(),
      threats: z.array(z.string()).optional(),
      evidence: z
        .array(
          z.object({
            category: z.string(),
            finding: z.string(),
            status: z.enum(["SAFE", "WARNING", "CRITICAL", "UNKNOWN"]),
          })
        )
        .optional(),
      indicators: z
        .array(
          z.object({
            name: z.string(),
            description: z.string(),
            detected: z.boolean(),
            severity: z.string().optional(),
            whySuspicious: z.string().optional(),
          })
        )
        .optional(),
    })
    .optional(),
  history: z
    .array(
      z.object({
        role: z.enum(["user", "model"]),
        content: z.string(),
      })
    )
    .optional(),
});

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const parsed = analystRequestSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        {
          error: "Validation failed",
          details: parsed.error.issues.map((i) => i.message),
        },
        { status: 400 }
      );
    }

    const { message, language, context, history } = parsed.data;

    // Defensive zero-knowledge rule
    if (looksLikeSecret(message)) {
      return NextResponse.json(
        {
          error: "Security Violation",
          details: [
            "CRITICAL: Never share private keys or seed phrases with the AI Analyst! TrustGuard operates on zero-knowledge architecture.",
          ],
        },
        { status: 400 }
      );
    }

    const result = await analyzeWithGemini(context, message, language, history);

    return NextResponse.json(result);
  } catch (err: unknown) {
    console.error("AI Analyst Error:", err);
    return NextResponse.json(
      {
        error: "AI Analyst Error",
        message: err instanceof Error ? err.message : "Unexpected error during AI analysis",
      },
      { status: 500 }
    );
  }
}

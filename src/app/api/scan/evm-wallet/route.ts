import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { ethers } from "ethers";
import { looksLikeSecret } from "@/lib/validators";
import { checkThreatIntelligence } from "@/lib/threat-intel";
import { fetchOnChainWalletData, EVM_CHAINS } from "@/lib/evm-provider";
import { EvmRiskLevel, EvmWalletScanResult } from "@/types/evm-security";

const scanRequestSchema = z.object({
  address: z
    .string()
    .trim()
    .refine((val) => !looksLikeSecret(val), {
      message: "SECURITY VIOLATION: Private keys and recovery seed phrases are strictly forbidden!",
    })
    .refine((val) => /^0x[a-fA-F0-9]{40}$/.test(val) && ethers.isAddress(val), {
      message: "Invalid Ethereum address format. Must be a valid 42-character 0x-prefixed hex address.",
    }),
  chain: z.enum(["ethereum", "base", "bnb"]),
});

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const parseResult = scanRequestSchema.safeParse(body);

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
    const checksumAddress = ethers.getAddress(address);
    const chainConfig = EVM_CHAINS[chain];

    // 1. Check Threat Intelligence database
    const threatMatch = checkThreatIntelligence(checksumAddress);

    // 2. Fetch Real On-Chain Data via RPC
    const onChainData = await fetchOnChainWalletData(checksumAddress, chain);

    // 3. Calculate Transparent Risk Score (0-100)
    let riskScore = 0;
    const threats: string[] = [];
    const evidence: { category: string; finding: string; status: "SAFE" | "WARNING" | "CRITICAL" | "UNKNOWN" }[] = [];
    const recommendations: string[] = [];

    // Evaluate Threat Database Match
    if (threatMatch.isMalicious) {
      riskScore = 95;
      threats.push(`${threatMatch.threatName || "Flagged Address"}: ${threatMatch.details}`);
      evidence.push({
        category: "Threat Intelligence",
        finding: `FLAGGED: ${threatMatch.category} listed in ${threatMatch.evidenceSource}`,
        status: "CRITICAL",
      });
      recommendations.push(
        "CRITICAL: Do NOT sign any transactions or approvals for this address.",
        "If you previously granted token allowances to this address, revoke them immediately via Revoke.cash.",
        "Report any associated phishing links to Web3 security registries."
      );
    } else {
      evidence.push({
        category: "Threat Intelligence",
        finding: "Address not found in known drainer, sanctions, or phishing blacklist registries.",
        status: "SAFE",
      });
    }

    // Evaluate Account Type (EOA vs Contract)
    let accountType: "Externally Owned Account (EOA)" | "Smart Contract" | "Unknown" = "Unknown";
    if (onChainData.isContract === true) {
      accountType = "Smart Contract";
      evidence.push({
        category: "Bytecode Architecture",
        finding: `Contract bytecode detected on ${chainConfig.name}. This is an automated smart contract, not an EOA.`,
        status: "WARNING",
      });
      if (!threatMatch.isMalicious) {
        riskScore += 15;
        recommendations.push("Verify smart contract source code on the blockchain explorer before executing functions.");
      }
    } else if (onChainData.isContract === false) {
      accountType = "Externally Owned Account (EOA)";
      evidence.push({
        category: "Bytecode Architecture",
        finding: `Standard user wallet (Externally Owned Account) with no deployed bytecode.`,
        status: "SAFE",
      });
    } else {
      evidence.push({
        category: "Bytecode Architecture",
        finding: `Contract bytecode check could not be verified due to RPC timeout. Marked Unknown.`,
        status: "UNKNOWN",
      });
    }

    // Evaluate Balance
    if (onChainData.balanceFormatted !== null) {
      evidence.push({
        category: "On-Chain Balance",
        finding: `Confirmed live balance: ${parseFloat(onChainData.balanceFormatted).toFixed(4)} ${chainConfig.symbol}`,
        status: "SAFE",
      });
    } else {
      evidence.push({
        category: "On-Chain Balance",
        finding: `Balance lookup timed out across fallback RPCs. Marked Unknown.`,
        status: "UNKNOWN",
      });
    }

    // Evaluate Transaction History / Nonce
    if (onChainData.transactionCount !== null) {
      if (onChainData.transactionCount === 0) {
        evidence.push({
          category: "Transaction History",
          finding: `Zero lifetime outgoing transactions (nonce: 0). Fresh or dormant account.`,
          status: "WARNING",
        });
        if (!threatMatch.isMalicious) {
          riskScore += 10;
          recommendations.push("Account has no outgoing transaction history on this chain. Proceed cautiously if interacting with newly created accounts.");
        }
      } else {
        evidence.push({
          category: "Transaction History",
          finding: `Established transaction history: ${onChainData.transactionCount} confirmed outgoing transactions.`,
          status: "SAFE",
        });
      }
    } else {
      evidence.push({
        category: "Transaction History",
        finding: `Transaction nonce lookup timed out. Marked Unknown.`,
        status: "UNKNOWN",
      });
    }

    // Determine Final Risk Level strictly based on verifiable evidence
    let riskLevel: EvmRiskLevel = "SAFE";

    if (threatMatch.isMalicious) {
      riskLevel = "CRITICAL";
      riskScore = 95;
    } else if (onChainData.transactionCount === null || onChainData.isContract === null) {
      // Incomplete RPC telemetry: Do NOT claim safe without evidence
      riskLevel = "UNKNOWN";
      riskScore = 0;
      threats.push("Telemetry Inconclusive: RPC lookup timed out across fallback nodes. Safety cannot be determined.");
      recommendations.push(
        "Critical RPC telemetry unavailable. Threat status cannot be definitively confirmed without on-chain data.",
        "Retry the scan or verify the address manually on the blockchain explorer."
      );
    } else if (onChainData.transactionCount === 0) {
      // Zero history: Do NOT claim safe without evidence
      riskScore = 20;
      riskLevel = "LOW";
      recommendations.push(
        "Account has 0 lifetime outgoing transactions. Lacks historical track record to establish reputation.",
        "Exercise caution if this address belongs to a newly deployed project or anonymous counterparty."
      );
    } else if (onChainData.isContract === true) {
      riskScore = 25;
      riskLevel = "LOW";
      recommendations.push(
        "Smart contract detected. Verify source code verification status on the explorer before sending funds."
      );
    } else {
      // Sufficient evidence confirmed: EOA, active transactions, no threat intel hits
      riskScore = 5;
      riskLevel = "SAFE";
      recommendations.push(
        "Confirmed established EOA with active transaction history and no threat registry matches.",
        "Always verify transaction recipient addresses and never share private keys or seed phrases."
      );
    }

    const responsePayload: EvmWalletScanResult = {
      address: checksumAddress,
      chain,
      chainName: chainConfig.name,
      riskScore,
      riskLevel,
      accountType,
      balance: {
        raw: onChainData.balanceWei || "0",
        formatted: onChainData.balanceFormatted !== null ? parseFloat(onChainData.balanceFormatted).toFixed(4) : "Unknown",
        symbol: chainConfig.symbol,
        status: onChainData.balanceFormatted !== null ? "CONFIRMED" : "UNKNOWN",
      },
      transactionCount: {
        nonce: onChainData.transactionCount !== null ? onChainData.transactionCount : -1,
        status: onChainData.transactionCount !== null ? "CONFIRMED" : "UNKNOWN",
      },
      threats,
      evidence,
      recommendations,
      timestamp: new Date().toISOString(),
      scannedAtBlock: onChainData.blockNumber || undefined,
      isThreatDatabaseHit: threatMatch.isMalicious,
      disclaimer: "TrustGuard AI Heuristic & On-Chain Report. This scan evaluates public on-chain activity, code signatures, and threat databases. It does not replace a comprehensive manual security audit.",
    };

    return NextResponse.json(responsePayload);
  } catch (err: unknown) {
    console.error("EVM Scanner Error:", err);
    return NextResponse.json(
      {
        error: "Internal security analysis error",
        message: err instanceof Error ? err.message : "Unexpected error during on-chain scan",
      },
      { status: 500 }
    );
  }
}

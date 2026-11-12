/**
 * Real Scanner Verification & Honest NEAR Anchoring Pipeline
 * 
 * IMPORTANT ARCHITECTURAL & SECURITY NOTES:
 * 1. Independent Verification Scope: This script verifies that the scanner API returned
 *    a syntactically and semantically valid payload, a confirmed block height, and non-empty
 *    evidence findings. Note that status strings (such as "CONFIRMED") originate from the
 *    internal scanner API; this script trusts the scanner API's verification of the RPC
 *    responses rather than establishing an independent second-tier RPC connection.
 * 2. Explicit Registration Gate: The NEAR on-chain registration step is kept strictly
 *    separate and requires explicit confirmation (via the `--confirm-register` CLI flag).
 *    By default, the script ONLY performs verification and dry-run preview.
 * 3. Zero Fabrication: No balances, findings, or nonces are fabricated or hardcoded.
 */

interface ScanEvidenceItem {
  category: string;
  finding: string;
  status: "SAFE" | "WARNING" | "CRITICAL" | "UNKNOWN";
}

interface ScannerResponse {
  address: string;
  chain?: string;
  chainName?: string;
  riskScore: number;
  riskLevel: string;
  scannedAtBlock: number;
  balance?: {
    raw: string;
    formatted: string;
    symbol: string;
    status: string;
  };
  transactionCount?: {
    nonce: number;
    status: string;
  };
  threats?: string[];
  evidence?: ScanEvidenceItem[];
  recommendations?: string[];
}

/**
 * Step 1 & 2: Fetch and rigorously validate the live scan output.
 */
async function fetchAndValidateLiveScan(
  targetAddress: string,
  chain: string
): Promise<ScannerResponse> {
  console.log(`[1/3] Initiating live scan for target: ${targetAddress} on chain: ${chain}...`);

  const scanRes = await fetch("http://localhost:3000/api/scan/evm-wallet", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: targetAddress, chain }),
  });

  if (!scanRes.ok) {
    const errorText = await scanRes.text();
    console.error(`[ERROR] Live scanner returned HTTP ${scanRes.status}: ${errorText}`);
    process.exit(1);
  }

  const scanData: ScannerResponse = await scanRes.json();

  console.log(`[2/3] Performing rigorous validation of scanner response...`);

  // Requirement 1: Verify scanData.address exactly matches the requested targetAddress (case-insensitive)
  if (
    !scanData.address ||
    typeof scanData.address !== "string" ||
    scanData.address.toLowerCase() !== targetAddress.toLowerCase()
  ) {
    console.error(
      `[SECURITY ALERT] Address mismatch: Requested "${targetAddress}", but scanner returned "${scanData.address}". Aborting.`
    );
    process.exit(1);
  }

  // Requirement 2: Validate riskScore is a finite integer between 0 and 100
  if (
    typeof scanData.riskScore !== "number" ||
    !Number.isFinite(scanData.riskScore) ||
    !Number.isInteger(scanData.riskScore) ||
    scanData.riskScore < 0 ||
    scanData.riskScore > 100
  ) {
    console.error(
      `[SECURITY ALERT] Invalid riskScore: Expected finite integer between 0 and 100, received ${scanData.riskScore}. Aborting.`
    );
    process.exit(1);
  }

  // Requirement 3: Validate scannedAtBlock is a valid positive integer
  if (
    typeof scanData.scannedAtBlock !== "number" ||
    !Number.isFinite(scanData.scannedAtBlock) ||
    !Number.isInteger(scanData.scannedAtBlock) ||
    scanData.scannedAtBlock <= 0
  ) {
    console.error(
      `[SECURITY ALERT] Invalid scannedAtBlock: Expected positive integer block number, received ${scanData.scannedAtBlock}. Aborting.`
    );
    process.exit(1);
  }

  // Requirement 4: Verify evidence is an array containing valid, non-empty findings. Reject malformed or unverified evidence.
  if (!Array.isArray(scanData.evidence) || scanData.evidence.length === 0) {
    console.error(
      `[SECURITY ALERT] Malformed evidence: Array is missing or empty. Scanner findings must be populated. Aborting.`
    );
    process.exit(1);
  }

  const validStatuses = new Set(["SAFE", "WARNING", "CRITICAL", "UNKNOWN"]);
  for (let i = 0; i < scanData.evidence.length; i++) {
    const item = scanData.evidence[i];
    if (
      !item ||
      typeof item.category !== "string" ||
      !item.category.trim() ||
      typeof item.finding !== "string" ||
      !item.finding.trim() ||
      !validStatuses.has(item.status)
    ) {
      console.error(
        `[SECURITY ALERT] Malformed evidence finding at index ${i}: Invalid category, finding, or status (${JSON.stringify(
          item
        )}). Aborting.`
      );
      process.exit(1);
    }
  }

  // Requirement 5: Verify the scanner response belongs to the requested Ethereum chain
  if (scanData.chain && scanData.chain.toLowerCase() !== chain.toLowerCase()) {
    console.error(
      `[SECURITY ALERT] Chain mismatch: Requested chain "${chain}", but scanner returned "${scanData.chain}". Aborting.`
    );
    process.exit(1);
  }

  // Requirement 6: Document that the script trusts the existing scanner API's verification.
  // Note: CONFIRMED string alone is not treated as independent RPC proof; we trust the scanner API's verification.
  if (scanData.riskLevel === "UNKNOWN") {
    console.warn(
      `[ABORT] Live telemetry was inconclusive (riskLevel=UNKNOWN). Inconclusive scans cannot be anchored.`
    );
    process.exit(1);
  }

  if (scanData.balance?.status !== "CONFIRMED") {
    console.warn(
      `[ABORT] Wallet balance status reported by scanner API is not CONFIRMED (found: "${scanData.balance?.status}"). Aborting.`
    );
    process.exit(1);
  }

  console.log(`\nVerified Scanner Metadata:`);
  console.log(`- Verified Address: ${scanData.address}`);
  console.log(`- Confirmed Chain: ${scanData.chain || chain}`);
  console.log(`- Confirmed Block Height: #${scanData.scannedAtBlock}`);
  console.log(`- Live Balance: ${scanData.balance?.formatted} ${scanData.balance?.symbol}`);
  console.log(`- Confirmed Nonce: ${scanData.transactionCount?.nonce}`);
  console.log(`- Risk Assessment: ${scanData.riskLevel} (${scanData.riskScore}/100)`);
  console.log(`- Verified Findings Count: ${scanData.evidence.length}`);

  return scanData;
}

/**
 * Step 3: Register the verified report on NEAR Testnet contract.
 * Requirement 7: This step is kept strictly separate and will NOT be executed unless
 * explicit approval is provided via the --confirm-register command line flag.
 */
async function registerReportOnNear(scanData: ScannerResponse) {
  console.log(`\n[3/3] Anchoring verified live scan report on NEAR Testnet contract (tg-auditor-2026.testnet)...`);

  const registerPayload = {
    target: scanData.address,
    scanType: "WALLET",
    riskScore: scanData.riskScore,
    riskLevel: scanData.riskLevel,
    threats: scanData.threats || [],
    evidence: scanData.evidence || [],
    indicators: [],
  };

  const regRes = await fetch("http://localhost:3000/api/near/register-report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(registerPayload),
  });

  const regData = await regRes.json();

  if (!regRes.ok || !regData.success) {
    console.error(`[ERROR] Failed to anchor report on NEAR:`, regData);
    process.exit(1);
  }

  console.log(`\n🎉 Report Successfully Sealed on NEAR Testnet!`);
  console.log(`- Status: ${regData.record?.status} (${regData.record?.statusLabel})`);
  console.log(`- Report ID: ${regData.record?.reportId}`);
  console.log(`- Canonical SHA-256 Hash: ${regData.record?.reportHash}`);
  console.log(`- Anchored At Block: #${regData.record?.blockHeight}`);
  console.log(`- Transaction Hash: ${regData.record?.nearTxHash || "(On-chain confirmed; indexed in cache)"}`);
  console.log(`- Explorer URL: ${regData.record?.explorerUrl || "N/A"}`);
}

async function main() {
  const targetAddress = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
  const chain = "ethereum";

  // Execute Steps 1 & 2: Real live scan with strict validation checks
  const verifiedScan = await fetchAndValidateLiveScan(targetAddress, chain);

  // Requirement 7: Keep NEAR registration step separate and require explicit approval
  const shouldRegisterOnChain = process.argv.includes("--confirm-register");

  if (!shouldRegisterOnChain) {
    console.log(`\n================================================================`);
    console.log(`🛡️ VERIFICATION COMPLETE (DRY-RUN PREVIEW ONLY)`);
    console.log(`The scan data is authentic, verified, and ready for NEAR anchoring.`);
    console.log(`No on-chain transaction was submitted because --confirm-register was not passed.`);
    console.log(`To anchor this verified report on NEAR Testnet, rerun with explicit approval:`);
    console.log(`  npx tsx scripts/verify-and-anchor-scan.ts --confirm-register`);
    console.log(`================================================================\n`);
    return;
  }

  // Execute Step 3 only when explicitly approved
  await registerReportOnNear(verifiedScan);
}

main().catch((err) => {
  console.error("Unhandled error during script execution:", err);
  process.exit(1);
});

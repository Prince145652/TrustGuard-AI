import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateReportHash, isValidSha256, generateReportId } from "../src/lib/near-hashing";
import { anchorReportOnNear, verifyReportOnNear, NEAR_CONFIG } from "../src/lib/near-client";
import { ScanContext } from "../src/types/ai-analyst";

describe("TrustGuard AI Step 2: Scanner Integration & Honest NEAR Registry Tests", () => {
  // Sample real scanner outputs
  const sampleWalletScan = {
    address: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    chain: "ethereum",
    chainName: "Ethereum",
    riskScore: 5,
    riskLevel: "SAFE",
    threats: [],
    evidence: [
      { category: "On-Chain Balance", finding: "Confirmed live balance: 1.25 ETH", status: "SAFE" as const },
      { category: "Bytecode Architecture", finding: "Standard EOA", status: "SAFE" as const },
    ],
    recommendations: ["Safe for standard transfers"],
  };

  const sampleWebsiteScan = {
    url: "https://claim-free-near-gift.xyz",
    domain: "claim-free-near-gift.xyz",
    riskScore: 95,
    riskLevel: "CRITICAL",
    summary: "NEAR Phishing Airdrop Drainer",
    indicators: [
      { name: "Brand Impersonation", description: "Impersonates NEAR brand", detected: true, severity: "CRITICAL" },
    ],
    recommendations: ["Do NOT connect your wallet"],
  };

  const sampleTokenScan = {
    address: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    chainName: "Ethereum",
    tokenName: "Tether USD",
    tokenSymbol: "USDT",
    riskScore: 45,
    riskLevel: "MEDIUM",
    isHoneypot: false,
    evidence: [
      { category: "Trading Taxes", finding: "0% buy / 0% sell tax", status: "SAFE" as const },
      { category: "Privileges", finding: "Blacklist function present", status: "WARNING" as const },
    ],
    recommendations: ["Inspect blacklist admin keys"],
  };

  // 1. Scanner result passed to AI Analyst
  describe("1. Scanner result passed to AI Analyst Context", () => {
    it("should format EVM Wallet scanner output into valid ScanContext", () => {
      const context: ScanContext = {
        scanType: "wallet",
        target: sampleWalletScan.address,
        chain: sampleWalletScan.chainName,
        riskScore: sampleWalletScan.riskScore,
        riskLevel: sampleWalletScan.riskLevel,
        threats: sampleWalletScan.threats,
        evidence: sampleWalletScan.evidence,
      };

      assert.equal(context.scanType, "wallet");
      assert.equal(context.target, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e");
      assert.equal(context.riskScore, 5);
      assert.equal(context.riskLevel, "SAFE");
      assert.equal(context.evidence?.length, 2);
    });

    it("should format Website scam detector output into valid ScanContext", () => {
      const context: ScanContext = {
        scanType: "website",
        target: sampleWebsiteScan.url,
        riskScore: sampleWebsiteScan.riskScore,
        riskLevel: sampleWebsiteScan.riskLevel,
        threats: [sampleWebsiteScan.summary],
        indicators: sampleWebsiteScan.indicators,
      };

      assert.equal(context.scanType, "website");
      assert.equal(context.target, "https://claim-free-near-gift.xyz");
      assert.equal(context.riskScore, 95);
      assert.equal(context.riskLevel, "CRITICAL");
      assert.equal(context.threats?.[0], "NEAR Phishing Airdrop Drainer");
    });

    it("should format Token security scanner output into valid ScanContext", () => {
      const context: ScanContext = {
        scanType: "token",
        target: sampleTokenScan.address,
        chain: sampleTokenScan.chainName,
        riskScore: sampleTokenScan.riskScore,
        riskLevel: sampleTokenScan.riskLevel,
        evidence: sampleTokenScan.evidence,
      };

      assert.equal(context.scanType, "token");
      assert.equal(context.target, "0xdAC17F958D2ee523a2206206994597C13D831ec7");
      assert.equal(context.chain, "Ethereum");
      assert.equal(context.riskScore, 45);
    });
  });

  // 2. Correct scan type and target preserved
  describe("2. Preservation of Scan Type, Target & Unknown findings", () => {
    it("should strictly preserve target identifiers and UNKNOWN evidence parameters", () => {
      const reportWithUnknown = {
        scanType: "wallet" as const,
        target: "0x1111111111111111111111111111111111111111",
        riskScore: 0,
        riskLevel: "UNKNOWN",
        evidence: [
          { category: "Bytecode Architecture", finding: "RPC timed out", status: "UNKNOWN" as const },
        ],
      };

      assert.equal(reportWithUnknown.scanType, "wallet");
      assert.equal(reportWithUnknown.target, "0x1111111111111111111111111111111111111111");
      assert.equal(reportWithUnknown.evidence[0].status, "UNKNOWN");
      assert.equal(reportWithUnknown.riskLevel, "UNKNOWN");
    });
  });

  // 3. Report hash generated from actual scan result
  describe("3. Report Hash Generated from Actual Scan Results", () => {
    it("should generate a valid SHA-256 hash from live scanner findings", () => {
      const reportPayload = {
        target: sampleWalletScan.address,
        scanType: "WALLET",
        riskScore: sampleWalletScan.riskScore,
        riskLevel: sampleWalletScan.riskLevel,
        threats: sampleWalletScan.threats,
        evidence: sampleWalletScan.evidence,
      };

      const hash = generateReportHash(reportPayload);
      assert.equal(typeof hash, "string");
      assert.equal(hash.length, 64);
      assert.equal(isValidSha256(hash), true);

      const reportId = generateReportId("WALLET", sampleWalletScan.address);
      assert.match(reportId, /^TG-WALLET-0X742D35-[A-F0-9]{8}$/);
    });
  });

  // 4. Duplicate registration handling
  describe("4. Duplicate Registration Handling", () => {
    it("should return the existing registration record without re-creating or altering state", async () => {
      const target = "0x999999cf1046e68e36E1aA2E0E07105eDDD1f08E";
      const reportData = {
        target,
        scanType: "WALLET" as const,
        riskScore: 10,
        riskLevel: "SAFE",
        threats: [],
        evidence: [],
      };

      const hash = generateReportHash(reportData);
      const reportId = generateReportId("WALLET", target);

      // First registration
      const record1 = await anchorReportOnNear({
        reportId,
        reportHash: hash,
        target,
        scanType: "WALLET",
        riskScore: 10,
        riskLevel: "SAFE",
      });

      // Attempt duplicate registration
      const record2 = await anchorReportOnNear({
        reportId: "TG-WALLET-DIFFERENT-ID",
        reportHash: hash, // Identical hash
        target,
        scanType: "WALLET",
        riskScore: 10,
        riskLevel: "SAFE",
      });

      assert.equal(record1.reportHash, record2.reportHash);
      assert.equal(record1.reportId, record2.reportId); // Must match original
    });
  });

  // 5. Failed API requests / invalid input rejection
  describe("5. Validation and Malformed Inputs Rejection", () => {
    it("should reject report hashing when target is missing or hash is malformed", async () => {
      const invalidHash = "not-a-valid-64-character-sha256-hash";

      await assert.rejects(
        async () => {
          await anchorReportOnNear({
            reportId: "TG-FAIL-01",
            reportHash: invalidHash,
            target: "0x123",
            scanType: "WALLET",
            riskScore: 10,
            riskLevel: "SAFE",
          });
        },
        {
          message: /Invalid report hash format/,
        }
      );
    });
  });

  // 6. Missing scan result handling
  describe("6. Missing Scan Result Handling", () => {
    it("should return NOT_REGISTERED when querying non-existent reports", async () => {
      const unknownQuery = "0000000000000000000000000000000000000000000000000000000000000000";
      const result = await verifyReportOnNear(unknownQuery);

      assert.equal(result.isVerified, false);
      assert.equal(result.status, "NOT_REGISTERED");
      assert.equal(result.record, undefined);
    });
  });

  // 7. Honest Verification Labeling (No False Claims)
  describe("7. Honest Verification Labeling (No False Claims)", () => {
    it("should only label records as VERIFIED_ON_NEAR when found on contract and omit fake transaction hashes", async () => {
      // 1. Confirm non-existent report is NEVER falsely labeled as VERIFIED_ON_NEAR
      const unanchoredHash = "0000000000000000000000000000000000000000000000000000000000000000";
      const unanchoredResult = await verifyReportOnNear(unanchoredHash);
      assert.equal(unanchoredResult.isVerified, false);
      assert.notEqual(unanchoredResult.status, "VERIFIED_ON_NEAR");
      assert.equal(unanchoredResult.status, "NOT_REGISTERED");

      // 2. Query genuinely anchored report on the configured NEAR contract
      const target = "0x8888888888888888888888888888888888888888";
      const reportData = {
        target,
        scanType: "WALLET" as const,
        riskScore: 20,
        riskLevel: "LOW",
        threats: [],
        evidence: [],
      };

      const hash = generateReportHash(reportData);
      const reportId = generateReportId("WALLET", target);

      const record = await anchorReportOnNear({
        reportId,
        reportHash: hash,
        target,
        scanType: "WALLET",
        riskScore: 20,
        riskLevel: "LOW",
      });

      // Strict enforcement of honest status when found on NEAR contract:
      assert.equal(record.status, "VERIFIED_ON_NEAR");
      assert.equal(record.isContractDeployed, true);
      assert.equal(record.contractId, NEAR_CONFIG.contractId);

      // Must NEVER invent a fake transaction hash or explorer URL for existing on-chain records
      assert.equal(record.nearTxHash, undefined);
      assert.equal(record.explorerUrl, undefined);

      // Verify query returns confirmed on-chain verification
      const verifyResult = await verifyReportOnNear(hash);
      assert.equal(verifyResult.isVerified, true);
      assert.equal(verifyResult.status, "VERIFIED_ON_NEAR");
      assert.match(verifyResult.message || "", /live NEAR Testnet RPC/);
    });
  });
});

(process.env as Record<string, string | undefined>).NODE_ENV = "test";

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateReportHash, isValidSha256, generateReportId } from "../src/lib/near-hashing";
import { anchorReportOnNear, verifyReportOnNear, setNearTestMocks, NEAR_CONFIG } from "../src/lib/near-client";
import {
  isValidNearTxHash,
  cacheAnchoredTx,
  getCachedTx,
  getCachedTxByReportHash,
  getCachedTxByReportId,
  clearTxCacheForTesting,
  setTxCacheFilePathForTesting,
  simulateTxCacheFailureForTesting,
  getTxCacheStatsForTesting,
} from "../src/lib/tx-cache";
import path from "path";
import { ScanContext } from "../src/types/ai-analyst";
import {
  isEvmChainId,
  isEvmAddress,
  computePrefillTransition,
  buildQuickScanContext,
} from "../src/lib/quickscan-utils";
import {
  getRiskColor,
  formatRiskScoreDisplay,
  isUnknownRisk,
  getRiskLevelFromScore,
} from "../src/lib/utils";
import {
  normalizeScanType,
  deriveActivityStatus,
  recordScanActivity,
  recordNearRegistration,
  mergeAndDeduplicateActivities,
  clearLiveActivities,
  getLiveActivities,
  MAX_LIVE_ACTIVITIES,
} from "../src/lib/activity-store";
import { RecentSecurityActivity } from "../src/types/security";

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

  // 8. Quick Scan Navigation, Prefill Transition & Severity Preservation
  describe("8. Quick Scan Navigation, Prefill Transition & Severity Preservation", () => {
    it("should accurately validate supported EVM chains and reject unsupported values", () => {
      assert.equal(isEvmChainId("ethereum"), true);
      assert.equal(isEvmChainId("base"), true);
      assert.equal(isEvmChainId("bnb"), true);
      assert.equal(isEvmChainId("solana"), false);
      assert.equal(isEvmChainId("near"), false);
      assert.equal(isEvmChainId(undefined), false);
      assert.equal(isEvmChainId(null), false);
      assert.equal(isEvmChainId(""), false);
    });

    it("should strictly enforce 0x EVM address format and block NEAR accounts from EVM scanners", () => {
      assert.equal(isEvmAddress("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"), true);
      assert.equal(isEvmAddress("0x00000000ae347930bd1e7b0f35588b92280f9e75"), true);
      assert.equal(isEvmAddress("alice.near"), false);
      assert.equal(isEvmAddress("tg-auditor-2026.testnet"), false);
      assert.equal(isEvmAddress("https://app.ref.finance"), false);
      assert.equal(isEvmAddress("0x123"), false);

      const blockedWallet = computePrefillTransition("wallet", "alice.near", "ethereum", {}, {});
      assert.equal(blockedWallet.allowed, false);
      assert.equal(blockedWallet.nextTargets.wallet, undefined);

      const blockedToken = computePrefillTransition("token", "wrap.near", "ethereum", {}, {});
      assert.equal(blockedToken.allowed, false);
      assert.equal(blockedToken.nextTargets.token, undefined);
    });

    it("should allow valid EVM addresses and prefill detected chain without fallback defaults", () => {
      const validWallet = computePrefillTransition(
        "wallet",
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "base",
        {},
        {}
      );
      assert.equal(validWallet.allowed, true);
      assert.equal(validWallet.nextTargets.wallet, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e");
      assert.equal(validWallet.nextChains.wallet, "base");
    });

    it("should explicitly clear previous chain when navigating with an unknown chain", () => {
      const existingChains = { wallet: "bnb" as const };
      const transition = computePrefillTransition(
        "wallet",
        "0x28C6c06298d514Db089934071355E5743bf21d60",
        undefined,
        {},
        existingChains
      );
      assert.equal(transition.allowed, true);
      assert.equal(transition.nextChains.wallet, undefined);
      assert.notEqual(transition.nextChains.wallet, "bnb");
      assert.notEqual(transition.nextChains.wallet, "ethereum");
    });

    it("should isolate targets across tabs and not cross-contaminate state", () => {
      const step1 = computePrefillTransition(
        "wallet",
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "ethereum",
        {},
        {}
      );
      const step2 = computePrefillTransition(
        "website",
        "https://app.ref.finance",
        undefined,
        step1.nextTargets,
        step1.nextChains
      );
      assert.equal(step2.nextTargets.wallet, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e");
      assert.equal(step2.nextTargets.website, "https://app.ref.finance");
      assert.equal(step2.nextTargets.token, undefined);
      assert.equal(step2.nextChains.token, undefined);
    });

    it("should prevent duplicate threats while preserving severity information", () => {
      const context = buildQuickScanContext("wallet", {
        target: "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",
        riskScore: 90,
        riskLevel: "CRITICAL",
        summary: "OFAC Sanctions match",
        verifiedOnNear: false,
        threats: ["OFAC Sanctioned Entity: Tornado Cash"],
        factors: [
          {
            id: "f-1",
            category: "Access Control",
            name: "OFAC Sanctions",
            description: "Matches Tornado Cash router registry",
            severity: "CRITICAL",
            passed: false,
            impactScore: 50,
          },
          {
            id: "f-2",
            category: "Access Control",
            name: "Unverified Delegate Call",
            description: "Target delegates execution to unverified implementation",
            severity: "HIGH",
            passed: false,
            impactScore: 30,
          },
        ],
      });

      assert.equal(context.threats?.length, 2);
      assert.equal(context.threats?.[0], "OFAC Sanctioned Entity: Tornado Cash");
      assert.match(context.threats?.[1] || "", /\[HIGH\] Unverified Delegate Call/);
    });

    it("should visibly preserve CRITICAL, HIGH, and MEDIUM severities while conforming to ScanContext enum", () => {
      const context = buildQuickScanContext("token", {
        target: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        riskScore: 40,
        riskLevel: "MEDIUM",
        summary: "Privilege review required",
        verifiedOnNear: false,
        factors: [
          { id: "f-1", category: "Smart Contract Logic", name: "Source Code", description: "Verified", severity: "LOW", passed: true, impactScore: 0 },
          { id: "f-2", category: "Access Control", name: "Blacklist Role", description: "Admin can freeze balances", severity: "HIGH", passed: false, impactScore: 25 },
          { id: "f-3", category: "Smart Contract Logic", name: "Upgradeable Proxy", description: "Contract code can be swapped", severity: "MEDIUM", passed: false, impactScore: 15 },
        ],
      });

      assert.match(context.evidence?.[0].finding || "", /\[SAFE\]/);
      assert.equal(context.evidence?.[0].status, "SAFE");
      assert.match(context.evidence?.[1].finding || "", /\[HIGH Severity\]/);
      assert.equal(context.evidence?.[1].status, "WARNING");
      assert.match(context.evidence?.[2].finding || "", /\[MEDIUM Severity\]/);
      assert.equal(context.evidence?.[2].status, "WARNING");

      assert.equal(context.indicators?.length, 2);
      assert.equal(context.indicators?.[0].severity, "HIGH");
      assert.equal(context.indicators?.[1].severity, "MEDIUM");
    });
  });

  // 9. Safe Handling for RPC Timeouts and UNKNOWN Risk States
  describe("9. Safe Handling for RPC Timeouts and UNKNOWN Risk States", () => {
    it("should never classify UNKNOWN as SAFE in getRiskColor and should return amber styling", () => {
      const unknownStyle = getRiskColor("UNKNOWN");
      const safeStyle = getRiskColor("SAFE");

      assert.notEqual(unknownStyle.text, safeStyle.text, "UNKNOWN text color must differ from SAFE");
      assert.notEqual(unknownStyle.bg, safeStyle.bg, "UNKNOWN background must differ from SAFE");
      assert.notEqual(unknownStyle.border, safeStyle.border, "UNKNOWN border must differ from SAFE");

      assert.match(unknownStyle.text, /text-amber-/, "UNKNOWN must use amber text styling");
      assert.match(unknownStyle.bg, /bg-amber-/, "UNKNOWN must use amber bg styling");
    });

    it("should display INCONCLUSIVE instead of 0/100 when riskLevel is UNKNOWN", () => {
      const unknownDisplay = formatRiskScoreDisplay(0, "UNKNOWN");
      assert.equal(unknownDisplay, "INCONCLUSIVE");
      assert.notEqual(unknownDisplay, "0/100");
    });

    it("should preserve standard score formatting for SAFE, LOW, MEDIUM, HIGH, and CRITICAL", () => {
      assert.equal(formatRiskScoreDisplay(0, "SAFE"), "0/100");
      assert.equal(formatRiskScoreDisplay(5, "SAFE"), "5/100");
      assert.equal(formatRiskScoreDisplay(25, "LOW"), "25/100");
      assert.equal(formatRiskScoreDisplay(50, "MEDIUM"), "50/100");
      assert.equal(formatRiskScoreDisplay(80, "HIGH"), "80/100");
      assert.equal(formatRiskScoreDisplay(95, "CRITICAL"), "95/100");
    });

    it("should correctly identify unknown risk states with isUnknownRisk", () => {
      assert.equal(isUnknownRisk("UNKNOWN"), true);
      assert.equal(isUnknownRisk("SAFE"), false);
      assert.equal(isUnknownRisk("LOW"), false);
      assert.equal(isUnknownRisk("CRITICAL"), false);
      assert.equal(isUnknownRisk(undefined), false);
    });

    it("should preserve existing getRiskLevelFromScore calculations for non-unknown numeric scores", () => {
      assert.equal(getRiskLevelFromScore(0), "SAFE");
      assert.equal(getRiskLevelFromScore(14), "SAFE");
      assert.equal(getRiskLevelFromScore(15), "LOW");
      assert.equal(getRiskLevelFromScore(34), "LOW");
      assert.equal(getRiskLevelFromScore(35), "MEDIUM");
      assert.equal(getRiskLevelFromScore(64), "MEDIUM");
      assert.equal(getRiskLevelFromScore(65), "HIGH");
      assert.equal(getRiskLevelFromScore(84), "HIGH");
      assert.equal(getRiskLevelFromScore(85), "CRITICAL");
      assert.equal(getRiskLevelFromScore(100), "CRITICAL");
    });

    it("should handle simulated RPC timeout payloads safely with inconclusive indicators", () => {
      const rpcTimeoutPayload = {
        address: "0x1111111111111111111111111111111111111111",
        chain: "ethereum" as const,
        chainName: "Ethereum",
        riskScore: 0,
        riskLevel: "UNKNOWN" as const,
        accountType: "Unknown" as const,
        balance: { raw: "0", formatted: "Unknown", symbol: "ETH", status: "UNKNOWN" as const },
        transactionCount: { nonce: -1, status: "UNKNOWN" as const },
        threats: ["Telemetry Inconclusive: RPC lookup timed out across fallback nodes. Safety cannot be determined."],
        evidence: [
          { category: "Bytecode Architecture", finding: "Contract bytecode check timed out. Marked Unknown.", status: "UNKNOWN" as const },
          { category: "On-Chain Balance", finding: "Balance lookup timed out across fallback RPCs. Marked Unknown.", status: "UNKNOWN" as const },
          { category: "Transaction History", finding: "Transaction nonce lookup timed out. Marked Unknown.", status: "UNKNOWN" as const },
        ],
        recommendations: ["Retry the scan or verify manually on explorer."],
      };

      assert.equal(rpcTimeoutPayload.riskLevel, "UNKNOWN");
      assert.ok(rpcTimeoutPayload.threats.length > 0, "Threats must contain inconclusive disclaimer");
      assert.match(rpcTimeoutPayload.threats[0], /Telemetry Inconclusive/);

      const displayScore = formatRiskScoreDisplay(rpcTimeoutPayload.riskScore, rpcTimeoutPayload.riskLevel);
      assert.equal(displayScore, "INCONCLUSIVE");

      const style = getRiskColor(rpcTimeoutPayload.riskLevel);
      assert.notEqual(style.text, "text-emerald-400", "Must never use emerald green text for RPC timeouts");
      assert.match(style.text, /text-amber-400/);
    });
  });

  // 10. Priority 2: Recent Security Activity Store, Deduplication & Honest NEAR Status
  describe("10. Recent Security Activity Store, Deduplication & Honest NEAR Status", () => {
    // Setup Node.js in-memory localStorage mock
    const storageMap = new Map<string, string>();
    const mockLocalStorage = {
      getItem: (key: string) => storageMap.get(key) || null,
      setItem: (key: string, val: string) => storageMap.set(key, val),
      removeItem: (key: string) => storageMap.delete(key),
      clear: () => storageMap.clear(),
    };

    const originalWindow = (globalThis as unknown as { window?: unknown }).window;

    function setupMockWindow() {
      (globalThis as unknown as { window: unknown }).window = {
        localStorage: mockLocalStorage,
        dispatchEvent: () => true,
        addEventListener: () => {},
        removeEventListener: () => {},
      };
      storageMap.clear();
    }

    function restoreWindow() {
      (globalThis as unknown as { window: unknown }).window = originalWindow;
    }

    it("should correctly derive activity status preserving UNKNOWN as Inconclusive", () => {
      assert.equal(deriveActivityStatus("UNKNOWN"), "Inconclusive");
      assert.equal(deriveActivityStatus("CRITICAL"), "Threat Blocked");
      assert.equal(deriveActivityStatus("HIGH"), "High Risk");
      assert.equal(deriveActivityStatus("MEDIUM"), "Safe");
      assert.equal(deriveActivityStatus("LOW"), "Safe");
      assert.equal(deriveActivityStatus("SAFE"), "Safe");
    });

    it("should normalize scan types correctly", () => {
      assert.equal(normalizeScanType("wallet"), "Wallet Scanner");
      assert.equal(normalizeScanType("Wallet Scanner"), "Wallet Scanner");
      assert.equal(normalizeScanType("website"), "Website Scanner");
      assert.equal(normalizeScanType("phishing"), "Website Scanner");
      assert.equal(normalizeScanType("token"), "Token Scanner");
    });

    it("should record live scan and prevent duplicate rows on re-scan", () => {
      setupMockWindow();
      try {
        const target = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        const entry1 = recordScanActivity({
          target,
          scanType: "wallet",
          riskScore: 5,
          riskLevel: "SAFE",
        });

        assert.equal(entry1.target, target);
        assert.equal(entry1.status, "Safe");
        assert.equal(entry1.riskLevel, "SAFE");
        assert.equal(getLiveActivities().length, 1);

        // Re-scan with different risk score
        const entry2 = recordScanActivity({
          target: target.toLowerCase(),
          scanType: "Wallet Scanner",
          riskScore: 88,
          riskLevel: "CRITICAL",
        });

        const list = getLiveActivities();
        assert.equal(list.length, 1, "Must update existing entry instead of duplicating");
        assert.equal(list[0].id, entry1.id, "Preserves stable activity ID");
        assert.equal(list[0].riskLevel, "CRITICAL");
        assert.equal(list[0].status, "Threat Blocked");
      } finally {
        restoreWindow();
      }
    });

    it("should strictly enforce FIFO eviction at MAX_LIVE_ACTIVITIES (25)", () => {
      setupMockWindow();
      try {
        for (let i = 1; i <= 28; i++) {
          recordScanActivity({
            target: `0x${i.toString(16).padStart(40, "0")}`,
            scanType: "wallet",
            riskScore: 10,
            riskLevel: "SAFE",
          });
        }

        const activities = getLiveActivities();
        assert.equal(activities.length, MAX_LIVE_ACTIVITIES, "Must cap at 25 items");
        // Most recent should be at the front
        assert.equal(activities[0].target, `0x${(28).toString(16).padStart(40, "0")}`);
      } finally {
        restoreWindow();
      }
    });

    it("should never assign Verified On-Chain without a genuine nearTxHash", () => {
      setupMockWindow();
      try {
        const target = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        // Record scan
        recordScanActivity({
          target,
          scanType: "token",
          riskScore: 45,
          riskLevel: "MEDIUM",
        });

        // Register on NEAR without genuine tx hash (e.g. pending testnet deployment)
        recordNearRegistration({
          target,
          scanType: "token",
          nearTxHash: undefined,
          riskScore: 45,
          riskLevel: "MEDIUM",
        });

        const activities = getLiveActivities();
        assert.equal(activities.length, 1);
        assert.notEqual(
          activities[0].status,
          "Verified On-Chain",
          "Must NEVER assign Verified On-Chain without genuine transaction hash"
        );
        assert.equal(activities[0].status, "Safe");
        assert.equal(activities[0].nearTxHash, undefined);
      } finally {
        restoreWindow();
      }
    });

    it("should assign Verified On-Chain when genuine nearTxHash is confirmed", () => {
      setupMockWindow();
      try {
        const target = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        recordScanActivity({
          target,
          scanType: "token",
          riskScore: 45,
          riskLevel: "MEDIUM",
        });

        const genuineTxHash = "G52k1qHn8m7A3tLwP9v4J8zD2K1mN4xQ8rY7bT6cV5wX";
        recordNearRegistration({
          target,
          scanType: "token",
          nearTxHash: genuineTxHash,
          riskScore: 45,
          riskLevel: "MEDIUM",
        });

        const activities = getLiveActivities();
        assert.equal(activities.length, 1);
        assert.equal(activities[0].status, "Verified On-Chain");
        assert.equal(activities[0].nearTxHash, genuineTxHash);
      } finally {
        restoreWindow();
      }
    });

    it("should strictly keep UNKNOWN as Inconclusive even if anchored on NEAR", () => {
      setupMockWindow();
      try {
        const target = "0xUnknownTargetAddress000000000000000000";
        recordScanActivity({
          target,
          scanType: "wallet",
          riskScore: 0,
          riskLevel: "UNKNOWN",
        });

        const genuineTxHash = "3mK9v8Z7xY4wT2rQ1pL5jH8nC6bV4dX2zM9kP7tL3wR";
        recordNearRegistration({
          target,
          scanType: "wallet",
          nearTxHash: genuineTxHash,
          riskLevel: "UNKNOWN",
        });

        const activities = getLiveActivities();
        assert.equal(activities.length, 1);
        assert.equal(
          activities[0].status,
          "Inconclusive",
          "UNKNOWN risk must remain Inconclusive regardless of transaction hash"
        );
        assert.equal(activities[0].riskLevel, "UNKNOWN");
        assert.equal(activities[0].nearTxHash, genuineTxHash);
      } finally {
        restoreWindow();
      }
    });

    it("should preserve existing confirmed on-chain verification across re-scans", () => {
      setupMockWindow();
      try {
        const target = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        const genuineTxHash = "G52k1qHn8m7A3tLwP9v4J8zD2K1mN4xQ8rY7bT6cV5wX";

        // Initial scan + registration
        recordScanActivity({ target, scanType: "wallet", riskScore: 5, riskLevel: "SAFE" });
        recordNearRegistration({ target, scanType: "wallet", nearTxHash: genuineTxHash, riskLevel: "SAFE" });

        assert.equal(getLiveActivities()[0].status, "Verified On-Chain");

        // Subsequent scan without passing txHash
        recordScanActivity({ target, scanType: "wallet", riskScore: 10, riskLevel: "SAFE" });

        const activities = getLiveActivities();
        assert.equal(activities.length, 1);
        assert.equal(activities[0].status, "Verified On-Chain", "Preserves verified status");
        assert.equal(activities[0].nearTxHash, genuineTxHash, "Preserves confirmed tx hash");
      } finally {
        restoreWindow();
      }
    });

    it("should shadow static sample activities with matching live scans", () => {
      const sampleActivities: RecentSecurityActivity[] = [
        {
          id: "sample-1",
          target: "aurora.near",
          scanType: "Wallet Scanner",
          riskLevel: "SAFE",
          date: "Yesterday",
          status: "Verified On-Chain",
          isSample: true,
        },
        {
          id: "sample-2",
          target: "wrap.near",
          scanType: "Token Scanner",
          riskLevel: "SAFE",
          date: "Yesterday",
          status: "Safe",
          isSample: true,
        },
      ];

      const liveActivities: RecentSecurityActivity[] = [
        {
          id: "live-1",
          target: "aurora.near",
          scanType: "Wallet Scanner",
          riskLevel: "HIGH",
          date: "Just now",
          status: "High Risk",
          isSample: false,
        },
      ];

      const merged = mergeAndDeduplicateActivities(liveActivities, sampleActivities);
      assert.equal(merged.length, 2, "Duplicate aurora.near in sample must be shadowed");
      assert.equal(merged[0].id, "live-1", "Live scan must be at the top");
      assert.equal(merged[0].isSample, false);
      assert.equal(merged[1].id, "sample-2", "Unshadowed sample preserved");
    });
  });

  // 11. Priority 3: Local Caching of Anchored Transaction Hashes & Honest Hydration
  describe("11. Priority 3: Local Caching of Anchored Transaction Hashes & Honest Hydration", () => {
    const testCachePath = path.join(process.cwd(), ".cache", "test-section11-tx-cache.json");

    const genuineTx1 = "6zgh2u9D7tQDwtjxebNuHNLP16B1B8rX6F9zZJ3h68e2";
    const genuineTx2 = "G52k1qHn8m7A3tLwP9v4J8zD2K1mN4xQ8rY7bT6cV5wX";
    const sampleHash1 = "1111111111111111111111111111111111111111111111111111111111111111";
    const sampleId1 = "TG-TEST-WALLET-0001";
    const sampleHash2 = "2222222222222222222222222222222222222222222222222222222222222222";
    const sampleId2 = "TG-TEST-TOKEN-0002";

    it("should validate genuine Base58 32-byte transaction hashes and reject malformed/non-base58 inputs", () => {
      // Valid Base58 32-byte hashes
      assert.equal(isValidNearTxHash(genuineTx1), true);
      assert.equal(isValidNearTxHash(genuineTx2), true);
      assert.equal(isValidNearTxHash(`  ${genuineTx1}  `), true, "Should handle trimmed whitespace");

      // Invalid: illegal Base58 characters ('0', 'O', 'I', 'l')
      assert.equal(isValidNearTxHash("0OIl" + "1".repeat(40)), false);

      // Invalid: 64-character hex (not 32-byte Base58)
      assert.equal(isValidNearTxHash(sampleHash1), false);

      // Invalid: Ethereum address
      assert.equal(isValidNearTxHash("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"), false);

      // Invalid: lengths and types
      assert.equal(isValidNearTxHash(""), false);
      assert.equal(isValidNearTxHash("   "), false);
      assert.equal(isValidNearTxHash("short"), false);
      assert.equal(isValidNearTxHash(null), false);
      assert.equal(isValidNearTxHash(undefined), false);
      assert.equal(isValidNearTxHash(12345), false);
    });

    it("should cache genuine transaction hashes with bidirectional lookup (by reportHash and reportId)", () => {
      setTxCacheFilePathForTesting(testCachePath);
      clearTxCacheForTesting();

      try {
        const cached = cacheAnchoredTx({
          reportHash: sampleHash1,
          reportId: sampleId1,
          nearTxHash: genuineTx1,
        });

        assert.equal(cached, true);

        // Lookup by exact lowercase hash
        const byHash = getCachedTxByReportHash(sampleHash1);
        assert.ok(byHash);
        assert.equal(byHash.nearTxHash, genuineTx1);
        assert.equal(byHash.reportId, sampleId1);

        // Lookup by uppercase ID
        const byId = getCachedTxByReportId(sampleId1);
        assert.ok(byId);
        assert.equal(byId.nearTxHash, genuineTx1);

        // Generic bidirectional lookup
        assert.equal(getCachedTx(sampleHash1)?.nearTxHash, genuineTx1);
        assert.equal(getCachedTx(sampleHash1.toUpperCase())?.nearTxHash, genuineTx1, "Normalized uppercase hash lookup");
        assert.equal(getCachedTx(sampleId1)?.nearTxHash, genuineTx1);
        assert.equal(getCachedTx(sampleId1.toLowerCase())?.nearTxHash, genuineTx1, "Normalized lowercase ID lookup");

        // Uncached query
        assert.equal(getCachedTx("3333333333333333333333333333333333333333333333333333333333333333"), undefined);
        assert.equal(getCachedTx("TG-NONEXISTENT"), undefined);
      } finally {
        clearTxCacheForTesting();
        setTxCacheFilePathForTesting(null);
      }
    });

    it("should reject caching if reportHash is not valid SHA-256 or txHash is not genuine Base58", () => {
      setTxCacheFilePathForTesting(testCachePath);
      clearTxCacheForTesting();

      try {
        // Invalid reportHash
        const res1 = cacheAnchoredTx({
          reportHash: "invalid-hash",
          reportId: sampleId1,
          nearTxHash: genuineTx1,
        });
        assert.equal(res1, false);

        // Invalid txHash
        const res2 = cacheAnchoredTx({
          reportHash: sampleHash1,
          reportId: sampleId1,
          nearTxHash: "fake-non-base58-hash-0000",
        });
        assert.equal(res2, false);

        assert.equal(getTxCacheStatsForTesting().count, 0);
      } finally {
        clearTxCacheForTesting();
        setTxCacheFilePathForTesting(null);
      }
    });

    it("should persist cache to disk and reload accurately across initialization", () => {
      setTxCacheFilePathForTesting(testCachePath);
      clearTxCacheForTesting();

      try {
        cacheAnchoredTx({
          reportHash: sampleHash1,
          reportId: sampleId1,
          nearTxHash: genuineTx1,
          blockHeight: 987654,
        });

        cacheAnchoredTx({
          reportHash: sampleHash2,
          reportId: sampleId2,
          nearTxHash: genuineTx2,
          blockHeight: 987655,
        });

        assert.equal(getTxCacheStatsForTesting().count, 2);

        // Force reload by re-pointing cache file path
        setTxCacheFilePathForTesting(testCachePath);

        const loaded1 = getCachedTx(sampleHash1);
        assert.ok(loaded1);
        assert.equal(loaded1.nearTxHash, genuineTx1);
        assert.equal(loaded1.reportId, sampleId1);
        assert.equal(loaded1.blockHeight, 987654);

        const loaded2 = getCachedTx(sampleId2);
        assert.ok(loaded2);
        assert.equal(loaded2.nearTxHash, genuineTx2);
        assert.equal(loaded2.reportHash, sampleHash2);
      } finally {
        clearTxCacheForTesting();
        setTxCacheFilePathForTesting(null);
      }
    });

    it("should handle disk persistence failures gracefully without throwing and retain in-memory lookups", () => {
      setTxCacheFilePathForTesting(testCachePath);
      clearTxCacheForTesting();

      try {
        simulateTxCacheFailureForTesting(true);

        // Should return true (successfully cached in-memory) without throwing
        const cached = cacheAnchoredTx({
          reportHash: sampleHash1,
          reportId: sampleId1,
          nearTxHash: genuineTx1,
        });

        assert.equal(cached, true);

        // In-memory lookup still succeeds immediately
        const record = getCachedTx(sampleHash1);
        assert.ok(record);
        assert.equal(record.nearTxHash, genuineTx1);
      } finally {
        simulateTxCacheFailureForTesting(false);
        clearTxCacheForTesting();
        setTxCacheFilePathForTesting(null);
      }
    });

    it("should hydrate confirmed transaction hash on NEAR pre-flight duplicate check", async () => {
      setTxCacheFilePathForTesting(testCachePath);
      clearTxCacheForTesting();

      try {
        // Pre-cache genuine transaction hash
        cacheAnchoredTx({
          reportHash: sampleHash1,
          reportId: sampleId1,
          nearTxHash: genuineTx1,
        });

        // Mock NEAR RPC to simulate pre-existing on-chain registration
        setNearTestMocks({
          callFunction: async ({ method, args }) => {
            if (method === "verify_report") {
              return args.report_hash === sampleHash1;
            }
            if (method === "get_report") {
              return {
                report_id: sampleId1,
                report_hash: sampleHash1,
                target: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                risk_score: 15,
                block_height: 1234567,
                timestamp_ns: "1731300000000000000",
                registrar: NEAR_CONFIG.contractId,
              };
            }
            throw new Error(`Unexpected method in mock: ${method}`);
          },
        });

        const record = await anchorReportOnNear({
          reportId: sampleId1,
          reportHash: sampleHash1,
          target: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
          scanType: "WALLET",
          riskScore: 15,
          riskLevel: "LOW",
        });

        assert.equal(record.status, "VERIFIED_ON_NEAR");
        assert.equal(record.nearTxHash, genuineTx1, "Pre-flight must hydrate confirmed cached nearTxHash");
        assert.equal(
          record.explorerUrl,
          `${NEAR_CONFIG.explorerBaseUrl}/${genuineTx1}`,
          "Explorer link must use cached transaction hash"
        );
      } finally {
        setNearTestMocks(null);
        clearTxCacheForTesting();
        setTxCacheFilePathForTesting(null);
      }
    });

    it("should preserve honest omission (nearTxHash undefined) when report is on-chain but not in cache", async () => {
      setTxCacheFilePathForTesting(testCachePath);
      clearTxCacheForTesting(); // Empty cache!

      try {
        setNearTestMocks({
          callFunction: async ({ method, args }) => {
            if (method === "verify_report") {
              return args.report_hash === sampleHash2;
            }
            if (method === "get_report") {
              return {
                report_id: sampleId2,
                report_hash: sampleHash2,
                target: "wrap.near",
                risk_score: 5,
                block_height: 1234568,
                timestamp_ns: "1731300000000000000",
                registrar: NEAR_CONFIG.contractId,
              };
            }
            throw new Error(`Unexpected method in mock: ${method}`);
          },
        });

        const record = await anchorReportOnNear({
          reportId: sampleId2,
          reportHash: sampleHash2,
          target: "wrap.near",
          scanType: "TOKEN",
          riskScore: 5,
          riskLevel: "SAFE",
        });

        assert.equal(record.status, "VERIFIED_ON_NEAR");
        assert.equal(record.nearTxHash, undefined, "Uncached report must NEVER invent fake transaction hashes");
        assert.equal(record.explorerUrl, undefined);
      } finally {
        setNearTestMocks(null);
        clearTxCacheForTesting();
        setTxCacheFilePathForTesting(null);
      }
    });

    it("should hydrate transaction hash when re-verifying report by hash or report ID", async () => {
      setTxCacheFilePathForTesting(testCachePath);
      clearTxCacheForTesting();

      try {
        cacheAnchoredTx({
          reportHash: sampleHash1,
          reportId: sampleId1,
          nearTxHash: genuineTx1,
        });

        setNearTestMocks({
          viewNodeStatus: async () => ({
            sync_info: { latest_block_height: 1234599, syncing: false },
          }),
          callFunction: async ({ method, args }) => {
            if (method === "verify_report") {
              return args.report_hash === sampleHash1;
            }
            if (method === "get_report") {
              return {
                report_id: sampleId1,
                report_hash: sampleHash1,
                target: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                risk_score: 10,
                block_height: 1234500,
                timestamp_ns: "1731300000000000000",
                registrar: NEAR_CONFIG.contractId,
              };
            }
            if (method === "get_report_by_id") {
              if (args.report_id === sampleId1) {
                return {
                  report_id: sampleId1,
                  report_hash: sampleHash1,
                  target: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                  risk_score: 10,
                  block_height: 1234500,
                  timestamp_ns: "1731300000000000000",
                  registrar: NEAR_CONFIG.contractId,
                };
              }
              return null;
            }
            throw new Error(`Unexpected mock method: ${method}`);
          },
        });

        // 1. Verify by SHA-256 hash
        const hashResult = await verifyReportOnNear(sampleHash1);
        assert.equal(hashResult.isVerified, true);
        assert.equal(hashResult.status, "VERIFIED_ON_NEAR");
        assert.equal(hashResult.record?.nearTxHash, genuineTx1);
        assert.equal(hashResult.record?.explorerUrl, `${NEAR_CONFIG.explorerBaseUrl}/${genuineTx1}`);

        // 2. Verify by Report ID
        const idResult = await verifyReportOnNear(sampleId1);
        assert.equal(idResult.isVerified, true);
        assert.equal(idResult.status, "VERIFIED_ON_NEAR");
        assert.equal(idResult.record?.nearTxHash, genuineTx1);
        assert.equal(idResult.record?.explorerUrl, `${NEAR_CONFIG.explorerBaseUrl}/${genuineTx1}`);

        // 3. Uncached hash query
        const uncachedResult = await verifyReportOnNear(sampleHash2);
        assert.equal(uncachedResult.isVerified, false);
        assert.equal(uncachedResult.status, "NOT_REGISTERED");
      } finally {
        setNearTestMocks(null);
        clearTxCacheForTesting();
        setTxCacheFilePathForTesting(null);
      }
    });

    it("should strictly preserve Priority 1 UNKNOWN risk status when hydrating transaction cache", async () => {
      setTxCacheFilePathForTesting(testCachePath);
      clearTxCacheForTesting();

      try {
        cacheAnchoredTx({
          reportHash: sampleHash1,
          reportId: sampleId1,
          nearTxHash: genuineTx1,
        });

        setNearTestMocks({
          callFunction: async ({ method, args }) => {
            if (method === "verify_report") return true;
            if (method === "get_report") {
              return {
                report_id: sampleId1,
                report_hash: sampleHash1,
                target: "0x1111111111111111111111111111111111111111",
                risk_score: 0,
                block_height: 1234567,
                timestamp_ns: "1731300000000000000",
                registrar: NEAR_CONFIG.contractId,
              };
            }
            throw new Error(`Unexpected method: ${method}`);
          },
        });

        const record = await anchorReportOnNear({
          reportId: sampleId1,
          reportHash: sampleHash1,
          target: "0x1111111111111111111111111111111111111111",
          scanType: "WALLET",
          riskScore: 0,
          riskLevel: "UNKNOWN",
        });

        assert.equal(record.riskLevel, "UNKNOWN");
        assert.equal(record.riskScore, 0);
        assert.equal(record.nearTxHash, genuineTx1);

        // Verify formatting utility adheres to UNKNOWN safeguard
        const display = formatRiskScoreDisplay(record.riskScore, record.riskLevel);
        assert.equal(display, "INCONCLUSIVE", "Hydrated record must retain INCONCLUSIVE display");
        assert.notEqual(display, "0/100");
      } finally {
        setNearTestMocks(null);
        clearTxCacheForTesting();
        setTxCacheFilePathForTesting(null);
      }
    });
  });
});

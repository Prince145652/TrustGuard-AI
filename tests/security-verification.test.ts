import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  canonicalStringify,
  generateReportHash,
  isValidSha256,
} from "../src/lib/near-hashing";
import { looksLikeSecret, walletScanSchema } from "../src/lib/validators";

describe("TrustGuard AI Security Verification Suite", () => {
  // 1. Canonical JSON Key Sorting
  describe("1. Canonical JSON Key Sorting", () => {
    it("should sort object keys in lexicographical order recursively", () => {
      const unorderedObj = {
        z_score: 95,
        a_target: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        m_metadata: {
          beta: "test",
          alpha: 1,
        },
      };

      const serialized = canonicalStringify(unorderedObj);
      const expected =
        '{"a_target":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e","m_metadata":{"alpha":1,"beta":"test"},"z_score":95}';

      assert.equal(serialized, expected);
    });

    it("should omit undefined keys while preserving null and empty arrays", () => {
      const objWithUndefined = {
        b: undefined,
        a: "value",
        c: null,
        d: [],
      };

      const serialized = canonicalStringify(objWithUndefined);
      assert.equal(serialized, '{"a":"value","c":null,"d":[]}');
    });
  });

  // 2. SHA-256 Hash Generation
  describe("2. SHA-256 Hash Generation", () => {
    it("should generate a valid 64-character hexadecimal SHA-256 digest", () => {
      const report = {
        target: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        scanType: "WALLET",
        riskScore: 10,
        riskLevel: "SAFE",
        threats: [],
        evidence: [
          { category: "Balance", finding: "Live balance: 1.5 ETH", status: "SAFE" },
        ],
      };

      const hash = generateReportHash(report);
      assert.equal(typeof hash, "string");
      assert.equal(hash.length, 64);
      assert.match(hash, /^[a-f0-9]{64}$/);
    });
  });

  // 3. Same Report Producing the Same Hash
  describe("3. Deterministic Hashing (Same Report -> Same Hash)", () => {
    it("should produce identical SHA-256 hashes even if object keys are shuffled", () => {
      const reportVariantA = {
        target: "aurora.near",
        scanType: "WALLET",
        riskScore: 5,
        riskLevel: "SAFE",
        threats: [],
        evidence: [{ category: "History", finding: "Active", status: "SAFE" }],
        indicators: [],
      };

      // Shuffled key order
      const reportVariantB = {
        indicators: [],
        threats: [],
        riskLevel: "SAFE",
        target: "aurora.near",
        evidence: [{ category: "History", finding: "Active", status: "SAFE" }],
        scanType: "WALLET",
        riskScore: 5,
      };

      const hashA = generateReportHash(reportVariantA);
      const hashB = generateReportHash(reportVariantB);

      assert.equal(hashA, hashB);
    });

    it("should ignore non-deterministic ephemeral timestamps", () => {
      const baseReport = {
        target: "0x1234567890123456789012345678901234567890",
        scanType: "TOKEN",
        riskScore: 25,
        riskLevel: "LOW",
        threats: [],
        evidence: [],
      };

      const hashWithTimestampA = generateReportHash({
        ...baseReport,
        clientTimestamp: "2026-10-30T10:00:00Z",
      });

      const hashWithTimestampB = generateReportHash({
        ...baseReport,
        clientTimestamp: "2026-10-30T12:00:00Z",
      });

      assert.equal(hashWithTimestampA, hashWithTimestampB);
    });
  });

  // 4. Different Reports Producing Different Hashes
  describe("4. Avalanche Effect (Different Reports -> Different Hashes)", () => {
    it("should produce completely different hashes when even a single metric changes", () => {
      const reportSafe = {
        target: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        scanType: "WALLET",
        riskScore: 10,
        riskLevel: "SAFE",
        threats: [],
        evidence: [],
      };

      const reportCompromised = {
        target: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        scanType: "WALLET",
        riskScore: 95, // Changed score
        riskLevel: "CRITICAL", // Changed level
        threats: ["Drainer match"],
        evidence: [],
      };

      const hashSafe = generateReportHash(reportSafe);
      const hashCompromised = generateReportHash(reportCompromised);

      assert.notEqual(hashSafe, hashCompromised);
      assert.equal(hashSafe.length, 64);
      assert.equal(hashCompromised.length, 64);
    });
  });

  // 5. SHA-256 Validation
  describe("5. SHA-256 Validation", () => {
    it("should validate legitimate 64-character hex strings", () => {
      const validHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
      assert.equal(isValidSha256(validHash), true);
      assert.equal(isValidSha256(validHash.toUpperCase()), true);
    });

    it("should reject non-64-character or malformed strings", () => {
      assert.equal(isValidSha256(""), false);
      assert.equal(isValidSha256("short-hash"), false);
      assert.equal(isValidSha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"), false); // 63 chars
      assert.equal(isValidSha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85500"), false); // 66 chars
      assert.equal(isValidSha256("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"), false); // non-hex
    });
  });

  // 6. Invalid Wallet Address Rejection
  describe("6. Invalid Wallet Address Rejection", () => {
    it("should reject malformed or invalid Ethereum addresses", () => {
      const invalidAddresses = [
        "0x123", // Too short
        "0xZZZd35Cc6634C0532925a3b844Bc454e4438f44e", // Invalid hex characters
        "742d35Cc6634C0532925a3b844Bc454e4438f44e", // Missing 0x prefix
        "", // Empty
        "   ", // Whitespace only
      ];

      for (const addr of invalidAddresses) {
        const parsed = walletScanSchema.safeParse({ target: addr });
        assert.equal(
          parsed.success,
          false,
          `Expected address "${addr}" to be rejected by schema`
        );
      }
    });

    it("should accept valid EVM and NEAR account formats", () => {
      const validAccounts = [
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "aurora.near",
        "alice.testnet",
      ];

      for (const acc of validAccounts) {
        const parsed = walletScanSchema.safeParse({ target: acc });
        assert.equal(
          parsed.success,
          true,
          `Expected valid account "${acc}" to pass validation`
        );
      }
    });
  });

  // 7. Private Key and Seed Phrase Rejection
  describe("7. Private Key and Seed Phrase Defense (Zero-Knowledge Rule)", () => {
    it("should detect and flag raw 64-hex EVM private keys", () => {
      const rawPrivateKeyWithPrefix =
        "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f3608a9";
      const rawPrivateKeyNoPrefix =
        "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f3608a9";

      assert.equal(looksLikeSecret(rawPrivateKeyWithPrefix), true);
      assert.equal(looksLikeSecret(rawPrivateKeyNoPrefix), true);

      // Must be rejected by schema validation
      const parseResult = walletScanSchema.safeParse({ target: rawPrivateKeyWithPrefix });
      assert.equal(parseResult.success, false);
      assert.match(
        parseResult.error!.issues[0].message,
        /Private keys and seed phrases are strictly forbidden/
      );
    });

    it("should detect and flag NEAR ed25519 private keys", () => {
      const nearPrivateKey =
        "ed25519:3D4YujbUjGq2e62mXk2fQ4C3eQf9A8F5x1K3h8j6e5c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1";

      assert.equal(looksLikeSecret(nearPrivateKey), true);

      const parseResult = walletScanSchema.safeParse({ target: nearPrivateKey });
      assert.equal(parseResult.success, false);
    });

    it("should detect and flag 12 and 24-word BIP-39 mnemonic seed phrases", () => {
      const twelveWordPhrase =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";
      const twentyFourWordPhrase =
        "abandon ability able about above absent absorb abstract absurd abuse access accident abandon ability able about above absent absorb abstract absurd abuse access account";

      assert.equal(looksLikeSecret(twelveWordPhrase), true);
      assert.equal(looksLikeSecret(twentyFourWordPhrase), true);

      const parseResult = walletScanSchema.safeParse({ target: twelveWordPhrase });
      assert.equal(parseResult.success, false);
      assert.match(
        parseResult.error!.issues[0].message,
        /Private keys and seed phrases are strictly forbidden/
      );
    });

    it("should not falsely flag natural conversational sentences containing punctuation", () => {
      const naturalSentence = "Why is this wallet flagged? Can I still connect?";
      assert.equal(looksLikeSecret(naturalSentence), false);

      const hindiSentence = "Yeh website flagged kyun hai? Kya main connect karoon?";
      assert.equal(looksLikeSecret(hindiSentence), false);
    });
  });
});

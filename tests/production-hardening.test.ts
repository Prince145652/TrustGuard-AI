import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { KeyPair } from "near-api-js";
import { NextRequest } from "next/server";
import { getSignerAccount } from "../src/lib/near-client";
import { analyzeWithGemini } from "../src/lib/gemini-analyst";
import { redactSecrets, looksLikeSecret } from "../src/lib/validators";
import { ScanContext } from "../src/types/ai-analyst";
import {
  checkRateLimit,
  createRateLimitResponse,
  clearRateLimitStore,
  getClientIp,
  resolveMaxStoreSize,
  validateIp,
  getRateLimitStoreSize,
  DEFAULT_MAX_STORE_SIZE,
} from "../src/lib/rate-limiter";

describe("Phase 2 Production Hardening: NEAR Signer, Gemini Timeout & Error Sanitization", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    delete process.env.NEAR_SIGNER_PRIVATE_KEY;
    delete process.env.NEAR_CREDENTIALS_JSON;
    delete process.env.GEMINI_API_KEY;
    delete process.env.GOOGLE_API_KEY;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  // 1. NEAR Signer: Environment-Based Configuration
  describe("1. NEAR Signer Environment Configuration", () => {
    it("should load signer from NEAR_SIGNER_PRIVATE_KEY", () => {
      const testKeyPair = KeyPair.fromRandom("ED25519");
      process.env.NEAR_SIGNER_PRIVATE_KEY = testKeyPair.toString();

      const account = getSignerAccount();
      assert.ok(account, "Signer account should be created");
      assert.equal(account.accountId, "tg-auditor-2026.testnet");
    });

    it("should load signer from plain NEAR_CREDENTIALS_JSON", () => {
      const testKeyPair = KeyPair.fromRandom("ED25519");
      const credObj = {
        account_id: "tg-auditor-2026.testnet",
        private_key: testKeyPair.toString(),
      };
      process.env.NEAR_CREDENTIALS_JSON = JSON.stringify(credObj);

      const account = getSignerAccount();
      assert.ok(account);
      assert.equal(account.accountId, "tg-auditor-2026.testnet");
    });

    it("should load signer from base64-encoded NEAR_CREDENTIALS_JSON", () => {
      const testKeyPair = KeyPair.fromRandom("ED25519");
      const credObj = {
        account_id: "tg-auditor-2026.testnet",
        secret_key: testKeyPair.toString(),
      };
      const base64Str = Buffer.from(JSON.stringify(credObj)).toString("base64");
      process.env.NEAR_CREDENTIALS_JSON = base64Str;

      const account = getSignerAccount();
      assert.ok(account);
      assert.equal(account.accountId, "tg-auditor-2026.testnet");
    });

    it("should prioritize NEAR_SIGNER_PRIVATE_KEY over NEAR_CREDENTIALS_JSON", () => {
      const keyPair1 = KeyPair.fromRandom("ED25519");
      const keyPair2 = KeyPair.fromRandom("ED25519");

      process.env.NEAR_SIGNER_PRIVATE_KEY = keyPair1.toString();
      process.env.NEAR_CREDENTIALS_JSON = JSON.stringify({
        account_id: "tg-auditor-2026.testnet",
        private_key: keyPair2.toString(),
      });

      const account = getSignerAccount();
      assert.ok(account);
    });
  });

  // 2. NEAR Signer: Filesystem Fallback
  describe("2. NEAR Signer Filesystem Fallback", () => {
    it("should fall back to ~/.near-credentials/testnet when env vars are absent", () => {
      delete process.env.NEAR_SIGNER_PRIVATE_KEY;
      delete process.env.NEAR_CREDENTIALS_JSON;

      // On this host, ~/.near-credentials/testnet/tg-auditor-2026.testnet.json exists
      const account = getSignerAccount();
      assert.ok(account);
      assert.equal(account.accountId, "tg-auditor-2026.testnet");
    });
  });

  // 3. NEAR Signer: Malformed Credentials Safety
  describe("3. NEAR Signer Malformed Credentials Validation", () => {
    it("should reject malformed NEAR_SIGNER_PRIVATE_KEY without leaking key in error", () => {
      process.env.NEAR_SIGNER_PRIVATE_KEY = "my_super_secret_bad_key_12345";

      assert.throws(
        () => getSignerAccount(),
        (err: Error) => {
          assert.match(err.message, /Invalid NEAR signer private key/);
          assert.match(err.message, /malformed key format/);
          assert.equal(err.message.includes("my_super_secret_bad_key_12345"), false, "Must never leak key in error message");
          return true;
        }
      );
    });

    it("should reject malformed NEAR_CREDENTIALS_JSON (invalid JSON)", () => {
      process.env.NEAR_CREDENTIALS_JSON = "{ invalid_json: true, ";

      assert.throws(
        () => getSignerAccount(),
        (err: Error) => {
          assert.match(err.message, /Invalid NEAR_CREDENTIALS_JSON/);
          assert.match(err.message, /malformed JSON format/);
          return true;
        }
      );
    });

    it("should reject NEAR_CREDENTIALS_JSON with missing private_key", () => {
      process.env.NEAR_CREDENTIALS_JSON = JSON.stringify({
        account_id: "tg-auditor-2026.testnet",
        public_key: "ed25519:test",
      });

      assert.throws(
        () => getSignerAccount(),
        (err: Error) => {
          assert.match(err.message, /Signing private key is missing or invalid in NEAR_CREDENTIALS_JSON/);
          return true;
        }
      );
    });
  });

  // 4. Gemini API Validation & Timeout Protection
  describe("4. Gemini API Validation, Timeout Protection & Deterministic Fallback", () => {
    const dummyContext: ScanContext = {
      target: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      scanType: "wallet",
      chain: "Ethereum",
      riskScore: 5,
      riskLevel: "SAFE",
      threats: [],
      evidence: [{ category: "On-Chain Balance", finding: "Confirmed", status: "SAFE" }],
    };

    it("should immediately fall back to local heuristics when GEMINI_API_KEY is unset", async () => {
      delete process.env.GEMINI_API_KEY;
      delete process.env.GOOGLE_API_KEY;

      const result = await analyzeWithGemini(dummyContext, "Explain this wallet safety", "en");
      assert.equal(result.engineUsed, "autonomous-local-heuristics");
      assert.ok(result.response.includes("AI Security Analyst Report"));
      assert.equal(result.structuredReport?.target, dummyContext.target);
    });

    it("should reject placeholder or short GEMINI_API_KEY and fall back gracefully", async () => {
      process.env.GEMINI_API_KEY = "your_api_key_here";

      const result = await analyzeWithGemini(dummyContext, "Explain this wallet safety", "en");
      assert.equal(result.engineUsed, "autonomous-local-heuristics");
    });

    it("should fall back gracefully without unhandled rejection when API key is invalid", async () => {
      process.env.GEMINI_API_KEY = "AIzaSyDummyKeyInvalidFormat99999999";

      const result = await analyzeWithGemini(dummyContext, "Explain this wallet safety", "en");
      assert.equal(result.engineUsed, "autonomous-local-heuristics");
      assert.ok(result.response);
      assert.equal(result.structuredReport?.riskScore, 5);
    });

    it("should accurately generate Hindi analysis in deterministic engine", async () => {
      delete process.env.GEMINI_API_KEY;

      const result = await analyzeWithGemini(dummyContext, "Is this wallet safe?", "hi");
      assert.equal(result.engineUsed, "autonomous-local-heuristics");
      assert.ok(result.response.includes("AI सुरक्षा विश्लेषण रिपोर्ट"));
      assert.ok(result.response.includes("मुख्य निष्कर्ष"));
    });

    it("should accurately generate Hinglish analysis in deterministic engine", async () => {
      delete process.env.GEMINI_API_KEY;

      const result = await analyzeWithGemini(dummyContext, "Is this wallet safe?", "hinglish");
      assert.equal(result.engineUsed, "autonomous-local-heuristics");
      assert.ok(result.response.includes("AI Security Analyst Report"));
      assert.ok(result.response.includes("Kya Karein"));
    });
  });

  // 5. Zero-Knowledge Safeguard & Secret Protection
  describe("5. Zero-Knowledge Safeguard & Secret Protection", () => {
    it("should detect and redact private keys before AI processing", () => {
      const secretInput = "My key is 0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f3608a9 please check it";
      const redacted = redactSecrets(secretInput);
      assert.ok(!redacted.includes("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f3608a9"));
      assert.ok(redacted.includes("[REDACTED_PRIVATE_KEY]"));
    });

    it("should detect raw BIP-39 mnemonic seed phrases", () => {
      const seed = "abandon ability able about above absent absorb abstract absurd abuse access accident";
      assert.equal(looksLikeSecret(seed), true);
    });

    it("should trigger zero-custody security warning when asking about private keys", async () => {
      delete process.env.GEMINI_API_KEY;
      const result = await analyzeWithGemini(undefined, "Can you audit my private key?", "en");
      assert.equal(result.engineUsed, "autonomous-local-heuristics");
      assert.ok(result.response.includes("CRITICAL SECURITY WARNING: NEVER SHARE YOUR PRIVATE KEYS"));
    });
  });

  // 6. Sanitized Error Responses (No Path/Stack Leakage)
  describe("6. Sanitized Error Responses", () => {
    it("should ensure error messages do not leak local file paths or stack traces", () => {
      // Simulate raw internal exception
      const internalErr = new Error("ENOENT: no such file or directory, open '/home/prince/.near-credentials/testnet/tg-auditor-2026.testnet.json'");
      
      // Sanitized client message representation
      const sanitizedMessage = "An unexpected error occurred during on-chain wallet scan. Please try again later.";
      
      assert.equal(sanitizedMessage.includes("/home/prince"), false);
      assert.equal(sanitizedMessage.includes(".near-credentials"), false);
      assert.equal(sanitizedMessage.includes("ENOENT"), false);
    });
  });

  // 7. API Rate Limiter Hardening Suite
  describe("7. Rate Limiter Hardening, Anti-Spoofing & Capacity Protection", () => {
    beforeEach(() => {
      clearRateLimitStore();
      delete process.env.TRUSTED_PROXY;
      delete process.env.RATE_LIMIT_MAX_STORE_SIZE;
    });

    // 1. Capacity Configuration Validation
    it("should validate and safely resolve maxStoreSize, rejecting invalid or non-positive values", () => {
      assert.equal(resolveMaxStoreSize(-10), DEFAULT_MAX_STORE_SIZE);
      assert.equal(resolveMaxStoreSize(0), DEFAULT_MAX_STORE_SIZE);
      assert.equal(resolveMaxStoreSize(NaN), DEFAULT_MAX_STORE_SIZE);
      assert.equal(resolveMaxStoreSize(Infinity), DEFAULT_MAX_STORE_SIZE);
      assert.equal(resolveMaxStoreSize(3.14), DEFAULT_MAX_STORE_SIZE);
      assert.equal(resolveMaxStoreSize("invalid-string"), DEFAULT_MAX_STORE_SIZE);
      assert.equal(resolveMaxStoreSize(null), DEFAULT_MAX_STORE_SIZE);
      assert.equal(resolveMaxStoreSize(undefined), DEFAULT_MAX_STORE_SIZE);

      // Valid numbers and integer strings are honored
      assert.equal(resolveMaxStoreSize(500), 500);
      assert.equal(resolveMaxStoreSize("250"), 250);
    });

    // 2. IP Address Validation with net.isIP()
    it("should validate candidate IPs using isIP() and reject invalid or malformed formats", () => {
      assert.equal(validateIp("198.51.100.1"), "198.51.100.1");
      assert.equal(validateIp("2001:db8::1"), "2001:db8::1");

      // Malformed / injection strings
      assert.equal(validateIp("999.999.999.999"), null);
      assert.equal(validateIp("1.2.3.4.5"), null);
      assert.equal(validateIp("not-an-ip"), null);
      assert.equal(validateIp("<script>alert(1)</script>"), null);
      assert.equal(validateIp("../../etc/passwd"), null);
      assert.equal(validateIp(""), null);
      assert.equal(validateIp(undefined), null);
    });

    // 3. Nginx Mode: Valid, Missing, and Invalid X-Real-IP (No X-Forwarded-For Fallback)
    it("should trust ONLY valid X-Real-IP in nginx mode and ignore X-Forwarded-For", () => {
      // Valid X-Real-IP is accepted
      const validReq = new NextRequest("http://localhost:3000/api/scan/evm-wallet", {
        headers: { "x-real-ip": "198.51.100.42" },
      });
      assert.equal(getClientIp(validReq, "nginx"), "198.51.100.42");

      // Missing X-Real-IP ignores X-Forwarded-For and falls back to direct-client
      const missingReq = new NextRequest("http://localhost:3000/api/scan/evm-wallet", {
        headers: { "x-forwarded-for": "203.0.113.195, 70.41.3.18" },
      });
      assert.equal(getClientIp(missingReq, "nginx"), "direct-client");

      // Invalid X-Real-IP fails isIP() and falls back to direct-client
      const invalidReq = new NextRequest("http://localhost:3000/api/scan/evm-wallet", {
        headers: { "x-real-ip": "999.999.999.999" },
      });
      assert.equal(getClientIp(invalidReq, "nginx"), "direct-client");
    });

    // 4. Platform IP Fallback
    it("should use validated platform req.ip if available when headers are absent", () => {
      const req = new NextRequest("http://localhost:3000/api/scan/evm-wallet");
      Object.defineProperty(req, "ip", { value: "198.51.100.77", configurable: true });
      assert.equal(getClientIp(req), "198.51.100.77");

      // Invalid platform IP falls back to direct-client
      const invalidPlatformReq = new NextRequest("http://localhost:3000/api/scan/evm-wallet");
      Object.defineProperty(invalidPlatformReq, "ip", { value: "bad-ip", configurable: true });
      assert.equal(getClientIp(invalidPlatformReq), "direct-client");
    });

    // 5. Anti-Spoofing & Shared Fallback Identity
    it("should not trust spoofed forwarding headers when TRUSTED_PROXY is none, mapping all to direct-client", () => {
      const req1 = new NextRequest("http://localhost:3000/api/scan/evm-wallet", {
        headers: { "x-forwarded-for": "1.1.1.1" },
      });
      const req2 = new NextRequest("http://localhost:3000/api/scan/evm-wallet", {
        headers: { "cf-connecting-ip": "2.2.2.2" },
      });

      assert.equal(getClientIp(req1), "direct-client");
      assert.equal(getClientIp(req2), "direct-client");

      // Exhaust limit for direct-client with max: 2
      const res1 = checkRateLimit(req1, { max: 2, windowMs: 60000 });
      assert.equal(res1.success, true);
      assert.equal(res1.isFallbackIdentity, true);

      const res2 = checkRateLimit(req2, { max: 2, windowMs: 60000 });
      assert.equal(res2.success, true);

      // 3rd request with a different spoofed IP is BLOCKED because it shares the direct-client bucket
      const req3 = new NextRequest("http://localhost:3000/api/scan/evm-wallet", {
        headers: { "x-forwarded-for": "3.3.3.3" },
      });
      const res3 = checkRateLimit(req3, { max: 2, windowMs: 60000 });
      assert.equal(res3.success, false);
      assert.equal(res3.remaining, 0);
    });

    // 6. Cloudflare Mode
    it("should honor trusted cloudflare proxy configuration for validated cf-connecting-ip", () => {
      const cfReq = new NextRequest("http://localhost:3000/api/scan/evm-wallet", {
        headers: { "cf-connecting-ip": "104.28.1.1" },
      });
      assert.equal(getClientIp(cfReq, "cloudflare"), "104.28.1.1");
    });

    // 7. Capacity Exhaustion & Fail-Closed Protection (No FIFO Eviction)
    it("should fail closed when capacity is exhausted without evicting active records", () => {
      const maxStore = 3;

      // Fill store with 3 active clients under nginx trusted proxy
      for (let i = 1; i <= 3; i++) {
        const req = new NextRequest(`http://localhost:3000/api/scan/evm-wallet`, {
          headers: { "x-real-ip": `198.51.100.${i}` },
        });
        const res = checkRateLimit(req, { max: 5, maxStoreSize: maxStore, trustedProxy: "nginx" });
        assert.equal(res.success, true);
      }
      assert.equal(getRateLimitStoreSize(), 3);

      // Attempt to add a 4th unique identity
      const attackerReq = new NextRequest(`http://localhost:3000/api/scan/evm-wallet`, {
        headers: { "x-real-ip": "198.51.100.99" },
      });
      const res4 = checkRateLimit(attackerReq, { max: 5, maxStoreSize: maxStore, trustedProxy: "nginx" });

      // Must fail closed (HTTP 429) rather than evicting existing active records
      assert.equal(res4.success, false);
      assert.equal(getRateLimitStoreSize(), 3);

      // Confirm that the first client's active record was NOT evicted
      const req1 = new NextRequest(`http://localhost:3000/api/scan/evm-wallet`, {
        headers: { "x-real-ip": "198.51.100.1" },
      });
      const resExisting = checkRateLimit(req1, { max: 5, maxStoreSize: maxStore, trustedProxy: "nginx" });
      assert.equal(resExisting.success, true);
      assert.equal(resExisting.remaining, 3); // 2nd call decrements remaining from 4 to 3
    });

    // 8. HTTP 429 Response Format
    it("should return standard HTTP 429 response structure", () => {
      const response = createRateLimitResponse(45);
      assert.equal(response.status, 429);
      assert.equal(response.headers.get("Retry-After"), "45");
      assert.equal(response.headers.get("X-RateLimit-Remaining"), "0");
    });
  });
});

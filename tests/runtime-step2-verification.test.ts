import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateReportHash, isValidSha256 } from "../src/lib/near-hashing";

const BASE_URL = process.env.TEST_BASE_URL || "http://localhost:3000";

describe("TrustGuard AI Step 2: Live Runtime End-to-End Verification", () => {
  // Test 1: EVM Wallet Scanner -> Analyze with AI Analyst
  describe("Test 1: EVM Wallet Scanner -> Analyze with AI Analyst", () => {
    it("should scan a live EVM wallet and successfully feed real evidence to AI Analyst", async () => {
      // 1. Scan live address
      const scanRes = await fetch(`${BASE_URL}/api/scan/evm-wallet`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
          chain: "ethereum",
        }),
      });

      assert.equal(scanRes.status, 200, "EVM Wallet scan should succeed with HTTP 200");
      const scanData = await scanRes.json();

      assert.equal(scanData.address, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
      assert.equal(scanData.chain, "ethereum");
      assert.equal(typeof scanData.riskScore, "number");
      assert.ok(scanData.evidence && scanData.evidence.length > 0, "Scan must include evidence");

      // 2. Pass real scanner result to AI Analyst
      const analystRes = await fetch(`${BASE_URL}/api/analyst/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "Explain the security evidence for this wallet",
          language: "en",
          context: {
            scanType: "wallet",
            target: scanData.address,
            chain: scanData.chainName,
            riskScore: scanData.riskScore,
            riskLevel: scanData.riskLevel,
            threats: scanData.threats,
            evidence: scanData.evidence,
          },
        }),
      });

      assert.equal(analystRes.status, 200, "AI Analyst should respond with HTTP 200");
      const analystData = await analystRes.json();

      assert.ok(analystData.response, "AI Analyst must provide a response");
      assert.equal(analystData.structuredReport?.target, scanData.address);
      assert.equal(analystData.structuredReport?.riskScore, scanData.riskScore);
      assert.equal(analystData.structuredReport?.riskLevel, scanData.riskLevel);
    });
  });

  // Test 2: Website Scam Detector -> Analyze with AI Analyst
  describe("Test 2: Website Scam Detector -> Analyze with AI Analyst", () => {
    it("should scan a website and successfully feed real evidence to AI Analyst", async () => {
      // 1. Scan live URL
      const scanRes = await fetch(`${BASE_URL}/api/scan/website`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: "https://app.ref.finance",
        }),
      });

      assert.equal(scanRes.status, 200, "Website scan should succeed with HTTP 200");
      const scanData = await scanRes.json();

      assert.equal(scanData.domain, "app.ref.finance");
      assert.equal(typeof scanData.riskScore, "number");
      assert.ok(Array.isArray(scanData.indicators), "Website scan must return indicators");

      // 2. Pass real website scan result to AI Analyst
      const analystRes = await fetch(`${BASE_URL}/api/analyst/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "Is this website safe to interact with?",
          language: "en",
          context: {
            scanType: "website",
            target: scanData.url,
            riskScore: scanData.riskScore,
            riskLevel: scanData.riskLevel,
            threats: scanData.verdict === "MALICIOUS" ? [scanData.summary] : [],
            indicators: scanData.indicators,
          },
        }),
      });

      assert.equal(analystRes.status, 200, "AI Analyst should respond with HTTP 200");
      const analystData = await analystRes.json();

      assert.ok(analystData.response);
      assert.equal(analystData.structuredReport?.target, scanData.url);
      assert.equal(analystData.structuredReport?.riskScore, scanData.riskScore);
    });
  });

  // Test 3: Token Security Scanner -> Analyze with AI Analyst
  describe("Test 3: Token Security Scanner -> Analyze with AI Analyst", () => {
    it("should scan an ERC-20 contract and feed real token findings to AI Analyst", async () => {
      // 1. Scan live token contract
      const scanRes = await fetch(`${BASE_URL}/api/scan/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
          chain: "ethereum",
        }),
      });

      assert.equal(scanRes.status, 200, "Token scan should succeed with HTTP 200");
      const scanData = await scanRes.json();

      assert.equal(scanData.tokenSymbol, "USDT");
      assert.equal(typeof scanData.riskScore, "number");
      assert.ok(Array.isArray(scanData.evidence));

      // 2. Pass real token findings to AI Analyst
      const analystRes = await fetch(`${BASE_URL}/api/analyst/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "Explain the admin privileges detected in this token",
          language: "en",
          context: {
            scanType: "token",
            target: scanData.address,
            chain: scanData.chainName,
            riskScore: scanData.riskScore,
            riskLevel: scanData.riskLevel,
            evidence: scanData.evidence,
          },
        }),
      });

      assert.equal(analystRes.status, 200, "AI Analyst should respond with HTTP 200");
      const analystData = await analystRes.json();

      assert.ok(analystData.response);
      assert.equal(analystData.structuredReport?.target, scanData.address);
      assert.equal(analystData.structuredReport?.riskScore, scanData.riskScore);
    });
  });

  // Test 4: EVM Wallet Scanner -> Register Report on NEAR
  describe("Test 4: EVM Wallet Scanner -> Register Report on NEAR", () => {
    it("should register a report generated from wallet scan and label it honestly off-chain", async () => {
      const payload = {
        target: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        scanType: "WALLET",
        riskScore: 25,
        riskLevel: "LOW",
        threats: [],
        evidence: [
          { category: "Bytecode Architecture", finding: "Smart Contract", status: "WARNING" },
          { category: "On-Chain Balance", finding: "Confirmed", status: "SAFE" },
        ],
      };

      // Calculate expected canonical hash
      const expectedHash = generateReportHash(payload);

      const regRes = await fetch(`${BASE_URL}/api/near/register-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      assert.equal(regRes.status, 200);
      const regData = await regRes.json();

      assert.equal(regData.success, true);
      assert.equal(regData.record.reportHash, expectedHash);
      assert.equal(isValidSha256(regData.record.reportHash), true);
      assert.match(regData.record.reportId, /^TG-WALLET-0XD8DA6B-[A-F0-9]{8}$/);

      // Strict honest status check:
      assert.equal(regData.record.status, "OFFCHAIN_REGISTERED_PENDING_DEPLOYMENT");
      assert.equal(
        regData.record.statusLabel,
        "Off-chain registration — Testnet contract deployment pending"
      );
      assert.equal(regData.record.nearTxHash, undefined, "Must NOT emit fake transaction hash");
      assert.equal(regData.record.explorerUrl, undefined, "Must NOT emit fake explorer link");

      // Test duplicate registration returns identical record
      const dupRes = await fetch(`${BASE_URL}/api/near/register-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const dupData = await dupRes.json();
      assert.equal(dupData.record.reportId, regData.record.reportId);
      assert.equal(dupData.record.reportHash, regData.record.reportHash);
    });
  });

  // Test 5: Website Scam Detector -> Register Report on NEAR
  describe("Test 5: Website Scam Detector -> Register Report on NEAR", () => {
    it("should register a report generated from website scan with correct hash and honest status", async () => {
      const payload = {
        target: "https://app.ref.finance",
        scanType: "WEBSITE",
        riskScore: 5,
        riskLevel: "SAFE",
        threats: [],
        evidence: [{ category: "Web3 Registry", finding: "Clean", status: "SAFE" }],
      };

      const expectedHash = generateReportHash(payload);

      const regRes = await fetch(`${BASE_URL}/api/near/register-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      assert.equal(regRes.status, 200);
      const regData = await regRes.json();

      assert.equal(regData.record.reportHash, expectedHash);
      assert.match(regData.record.reportId, /^TG-WEBSITE-HTTPSAPP-[A-F0-9]{8}$/);
      assert.equal(regData.record.status, "OFFCHAIN_REGISTERED_PENDING_DEPLOYMENT");
      assert.equal(regData.record.nearTxHash, undefined);
    });
  });

  // Test 6: Token Security Scanner -> Register Report on NEAR
  describe("Test 6: Token Security Scanner -> Register Report on NEAR", () => {
    it("should register a report generated from token scan with correct hash and honest status", async () => {
      const payload = {
        target: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        scanType: "TOKEN",
        riskScore: 45,
        riskLevel: "MEDIUM",
        threats: [],
        evidence: [
          { category: "Privileges", finding: "Mintable: true, Blacklist: true", status: "WARNING" },
        ],
      };

      const expectedHash = generateReportHash(payload);

      const regRes = await fetch(`${BASE_URL}/api/near/register-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      assert.equal(regRes.status, 200);
      const regData = await regRes.json();

      assert.equal(regData.record.reportHash, expectedHash);
      assert.match(regData.record.reportId, /^TG-TOKEN-0XDAC17F-[A-F0-9]{8}$/);
      assert.equal(regData.record.status, "OFFCHAIN_REGISTERED_PENDING_DEPLOYMENT");
      assert.equal(regData.record.nearTxHash, undefined);
    });
  });

  // Test 7: API Error Handling
  describe("Test 7: API Error Handling", () => {
    it("should reject invalid registration requests with HTTP 400 and validation details", async () => {
      const badRes = await fetch(`${BASE_URL}/api/near/register-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: "", // Empty
          scanType: "INVALID",
          riskScore: 200, // Too high
        }),
      });

      assert.equal(badRes.status, 400);
      const badData = await badRes.json();
      assert.equal(badData.error, "Validation failed");
      assert.ok(Array.isArray(badData.details) && badData.details.length >= 2);
    });
  });

  // Test 8: Security & Zero-Knowledge Checks
  describe("Test 8: Security and Zero-Knowledge Defense", () => {
    it("should reject private keys on scan endpoints", async () => {
      const secretRes = await fetch(`${BASE_URL}/api/scan/evm-wallet`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f3608a9",
          chain: "ethereum",
        }),
      });

      assert.equal(secretRes.status, 400);
      const secretData = await secretRes.json();
      assert.match(secretData.details[0], /SECURITY VIOLATION/);
    });

    it("should reject seed phrases on AI Analyst endpoint", async () => {
      const secretRes = await fetch(`${BASE_URL}/api/analyst/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "abandon ability able about above absent absorb abstract absurd abuse access accident",
        }),
      });

      assert.equal(secretRes.status, 400);
      const secretData = await secretRes.json();
      assert.equal(secretData.error, "Security Violation");
    });
  });
});

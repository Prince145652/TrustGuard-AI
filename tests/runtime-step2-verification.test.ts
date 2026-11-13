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

      // Honest live on-chain status verification:
      assert.equal(regData.record.status, "VERIFIED_ON_NEAR");
      assert.equal(regData.record.isContractDeployed, true);
      if (regData.record.nearTxHash) {
        assert.ok(typeof regData.record.nearTxHash === "string");
        assert.ok(regData.record.explorerUrl?.includes(regData.record.nearTxHash));
      }

      // Test duplicate registration returns identical record
      const dupRes = await fetch(`${BASE_URL}/api/near/register-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const dupData = await dupRes.json();
      assert.equal(dupData.record.reportId, regData.record.reportId);
      assert.equal(dupData.record.reportHash, regData.record.reportHash);
      assert.equal(dupData.record.status, "VERIFIED_ON_NEAR");
      assert.equal(dupData.record.isContractDeployed, true);
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
      assert.equal(regData.record.status, "VERIFIED_ON_NEAR");
      assert.equal(regData.record.isContractDeployed, true);
      if (regData.record.nearTxHash) {
        assert.ok(typeof regData.record.nearTxHash === "string");
        assert.ok(regData.record.explorerUrl?.includes(regData.record.nearTxHash));
      }
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
      assert.equal(regData.record.status, "VERIFIED_ON_NEAR");
      assert.equal(regData.record.isContractDeployed, true);
      if (regData.record.nearTxHash) {
        assert.ok(typeof regData.record.nearTxHash === "string");
        assert.ok(regData.record.explorerUrl?.includes(regData.record.nearTxHash));
      }
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

  // Test 9: Browser E2E: Scanner Component Lifecycle, Prefill Clearing & Repeated Same-Target Re-selection via Public UI (< 375px)
  describe("Test 9: Browser E2E: Scanner Component Lifecycle, Prefill Clearing & Repeated Same-Target Re-selection via Public UI (< 375px)", () => {
    it("should mount actual scanners, verify prefill clearing & repeated same-target re-selection via public UI behavior, and verify mobile layout at 360px width", async () => {
      const { spawn } = await import("node:child_process");
      const net = await import("node:net");
      const os = await import("node:os");
      const path = await import("node:path");
      const fs = await import("node:fs");

      // 1. Verify local Next.js server is reachable before launching Chrome
      try {
        const healthCheck = await fetch(`${BASE_URL}/`, { method: "HEAD" });
        assert.ok(healthCheck.status < 500, `Server responded with status ${healthCheck.status}`);
      } catch (err: unknown) {
        throw new Error(`Next.js development server is not reachable at ${BASE_URL}. Ensure server is running before executing E2E.`);
      }

      // 2. Allocate dynamic ephemeral port for Chrome CDP
      const cdpPort = await new Promise<number>((resolve, reject) => {
        const srv = net.createServer();
        srv.unref();
        srv.on("error", reject);
        srv.listen(0, "127.0.0.1", () => {
          const addr = srv.address();
          const port = typeof addr === "object" && addr !== null ? addr.port : 0;
          srv.close(() => resolve(port));
        });
      });

      // 3. Launch headless Chrome with dynamic port, isolated user data directory, and explicit error handling
      const userDataDir = path.join(os.tmpdir(), `tg-chrome-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
      fs.mkdirSync(userDataDir, { recursive: true });

      let chromeSpawnError: unknown = null;
      const chrome = spawn("google-chrome", [
        "--headless=new",
        `--remote-debugging-port=${cdpPort}`,
        `--user-data-dir=${userDataDir}`,
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
      ]);
      chrome.on("error", (err) => {
        chromeSpawnError = err;
      });

      let ws: WebSocket | null = null;

      try {
        // 4. Wait for Chrome / CDP readiness with timeout (poll /json/version up to 8000ms)
        const startWait = Date.now();
        let webSocketDebuggerUrl = "";
        while (Date.now() - startWait < 8000) {
          if (chromeSpawnError) {
            const errMsg = chromeSpawnError instanceof Error ? chromeSpawnError.message : String(chromeSpawnError);
            throw new Error(`Failed to launch Chrome process: ${errMsg}`);
          }
          if (chrome.exitCode !== null || chrome.signalCode !== null) {
            throw new Error(`Chrome process exited prematurely with code ${chrome.exitCode}, signal ${chrome.signalCode}`);
          }
          try {
            const versionRes = await fetch(`http://127.0.0.1:${cdpPort}/json/version`);
            if (versionRes.ok) {
              const data = await versionRes.json();
              if (data.webSocketDebuggerUrl) {
                webSocketDebuggerUrl = data.webSocketDebuggerUrl;
                break;
              }
            }
          } catch {
            // Chrome still initializing
          }
          await new Promise((r) => setTimeout(r, 150));
        }
        if (chromeSpawnError) {
          const errMsg = chromeSpawnError instanceof Error ? chromeSpawnError.message : String(chromeSpawnError);
          throw new Error(`Failed to launch Chrome process: ${errMsg}`);
        }
        assert.ok(webSocketDebuggerUrl, "Chrome CDP failed to initialize within 8 seconds");

        // 5. Open new tab pointing to BASE_URL
        const tabRes = await fetch(`http://127.0.0.1:${cdpPort}/json/new?${BASE_URL}`, { method: "PUT" });
        const tabData = await tabRes.json();
        const tabWsUrl = tabData.webSocketDebuggerUrl;
        assert.ok(tabWsUrl, "Failed to create new browser tab");

        // 6. Connect WebSocket with explicit 5000ms connection timeout
        ws = new WebSocket(tabWsUrl);
        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error("WebSocket connection to Chrome timed out after 5000ms")), 5000);
          ws!.onopen = () => {
            clearTimeout(timer);
            resolve();
          };
          ws!.onerror = (err) => {
            clearTimeout(timer);
            reject(err);
          };
        });

        let idCounter = 0;
        const pending = new Map<number, { resolve: (val: any) => void; reject: (err: any) => void }>();

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data.toString());
            if (msg.id && pending.has(msg.id)) {
              const { resolve, reject } = pending.get(msg.id)!;
              pending.delete(msg.id);
              if (msg.error) reject(new Error(msg.error.message));
              else resolve(msg.result);
            }
          } catch (e) {
            console.error("CDP parse error:", e);
          }
        };

        // 7. CDP command dispatcher with explicit 5000ms timeout per command
        const sendCdp = (method: string, params: Record<string, any> = {}, timeoutMs = 5000) => {
          return new Promise<any>((resolve, reject) => {
            const id = ++idCounter;
            const timer = setTimeout(() => {
              pending.delete(id);
              reject(new Error(`CDP command '${method}' timed out after ${timeoutMs}ms`));
            }, timeoutMs);

            pending.set(id, {
              resolve: (val) => {
                clearTimeout(timer);
                resolve(val);
              },
              reject: (err) => {
                clearTimeout(timer);
                reject(err);
              },
            });
            ws!.send(JSON.stringify({ id, method, params }));
          });
        };

        const evaluate = async (expression: string) => {
          const res = await sendCdp("Runtime.evaluate", {
            expression,
            returnByValue: true,
            awaitPromise: true,
          });
          return res?.result?.value;
        };

        // Helper to poll until a predicate is true, ensuring React renders and effects commit
        const waitForPredicate = async (expression: string, timeoutMs = 5000) => {
          const start = Date.now();
          while (Date.now() - start < timeoutMs) {
            const ok = await evaluate(expression);
            if (ok) return true;
            await new Promise((r) => setTimeout(r, 100));
          }
          throw new Error(`Predicate timed out after ${timeoutMs}ms: ${expression}`);
        };

        // 8. Apply genuine mobile device emulation (360px viewport width, Android Pixel ratio)
        await sendCdp("Emulation.setDeviceMetricsOverride", {
          width: 360,
          height: 800,
          deviceScaleFactor: 2,
          mobile: true,
          fitWindow: false,
        });
        await sendCdp("Emulation.setTouchEmulationEnabled", { enabled: true });

        // Wait for page hydration on Overview tab
        await waitForPredicate(`document.readyState === 'complete' && Boolean(document.querySelector('aside'))`);

        // Helper: Genuine Chrome CDP browser interaction (focus, Ctrl+A select, insertText or backspace)
        const typeInputWithCdp = async (selector: string, text: string) => {
          // 1. Focus the target input element and select any existing value safely using JSON.stringify
          await evaluate(`(() => {
            const el = document.querySelector(${JSON.stringify(selector)});
            if (el) {
              el.focus();
              el.select();
            }
          })()`);

          // 2. Select all existing text using CDP Ctrl+A key events
          await sendCdp("Input.dispatchKeyEvent", {
            type: "rawKeyDown",
            windowsVirtualKeyCode: 65,
            key: "a",
            code: "KeyA",
            modifiers: 2, // Control modifier
          });
          await sendCdp("Input.dispatchKeyEvent", {
            type: "keyUp",
            windowsVirtualKeyCode: 65,
            key: "a",
            code: "KeyA",
            modifiers: 0,
          });

          // 3. Clear via Backspace key or insert new text via CDP Input.insertText
          if (text === "") {
            await sendCdp("Input.dispatchKeyEvent", {
              type: "rawKeyDown",
              windowsVirtualKeyCode: 8,
              key: "Backspace",
              code: "Backspace",
            });
            await sendCdp("Input.dispatchKeyEvent", {
              type: "keyUp",
              windowsVirtualKeyCode: 8,
              key: "Backspace",
              code: "Backspace",
            });
          } else {
            await sendCdp("Input.insertText", { text });
          }

          // 4. Wait for React to process native input events and commit the state update safely
          await waitForPredicate(
            `(() => {
              const el = document.querySelector(${JSON.stringify(selector)});
              return el ? el.value === ${JSON.stringify(text)} : false;
            })()`
          );
        };

        // Helper: Navigate back to Overview tab
        const navigateToOverview = async () => {
          await evaluate(`(() => {
            const btn = Array.from(document.querySelectorAll('aside nav button')).find(b => b.textContent && b.textContent.includes('Overview'));
            if (btn) btn.click();
          })()`);
          await waitForPredicate(`Boolean(document.querySelector('input[placeholder*="alice.near"]'))`);
        };

        // =========================================================================
        // LIFECYCLE 1: EVM Wallet Scanner Parent-to-Scanner Prefill & Re-selection
        // =========================================================================
        // Step 1: In ScannerCards on Overview, populate EVM wallet address via CDP
        const walletTarget = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        await typeInputWithCdp('input[placeholder*="alice.near"]', walletTarget);
        await evaluate(`(() => {
          const scanBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.trim() === 'Scan');
          if (scanBtn) scanBtn.click();
        })()`);
        await waitForPredicate(`Boolean(Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner')))`);

        // Step 2: Navigate to Full Scanner
        await evaluate(`(() => {
          const fullBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner'));
          if (fullBtn) fullBtn.click();
        })()`);
        await waitForPredicate(`Boolean(document.querySelector('input[placeholder*="0xd8dA6BF"]')) && document.querySelector('input[placeholder*="0xd8dA6BF"]').value === '${walletTarget}'`);

        // Step 3: Clear input via CDP Backspace to test parent re-population
        await typeInputWithCdp('input[placeholder*="0xd8dA6BF"]', "");

        // Step 4: Navigate back to Overview tab (ScannerCards remounts fresh)
        await navigateToOverview();

        // Step 4b: Verify parent prefill clearing via public UI behavior
        const overviewWalletVal = await evaluate(`document.querySelector('input[placeholder*="alice.near"]').value`);
        assert.equal(overviewWalletVal, "", "Overview wallet card input must be reset/empty");
        const hasWalletFullBtn = await evaluate(`Boolean(Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner')))`);
        assert.equal(hasWalletFullBtn, false, "Overview card must not retain stale scan result or Full Scanner button");

        // Step 5: Scan the EXACT SAME wallet address in ScannerCards again via CDP
        await typeInputWithCdp('input[placeholder*="alice.near"]', walletTarget);
        await evaluate(`(() => {
          const scanBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.trim() === 'Scan');
          if (scanBtn) scanBtn.click();
        })()`);
        await waitForPredicate(`Boolean(Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner')))`);

        // Step 6: Click "Full Scanner" with the EXACT SAME address a second time
        await evaluate(`(() => {
          const fullBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner'));
          if (fullBtn) fullBtn.click();
        })()`);

        // Step 7: Verify EvmWalletScanner re-synchronizes the identical target cleanly
        await waitForPredicate(`Boolean(document.querySelector('input[placeholder*="0xd8dA6BF"]')) && document.querySelector('input[placeholder*="0xd8dA6BF"]').value === '${walletTarget}'`);
        const walletInputVal = await evaluate(`document.querySelector('input[placeholder*="0xd8dA6BF"]').value`);
        assert.equal(walletInputVal, walletTarget, "EvmWalletScanner must re-synchronize exact same target after parent clears prefill");

        // Step 8: Verify chain switching in EvmWalletScanner without retaining stale selection (switch to Base)
        await evaluate(`(() => {
          const baseBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Base Ecosystem Wallet'));
          if (baseBtn) baseBtn.click();
        })()`);
        await waitForPredicate(`document.querySelector('input[placeholder*="0xd8dA6BF"]').value === '0x4200000000000000000000000000000000000006'`);
        const isBaseSelected = await evaluate(`(() => {
          const b = Array.from(document.querySelectorAll('button')).find(btn => btn.textContent && btn.textContent.includes('Base') && btn.textContent.includes('Chain ID: 8453'));
          return b ? b.className.includes('border-emerald-500') : false;
        })()`);
        assert.ok(isBaseSelected, "Chain selection must update to Base without stale Ethereum values");

        // Step 9: Verify 360px mobile viewport containment (no horizontal scrollbar)
        const walletOverflow = await evaluate(`document.documentElement.scrollWidth <= window.innerWidth`);
        assert.ok(walletOverflow, "Wallet Scanner UI must not cause document horizontal scroll at 360px");

        // =========================================================================
        // LIFECYCLE 2: Website Scam Detector Parent-to-Scanner Prefill & Re-selection
        // =========================================================================
        await navigateToOverview();

        // Step 1: On Overview Website card, select preset chip "ref.finance" and scan
        const websiteTarget = "https://app.ref.finance";
        const websiteExpectedPrefill = "app.ref.finance";
        await evaluate(`(() => {
          const chip = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.trim() === 'ref.finance');
          if (chip) chip.click();
        })()`);
        await waitForPredicate(`document.querySelector('input[placeholder*="https://ref-finance"]').value === '${websiteTarget}'`);

        await evaluate(`(() => {
          const scanBtns = Array.from(document.querySelectorAll('button')).filter(b => b.textContent && b.textContent.trim() === 'Scan');
          if (scanBtns[1]) scanBtns[1].click(); // second Scan button is for Website card
        })()`);
        await waitForPredicate(`Boolean(Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner')))`);

        // Step 2: Navigate to Full Scanner
        await evaluate(`(() => {
          const fullBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner'));
          if (fullBtn) fullBtn.click();
        })()`);
        await waitForPredicate(`Boolean(document.querySelector('input[placeholder*="app.ref.finance"]')) && document.querySelector('input[placeholder*="app.ref.finance"]').value === '${websiteExpectedPrefill}'`);

        // Step 3: Clear input via CDP Backspace
        await typeInputWithCdp('input[placeholder*="app.ref.finance"]', "");

        // Step 4: Navigate back to Overview tab (remounts fresh)
        await navigateToOverview();

        // Step 4b: Verify parent prefill clearing via public UI behavior
        const overviewWebsiteVal = await evaluate(`document.querySelector('input[placeholder*="https://ref-finance"]').value`);
        assert.equal(overviewWebsiteVal, "", "Overview website card input must be reset/empty");
        const hasWebsiteFullBtn = await evaluate(`Boolean(Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner')))`);
        assert.equal(hasWebsiteFullBtn, false, "Overview website card must not retain stale scan result or Full Scanner button");

        // Step 5: Click preset chip "ref.finance" and scan again
        await evaluate(`(() => {
          const chip = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.trim() === 'ref.finance');
          if (chip) chip.click();
        })()`);
        await waitForPredicate(`document.querySelector('input[placeholder*="https://ref-finance"]').value === '${websiteTarget}'`);
        await evaluate(`(() => {
          const scanBtns = Array.from(document.querySelectorAll('button')).filter(b => b.textContent && b.textContent.trim() === 'Scan');
          if (scanBtns[1]) scanBtns[1].click();
        })()`);
        await waitForPredicate(`Boolean(Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner')))`);

        // Step 6: Click "Full Scanner" with the EXACT SAME URL a second time
        await evaluate(`(() => {
          const fullBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner'));
          if (fullBtn) fullBtn.click();
        })()`);

        // Step 7: Verify WebsiteScamDetector re-synchronizes the identical URL cleanly
        await waitForPredicate(`Boolean(document.querySelector('input[placeholder*="app.ref.finance"]')) && document.querySelector('input[placeholder*="app.ref.finance"]').value === '${websiteExpectedPrefill}'`);
        const websiteInputVal = await evaluate(`document.querySelector('input[placeholder*="app.ref.finance"]').value`);
        assert.equal(websiteInputVal, websiteExpectedPrefill, "WebsiteScamDetector must re-synchronize exact same target after parent clears prefill");

        // Step 8: Verify 360px mobile viewport containment
        const websiteOverflow = await evaluate(`document.documentElement.scrollWidth <= window.innerWidth`);
        assert.ok(websiteOverflow, "Website Scanner UI must not cause document horizontal scroll at 360px");

        // =========================================================================
        // LIFECYCLE 3: Token Security Scanner Parent-to-Scanner Prefill & Re-selection
        // =========================================================================
        await navigateToOverview();

        // Step 1: On Overview Token card, enter EVM token address (USDT) via CDP and scan
        const tokenTarget = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        await typeInputWithCdp('input[placeholder*="token.sweat"]', tokenTarget);
        await evaluate(`(() => {
          const scanBtns = Array.from(document.querySelectorAll('button')).filter(b => b.textContent && b.textContent.trim() === 'Scan');
          if (scanBtns[2]) scanBtns[2].click(); // third Scan button is for Token card
        })()`);
        await waitForPredicate(`Boolean(Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner')))`);

        // Step 2: Navigate to Full Scanner
        await evaluate(`(() => {
          const fullBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner'));
          if (fullBtn) fullBtn.click();
        })()`);
        await waitForPredicate(`Boolean(document.querySelector('input[placeholder*="0xdAC17F"]')) && document.querySelector('input[placeholder*="0xdAC17F"]').value === '${tokenTarget}'`);

        // Step 3: Clear input via CDP Backspace
        await typeInputWithCdp('input[placeholder*="0xdAC17F"]', "");

        // Step 4: Navigate back to Overview tab (remounts fresh)
        await navigateToOverview();

        // Step 4b: Verify parent prefill clearing via public UI behavior
        const overviewTokenVal = await evaluate(`document.querySelector('input[placeholder*="token.sweat"]').value`);
        assert.equal(overviewTokenVal, "", "Overview token card input must be reset/empty");
        const hasTokenFullBtn = await evaluate(`Boolean(Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner')))`);
        assert.equal(hasTokenFullBtn, false, "Overview token card must not retain stale scan result or Full Scanner button");

        // Step 5: Enter the EXACT SAME token address via CDP and scan again
        await typeInputWithCdp('input[placeholder*="token.sweat"]', tokenTarget);
        await evaluate(`(() => {
          const scanBtns = Array.from(document.querySelectorAll('button')).filter(b => b.textContent && b.textContent.trim() === 'Scan');
          if (scanBtns[2]) scanBtns[2].click();
        })()`);
        await waitForPredicate(`Boolean(Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner')))`);

        // Step 6: Click "Full Scanner" with the EXACT SAME address a second time
        await evaluate(`(() => {
          const fullBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Full Scanner'));
          if (fullBtn) fullBtn.click();
        })()`);

        // Step 7: Verify TokenSecurityScanner re-synchronizes the identical token contract cleanly
        await waitForPredicate(`Boolean(document.querySelector('input[placeholder*="0xdAC17F"]')) && document.querySelector('input[placeholder*="0xdAC17F"]').value === '${tokenTarget}'`);
        const tokenInputVal = await evaluate(`document.querySelector('input[placeholder*="0xdAC17F"]').value`);
        assert.equal(tokenInputVal, tokenTarget, "TokenSecurityScanner must re-synchronize exact same target after parent clears prefill");

        // Step 8: Switch chains to BNB Chain in TokenSecurityScanner without retaining stale Ethereum selection
        await evaluate(`(() => {
          const bnbBtn = Array.from(document.querySelectorAll('button')).find(b => b.textContent && b.textContent.includes('Wrapped BNB (WBNB - BSC)'));
          if (bnbBtn) bnbBtn.click();
        })()`);
        await waitForPredicate(`document.querySelector('input[placeholder*="0xdAC17F"]').value === '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c'`);
        const isBnbSelected = await evaluate(`(() => {
          const b = Array.from(document.querySelectorAll('button')).find(btn => btn.textContent && btn.textContent.includes('BNB Chain') && btn.textContent.includes('Chain ID: 56'));
          return b ? b.className.includes('border-emerald-500') : false;
        })()`);
        assert.ok(isBnbSelected, "Token scanner chain selection must update to BNB without stale Ethereum values");

        // Step 9: Verify 360px mobile viewport containment
        const tokenOverflow = await evaluate(`document.documentElement.scrollWidth <= window.innerWidth`);
        assert.ok(tokenOverflow, "Token Security Scanner UI must not cause document horizontal scroll at 360px");
      } finally {
        // Clean up WebSocket connection
        if (ws && ws.readyState === WebSocket.OPEN) {
          try { ws.close(); } catch {}
        }

        // Ensure Chrome process exits completely before deleting the temporary user-data directory
        let chromeExited = false;
        if (chromeSpawnError) {
          // Chrome never successfully spawned, cleanup directory safely
          chromeExited = true;
        } else if (chrome) {
          // Check if process has already exited (either normally via exitCode or via signalCode)
          if (chrome.exitCode !== null || chrome.signalCode !== null) {
            chromeExited = true;
          } else {
            chromeExited = await new Promise<boolean>((resolve) => {
              let sigkillTimer: NodeJS.Timeout | null = null;
              let giveUpTimer: NodeJS.Timeout | null = null;

              const onExit = () => {
                if (sigkillTimer) clearTimeout(sigkillTimer);
                if (giveUpTimer) clearTimeout(giveUpTimer);
                resolve(true);
              };

              // 1. Escalate to SIGKILL after 3 seconds if Chrome hasn't exited
              sigkillTimer = setTimeout(() => {
                if (chrome.exitCode === null && chrome.signalCode === null) {
                  try { chrome.kill("SIGKILL"); } catch {}
                }
              }, 3000);

              // 2. If termination cannot be confirmed within 10 seconds, do not hang indefinitely
              giveUpTimer = setTimeout(() => {
                chrome.removeListener("exit", onExit);
                if (chrome.exitCode !== null || chrome.signalCode !== null) {
                  resolve(true);
                } else {
                  resolve(false);
                }
              }, 10000);

              chrome.once("exit", onExit);

              // 3. Send SIGTERM first if still running
              if (chrome.exitCode === null && chrome.signalCode === null) {
                try { chrome.kill("SIGTERM"); } catch {}
              }
            });
          }
        }

        // Delete temporary user data directory ONLY after Chrome process termination is confirmed
        if (chromeExited) {
          try {
            fs.rmSync(userDataDir, { recursive: true, force: true });
          } catch (err: unknown) {
            console.warn(`[Cleanup Warning] Failed to delete userDataDir ${userDataDir}:`, err);
          }
        } else {
          console.warn(`[Cleanup Warning] Chrome process did not emit exit event; skipping directory deletion for ${userDataDir}`);
        }
      }
    });
  });
});

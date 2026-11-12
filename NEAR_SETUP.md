# NEAR Protocol Setup Guide for TrustGuard AI

Welcome to the **TrustGuard AI** NEAR integration guide! This document explains how our Web3 security platform connects with the **NEAR Protocol Testnet** to timestamp and immutably verify audit reports.

---

## 1. Architecture Overview

TrustGuard AI implements a **Zero-Knowledge Off-Chain Compute, On-Chain Verification** pattern:

1. **Security Scan**: The user scans a wallet, website, or token on EVM/NEAR networks.
2. **Canonical Hashing**: The scan result is transformed into deterministic, sorted JSON and hashed using **SHA-256**.
3. **NEAR Anchoring**: The SHA-256 hash, Report ID, target, and risk score are registered on the NEAR Testnet smart contract.
4. **Third-Party Verification**: Anyone can verify the authenticity of an audit report at any time by recalculating the SHA-256 hash and checking the NEAR ledger.

> [!IMPORTANT]
> **Zero-Knowledge Privacy Guarantee**:
> TrustGuard AI never transmits private keys, mnemonic seed phrases, or sensitive user data to the blockchain. Only cryptographic hashes and high-level risk metrics are stored on-chain.

---

## 2. Prerequisites

To build and deploy the NEAR smart contract, you need the following tools installed on your development machine:

### A. Node.js & npm
- **Node.js**: v18.0.0 or higher (Current environment: `v22.22.1`)
- **npm**: v9.0.0 or higher

Check your installation:
```bash
node -v
npm -v
```

### B. Rust & Wasm Target (for Smart Contract compilation)
The smart contract registry is written in Rust. You need the Rust compiler and the WebAssembly (`wasm32`) target:

```bash
# 1. Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Add the wasm32 compilation target
rustup target add wasm32-unknown-unknown
```

### C. NEAR CLI
Install the official NEAR CLI tool to manage accounts and deploy contracts:

```bash
# Option 1: Modern NEAR CLI RS (Recommended by NEAR Foundation)
cargo install near-cli-rs

# Option 2: Node.js NEAR CLI
npm install -g near-cli
```

---

## 3. Creating a NEAR Testnet Account

1. Open your browser and go to [MyNearWallet Testnet](https://testnet.mynearwallet.com/).
2. Click **Create Account** and pick an account ID (e.g. `your-team.testnet`).
3. Store the 12-word recovery phrase safely.
4. The testnet faucet will automatically fund your account with free Testnet NEAR tokens.

Alternatively, you can create an account using NEAR CLI:
```bash
near account create-account sponsor-by-faucet-service your-team.testnet autogenerate-new-keypair save-to-keychain network-config testnet
```

---

## 4. Environment Variables Configuration

Create or update `.env.local` in the root of the project with your NEAR Testnet configuration:

```bash
# ==========================================
# NEAR PROTOCOL CONFIGURATION (Testnet Only)
# ==========================================
NEAR_NETWORK_ID="testnet"
NEAR_NODE_URL="https://rpc.testnet.near.org"
NEAR_CONTRACT_ID="tg-auditor-2026.testnet"

# Optional: Server-Side Automated Anchoring Signer
# (Never share or commit private keys to GitHub!)
# NEAR_SIGNER_ACCOUNT_ID="your-relayer.testnet"
# NEAR_SIGNER_PRIVATE_KEY="ed25519:YOUR_SECRET_KEY_HERE"
```

> [!WARNING]
> Never set `NEAR_NETWORK_ID="mainnet"` during development or testing. All hackathon testing must strictly be conducted on `testnet`.

---

## 5. Verifying the Connection

You can check whether TrustGuard AI is successfully communicating with the NEAR Testnet RPC:

1. Start the development server:
   ```bash
   npm run dev
   ```
2. Make a query to our local API route:
   ```bash
   curl -s "http://localhost:3000/api/near/verify-report?hash=query-status"
   ```
3. You will receive a response confirming live block synchronization:
   ```json
   {
     "isVerified": false,
     "status": "UNVERIFIED",
     "queriedAtBlock": 275446158,
     "network": "testnet",
     "message": "Report hash not found in NEAR Testnet registry contract."
   }
   ```

---

## 6. Directory Structure

The NEAR integration files in this codebase are organized as follows:

```
├── contracts/
│   └── trustguard-registry/          # Rust Smart Contract
│       ├── Cargo.toml                # near-sdk v5.1.0 dependencies
│       └── src/
│           └── lib.rs                # On-chain registry & verification logic
├── src/
│   ├── types/
│   │   └── near-verification.ts      # TypeScript interfaces for on-chain records
│   ├── lib/
│   │   ├── near-config.ts            # NEAR Testnet configuration constants
│   │   ├── near-hashing.ts           # Canonical JSON serialization & SHA-256
│   │   ├── tx-cache.ts               # Base58 32-byte transaction hash caching & persistence
│   │   └── near-client.ts            # near-api-js RPC client & contract caller
│   ├── app/api/near/
│   │   ├── register-report/route.ts  # POST endpoint to anchor report
│   │   └── verify-report/route.ts    # GET & POST endpoints to verify reports
│   └── components/near/
│       └── NearVerificationDashboard.tsx # Frontend verification interface
```

For instructions on building and deploying the smart contract to NEAR Testnet, refer to [CONTRACT_DEPLOYMENT.md](file:///home/prince/agy-demo/CONTRACT_DEPLOYMENT.md).

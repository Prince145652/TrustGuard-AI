const fs = require("fs");
const path = require("path");
const os = require("os");
const { KeyPair, connect, keyStores } = require("near-api-js");

const CREDENTIALS_DIR = path.join(os.homedir(), ".near-credentials", "testnet");
const PENDING_FILE = path.join(CREDENTIALS_DIR, "_pending_auth.json");

const NEAR_CONFIG = {
  networkId: "testnet",
  nodeUrl: "https://rpc.testnet.near.org",
  walletUrl: "https://testnet.mynearwallet.com",
};

async function init() {
  if (!fs.existsSync(CREDENTIALS_DIR)) {
    fs.mkdirSync(CREDENTIALS_DIR, { recursive: true, mode: 0o700 });
  }

  // Generate deterministic/fresh random ed25519 keypair
  const keyPair = KeyPair.fromRandom("ed25519");
  const publicKey = keyPair.getPublicKey().toString();
  const privateKey = keyPair.toString();

  // Persist pending key safely so it survives timeouts
  fs.writeFileSync(
    PENDING_FILE,
    JSON.stringify({ public_key: publicKey, private_key: privateKey }),
    { mode: 0o600 }
  );

  const authUrl = `${NEAR_CONFIG.walletUrl}/login/?referrer=TrustGuard+AI&public_key=${encodeURIComponent(
    publicKey
  )}`;

  console.log(JSON.stringify({
    status: "PENDING_AUTHORIZATION",
    publicKey,
    authUrl,
  }));
}

async function verifyAndComplete(accountId) {
  if (!accountId || typeof accountId !== "string" || !accountId.trim()) {
    console.error(JSON.stringify({ error: "Please provide a valid NEAR Testnet account ID" }));
    process.exit(1);
  }

  const cleanAccountId = accountId.trim().toLowerCase();

  // Check if credentials already exist
  const finalCredFile = path.join(CREDENTIALS_DIR, `${cleanAccountId}.json`);

  let keyPair;
  if (fs.existsSync(finalCredFile)) {
    const data = JSON.parse(fs.readFileSync(finalCredFile, "utf8"));
    keyPair = KeyPair.fromString(data.private_key || data.secret_key);
  } else if (fs.existsSync(PENDING_FILE)) {
    const data = JSON.parse(fs.readFileSync(PENDING_FILE, "utf8"));
    keyPair = KeyPair.fromString(data.private_key);
  } else {
    console.error(JSON.stringify({ error: "No pending or saved keypair found. Run init first." }));
    process.exit(1);
  }

  const publicKey = keyPair.getPublicKey().toString();

  // Connect to NEAR Testnet in read-only mode
  const keyStore = new keyStores.InMemoryKeyStore();
  await keyStore.setKey(NEAR_CONFIG.networkId, cleanAccountId, keyPair);

  const near = await connect({
    networkId: NEAR_CONFIG.networkId,
    nodeUrl: NEAR_CONFIG.nodeUrl,
    keyStore,
  });

  const account = await near.account(cleanAccountId);

  // 1. Read-only query: check access keys
  let accessKeys = [];
  try {
    accessKeys = await account.getAccessKeys();
  } catch (err) {
    console.error(JSON.stringify({
      error: `Failed to fetch access keys for ${cleanAccountId}: ${err.message}`,
      network: "testnet",
    }));
    process.exit(1);
  }

  const keyFound = accessKeys.some((k) => k.public_key === publicKey);

  // If not found in accessKeys, check if it was already confirmed or if user has full access
  if (!keyFound && !fs.existsSync(finalCredFile)) {
    console.log(JSON.stringify({
      status: "KEY_NOT_YET_AUTHORIZED",
      accountId: cleanAccountId,
      expectedPublicKey: publicKey,
      authorizedKeys: accessKeys.map((k) => k.public_key),
      message: `The account ${cleanAccountId} does not have access key ${publicKey} on NEAR Testnet yet.`,
    }));
    process.exit(1);
  }

  // 2. Persist in official credentials directory
  fs.writeFileSync(
    finalCredFile,
    JSON.stringify({
      account_id: cleanAccountId,
      public_key: publicKey,
      private_key: keyPair.toString(),
    }, null, 2),
    { mode: 0o600 }
  );

  if (fs.existsSync(PENDING_FILE)) {
    fs.unlinkSync(PENDING_FILE);
  }

  // 3. Read-only query: check account state (balance, storage)
  const state = await account.state();

  // yoctoNEAR is 10^24
  const rawAmount = BigInt(state.amount);
  const rawStorageUsage = BigInt(state.storage_usage);
  const nearAmount = (Number(rawAmount / BigInt(10 ** 20)) / 10000).toFixed(4);

  console.log(JSON.stringify({
    status: "AUTHORIZED",
    accountId: cleanAccountId,
    network: "NEAR Testnet (testnet)",
    nodeUrl: NEAR_CONFIG.nodeUrl,
    balanceNear: `${nearAmount} NEAR`,
    rawAmountYocto: state.amount,
    storageUsageBytes: state.storage_usage,
    blockHeight: state.block_height,
    publicKey,
  }));
}

const action = process.argv[2];
const accountArg = process.argv[3];

if (action === "init") {
  init().catch((err) => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (action === "complete" || action === "check") {
  verifyAndComplete(accountArg).catch((err) => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else {
  console.log("Usage: node scripts/near-auth.js [init|complete <accountId>]");
}

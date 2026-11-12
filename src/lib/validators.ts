import { z } from "zod";

// Defensive check: detect if someone accidentally pastes a seed phrase or private key
export function looksLikeSecret(value: string): boolean {
  if (!value || typeof value !== "string") return false;
  const trimmed = value.trim();

  // Explicit safety placeholder check
  const placeholderRegex = /\[REDACTED_(PRIVATE_KEY|SECRET|SEED_PHRASE)\]|\[(PRIVATE_KEY|SEED_PHRASE)\]/i;
  if (placeholderRegex.test(trimmed)) {
    return true;
  }

  // Raw 64-hex EVM Private Key (with or without 0x)
  if (/\b(0x)?[0-9a-fA-F]{64}\b/.test(trimmed)) {
    return true;
  }

  // Raw NEAR ed25519 or secp256k1 private key
  if (/\b(ed25519|secp256k1):[a-zA-Z0-9]{40,}\b/.test(trimmed)) {
    return true;
  }

  // If text contains question marks, exclamation marks, commas, or common sentence punctuation,
  // it is natural language dialogue, not a raw mnemonic phrase
  if (/[?!,;]/.test(trimmed)) {
    return false;
  }

  // BIP-39 mnemonic seed phrase check:
  // Must be exactly 12, 15, 18, 21, or 24 words of pure alphabetic lowercase letters
  const words = trimmed.split(/\s+/);
  const validMnemonicLengths = [12, 15, 18, 21, 24];
  if (validMnemonicLengths.includes(words.length)) {
    const allPureWords = words.every((w) => /^[a-zA-Z]{3,12}$/.test(w));
    // If every word is pure letters without punctuation, check if it's not a common question sentence
    const conversationalStopWords = new Set([
      "why", "what", "how", "when", "where", "who", "which", "is", "are", "can",
      "could", "should", "would", "the", "this", "that", "please", "explain",
      "tell", "kyun", "hai", "kya", "kaise", "hain", "karna", "mujhe", "wallet", "website"
    ]);
    const hasConversationalWords = words.some((w) => conversationalStopWords.has(w.toLowerCase()));
    if (allPureWords && !hasConversationalWords) {
      return true;
    }
  }

  return false;
}

/**
 * Sanitizes and masks sensitive credentials before logging or forwarding to external APIs.
 */
export function redactSecrets(text: string): string {
  if (!text || typeof text !== "string") return text;
  let sanitized = text;

  // 1. Redact placeholders
  sanitized = sanitized.replace(/\[REDACTED_(PRIVATE_KEY|SECRET|SEED_PHRASE)\]/gi, "[REDACTED_PRIVATE_KEY]");
  sanitized = sanitized.replace(/\[(PRIVATE_KEY|SEED_PHRASE)\]/gi, "[REDACTED_PRIVATE_KEY]");

  // 2. Redact 64-hex EVM private keys (preserving 40-character public addresses)
  sanitized = sanitized.replace(/\b0x[0-9a-fA-F]{64}\b/g, "[REDACTED_PRIVATE_KEY]");
  sanitized = sanitized.replace(/\b[0-9a-fA-F]{64}\b/g, "[REDACTED_PRIVATE_KEY]");

  // 3. Redact NEAR ed25519 / secp256k1 private keys
  sanitized = sanitized.replace(/\b(ed25519|secp256k1):[a-zA-Z0-9]{40,}\b/g, "[REDACTED_NEAR_KEY]");

  return sanitized;
}

/**
 * Detects whether a user message is inquiring about, sharing, or attempting to audit a private key or seed phrase.
 */
export function isAskingAboutPrivateKey(text: string): boolean {
  if (!text || typeof text !== "string") return false;
  const lower = text.toLowerCase();
  return (
    lower.includes("[redacted_private_key]") ||
    lower.includes("[redacted_secret]") ||
    lower.includes("[redacted_seed_phrase]") ||
    lower.includes("private key") ||
    lower.includes("private-key") ||
    lower.includes("seed phrase") ||
    lower.includes("seedphrase") ||
    lower.includes("recovery phrase") ||
    lower.includes("mnemonic") ||
    lower.includes("secret key")
  );
}

// NEAR Account ID validation
// Pattern: 2-64 chars, lowercase alphanumeric, -, _, .
const NEAR_ACCOUNT_REGEX = /^(([a-z0-9_-]+\.)*[a-z0-9_-]+|[0-9a-f]{64})$/;

export const walletScanSchema = z.object({
  target: z
    .string()
    .trim()
    .min(2, "Wallet address or NEAR account ID must be at least 2 characters")
    .refine((val) => !looksLikeSecret(val), {
      message: "SECURITY WARNING: Private keys and seed phrases are strictly forbidden!",
    })
    .max(64, "Account identifier too long")
    .refine(
      (val) => {
        const lower = val.toLowerCase();
        // Reject 40-character hex strings missing the required 0x prefix
        if (/^[a-f0-9]{40}$/.test(lower)) {
          return false;
        }
        if (lower.startsWith("0x")) {
          return /^0x[a-f0-9]{40}$/.test(lower) || /^0x[a-f0-9]{64}$/.test(lower);
        }
        return NEAR_ACCOUNT_REGEX.test(lower);
      },
      {
        message: "Please enter a valid NEAR account (e.g. 'alice.near') or public EVM address",
      }
    ),
});

export const tokenScanSchema = z.object({
  target: z
    .string()
    .trim()
    .min(2, "Token contract address must be at least 2 characters")
    .max(128, "Token contract address too long")
    .refine((val) => !looksLikeSecret(val), {
      message: "SECURITY WARNING: Never provide private keys or secrets!",
    }),
});

export const urlScanSchema = z.object({
  target: z
    .string()
    .trim()
    .min(4, "URL is too short")
    .refine((val) => {
      try {
        const urlToTest = val.startsWith("http://") || val.startsWith("https://") ? val : `https://${val}`;
        const parsed = new URL(urlToTest);
        return parsed.hostname.includes(".");
      } catch {
        return false;
      }
    }, "Please provide a valid website URL or domain (e.g., https://near-claim.fake.org)"),
});

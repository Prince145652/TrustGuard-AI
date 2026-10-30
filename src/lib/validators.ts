import { z } from "zod";

// Defensive check: detect if someone accidentally pastes a seed phrase or private key
export function looksLikeSecret(value: string): boolean {
  const trimmed = value.trim();

  // If text contains question marks, exclamation marks, commas, or common sentence punctuation,
  // it is natural language dialogue, not a raw mnemonic or private key
  if (/[?!,;]/.test(trimmed)) {
    return false;
  }

  // Raw 64-hex EVM Private Key (with or without 0x)
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(trimmed)) {
    return true;
  }

  // Raw NEAR ed25519 or secp256k1 private key
  if (trimmed.startsWith("ed25519:") && trimmed.length > 70) return true;
  if (trimmed.startsWith("secp256k1:") && trimmed.length > 70) return true;

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

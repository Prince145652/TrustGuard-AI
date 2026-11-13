import { NextRequest, NextResponse } from "next/server";
import { isIP } from "node:net";

/**
 * ARCHITECTURAL SECURITY AUDIT NOTES:
 *
 * 1. Process-Local / Single-Instance Store:
 *    Rate limiting is tracked in process-local memory (`ipStore = new Map()`).
 *    In a distributed, multi-instance, or serverless deployment (e.g., AWS Lambda,
 *    Vercel Serverless Functions, or Kubernetes multi-pod clusters), in-memory state
 *    is NOT synchronized across instances. To enforce distributed rate limiting in
 *    production, an external distributed store such as Redis or Upstash must be used.
 *
 * 2. Trusted Proxy & Anti-Spoofing Architecture:
 *    Forwarding headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP) are untrusted
 *    and easily spoofed by clients in direct HTTP connections. Therefore, forwarding
 *    headers are ONLY inspected when `TRUSTED_PROXY` is explicitly configured
 *    ('cloudflare', 'nginx', etc.).
 *
 *    - Cloudflare Mode ('cloudflare'):
 *      Inspects CF-Connecting-IP, verified with `isIP()`.
 *
 *    - Nginx / Custom Reverse Proxy Mode ('nginx' | 'custom'):
 *      CRITICAL PROXY HARDENING ENFORCEMENT:
 *      In Nginx/custom proxy mode, this implementation trusts ONLY a validated `X-Real-IP`
 *      header set authoritatively by the reverse proxy (e.g., `proxy_set_header X-Real-IP $remote_addr;`).
 *      `X-Forwarded-For` fallback is completely removed to prevent accepting spoofed client-supplied
 *      entries if an upstream proxy configuration erroneously appends rather than overwrites headers.
 *      If `X-Real-IP` is missing or invalid, it safely falls back to a verified platform IP or "direct-client".
 *
 * 3. Shared Fallback Identity ("direct-client"):
 *    When TRUSTED_PROXY is 'none' (or unset) and no platform-provided `req.ip` is present:
 *    All unproxied requests resolve to the safe fallback identity "direct-client" (or "127.0.0.1").
 *    WARNING: "direct-client" intentionally causes all requests without a verified client IP to
 *    share a single rate-limit bucket. This fail-safe prevents attackers from bypassing limits by
 *    spoofing arbitrary IP headers, but requires production deployments to configure a trusted
 *    reverse proxy or platform-verified client IP for true per-client rate limiting.
 *    Do not claim per-client rate limiting in production when client identity is unverified.
 *
 * 4. Fail-Closed Capacity & Anti-Eviction Defense (No FIFO Eviction):
 *    To prevent unbounded memory growth and cache-flooding attacks, the store enforces
 *    a configurable `maxStoreSize` (default: 10,000 keys).
 *    Capacity configuration is strictly validated against non-positive, NaN, or unsafe values
 *    via `resolveMaxStoreSize()` to ensure capacity limits cannot be accidentally disabled.
 *    When capacity is reached:
 *    - Expired records are immediately purged.
 *    - Active (unexpired) records are NEVER evicted via FIFO.
 *    - If capacity remains exhausted with active records, the rate limiter FAILS CLOSED:
 *      new identities are rejected with HTTP 429 until active entries expire.
 *    This prevents malicious actors from flooding synthetic identities to evict active
 *    rate-limit records and bypass rate limits.
 */

export type TrustedProxyConfig = "cloudflare" | "nginx" | "custom" | "none";

export interface RateLimitConfig {
  max: number; // Maximum allowed requests within window
  windowMs: number; // Time window in milliseconds
  maxStoreSize?: number; // Maximum capacity of tracking store before fail-closed behavior
  trustedProxy?: TrustedProxyConfig; // Override trusted proxy configuration
}

interface RateLimitRecord {
  count: number;
  resetTime: number;
}

export const DEFAULT_MAX_STORE_SIZE = 10000;

// In-memory sliding window store (Process-local Map)
const ipStore = new Map<string, RateLimitRecord>();

/**
 * Validates and resolves the maximum store size.
 * Rejects invalid, non-positive, NaN, float, or unsafe integer values.
 * Never allows invalid configuration to disable or bypass the capacity limit.
 */
export function resolveMaxStoreSize(configuredSize?: unknown): number {
  if (configuredSize !== undefined && configuredSize !== null) {
    if (typeof configuredSize === "number") {
      if (Number.isSafeInteger(configuredSize) && configuredSize > 0) {
        return configuredSize;
      }
      return DEFAULT_MAX_STORE_SIZE;
    }
    if (typeof configuredSize === "string") {
      const parsed = Number(configuredSize.trim());
      if (Number.isSafeInteger(parsed) && parsed > 0) {
        return parsed;
      }
      return DEFAULT_MAX_STORE_SIZE;
    }
    return DEFAULT_MAX_STORE_SIZE;
  }

  const envVal = process.env.RATE_LIMIT_MAX_STORE_SIZE;
  if (envVal !== undefined && envVal.trim().length > 0) {
    const parsed = Number(envVal.trim());
    if (Number.isSafeInteger(parsed) && parsed > 0) {
      return parsed;
    }
  }

  return DEFAULT_MAX_STORE_SIZE;
}

/**
 * Returns active trusted proxy configuration.
 * Default is "none" to prevent header spoofing unless explicitly configured.
 */
export function getTrustedProxyConfig(override?: TrustedProxyConfig): TrustedProxyConfig {
  if (override) return override;
  const envProxy = process.env.TRUSTED_PROXY?.toLowerCase().trim();
  if (envProxy === "cloudflare" || envProxy === "cf") return "cloudflare";
  if (envProxy === "nginx" || envProxy === "custom" || envProxy === "reverse-proxy") return "nginx";
  return "none";
}

/**
 * Helper to validate an IP address string using Node.js net.isIP().
 * Returns the trimmed IP if valid (IPv4 or IPv6), or null if invalid.
 */
export function validateIp(candidate: string | null | undefined): string | null {
  if (!candidate || typeof candidate !== "string") return null;
  const trimmed = candidate.trim();
  // isIP returns 4 for IPv4, 6 for IPv6, 0 for invalid
  if (isIP(trimmed) !== 0) {
    return trimmed;
  }
  return null;
}

/**
 * Extracts client IP securely based on trusted proxy configuration.
 *
 * Never blindly trusts X-Forwarded-For, X-Real-IP, or CF-Connecting-IP unless
 * an explicit trusted proxy environment is active.
 * In Nginx mode, trusts ONLY a validated X-Real-IP (no X-Forwarded-For fallback).
 * All extracted candidates are strictly validated with isIP().
 */
export function getClientIp(req: NextRequest, trustedProxyOverride?: TrustedProxyConfig): string {
  const trustedProxy = getTrustedProxyConfig(trustedProxyOverride);

  // 1. Cloudflare proxy configured
  if (trustedProxy === "cloudflare") {
    const cfIp = validateIp(req.headers.get("cf-connecting-ip"));
    if (cfIp) return cfIp;
  }

  // 2. Nginx / custom reverse proxy configured:
  // Trust ONLY validated X-Real-IP; X-Forwarded-For is deliberately omitted.
  if (trustedProxy === "nginx" || trustedProxy === "custom") {
    const realIp = validateIp(req.headers.get("x-real-ip"));
    if (realIp) return realIp;
  }

  // 3. Platform / framework-provided trusted client IP (e.g. Next.js / Vercel runtime req.ip)
  const platformIpCandidate = (req as unknown as { ip?: string }).ip;
  const validPlatformIp = validateIp(platformIpCandidate);
  if (validPlatformIp) {
    return validPlatformIp;
  }

  // 4. Safe fallback identity when no trusted client IP can be verified.
  // Note: All unverified clients share this single bucket.
  return "direct-client";
}

/**
 * Purges expired entries from the store.
 * Returns the count of purged entries.
 */
export function purgeExpiredEntries(now: number): number {
  let purged = 0;
  for (const [key, record] of ipStore.entries()) {
    if (now > record.resetTime) {
      ipStore.delete(key);
      purged++;
    }
  }
  return purged;
}

// Periodic garbage collection for expired entries (runs every 60s)
let lastCleanup = Date.now();
function runPeriodicCleanup(now: number) {
  if (now - lastCleanup < 60000) return;
  lastCleanup = now;
  purgeExpiredEntries(now);
}

export interface RateLimitResult {
  success: boolean;
  limit: number;
  remaining: number;
  reset: number;
  clientIp: string;
  isFallbackIdentity: boolean;
}

/**
 * Checks rate limit for a request based on client IP and target route.
 *
 * FAIL-CLOSED STORE CAPACITY PROTECTION:
 * - Capacity size is strictly validated via resolveMaxStoreSize().
 * - Active records are NEVER evicted via FIFO when capacity is reached.
 * - Expired entries are purged first.
 * - If the store remains full of active records, new unrecognized keys are rejected
 *   with HTTP 429 (fail-closed) until capacity frees up naturally.
 */
export function checkRateLimit(
  req: NextRequest,
  config: Partial<RateLimitConfig> = {}
): RateLimitResult {
  const isTest = process.env.NODE_ENV === "test" || Boolean(process.env.NODE_TEST_CONTEXT);
  const max = config.max ?? (isTest ? 500 : 30);
  const windowMs = config.windowMs ?? 60000;
  const maxStoreSize = resolveMaxStoreSize(config.maxStoreSize);

  const now = Date.now();
  runPeriodicCleanup(now);

  const clientIp = getClientIp(req, config.trustedProxy);
  const isFallbackIdentity = clientIp === "direct-client" || clientIp === "127.0.0.1";
  const path = req.nextUrl?.pathname || (req.url ? new URL(req.url, "http://localhost").pathname : "/");
  const key = `${clientIp}:${path}`;

  const record = ipStore.get(key);

  // If entry exists and has expired, delete it so it can start fresh
  if (record && now > record.resetTime) {
    ipStore.delete(key);
  }

  const activeRecord = ipStore.get(key);

  if (!activeRecord) {
    // Check store capacity before inserting a new key
    if (ipStore.size >= maxStoreSize) {
      // Opportunistic purge of all expired entries first
      purgeExpiredEntries(now);

      // If still at capacity with active, unexpired records: FAIL CLOSED!
      // Do not evict active records (prevents attackers from evicting blocked records).
      if (ipStore.size >= maxStoreSize) {
        return {
          success: false,
          limit: max,
          remaining: 0,
          reset: Math.ceil(windowMs / 1000),
          clientIp,
          isFallbackIdentity,
        };
      }
    }

    // Allocate new tracking entry
    const resetTime = now + windowMs;
    ipStore.set(key, { count: 1, resetTime });
    return {
      success: true,
      limit: max,
      remaining: max - 1,
      reset: Math.ceil((resetTime - now) / 1000),
      clientIp,
      isFallbackIdentity,
    };
  }

  // Active record exists
  activeRecord.count += 1;
  const remaining = Math.max(0, max - activeRecord.count);
  const resetSeconds = Math.ceil((activeRecord.resetTime - now) / 1000);

  if (activeRecord.count > max) {
    return {
      success: false,
      limit: max,
      remaining: 0,
      reset: resetSeconds,
      clientIp,
      isFallbackIdentity,
    };
  }

  return {
    success: true,
    limit: max,
    remaining,
    reset: resetSeconds,
    clientIp,
    isFallbackIdentity,
  };
}

/**
 * Generates an HTTP 429 Too Many Requests response with standard headers
 */
export function createRateLimitResponse(resetSeconds: number): NextResponse {
  return NextResponse.json(
    {
      error: "Too Many Requests",
      message: `Rate limit exceeded. Please wait ${resetSeconds} seconds before retrying.`,
      retryAfterSeconds: resetSeconds,
    },
    {
      status: 429,
      headers: {
        "Retry-After": String(resetSeconds),
        "X-RateLimit-Remaining": "0",
      },
    }
  );
}

/**
 * Returns current store size (useful for diagnostics and tests)
 */
export function getRateLimitStoreSize(): number {
  return ipStore.size;
}

/**
 * Clears the in-memory rate limit store (useful for tests)
 */
export function clearRateLimitStore(): void {
  ipStore.clear();
}

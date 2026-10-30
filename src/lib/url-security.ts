import { looksLikeSecret } from "@/lib/validators";

export interface UrlValidationResult {
  valid: boolean;
  error?: string;
  url?: URL;
  normalizedUrl?: string;
}

// IP Range checks for SSRF protection
function isPrivateOrLocalIp(ip: string): boolean {
  // IPv6 checks
  if (ip === "::1" || ip === "0:0:0:0:0:0:0:1" || ip === "::") return true;
  if (ip.toLowerCase().startsWith("fe80:") || ip.toLowerCase().startsWith("fc") || ip.toLowerCase().startsWith("fd")) {
    return true;
  }

  // IPv4 dotted-decimal
  const parts = ip.split(".").map(Number);
  if (parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
    const [p0, p1] = parts;
    // 127.0.0.0/8 (Loopback)
    if (p0 === 127) return true;
    // 0.0.0.0/8 (Current network)
    if (p0 === 0) return true;
    // 10.0.0.0/8 (Private RFC 1918)
    if (p0 === 10) return true;
    // 172.16.0.0/12 (Private RFC 1918: 172.16 - 172.31)
    if (p0 === 172 && p1 >= 16 && p1 <= 31) return true;
    // 192.168.0.0/16 (Private RFC 1918)
    if (p0 === 192 && p1 === 168) return true;
    // 169.254.0.0/16 (Link-local / Cloud metadata 169.254.169.254)
    if (p0 === 169 && p1 === 254) return true;
    // 100.64.0.0/10 (Carrier NAT)
    if (p0 === 100 && p1 >= 64 && p1 <= 127) return true;
    // 255.255.255.255 (Broadcast)
    if (p0 === 255) return true;
  }

  return false;
}

// Check for numeric decimal or hex representations of IPs (e.g. 2130706433 or 0x7f000001)
function isNumericOrHexIp(hostname: string): boolean {
  if (/^\d+$/.test(hostname)) return true;
  if (/^0x[0-9a-fA-F]+$/.test(hostname)) return true;
  return false;
}

/**
 * Strict URL Validation & SSRF Prevention
 * Rejects dangerous protocols and private network ranges.
 */
export function validateAndSanitizeUrl(rawInput: string): UrlValidationResult {
  const trimmed = rawInput.trim();

  if (!trimmed) {
    return { valid: false, error: "Please enter a website URL." };
  }

  // Defensive zero-knowledge check
  if (looksLikeSecret(trimmed)) {
    return {
      valid: false,
      error: "SECURITY ALERT: Never enter private keys or recovery seed phrases! Only enter public website URLs.",
    };
  }

  // Reject dangerous schemes explicitly before parsing
  const dangerousSchemes = [
    "javascript:",
    "data:",
    "file:",
    "blob:",
    "vbscript:",
    "view-source:",
    "about:",
    "chrome:",
  ];
  const lower = trimmed.toLowerCase();
  for (const scheme of dangerousSchemes) {
    if (lower.startsWith(scheme)) {
      return {
        valid: false,
        error: `SECURITY VIOLATION: Scheme '${scheme}' is dangerous and strictly forbidden.`,
      };
    }
  }

  // Auto-prefix with https:// if user entered domain directly
  const urlToParse =
    trimmed.startsWith("http://") || trimmed.startsWith("https://")
      ? trimmed
      : `https://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(urlToParse);
  } catch {
    return {
      valid: false,
      error: "Invalid URL format. Please enter a valid address (e.g., https://example.com).",
    };
  }

  // Ensure protocol is strictly HTTP or HTTPS
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      valid: false,
      error: `Protocol '${parsed.protocol}' is unsupported. Only HTTP and HTTPS are permitted.`,
    };
  }

  // Clean hostname
  const host = parsed.hostname.toLowerCase().trim();

  if (!host) {
    return { valid: false, error: "URL is missing a valid hostname." };
  }

  // SSRF Protection: Block localhost and internal names
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "local" ||
    host.endsWith(".local") ||
    host === "internal" ||
    host.endsWith(".internal")
  ) {
    return {
      valid: false,
      error: "SECURITY VIOLATION: Access to localhost or internal network names is forbidden (SSRF protection).",
    };
  }

  // SSRF Protection: Check numeric / hex IP bypasses
  if (isNumericOrHexIp(host)) {
    return {
      valid: false,
      error: "SECURITY VIOLATION: Numeric or hex-encoded IP addresses are blocked (SSRF protection).",
    };
  }

  // SSRF Protection: Check raw IP addresses
  const cleanIp = host.replace(/^\[|\]$/g, "");
  if (isPrivateOrLocalIp(cleanIp)) {
    return {
      valid: false,
      error: `SECURITY VIOLATION: Target address '${host}' is in a private, loopback, or link-local network (SSRF protection).`,
    };
  }

  return {
    valid: true,
    url: parsed,
    normalizedUrl: parsed.toString(),
  };
}

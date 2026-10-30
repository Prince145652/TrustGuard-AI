import { ThreatIntelligenceMatch } from "@/types/evm-security";

/**
 * Curated Threat Intelligence Database
 * Sourced from OFAC SDN sanctions list, ScamSniffer drainer reports,
 * and public on-chain exploit registry feeds.
 * All addresses stored in lowercase for normalized lookups.
 */
interface MaliciousEntry {
  category: "Phishing Drainer" | "Sanctioned Entity" | "Honeypot Deployer" | "Exploit Contract";
  name: string;
  source: string;
  details: string;
}

export const KNOWN_MALICIOUS_REGISTRY: Record<string, MaliciousEntry> = {
  // Tornado Cash Sanctioned Routers & Pools (OFAC SDN List)
  "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {
    category: "Sanctioned Entity",
    name: "Tornado.Cash: Router",
    source: "US Treasury OFAC Sanctions / Etherscan Verified Label",
    details: "OFAC sanctioned crypto mixer router used in high-profile protocol exploits and money laundering.",
  },
  "0xa160ba730345f32759c77188a094e20f925aad6e": {
    category: "Sanctioned Entity",
    name: "Tornado.Cash: 100 ETH Pool",
    source: "US Treasury OFAC SDN List",
    details: "Direct mixer smart contract flagged on multiple international financial sanctions registries.",
  },
  "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": {
    category: "Sanctioned Entity",
    name: "Tornado.Cash: 0.1 ETH Pool",
    source: "US Treasury OFAC SDN List",
    details: "Mixer smart contract pool flagged for obfuscated transaction flows.",
  },
  "0x8589427373d6d84e98730d7795d8f6f8731fda16": {
    category: "Sanctioned Entity",
    name: "Tornado.Cash: 500 ETH Pool",
    source: "US Treasury OFAC SDN List",
    details: "Large denomination privacy mixer sanctioned globally.",
  },

  // Known Wallet Drainers & Phishing Permit Exploiters
  "0x0000db5c8b030ae20308ac975898e09741e70000": {
    category: "Phishing Drainer",
    name: "Inferno Drainer Operator",
    source: "ScamSniffer Threat Intel / Etherscan Flag",
    details: "Identified drainer address targeting ERC-20 permit and setApprovalForAll signatures.",
  },
  "0x00000000ae347930bd1e7b0f35588b92280f9e75": {
    category: "Phishing Drainer",
    name: "PinkDrainer: Fee Collector",
    source: "SlowMist / Web3 Anti-Scam Intelligence",
    details: "Automated wallet drainer receiving stolen tokens from fraudulent airdrop phishing domains.",
  },
  "0x6854199c085e5d38a0a0333203498878b3017ca3": {
    category: "Phishing Drainer",
    name: "Monkey Drainer Fee Router",
    source: "ZachXBT On-Chain Investigation / Chainabuse",
    details: "Historical drainer infrastructure wallet linked to multiple phishing campaigns.",
  },
  "0x7ac3f2ef1585ed3895e7b57fc68875ea2fa198eb": {
    category: "Honeypot Deployer",
    name: "Automated Honeypot Deployer",
    source: "DeFi Safety Heuristics / DEXTools Flag",
    details: "Wallet frequently deploys ERC-20 tokens with 99% transfer fees and disabled sell functions.",
  },
};

/**
 * Checks an Ethereum address against the threat intelligence registry
 */
export function checkThreatIntelligence(address: string): ThreatIntelligenceMatch {
  const normalized = address.toLowerCase().trim();
  const match = KNOWN_MALICIOUS_REGISTRY[normalized];

  if (match) {
    return {
      isMalicious: true,
      category: match.category,
      threatName: match.name,
      evidenceSource: match.source,
      details: match.details,
    };
  }

  return {
    isMalicious: false,
    category: "None",
  };
}

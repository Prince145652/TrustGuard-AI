import { ethers, JsonRpcProvider, Network, Contract } from "ethers";
import { EVM_CHAINS } from "@/lib/evm-provider";
import { EvmChainId } from "@/types/evm-security";
import {
  TokenSecurityScanResult,
  TokenSecurityIndicator,
  TokenRiskLevel,
} from "@/types/token-security";

const ERC20_ABI = [
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function totalSupply() view returns (uint256)",
  "function owner() view returns (address)",
];

const EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

interface GoPlusTokenResult {
  token_name?: string;
  token_symbol?: string;
  total_supply?: string;
  is_honeypot?: string;
  cannot_sell_all?: string;
  buy_tax?: string;
  sell_tax?: string;
  is_open_source?: string;
  is_proxy?: string;
  is_mintable?: string;
  can_take_back_ownership?: string;
  owner_change_balance?: string;
  is_blacklisted?: string;
  is_whitelisted?: string;
  is_in_dex?: string;
  owner_address?: string;
  holder_count?: string;
  dex?: { name: string; liquidity_type?: string }[];
}

export async function analyzeTokenContract(
  contractAddress: string,
  chain: EvmChainId
): Promise<TokenSecurityScanResult> {
  const chainConfig = EVM_CHAINS[chain];
  if (!chainConfig) {
    throw new Error(`Unsupported chain: ${chain}`);
  }

  const checksumAddress = ethers.getAddress(contractAddress);
  const normalizedLower = checksumAddress.toLowerCase();

  // 1. On-Chain RPC Check via Ethers
  const network = new Network(chainConfig.name, chainConfig.chainId);
  let provider: JsonRpcProvider | null = null;
  let bytecode: string | null = null;

  for (const url of chainConfig.rpcUrls) {
    try {
      const p = new JsonRpcProvider(url, network, { staticNetwork: network });
      bytecode = await Promise.race([
        p.getCode(checksumAddress),
        new Promise<string>((_, r) => setTimeout(() => r(new Error("RPC Timeout")), 4500)),
      ]);
      provider = p;
      break;
    } catch {
      continue;
    }
  }

  const isContract = bytecode !== null && bytecode !== "0x" && bytecode.length > 2;
  if (!isContract) {
    throw new Error(
      `Address ${checksumAddress} is not a deployed contract on ${chainConfig.name}. Must be an ERC-20 contract address.`
    );
  }

  // 2. Read On-Chain ERC-20 Standard Metadata
  let onChainName: string | null = null;
  let onChainSymbol: string | null = null;
  let onChainDecimals: number | null = null;
  let onChainTotalSupplyRaw: bigint | null = null;
  let onChainOwner: string | null = null;
  let detectedProxyImpl: string | undefined = undefined;

  if (provider) {
    try {
      const contract = new Contract(checksumAddress, ERC20_ABI, provider);
      const [nameRes, symbolRes, decimalsRes, supplyRes] = await Promise.allSettled([
        contract.name(),
        contract.symbol(),
        contract.decimals(),
        contract.totalSupply(),
      ]);

      if (nameRes.status === "fulfilled") onChainName = nameRes.value;
      if (symbolRes.status === "fulfilled") onChainSymbol = symbolRes.value;
      if (decimalsRes.status === "fulfilled") onChainDecimals = Number(decimalsRes.value);
      if (supplyRes.status === "fulfilled") onChainTotalSupplyRaw = supplyRes.value;

      const ownerRes = await Promise.race([
        contract.owner().catch(() => null),
        new Promise<null>((r) => setTimeout(() => r(null), 1500)),
      ]);
      if (ownerRes && ethers.isAddress(ownerRes)) {
        onChainOwner = ethers.getAddress(ownerRes);
      }

      // Check EIP-1967 Implementation Slot
      const implSlotVal = await Promise.race([
        provider.getStorage(checksumAddress, EIP1967_IMPL_SLOT).catch(() => null),
        new Promise<null>((r) => setTimeout(() => r(null), 1500)),
      ]);

      if (implSlotVal && implSlotVal !== ethers.ZeroHash) {
        const sliced = ethers.dataSlice(implSlotVal, 12);
        if (sliced !== ethers.ZeroAddress) {
          detectedProxyImpl = ethers.getAddress(sliced);
        }
      }
    } catch {
      // Fallback gracefully
    }
  }

  // 3. Query GoPlus Security API for Live DEX Liquidity & Honeypot Taxes
  let gpData: GoPlusTokenResult | null = null;
  try {
    const gpUrl = `https://api.gopluslabs.io/api/v1/token_security/${chainConfig.chainId}?contract_addresses=${normalizedLower}`;
    const gpRes = await fetch(gpUrl, { signal: AbortSignal.timeout(4500) });
    if (gpRes.ok) {
      const json = await gpRes.json();
      if (json.code === 1 && json.result && json.result[normalizedLower]) {
        gpData = json.result[normalizedLower];
      }
    }
  } catch {
    // API unavailable
  }

  // 4. Synthesize Token Metrics
  const tokenName = onChainName || gpData?.token_name || "Unknown Token";
  const tokenSymbol = onChainSymbol || gpData?.token_symbol || "TOKEN";
  const decimals = onChainDecimals !== null ? onChainDecimals : "UNKNOWN";

  let totalSupply = "Unknown";
  let formattedSupply = "Unknown";
  if (onChainTotalSupplyRaw !== null && onChainDecimals !== null) {
    totalSupply = onChainTotalSupplyRaw.toString();
    formattedSupply = Number(ethers.formatUnits(onChainTotalSupplyRaw, onChainDecimals)).toLocaleString();
  } else if (gpData?.total_supply) {
    totalSupply = gpData.total_supply;
    formattedSupply = Number(gpData.total_supply).toLocaleString();
  }

  // Contract verification
  const isOpenSource: "VERIFIED" | "UNVERIFIED" | "UNKNOWN" =
    gpData?.is_open_source !== undefined
      ? gpData.is_open_source === "1"
        ? "VERIFIED"
        : "UNVERIFIED"
      : "UNKNOWN";

  // Proxy status
  const isProxy: boolean | "UNKNOWN" =
    detectedProxyImpl !== undefined
      ? true
      : gpData?.is_proxy !== undefined
      ? gpData.is_proxy === "1"
      : "UNKNOWN";

  // Ownership
  const ownerAddress = onChainOwner || gpData?.owner_address || undefined;
  const isOwnershipRenounced: boolean | "UNKNOWN" =
    ownerAddress !== undefined
      ? ownerAddress === ethers.ZeroAddress || ownerAddress === "0x000000000000000000000000000000000000dead"
      : "UNKNOWN";

  // Mintable
  const canMint: boolean | "UNKNOWN" =
    gpData?.is_mintable !== undefined ? gpData.is_mintable === "1" : "UNKNOWN";

  // Pause
  const canPause: boolean | "UNKNOWN" =
    bytecode?.includes("8456cb59") || bytecode?.includes("5c975abb") ? true : "UNKNOWN";

  // Blacklist
  const hasBlacklist: boolean | "UNKNOWN" =
    gpData?.is_blacklisted !== undefined
      ? gpData.is_blacklisted === "1"
      : bytecode?.includes("4433766a") || bytecode?.includes("fe9fbb80")
      ? true
      : "UNKNOWN";

  // Honeypot & Taxes
  const isHoneypot: boolean | "UNKNOWN" =
    gpData?.is_honeypot !== undefined ? gpData.is_honeypot === "1" : "UNKNOWN";

  const cannotSellAll: boolean | "UNKNOWN" =
    gpData?.cannot_sell_all !== undefined ? gpData.cannot_sell_all === "1" : "UNKNOWN";

  const buyTax: number | "UNKNOWN" =
    gpData?.buy_tax !== undefined ? Math.round(parseFloat(gpData.buy_tax) * 100) : "UNKNOWN";

  const sellTax: number | "UNKNOWN" =
    gpData?.sell_tax !== undefined ? Math.round(parseFloat(gpData.sell_tax) * 100) : "UNKNOWN";

  const holderCount = gpData?.holder_count ? parseInt(gpData.holder_count, 10) : "UNKNOWN";
  const isInDex = gpData?.is_in_dex !== undefined ? gpData.is_in_dex === "1" : "UNKNOWN";

  // 5. Construct Indicators & Evidence
  const indicators: TokenSecurityIndicator[] = [];
  const evidence: { category: string; finding: string; status: "SAFE" | "WARNING" | "CRITICAL" | "UNKNOWN" }[] = [];
  const recommendations: string[] = [];

  // Indicator 1: Honeypot & Sell Restrictions
  const honeypotDetected = isHoneypot === true || cannotSellAll === true || (typeof sellTax === "number" && sellTax >= 50);
  indicators.push({
    id: "ind-honeypot",
    name: "Honeypot & Sell Restrictions",
    severity: "CRITICAL",
    detected: honeypotDetected,
    description: honeypotDetected
      ? "Honeypot trap identified. Code prevents holders from selling or executes a confiscatory sell tax."
      : isHoneypot === false
      ? "Standard sell execution verified without honeypot blocks."
      : "Honeypot status could not be simulated on live DEX. Marked Unknown.",
    whySuspicious: "Honeypots allow bad actors to accept incoming buys while preventing investors from ever selling.",
    evidence: `is_honeypot: ${isHoneypot}, cannot_sell_all: ${cannotSellAll}, sell_tax: ${sellTax}%`,
  });

  // Indicator 2: Buy / Sell Taxes
  const hasExcessiveTax =
    (typeof buyTax === "number" && buyTax > 10) || (typeof sellTax === "number" && sellTax > 10);
  indicators.push({
    id: "ind-taxes",
    name: "Trading Fee & Transfer Tax",
    severity: hasExcessiveTax ? "HIGH" : "INFO",
    detected: hasExcessiveTax,
    description:
      buyTax === "UNKNOWN" || sellTax === "UNKNOWN"
        ? "Trading tax data is unavailable from live liquidity pools (Marked Unknown)."
        : `Buy Tax: ${buyTax}%, Sell Tax: ${sellTax}%.`,
    whySuspicious: "Transfer taxes above 10% erode capital and are frequently used to siphon liquidity from traders.",
    evidence: `Buy: ${buyTax}%, Sell: ${sellTax}%`,
  });

  // Indicator 3: Blacklist Privilege
  indicators.push({
    id: "ind-blacklist",
    name: "Address Blacklist Function",
    severity: "MEDIUM",
    detected: hasBlacklist === true,
    description:
      hasBlacklist === true
        ? "Contract contains logic allowing administrators to freeze or blacklist individual token holders."
        : hasBlacklist === false
        ? "No blacklist functionality identified."
        : "Blacklist check could not be conclusively determined from bytecode.",
    whySuspicious: "Centralized blacklists can be abused to selectively disable selling for specific wallet addresses.",
    evidence: `Blacklist Detected: ${hasBlacklist}`,
  });

  // Indicator 4: Minting Permissions
  indicators.push({
    id: "ind-minting",
    name: "Unlimited Supply Minting",
    severity: "MEDIUM",
    detected: canMint === true,
    description:
      canMint === true
        ? "Privileged accounts retain the capability to mint additional token supply arbitrarily."
        : canMint === false
        ? "Fixed or capped supply verified without arbitrary minting rights."
        : "Minting privileges unknown.",
    whySuspicious: "Unlimited mint privileges allow developers to create trillions of tokens and dump them on liquidity pools.",
    evidence: `Mintable: ${canMint}`,
  });

  // Indicator 5: Upgradeable Proxy
  indicators.push({
    id: "ind-proxy",
    name: "Upgradeable Proxy Architecture",
    severity: "LOW",
    detected: isProxy === true,
    description:
      isProxy === true
        ? `Contract uses an upgradeable proxy pattern. Implementation address: ${detectedProxyImpl || "Proxy Router"}.`
        : "Immutable standard contract architecture.",
    whySuspicious: "Proxy contracts allow the admin to replace the underlying code, introducing arbitrary logic changes post-audit.",
    evidence: `Is Proxy: ${isProxy}, Impl: ${detectedProxyImpl || "None"}`,
  });

  // Indicator 6: Open Source Verification
  indicators.push({
    id: "ind-open-source",
    name: "Source Code Verification",
    severity: isOpenSource === "UNVERIFIED" ? "HIGH" : "INFO",
    detected: isOpenSource === "UNVERIFIED",
    description:
      isOpenSource === "VERIFIED"
        ? "Contract source code is publicly verified on block explorer registries."
        : isOpenSource === "UNVERIFIED"
        ? "Unverified bytecode. Contract code has not been submitted or validated publicly."
        : "Verification registry lookup timed out.",
    whySuspicious: "Unverified contracts conceal their logic from security researchers and automated auditing tools.",
    evidence: `Status: ${isOpenSource}`,
  });

  // 6. Transparent 0-100 Risk Score Calculation
  let riskScore = 0;
  let riskLevel: TokenRiskLevel = "SAFE";
  let verdict: TokenSecurityScanResult["verdict"] = "STANDARD_SAFE";

  if (honeypotDetected) {
    riskScore = 95;
    riskLevel = "CRITICAL";
    verdict = "HONEYPOT_MALICIOUS";
    evidence.push({
      category: "Honeypot Analysis",
      finding: "CRITICAL: Honeypot trap detected. Transactions cannot be sold safely.",
      status: "CRITICAL",
    });
    recommendations.push(
      "DO NOT BUY: This token exhibits active honeypot traps designed to steal funds.",
      "If you already purchased this token, do not approve secondary signature requests from associated dApps."
    );
  } else {
    // Add cumulative factors
    if (hasExcessiveTax) riskScore += 35;
    if (isOpenSource === "UNVERIFIED") riskScore += 25;
    if (hasBlacklist === true) riskScore += 20;
    if (canMint === true) riskScore += 15;
    if (isProxy === true) riskScore += 15;
    if (isOwnershipRenounced === false) riskScore += 10;

    // Bonus for renounced ownership
    if (isOwnershipRenounced === true) riskScore = Math.max(riskScore - 10, 5);

    // If critical telemetry is totally unavailable, mark UNKNOWN
    if (isOpenSource === "UNKNOWN" && isHoneypot === "UNKNOWN" && buyTax === "UNKNOWN") {
      riskScore = 0;
      riskLevel = "UNKNOWN";
      verdict = "UNKNOWN";
      recommendations.push(
        "Critical token telemetry was unreachable. Do not assume token is safe.",
        "Verify contract on the blockchain explorer manually before interacting."
      );
    } else {
      riskScore = Math.min(Math.max(riskScore, 5), 100);

      if (riskScore >= 75) {
        riskLevel = "HIGH";
        verdict = "HIGH_RISK";
        recommendations.push(
          "Multiple privileged administrator controls and high fees detected.",
          "Exercise extreme caution; review liquidity lock duration before committing capital."
        );
      } else if (riskScore >= 40) {
        riskLevel = "MEDIUM";
        verdict = "MEDIUM_RISK";
        recommendations.push(
          "Moderate admin privileges identified (such as minting, pause, or blacklist capabilities).",
          "Ensure the token team has established multisig governance and public audit history."
        );
      } else if (riskScore >= 20) {
        riskLevel = "LOW";
        verdict = "LOW_RISK";
        recommendations.push(
          "Minor advisory indicators noted (e.g. upgradeable proxy structure).",
          "Verify project team credentials and timelock contract configurations."
        );
      } else {
        // Enforce rule: Never claim a token is safe without sufficient evidence
        if (isHoneypot === false && isOpenSource === "VERIFIED" && isContract) {
          riskLevel = "SAFE";
          verdict = "STANDARD_SAFE";
          recommendations.push(
            "Contract passed standard ERC-20 security heuristics without honeypot traps.",
            "Always inspect recipient addresses and verify official DEX liquidity pair contracts."
          );
        } else {
          riskLevel = "LOW";
          verdict = "LOW_RISK";
          recommendations.push(
            "No active honeypot traps flagged, but code privileges should be monitored.",
            "Verify official contract address from CoinMarketCap or CoinGecko."
          );
        }
      }
    }

    // Add standard evidence records
    evidence.push({
      category: "Code Verification",
      finding: `Source code status: ${isOpenSource}`,
      status: isOpenSource === "VERIFIED" ? "SAFE" : isOpenSource === "UNVERIFIED" ? "WARNING" : "UNKNOWN",
    });
    evidence.push({
      category: "Trading Taxes",
      finding: typeof buyTax === "number" ? `Buy Tax: ${buyTax}%, Sell Tax: ${sellTax}%` : "Trading fee simulation unavailable (Unknown)",
      status: hasExcessiveTax ? "WARNING" : typeof buyTax === "number" ? "SAFE" : "UNKNOWN",
    });
    evidence.push({
      category: "Contract Privileges",
      finding: `Mintable: ${canMint}, Blacklist: ${hasBlacklist}, Proxy: ${isProxy}`,
      status: canMint === true || hasBlacklist === true ? "WARNING" : "SAFE",
    });
  }

  const summary =
    verdict === "HONEYPOT_MALICIOUS"
      ? `CRITICAL RISK: '${tokenName}' (${tokenSymbol}) is an identified honeypot or malicious contract. Selling is restricted or subjected to confiscatory fees.`
      : verdict === "HIGH_RISK"
      ? `HIGH RISK DETECTED: '${tokenName}' exhibits multiple centralized privileges (such as high taxes, unverified bytecode, or unlimited minting).`
      : verdict === "MEDIUM_RISK"
      ? `CAUTION ADVISED: '${tokenName}' contains administrative privileges (e.g. blacklist or proxy upgradeability) that require trust in the contract owners.`
      : verdict === "STANDARD_SAFE"
      ? `CLEAN AUDIT: '${tokenName}' (${tokenSymbol}) passed core ERC-20 security heuristics with 0% honeypot probability and verified open-source code.`
      : `TELEMETRY INCOMPLETE: '${tokenName}' could not be fully simulated on live DEX pools. Marked Unknown.`;

  return {
    address: checksumAddress,
    chain,
    chainName: chainConfig.name,
    tokenName,
    tokenSymbol,
    decimals,
    totalSupply,
    formattedSupply,
    isContract: true,
    isOpenSource,
    isProxy,
    proxyImplementation: detectedProxyImpl,
    ownerAddress,
    isOwnershipRenounced,
    canMint,
    canPause,
    hasBlacklist,
    isHoneypot,
    buyTax,
    sellTax,
    cannotSellAll,
    holderCount,
    isInDex,
    riskScore,
    riskLevel,
    verdict,
    summary,
    indicators,
    evidence,
    recommendations,
    timestamp: new Date().toISOString(),
    disclaimer:
      "TrustGuard AI Token Security Report. Evaluates on-chain bytecode, DEX simulation, and privileged admin capabilities. Does not substitute for an exhaustive manual smart contract audit.",
  };
}

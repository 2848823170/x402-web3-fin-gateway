/**
 * Live On-Chain Base (ERC-20) & Solana (SPL / Token-2022) Honeypot, Rug-Pull & Liquidity Risk Oracle
 * (`token-rug-scanner.mjs`).
 *
 * Pure Node.js >= 20 (zero external npm dependencies). Designed for <400ms execution
 * by autonomous trading agents (`ElizaOS`, `Coinbase AgentKit`, `Virtuals`, `GOAT`).
 */

import { toEip55Address } from './crypto-primitives.mjs';

export const DEFAULT_BASE_SCAN_RPCS = [
  'https://mainnet.base.org',
  'https://base-rpc.publicnode.com',
];

export const DEFAULT_SOLANA_SCAN_RPCS = [
  'https://api.mainnet-beta.solana.com',
  'https://solana-rpc.publicnode.com',
];

// Base Mainnet DEX & Canonical Addresses
const BASE_WETH = '0x4200000000000000000000000000000000000006';
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const UNISWAP_V2_FACTORY_BASE = '0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6';
const AERODROME_FACTORY_BASE = '0x420DD381b31aEf6683db6B902084cB0FFECe40Da';
const UNISWAP_V3_FACTORY_BASE = '0x33128a8fC17869897dcE68Ed026d694621f6FDfD';
const ZERO_ADDR = '0x0000000000000000000000000000000000000000';
const DEAD_ADDR = '0x000000000000000000000000000000000000dEaD';
const PROBE_RECIPIENT = '0x0000000000000000000000000000000000010402';

// EIP-1967 Standard Proxy Storage Slots
const EIP1967_IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const EIP1967_ADMIN_SLOT = '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';

// Known Canonical Regulated Assets (prevents false-positive scam flags on USDC / WETH / SOL)
const CANONICAL_BASE_TOKENS = new Map([
  ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', { symbol: 'USDC', issuer: 'Circle (Regulated FiatTokenProxy)' }],
  ['0x4200000000000000000000000000000000000006', { symbol: 'WETH', issuer: 'Base Canonical Wrapped Ether' }],
  ['0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf', { symbol: 'cbBTC', issuer: 'Coinbase Wrapped BTC (Regulated)' }],
]);

const CANONICAL_SOLANA_MINTS = new Map([
  ['EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', { symbol: 'USDC', issuer: 'Circle (Regulated SPL Mint)' }],
  ['Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', { symbol: 'USDT', issuer: 'Tether (Regulated SPL Mint)' }],
  ['So11111111111111111111111111111111111111112', { symbol: 'WSOL', issuer: 'Native Wrapped SOL' }],
]);

const SPL_TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';

function padAddress32(addr) {
  return addr.slice(2).toLowerCase().padStart(64, '0');
}

function padUint32(numBig) {
  return BigInt(numBig).toString(16).padStart(64, '0');
}

function parseAddressWord(hex) {
  if (!hex || typeof hex !== 'string' || hex === '0x' || hex.length < 42) return ZERO_ADDR;
  const clean = hex.slice(-40);
  if (!/^[0-9a-fA-F]{40}$/.test(clean) || /^0+$/.test(clean)) return ZERO_ADDR;
  return toEip55Address(`0x${clean}`);
}

function parseUintWord(hex) {
  if (!hex || typeof hex !== 'string' || hex === '0x') return 0n;
  const clean = hex.replace(/^0x/, '');
  if (!clean || !/^[0-9a-fA-F]+$/.test(clean)) return 0n;
  return BigInt(`0x${clean.slice(0, 64)}`);
}

function decodeAbiString(hex) {
  if (!hex || typeof hex !== 'string' || hex === '0x' || hex.length < 10) return '';
  const clean = hex.replace(/^0x/, '');
  try {
    // Dynamic ABI string: word0 = offset (0x20), word1 = length, word2+ = utf8 bytes
    if (clean.length >= 128) {
      const len = Number(BigInt(`0x${clean.slice(64, 128)}`));
      if (len > 0 && len <= 256 && clean.length >= 128 + len * 2) {
        return Buffer.from(clean.slice(128, 128 + len * 2), 'hex')
          .toString('utf8')
          .replace(/\0/g, '')
          .trim();
      }
    }
    // Fallback bytes32 string (e.g. MKR / older ERC-20s)
    if (clean.length === 64) {
      return Buffer.from(clean, 'hex').toString('utf8').replace(/\0/g, '').trim();
    }
  } catch {
    // ignore
  }
  return '';
}

function formatUnits(rawBig, decimals) {
  const d = Math.max(0, Math.min(36, Number(decimals) || 0));
  if (d === 0) return rawBig.toString();
  const base = 10n ** BigInt(d);
  const whole = rawBig / base;
  const frac = (rawBig % base).toString().padStart(d, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac.slice(0, 6)}` : whole.toString();
}

/**
 * Disassembles EVM runtime bytecode skipping PUSH1..PUSH32 immediate operands
 * to detect dangerous opcodes and admin/honeypot function selectors without false positives.
 */
export function scanEvmBytecodeCapabilities(bytecodeHex) {
  const out = {
    byteLength: 0,
    hasSelfdestruct: false,
    hasDelegatecall: false,
    hasMintSelector: false,
    hasBlacklistSelector: false,
    hasFeeSetterSelector: false,
    hasMaxTxSetterSelector: false,
    hasPauseSelector: false,
    detectedSelectors: [],
  };
  if (!bytecodeHex || typeof bytecodeHex !== 'string' || bytecodeHex === '0x') return out;
  const clean = bytecodeHex.replace(/^0x/, '').toLowerCase();
  if (clean.length % 2 !== 0) return out;

  const bytes = Buffer.from(clean, 'hex');
  out.byteLength = bytes.length;

  const selectorSet = new Set();
  for (let pc = 0; pc < bytes.length; pc++) {
    const op = bytes[pc];
    if (op === 0xff) out.hasSelfdestruct = true;
    else if (op === 0xf4) out.hasDelegatecall = true;
    else if (op === 0x63 && pc + 4 < bytes.length) {
      // PUSH4 selector candidate
      const sel = bytes.subarray(pc + 1, pc + 5).toString('hex');
      selectorSet.add(sel);
    }
    // Skip PUSH1 (0x60) .. PUSH32 (0x7f) immediate data bytes
    if (op >= 0x60 && op <= 0x7f) {
      pc += op - 0x5f;
    }
  }

  const MINT_SELS = ['40c10f19', 'a0712d68', '4e6ec247']; // mint(address,uint256), mint(uint256), _mint
  const BLACKLIST_SELS = ['f9f92be4', 'fe575a87', '404e5129', '1694505e', 'e47d6060']; // blacklist / isBlacklisted / setBots
  const FEE_SELS = ['69fe0e2d', '8ea5220f', 'c0246668', 'fd927f3b', '09bc33a7']; // setFee / setTaxes / excludeFromFees
  const MAXTX_SELS = ['ec28438a', 'e2f45605', '74010ece']; // setMaxTxAmount / setSwapTokensAtAmount
  const PAUSE_SELS = ['8456cb59', '5c975abb']; // pause() / paused()

  for (const s of MINT_SELS) if (selectorSet.has(s)) { out.hasMintSelector = true; out.detectedSelectors.push(`0x${s}`); }
  for (const s of BLACKLIST_SELS) if (selectorSet.has(s)) { out.hasBlacklistSelector = true; out.detectedSelectors.push(`0x${s}`); }
  for (const s of FEE_SELS) if (selectorSet.has(s)) { out.hasFeeSetterSelector = true; out.detectedSelectors.push(`0x${s}`); }
  for (const s of MAXTX_SELS) if (selectorSet.has(s)) { out.hasMaxTxSetterSelector = true; out.detectedSelectors.push(`0x${s}`); }
  for (const s of PAUSE_SELS) if (selectorSet.has(s)) { out.hasPauseSelector = true; out.detectedSelectors.push(`0x${s}`); }

  return out;
}

async function postJsonRpc(rpcUrls, payload, fetchFn, timeoutMs = 4500) {
  let lastErr = 'All RPC endpoints failed';
  for (const url of rpcUrls) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchFn(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      if (!res.ok) {
        lastErr = `${url} HTTP ${res.status}`;
        continue;
      }
      const json = await res.json();
      if (json && !Array.isArray(json) && json.error) {
        lastErr = `${url} RPC error: ${json.error.message || JSON.stringify(json.error)}`;
        continue;
      }
      return { url, json };
    } catch (err) {
      lastErr = `${url}: ${err.message}`;
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error(lastErr);
}

function scoreToVerdict(score) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  if (clamped >= 75) return { riskScore: clamped, riskLevel: 'CRITICAL', safeToTrade: false, recommendation: 'BLOCK_HONEYPOT_OR_RUG_RISK' };
  if (clamped >= 45) return { riskScore: clamped, riskLevel: 'HIGH', safeToTrade: false, recommendation: 'AVOID_HIGH_RUG_EXPOSURE' };
  if (clamped >= 20) return { riskScore: clamped, riskLevel: 'MEDIUM', safeToTrade: true, recommendation: 'CAUTION_SIZE_LIMIT_RECOMMENDED' };
  return { riskScore: clamped, riskLevel: 'LOW', safeToTrade: true, recommendation: 'PROCEED_STANDARD_SLIPPAGE' };
}

async function scanBaseErc20Token({ tokenAddress, baseRpcUrls, fetchFn, startedAt }) {
  const checksumToken = toEip55Address(tokenAddress);
  const lowerToken = checksumToken.toLowerCase();
  const canonical = CANONICAL_BASE_TOKENS.get(lowerToken) || null;

  const tPad = padAddress32(checksumToken);
  const wethPad = padAddress32(BASE_WETH);
  const usdcPad = padAddress32(BASE_USDC);

  // Batch 1: Contract code, EIP-1967 proxy slots, ERC-20 metadata/owner/paused, and DEX pools
  const batch1 = [
    { jsonrpc: '2.0', id: 1, method: 'eth_getCode', params: [checksumToken, 'latest'] },
    { jsonrpc: '2.0', id: 2, method: 'eth_getStorageAt', params: [checksumToken, EIP1967_IMPL_SLOT, 'latest'] },
    { jsonrpc: '2.0', id: 3, method: 'eth_getStorageAt', params: [checksumToken, EIP1967_ADMIN_SLOT, 'latest'] },
    { jsonrpc: '2.0', id: 4, method: 'eth_call', params: [{ to: checksumToken, data: '0x06fdde03' }, 'latest'] }, // name()
    { jsonrpc: '2.0', id: 5, method: 'eth_call', params: [{ to: checksumToken, data: '0x95d89b41' }, 'latest'] }, // symbol()
    { jsonrpc: '2.0', id: 6, method: 'eth_call', params: [{ to: checksumToken, data: '0x313ce567' }, 'latest'] }, // decimals()
    { jsonrpc: '2.0', id: 7, method: 'eth_call', params: [{ to: checksumToken, data: '0x18160ddd' }, 'latest'] }, // totalSupply()
    { jsonrpc: '2.0', id: 8, method: 'eth_call', params: [{ to: checksumToken, data: '0x8da5cb5b' }, 'latest'] }, // owner()
    { jsonrpc: '2.0', id: 9, method: 'eth_call', params: [{ to: checksumToken, data: '0x5c975abb' }, 'latest'] }, // paused()
    // Uniswap V2 getPair(token, WETH) -> 0xe6a43905
    { jsonrpc: '2.0', id: 10, method: 'eth_call', params: [{ to: UNISWAP_V2_FACTORY_BASE, data: `0xe6a43905${tPad}${wethPad}` }, 'latest'] },
    // Aerodrome Classic getPool(token, WETH, false) -> 0x79bc57d5
    { jsonrpc: '2.0', id: 11, method: 'eth_call', params: [{ to: AERODROME_FACTORY_BASE, data: `0x79bc57d5${tPad}${wethPad}${'0'.repeat(64)}` }, 'latest'] },
    // Uniswap V3 getPool(token, WETH, 3000) & getPool(token, USDC, 500) -> 0x1698ee82
    { jsonrpc: '2.0', id: 12, method: 'eth_call', params: [{ to: UNISWAP_V3_FACTORY_BASE, data: `0x1698ee82${tPad}${wethPad}${padUint32(3000n)}` }, 'latest'] },
    { jsonrpc: '2.0', id: 13, method: 'eth_call', params: [{ to: UNISWAP_V3_FACTORY_BASE, data: `0x1698ee82${tPad}${usdcPad}${padUint32(500n)}` }, 'latest'] },
  ];

  const { url: rpcUsed, json: res1Raw } = await postJsonRpc(baseRpcUrls, batch1, fetchFn);
  const byId = new Map((Array.isArray(res1Raw) ? res1Raw : []).map((r) => [r.id, r.result]));

  const bytecode = byId.get(1) || '0x';
  if (!bytecode || bytecode === '0x') {
    return {
      chain: 'base',
      chainId: 8453,
      tokenAddress: checksumToken,
      latencyMs: Date.now() - startedAt,
      rpcUsed,
      ...scoreToVerdict(100),
      token: null,
      findings: [
        {
          severity: 'CRITICAL',
          code: 'NO_CONTRACT_BYTECODE',
          message: `Address ${checksumToken} has zero contract bytecode on Base Mainnet (EOA or undeployed address).`,
        },
      ],
    };
  }

  let implAddr = parseAddressWord(byId.get(2));
  const proxyAdminAddr = parseAddressWord(byId.get(3));
  // Minimal EIP-1167 clone target detection (`363d3d373d3d3d363d73<20-byte-addr>5af43d82803e903d91602b57fd5bf3`)
  const cleanCode = bytecode.replace(/^0x/, '').toLowerCase();
  let isEip1167Clone = false;
  if (implAddr === ZERO_ADDR && cleanCode.startsWith('363d3d373d3d3d363d73') && cleanCode.length >= 60) {
    implAddr = toEip55Address(`0x${cleanCode.slice(20, 60)}`);
    isEip1167Clone = true;
  }
  const isUpgradeableProxy = !isEip1167Clone && (implAddr !== ZERO_ADDR || proxyAdminAddr !== ZERO_ADDR);

  const name = decodeAbiString(byId.get(4)) || canonical?.symbol || 'Unknown';
  const symbol = decodeAbiString(byId.get(5)) || canonical?.symbol || 'UNKNOWN';
  const decimals = Number(parseUintWord(byId.get(6)) || 18n);
  const totalSupplyRaw = parseUintWord(byId.get(7));
  const ownerAddr = parseAddressWord(byId.get(8));
  const isPaused = parseUintWord(byId.get(9)) === 1n;

  const uniV2Pair = parseAddressWord(byId.get(10));
  const aeroPool = parseAddressWord(byId.get(11));
  const uniV3WethPool = parseAddressWord(byId.get(12));
  const uniV3UsdcPool = parseAddressWord(byId.get(13));

  const candidatePools = [
    uniV2Pair !== ZERO_ADDR ? { dex: 'uniswap-v2', address: uniV2Pair, style: 'v2' } : null,
    aeroPool !== ZERO_ADDR ? { dex: 'aerodrome-v2', address: aeroPool, style: 'v2' } : null,
    uniV3WethPool !== ZERO_ADDR ? { dex: 'uniswap-v3-weth-0.3%', address: uniV3WethPool, style: 'v3' } : null,
    uniV3UsdcPool !== ZERO_ADDR ? { dex: 'uniswap-v3-usdc-0.05%', address: uniV3UsdcPool, style: 'v3' } : null,
  ].filter(Boolean);

  // Batch 2 (single fast follow-up): fetch implementation bytecode (if proxy/clone) + reserves across ALL discovered pools!
  const batch2 = [];
  if (implAddr !== ZERO_ADDR) {
    batch2.push({ jsonrpc: '2.0', id: 20, method: 'eth_getCode', params: [implAddr, 'latest'] });
  }
  candidatePools.forEach((p, idx) => {
    const baseId = 100 + idx * 10;
    const poolPad = padAddress32(p.address);
    batch2.push({ jsonrpc: '2.0', id: baseId + 1, method: 'eth_call', params: [{ to: checksumToken, data: `0x70a08231${poolPad}` }, 'latest'] });
    batch2.push({ jsonrpc: '2.0', id: baseId + 2, method: 'eth_call', params: [{ to: BASE_WETH, data: `0x70a08231${poolPad}` }, 'latest'] });
    batch2.push({ jsonrpc: '2.0', id: baseId + 3, method: 'eth_call', params: [{ to: BASE_USDC, data: `0x70a08231${poolPad}` }, 'latest'] });
    if (p.style === 'v2') {
      batch2.push({ jsonrpc: '2.0', id: baseId + 4, method: 'eth_call', params: [{ to: p.address, data: '0x18160ddd' }, 'latest'] });
      batch2.push({ jsonrpc: '2.0', id: baseId + 5, method: 'eth_call', params: [{ to: p.address, data: `0x70a08231${padAddress32(ZERO_ADDR)}` }, 'latest'] });
      batch2.push({ jsonrpc: '2.0', id: baseId + 6, method: 'eth_call', params: [{ to: p.address, data: `0x70a08231${padAddress32(DEAD_ADDR)}` }, 'latest'] });
    }
    batch2.push({
      jsonrpc: '2.0',
      id: baseId + 7,
      method: 'eth_call',
      params: [
        {
          from: p.address,
          to: checksumToken,
          data: `0xa9059cbb${padAddress32(PROBE_RECIPIENT)}${padUint32(1n)}`,
        },
        'latest',
      ],
    });
  });

  let res2Map = new Map();
  let res2RawMap = new Map();
  if (batch2.length > 0) {
    const { json: res2Raw } = await postJsonRpc([rpcUsed, ...baseRpcUrls], batch2, fetchFn);
    if (Array.isArray(res2Raw)) {
      res2Map = new Map(res2Raw.map((r) => [r.id, r.result]));
      res2RawMap = new Map(res2Raw.map((r) => [r.id, r]));
    }
  }

  // Score each discovered pool by USD-equivalent quote depth (1 WETH ~= 2500 USDC rough weight) and pick the deepest!
  let primaryAmmPool = null;
  let primaryPoolIdx = -1;
  let bestDepthScore = -1n;
  let totalWethAcrossPools = 0n;
  let totalUsdcAcrossPools = 0n;

  candidatePools.forEach((p, idx) => {
    const baseId = 100 + idx * 10;
    const wethBal = parseUintWord(res2Map.get(baseId + 2));
    const usdcBal = parseUintWord(res2Map.get(baseId + 3));
    totalWethAcrossPools += wethBal;
    totalUsdcAcrossPools += usdcBal;
    // Normalize to 6-decimal USD-like units for comparison (1 WETH ~ 2500 * 1e6 = wethBal * 2500 / 1e12)
    const depth = (wethBal * 2500n) / 1_000_000_000_000n + usdcBal;
    if (depth > bestDepthScore) {
      bestDepthScore = depth;
      primaryAmmPool = p;
      primaryPoolIdx = idx;
    }
  });

  const effectiveBytecode = res2Map.get(20) && res2Map.get(20) !== '0x' ? res2Map.get(20) : bytecode;
  const codeCaps = scanEvmBytecodeCapabilities(effectiveBytecode);

  const findings = [];
  let riskScore = 0;

  if (canonical) {
    findings.push({
      severity: 'INFO',
      code: 'VERIFIED_CANONICAL_ASSET',
      message: `Verified canonical Base Mainnet asset: ${canonical.symbol} (${canonical.issuer}).`,
    });
  }

  if (isPaused) {
    riskScore += 85;
    findings.push({
      severity: 'CRITICAL',
      code: 'TOKEN_PAUSED',
      message: 'Contract `paused()` is currently TRUE on-chain — transfers are halted.',
    });
  }

  if (!canonical) {
    if (isUpgradeableProxy) {
      riskScore += 35;
      findings.push({
        severity: 'HIGH',
        code: 'UPGRADEABLE_PROXY_CONTRACT',
        message: `Token is an upgradeable proxy (implementation: ${implAddr}); proxy admin can swap logic into a honeypot at any block.`,
      });
    }

    const ownerRenounced =
      ownerAddr === ZERO_ADDR || ownerAddr.toLowerCase() === DEAD_ADDR.toLowerCase();
    if (!ownerRenounced) {
      riskScore += 18;
      findings.push({
        severity: 'MEDIUM',
        code: 'OWNERSHIP_NOT_RENOUNCED',
        message: `Contract has an active owner (${ownerAddr}) — privileged setters remain callable.`,
      });
    }

    if (codeCaps.hasSelfdestruct) {
      riskScore += 50;
      findings.push({
        severity: 'CRITICAL',
        code: 'SELFDESTRUCT_OPCODE_DETECTED',
        message: 'Runtime bytecode contains `SELFDESTRUCT` (0xff).',
      });
    }
    if (codeCaps.hasDelegatecall && !isEip1167Clone && !isUpgradeableProxy) {
      riskScore += 25;
      findings.push({
        severity: 'HIGH',
        code: 'RAW_DELEGATECALL_DETECTED',
        message: 'Non-proxy runtime bytecode contains `DELEGATECALL` (0xf4), enabling external code execution.',
      });
    }
    if (codeCaps.hasMintSelector && !ownerRenounced) {
      riskScore += 25;
      findings.push({
        severity: 'HIGH',
        code: 'ACTIVE_MINT_CAPABILITY',
        message: 'Bytecode exposes `mint` selector while contract ownership is not renounced (supply dilution / rug-mint risk).',
      });
    }
    if (codeCaps.hasBlacklistSelector) {
      riskScore += 28;
      findings.push({
        severity: 'HIGH',
        code: 'BLACKLIST_HONEYPOT_SELECTOR',
        message: 'Bytecode contains wallet blacklist / bot-blocking selectors capable of selectively blocking sells.',
      });
    }
    if (codeCaps.hasFeeSetterSelector || codeCaps.hasMaxTxSetterSelector) {
      riskScore += 22;
      findings.push({
        severity: 'MEDIUM',
        code: 'DYNAMIC_TAX_OR_MAXTX_SETTER',
        message: 'Bytecode contains dynamic transfer-tax or max-transaction-limit setter selectors.',
      });
    }
  }

  let liquidity = {
    dexPoolFound: Boolean(primaryAmmPool),
    dex: primaryAmmPool?.dex || null,
    poolAddress: primaryAmmPool?.address || null,
    poolWethReserve: '0',
    poolUsdcReserve: '0',
    lpBurnedPercent: null,
    transferSimulation: 'not_tested',
  };

  if (!primaryAmmPool && lowerToken !== BASE_WETH.toLowerCase() && !canonical) {
    riskScore += 40;
    findings.push({
      severity: 'HIGH',
      code: 'NO_MAJOR_DEX_LIQUIDITY_FOUND',
      message: 'No Uniswap V2, Uniswap V3, or Aerodrome WETH/USDC pool discovered on Base Mainnet.',
    });
  } else if (primaryAmmPool) {
    const baseId = 100 + primaryPoolIdx * 10;
    const poolTokenBal = parseUintWord(res2Map.get(baseId + 1));
    liquidity.poolWethReserve = formatUnits(totalWethAcrossPools, 18);
    liquidity.poolUsdcReserve = formatUnits(totalUsdcAcrossPools, 6);
    liquidity.discoveredPoolsCount = candidatePools.length;

    if (primaryAmmPool.style === 'v2') {
      const lpTotal = parseUintWord(res2Map.get(baseId + 4));
      const lpBurn0 = parseUintWord(res2Map.get(baseId + 5));
      const lpBurnDead = parseUintWord(res2Map.get(baseId + 6));
      if (lpTotal > 0n) {
        const burnedPct = Number(((lpBurn0 + lpBurnDead) * 10000n) / lpTotal) / 100;
        liquidity.lpBurnedPercent = burnedPct;
        if (burnedPct < 50 && !canonical) {
          riskScore += 20;
          findings.push({
            severity: 'MEDIUM',
            code: 'LP_NOT_BURNED',
            message: `Only ${burnedPct.toFixed(2)}% of V2 LP tokens are burned at 0x0/0xdEaD (verify external locker before trading).`,
          });
        }
      }
    }

    // Check shallow aggregate liquidity (< 0.15 WETH and < $500 USDC)
    if (!canonical && totalWethAcrossPools < 150000000000000000n && totalUsdcAcrossPools < 500_000000n) {
      riskScore += 30;
      findings.push({
        severity: 'HIGH',
        code: 'EXTREMELY_SHALLOW_LIQUIDITY',
        message: `Aggregate DEX reserves are critically thin (${liquidity.poolWethReserve} WETH / ${liquidity.poolUsdcReserve} USDC) — extreme rug/slippage risk.`,
      });
    }

    // Evaluate live transfer simulation from deepest DEX pool
    const simEntry = res2RawMap.get(baseId + 7);
    if (poolTokenBal > 0n && simEntry) {
      if (simEntry.error) {
        liquidity.transferSimulation = 'reverted';
        if (!canonical) {
          riskScore += 65;
          findings.push({
            severity: 'CRITICAL',
            code: 'HONEYPOT_TRANSFER_REVERTED',
            message: `Live eth_call transfer() simulation from DEX pool reverted: ${simEntry.error.message || 'execution reverted'}.`,
          });
        }
      } else if (simEntry.result && simEntry.result !== '0x' && parseUintWord(simEntry.result) === 0n) {
        liquidity.transferSimulation = 'returned_false';
        riskScore += 75;
        findings.push({
          severity: 'CRITICAL',
          code: 'HONEYPOT_TRANSFER_FALSE',
          message: 'Live eth_call transfer() simulation returned `false` — transfers are blocked.',
        });
      } else {
        liquidity.transferSimulation = 'passed';
      }
    }
  }

  return {
    chain: 'base',
    chainId: 8453,
    tokenAddress: checksumToken,
    latencyMs: Date.now() - startedAt,
    rpcUsed,
    ...scoreToVerdict(canonical ? Math.min(riskScore, 10) : riskScore),
    token: {
      name,
      symbol,
      decimals,
      totalSupplyFormatted: formatUnits(totalSupplyRaw, decimals),
      totalSupplyAtomic: totalSupplyRaw.toString(),
      owner: ownerAddr === ZERO_ADDR ? null : ownerAddr,
      ownerRenounced: ownerAddr === ZERO_ADDR || ownerAddr.toLowerCase() === DEAD_ADDR.toLowerCase(),
      paused: isPaused,
      isUpgradeableProxy,
      isEip1167Clone,
      implementationAddress: implAddr === ZERO_ADDR ? null : implAddr,
      canonicalIssuer: canonical?.issuer || null,
    },
    bytecodeFlags: codeCaps,
    liquidity,
    findings,
  };
}

async function scanSolanaMint({ tokenAddress, solanaRpcUrls, fetchFn, startedAt }) {
  const mint = tokenAddress.trim();
  const canonical = CANONICAL_SOLANA_MINTS.get(mint) || null;

  // Parallel HTTP/2 RPC calls (supported universally across all Solana RPC providers)
  const [acctOut, largestOut] = await Promise.all([
    postJsonRpc(
      solanaRpcUrls,
      {
        jsonrpc: '2.0',
        id: 1,
        method: 'getAccountInfo',
        params: [mint, { encoding: 'jsonParsed', commitment: 'confirmed' }],
      },
      fetchFn,
    ),
    postJsonRpc(
      solanaRpcUrls,
      {
        jsonrpc: '2.0',
        id: 2,
        method: 'getTokenLargestAccounts',
        params: [mint, { commitment: 'confirmed' }],
      },
      fetchFn,
      900,
    ).catch(() => ({ url: null, json: { result: { value: [] } } })),
  ]);

  const rpcUsed = acctOut.url;
  const acctVal = acctOut.json?.result?.value;
  if (!acctVal) {
    return {
      chain: 'solana',
      tokenAddress: mint,
      latencyMs: Date.now() - startedAt,
      rpcUsed,
      ...scoreToVerdict(100),
      token: null,
      findings: [
        {
          severity: 'CRITICAL',
          code: 'MINT_ACCOUNT_NOT_FOUND',
          message: `Account ${mint} does not exist on Solana Mainnet.`,
        },
      ],
    };
  }

  const programOwner = acctVal.owner;
  if (programOwner !== SPL_TOKEN_PROGRAM && programOwner !== TOKEN_2022_PROGRAM) {
    return {
      chain: 'solana',
      tokenAddress: mint,
      latencyMs: Date.now() - startedAt,
      rpcUsed,
      ...scoreToVerdict(95),
      token: { programOwner },
      findings: [
        {
          severity: 'CRITICAL',
          code: 'NOT_SPL_TOKEN_MINT',
          message: `Account ${mint} is owned by ${programOwner}, not SPL Token or Token-2022.`,
        },
      ],
    };
  }

  const info = acctVal.data?.parsed?.info || {};
  const decimals = Number(info.decimals ?? 0);
  const supplyRaw = BigInt(info.supply || '0');
  const mintAuthority = info.mintAuthority || null;
  const freezeAuthority = info.freezeAuthority || null;
  const extensions = Array.isArray(info.extensions) ? info.extensions : [];
  const tokenStandard = programOwner === TOKEN_2022_PROGRAM ? 'token-2022' : 'spl-token';

  const findings = [];
  let riskScore = 0;

  if (canonical) {
    findings.push({
      severity: 'INFO',
      code: 'VERIFIED_CANONICAL_MINT',
      message: `Verified canonical Solana asset: ${canonical.symbol} (${canonical.issuer}).`,
    });
  }

  if (!canonical) {
    if (mintAuthority) {
      riskScore += 38;
      findings.push({
        severity: 'HIGH',
        code: 'MINT_AUTHORITY_ACTIVE',
        message: `Mint authority is NOT renounced (${mintAuthority}) — creator can mint unlimited supply and dump liquidity.`,
      });
    }
    if (freezeAuthority) {
      riskScore += 55;
      findings.push({
        severity: 'CRITICAL',
        code: 'FREEZE_AUTHORITY_ACTIVE',
        message: `Freeze authority is ACTIVE (${freezeAuthority}) — creator can freeze buyer token accounts (classic Solana honeypot).`,
      });
    }
  }

  // Inspect Token-2022 extensions for hidden rug vectors
  const parsedExtensions = [];
  for (const ext of extensions) {
    const extType = ext?.extension;
    const state = ext?.state || {};
    if (!extType) continue;
    parsedExtensions.push(extType);

    if (extType === 'permanentDelegate' && state.delegate) {
      riskScore += 80;
      findings.push({
        severity: 'CRITICAL',
        code: 'TOKEN2022_PERMANENT_DELEGATE',
        message: `Token-2022 Permanent Delegate is set (${state.delegate}) — delegate can burn or transfer tokens out of ANY user wallet!`,
      });
    } else if (extType === 'transferFeeConfig') {
      const bps = Number(
        state.newerTransferFee?.transferFeeBasisPoints ??
          state.olderTransferFee?.transferFeeBasisPoints ??
          0,
      );
      const feeAuth = state.transferFeeConfigAuthority || null;
      if (bps >= 1000) {
        riskScore += 65;
        findings.push({
          severity: 'CRITICAL',
          code: 'TOKEN2022_EXTREME_TRANSFER_TAX',
          message: `Token-2022 enforces a ${(bps / 100).toFixed(2)}% (${bps} bps) protocol-level transfer fee.`,
        });
      } else if (bps > 0 || feeAuth) {
        riskScore += 20;
        findings.push({
          severity: 'MEDIUM',
          code: 'TOKEN2022_TRANSFER_FEE_CONFIG',
          message: `Token-2022 transfer fee configured (${bps} bps, feeAuthority: ${feeAuth || 'none'}).`,
        });
      }
    } else if (extType === 'transferHook' && state.programId) {
      riskScore += 40;
      findings.push({
        severity: 'HIGH',
        code: 'TOKEN2022_TRANSFER_HOOK',
        message: `Token-2022 invokes external transferHook program (${state.programId}) on every transfer — can selectively revert sells.`,
      });
    } else if (extType === 'defaultAccountState' && state.state === 'frozen') {
      riskScore += 75;
      findings.push({
        severity: 'CRITICAL',
        code: 'TOKEN2022_DEFAULT_FROZEN',
        message: 'Token-2022 `defaultAccountState` is `frozen` — new buyer accounts cannot transfer tokens.',
      });
    } else if (extType === 'nonTransferable') {
      riskScore += 90;
      findings.push({
        severity: 'CRITICAL',
        code: 'TOKEN2022_NON_TRANSFERABLE',
        message: 'Token-2022 `nonTransferable` extension enabled — tokens cannot be sold after purchase.',
      });
    }
  }

  // Compute Top-Holder Concentration
  const largestAccounts = Array.isArray(largestOut?.json?.result?.value)
    ? largestOut.json.result.value
    : [];
  let top1Raw = 0n;
  let top5Raw = 0n;
  let top10Raw = 0n;
  const topHolders = [];

  largestAccounts.slice(0, 10).forEach((acc, idx) => {
    const amt = BigInt(acc?.amount || '0');
    if (idx === 0) top1Raw = amt;
    if (idx < 5) top5Raw += amt;
    top10Raw += amt;
    if (idx < 5 && supplyRaw > 0n) {
      topHolders.push({
        tokenAccount: acc.address,
        uiAmountString: acc.uiAmountString || formatUnits(amt, decimals),
        percentOfSupply: Number((amt * 10000n) / supplyRaw) / 100,
      });
    }
  });

  const top1Pct = supplyRaw > 0n ? Number((top1Raw * 10000n) / supplyRaw) / 100 : 0;
  const top5Pct = supplyRaw > 0n ? Number((top5Raw * 10000n) / supplyRaw) / 100 : 0;
  const top10Pct = supplyRaw > 0n ? Number((top10Raw * 10000n) / supplyRaw) / 100 : 0;

  if (!canonical && supplyRaw > 0n) {
    if (top1Pct >= 50) {
      riskScore += 35;
      findings.push({
        severity: 'HIGH',
        code: 'EXTREME_SINGLE_HOLDER_CONCENTRATION',
        message: `Largest token account holds ${top1Pct.toFixed(2)}% of total supply (verify LP lock vs insider wallet).`,
      });
    } else if (top5Pct >= 75) {
      riskScore += 22;
      findings.push({
        severity: 'MEDIUM',
        code: 'HIGH_TOP5_CONCENTRATION',
        message: `Top 5 token accounts control ${top5Pct.toFixed(2)}% of total supply.`,
      });
    }
  }

  return {
    chain: 'solana',
    tokenAddress: mint,
    latencyMs: Date.now() - startedAt,
    rpcUsed,
    ...scoreToVerdict(canonical ? Math.min(riskScore, 10) : riskScore),
    token: {
      symbol: canonical?.symbol || null,
      tokenStandard,
      programId: programOwner,
      decimals,
      totalSupplyFormatted: formatUnits(supplyRaw, decimals),
      totalSupplyAtomic: supplyRaw.toString(),
      mintAuthority,
      mintAuthorityRenounced: mintAuthority === null,
      freezeAuthority,
      freezeAuthorityRenounced: freezeAuthority === null,
      token2022Extensions: parsedExtensions,
      canonicalIssuer: canonical?.issuer || null,
    },
    holderConcentration: {
      top1Percent: top1Pct,
      top5Percent: top5Pct,
      top10Percent: top10Pct,
      top5Accounts: topHolders,
    },
    findings,
  };
}

/**
 * Main entry point: scans a Base ERC-20 or Solana SPL / Token-2022 mint for honeypot,
 * rug-pull, authority, bytecode, and liquidity concentration risks.
 */
export async function scanOnChainTokenRugRisk({
  tokenAddress,
  chain = 'auto',
  baseRpcUrls = DEFAULT_BASE_SCAN_RPCS,
  solanaRpcUrls = DEFAULT_SOLANA_SCAN_RPCS,
  fetchFn = globalThis.fetch,
} = {}) {
  const startedAt = Date.now();
  const addr = String(tokenAddress || '').trim();
  const normalizedChain = String(chain || 'auto').trim().toLowerCase();

  let targetChain = normalizedChain;
  if (targetChain === 'auto') {
    if (/^0x[0-9a-fA-F]{40}$/.test(addr)) {
      targetChain = 'base';
    } else if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(addr)) {
      targetChain = 'solana';
    } else {
      throw new Error(
        'Unable to auto-detect token address format. Expected 0x + 40 hex (Base ERC-20) or 32–44 char Base58 (Solana SPL/Token-2022 mint).',
      );
    }
  }

  if (targetChain === 'base' || targetChain === 'evm') {
    if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) {
      throw new Error('Invalid Base ERC-20 contract address: expected 0x + 40 hex characters.');
    }
    return scanBaseErc20Token({ tokenAddress: addr, baseRpcUrls, fetchFn, startedAt });
  }

  if (targetChain === 'solana' || targetChain === 'sol') {
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(addr)) {
      throw new Error('Invalid Solana mint address: expected 32–44 Base58 characters.');
    }
    return scanSolanaMint({ tokenAddress: addr, solanaRpcUrls, fetchFn, startedAt });
  }

  throw new Error(`Unsupported chain "${chain}". Supported live RPC chains: "auto", "base", "solana".`);
}

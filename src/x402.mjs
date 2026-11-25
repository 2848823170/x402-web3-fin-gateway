/**
 * Native Direct 0%-Fee Multi-Chain x402 (HTTP 402 Payment Required) Engine (`x402.mjs`).
 *
 * - Official Receiving Wallets (100% direct, 0% middleman fee):
 *   - EVM (`Base`, `Celo`, `Arbitrum`, `Polygon`, `Optimism`, `Avalanche`): `0xfEbDbB880C7f323c145d61683874a45540208a68`
 *   - Solana (`SPL USDC`): `2h68rTXHZW65UWnM1uXnE5ABD4Tj62qN14vFZvVaX3bC`
 * - Supported Keyless Mainnet Networks & Assets:
 *   1. Base Mainnet (`base` / `eip155:8453`, chainId 8453): USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)
 *   2. Celo Mainnet (`celo` / `eip155:42220`, chainId 42220):
 *      - USDC (`0xcebA9300f2b948710d2653dD7B07f33A8B32118C`, EIP-712 `{ name: "USDC", version: "2" }`)
 *      - USDT (`0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e`, EIP-712 `{ name: "Tether USD", version: "1" }`)
 *   3. Arbitrum One (`arbitrum` / `eip155:42161`, chainId 42161): USDC (`0xaf88d065e77c8cC2239327C5EDb3A432268e5831`)
 *   4. Polygon PoS (`polygon` / `eip155:137`, chainId 137): USDC (`0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359`)
 *   5. Optimism (`optimism` / `eip155:10`, chainId 10): USDC (`0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85`)
 *   6. Avalanche C-Chain (`avalanche` / `eip155:43114`, chainId 43114): USDC (`0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E`)
 *   7. Solana Mainnet (`solana` / `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`): SPL USDC (`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`)
 */

import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

export const PAY_TO = '0xfEbDbB880C7f323c145d61683874a45540208a68';
export const SOLANA_PAY_TO = '2h68rTXHZW65UWnM1uXnE5ABD4Tj62qN14vFZvVaX3bC';

export const BASE_USDC_ASSET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const BASE_CHAIN_ID = 8453;
export const BASE_CAIP2_NETWORK = 'eip155:8453';
export const BASE_V1_NETWORK = 'base';
export const USDC_EIP712_EXTRA = Object.freeze({
  name: 'USD Coin',
  version: '2',
});

export const CELO_CHAIN_ID = 42220;
export const CELO_CAIP2_NETWORK = 'eip155:42220';
export const CELO_V1_NETWORK = 'celo';
export const CELO_USDC_ASSET = '0xcebA9300f2b948710d2653dD7B07f33A8B32118C';
export const CELO_USDC_EIP712_EXTRA = Object.freeze({
  name: 'USDC',
  version: '2',
});
export const CELO_USDT_ASSET = '0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e';
export const CELO_USDT_EIP712_EXTRA = Object.freeze({
  name: 'Tether USD',
  version: '1',
});

export const CELO_PAYMENT_ASSETS = Object.freeze([
  { symbol: 'USDC', asset: CELO_USDC_ASSET, extra: CELO_USDC_EIP712_EXTRA },
  { symbol: 'USDT', asset: CELO_USDT_ASSET, extra: CELO_USDT_EIP712_EXTRA },
]);

export const ARBITRUM_CHAIN_ID = 42161;
export const ARBITRUM_CAIP2_NETWORK = 'eip155:42161';
export const ARBITRUM_V1_NETWORK = 'arbitrum';
export const ARBITRUM_USDC_ASSET = '0xaf88d065e77c8cC2239327C5EDb3A432268e5831';

export const POLYGON_CHAIN_ID = 137;
export const POLYGON_CAIP2_NETWORK = 'eip155:137';
export const POLYGON_V1_NETWORK = 'polygon';
export const POLYGON_USDC_ASSET = '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359';

export const OPTIMISM_CHAIN_ID = 10;
export const OPTIMISM_CAIP2_NETWORK = 'eip155:10';
export const OPTIMISM_V1_NETWORK = 'optimism';
export const OPTIMISM_USDC_ASSET = '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85';

export const AVALANCHE_CHAIN_ID = 43114;
export const AVALANCHE_CAIP2_NETWORK = 'eip155:43114';
export const AVALANCHE_V1_NETWORK = 'avalanche';
export const AVALANCHE_USDC_ASSET = '0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E';

export const ADDITIONAL_EVM_USDC_CHAINS = Object.freeze([
  {
    key: 'arbitrum',
    label: 'Arbitrum One',
    chainId: ARBITRUM_CHAIN_ID,
    v1Network: ARBITRUM_V1_NETWORK,
    caip2Network: ARBITRUM_CAIP2_NETWORK,
    asset: ARBITRUM_USDC_ASSET,
    extra: USDC_EIP712_EXTRA,
    primaryFacilitator: 'payai',
    rpcUrls: ['https://arb1.arbitrum.io/rpc', 'https://arbitrum-one-rpc.publicnode.com'],
  },
  {
    key: 'polygon',
    label: 'Polygon Mainnet',
    chainId: POLYGON_CHAIN_ID,
    v1Network: POLYGON_V1_NETWORK,
    caip2Network: POLYGON_CAIP2_NETWORK,
    asset: POLYGON_USDC_ASSET,
    extra: USDC_EIP712_EXTRA,
    primaryFacilitator: 'payai',
    rpcUrls: ['https://polygon-bor-rpc.publicnode.com', 'https://polygon-rpc.com'],
  },
  {
    key: 'optimism',
    label: 'Optimism Mainnet',
    chainId: OPTIMISM_CHAIN_ID,
    v1Network: OPTIMISM_V1_NETWORK,
    caip2Network: OPTIMISM_CAIP2_NETWORK,
    asset: OPTIMISM_USDC_ASSET,
    extra: USDC_EIP712_EXTRA,
    primaryFacilitator: 'ultravioletadao',
    rpcUrls: ['https://mainnet.optimism.io', 'https://optimism-rpc.publicnode.com'],
  },
  {
    key: 'avalanche',
    label: 'Avalanche C-Chain',
    chainId: AVALANCHE_CHAIN_ID,
    v1Network: AVALANCHE_V1_NETWORK,
    caip2Network: AVALANCHE_CAIP2_NETWORK,
    asset: AVALANCHE_USDC_ASSET,
    extra: USDC_EIP712_EXTRA,
    primaryFacilitator: 'payai',
    rpcUrls: ['https://api.avax.network/ext/bc/C/rpc', 'https://avalanche-c-chain-rpc.publicnode.com'],
  },
]);

export const SOLANA_V1_NETWORK = 'solana';
export const SOLANA_CAIP2_NETWORK = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
export const SOLANA_USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
export const SOLANA_PAYAI_FEE_PAYER = 'CjNFTjvBhbJJd2B5ePPMHRLx1ELZpa8dwQgGL727eKww';
export const SOLANA_X402_EXTRA = Object.freeze({
  feePayer: SOLANA_PAYAI_FEE_PAYER,
});

export const ERC20_TRANSFER_TOPIC0 =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

export const DEFAULT_FACILITATOR_URLS = [
  'https://facilitator.payai.network',
  'https://x402.org/facilitator',
];

export const DEFAULT_CELO_FACILITATOR_URLS = [
  'https://facilitator.ultravioletadao.xyz',
];

export const DEFAULT_BASE_RPC_URLS = [
  'https://mainnet.base.org',
  'https://base-rpc.publicnode.com',
];

export const DEFAULT_CELO_RPC_URLS = [
  'https://forno.celo.org',
  'https://celo-rpc.publicnode.com',
];

export const DEFAULT_SOLANA_RPC_URLS = [
  'https://api.mainnet-beta.solana.com',
  'https://solana-rpc.publicnode.com',
];

const EVM_NETWORK_LOOKUP = new Map([
  [BASE_V1_NETWORK, 'base'],
  [BASE_CAIP2_NETWORK, 'base'],
  [CELO_V1_NETWORK, 'celo'],
  [CELO_CAIP2_NETWORK, 'celo'],
  ...ADDITIONAL_EVM_USDC_CHAINS.flatMap((c) => [
    [c.v1Network, c.key],
    [c.caip2Network, c.key],
  ]),
]);

const ADDITIONAL_EVM_BY_KEY = new Map(ADDITIONAL_EVM_USDC_CHAINS.map((c) => [c.key, c]));

function toBase64Json(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64');
}

function parsePaymentHeaderValue(raw) {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw;
  }
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error('Empty payment header.');
  }
  const trimmed = raw.trim();
  if (trimmed.startsWith('{')) {
    return JSON.parse(trimmed);
  }
  const normalized = trimmed.replace(/-/g, '+').replace(/_/g, '/');
  const decoded = Buffer.from(normalized, 'base64').toString('utf8');
  return JSON.parse(decoded);
}

function parseDecimalOrHexBigInt(val, label) {
  if (typeof val === 'bigint') return val;
  if (typeof val === 'number' && Number.isInteger(val) && val >= 0) return BigInt(val);
  if (typeof val === 'string' && val.trim() !== '') {
    const s = val.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s) || /^[0-9]+$/.test(s)) {
      return BigInt(s);
    }
  }
  throw new Error(`Invalid numeric value for ${label}.`);
}

export class SettledLedger {
  constructor(filePath) {
    this.filePath = filePath;
    this.settledKeys = new Set();
    this.inFlightKeys = new Set();
    this.settledCount = 0;
    this.totalAtomicUsdc = 0n;
    this._load();
  }

  _load() {
    if (!this.filePath || !existsSync(this.filePath)) return;
    const content = readFileSync(this.filePath, 'utf8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const entry = JSON.parse(trimmed);
        if (entry.replayKey) {
          this.settledKeys.add(entry.replayKey);
        }
        this.settledCount += 1;
        if (entry.amountAtomic) {
          this.totalAtomicUsdc += BigInt(entry.amountAtomic);
        }
      } catch {
        // Ignore malformed trailing lines
      }
    }
  }

  has(replayKey) {
    return this.settledKeys.has(replayKey);
  }

  acquireLock(replayKey) {
    if (this.settledKeys.has(replayKey)) {
      return { ok: false, reason: 'Payment credential has already been settled (replay rejected).' };
    }
    if (this.inFlightKeys.has(replayKey)) {
      return { ok: false, reason: 'Payment credential is currently being processed.' };
    }
    this.inFlightKeys.add(replayKey);
    return { ok: true };
  }

  releaseLock(replayKey) {
    this.inFlightKeys.delete(replayKey);
  }

  recordSettlement(entry) {
    const record = {
      settledAt: new Date().toISOString(),
      ...entry,
    };
    if (record.replayKey) {
      this.settledKeys.add(record.replayKey);
      this.inFlightKeys.delete(record.replayKey);
    }
    this.settledCount += 1;
    if (record.amountAtomic) {
      this.totalAtomicUsdc += BigInt(record.amountAtomic);
    }
    if (this.filePath) {
      mkdirSync(dirname(this.filePath), { recursive: true });
      appendFileSync(this.filePath, `${JSON.stringify(record)}\n`, 'utf8');
    }
    return record;
  }

  stats() {
    const whole = this.totalAtomicUsdc / 1_000_000n;
    const frac = (this.totalAtomicUsdc % 1_000_000n).toString().padStart(6, '0');
    return {
      settledPayments: this.settledCount,
      totalSettledAtomicUsdc: this.totalAtomicUsdc.toString(),
      totalSettledUsdc: `${whole}.${frac}`,
    };
  }
}

export function buildPaymentRequirementsV1(
  endpoint,
  resourceUrl,
  payTo = PAY_TO,
  { network = BASE_V1_NETWORK, asset = BASE_USDC_ASSET, extra = USDC_EIP712_EXTRA } = {},
) {
  return {
    scheme: 'exact',
    network,
    maxAmountRequired: endpoint.amountAtomic,
    resource: resourceUrl,
    description: endpoint.description,
    mimeType: 'application/json',
    payTo,
    maxTimeoutSeconds: 300,
    asset,
    outputSchema: {
      input: {
        type: 'http',
        method: 'POST',
        bodyType: 'json',
        bodyFields: endpoint.bodyFields,
      },
      output: endpoint.outputSchemaShape,
    },
    extra: { ...extra },
  };
}

export function buildPaymentRequirementsV2(
  endpoint,
  payTo = PAY_TO,
  { network = BASE_CAIP2_NETWORK, asset = BASE_USDC_ASSET, extra = USDC_EIP712_EXTRA } = {},
) {
  return {
    scheme: 'exact',
    network,
    amount: endpoint.amountAtomic,
    asset,
    payTo,
    maxTimeoutSeconds: 300,
    extra: { ...extra },
  };
}

export function buildCeloPaymentRequirementsV1(endpoint, resourceUrl, payTo = PAY_TO) {
  return CELO_PAYMENT_ASSETS.map((tok) =>
    buildPaymentRequirementsV1(endpoint, resourceUrl, payTo, {
      network: CELO_V1_NETWORK,
      asset: tok.asset,
      extra: tok.extra,
    }),
  );
}

export function buildCeloPaymentRequirementsV2(endpoint, payTo = PAY_TO) {
  return CELO_PAYMENT_ASSETS.map((tok) =>
    buildPaymentRequirementsV2(endpoint, payTo, {
      network: CELO_CAIP2_NETWORK,
      asset: tok.asset,
      extra: tok.extra,
    }),
  );
}

export function buildAdditionalEvmRequirementsV1(endpoint, resourceUrl, payTo = PAY_TO) {
  return ADDITIONAL_EVM_USDC_CHAINS.map((c) =>
    buildPaymentRequirementsV1(endpoint, resourceUrl, payTo, {
      network: c.v1Network,
      asset: c.asset,
      extra: c.extra,
    }),
  );
}

export function buildAdditionalEvmRequirementsV2(endpoint, payTo = PAY_TO) {
  return ADDITIONAL_EVM_USDC_CHAINS.map((c) =>
    buildPaymentRequirementsV2(endpoint, payTo, {
      network: c.caip2Network,
      asset: c.asset,
      extra: c.extra,
    }),
  );
}

export function buildSolanaPaymentRequirementsV1(endpoint, resourceUrl, solanaPayTo = SOLANA_PAY_TO) {
  return buildPaymentRequirementsV1(endpoint, resourceUrl, solanaPayTo, {
    network: SOLANA_V1_NETWORK,
    asset: SOLANA_USDC_MINT,
    extra: SOLANA_X402_EXTRA,
  });
}

export function buildSolanaPaymentRequirementsV2(endpoint, solanaPayTo = SOLANA_PAY_TO) {
  return buildPaymentRequirementsV2(endpoint, solanaPayTo, {
    network: SOLANA_CAIP2_NETWORK,
    asset: SOLANA_USDC_MINT,
    extra: SOLANA_X402_EXTRA,
  });
}

export function buildAllAcceptsV1(endpoint, resourceUrl, payTo = PAY_TO, solanaPayTo = SOLANA_PAY_TO) {
  return [
    buildPaymentRequirementsV1(endpoint, resourceUrl, payTo),
    ...buildCeloPaymentRequirementsV1(endpoint, resourceUrl, payTo),
    ...buildAdditionalEvmRequirementsV1(endpoint, resourceUrl, payTo),
    buildSolanaPaymentRequirementsV1(endpoint, resourceUrl, solanaPayTo),
  ];
}

export function buildAllAcceptsV2(endpoint, payTo = PAY_TO, solanaPayTo = SOLANA_PAY_TO) {
  return [
    buildPaymentRequirementsV2(endpoint, payTo),
    ...buildCeloPaymentRequirementsV2(endpoint, payTo),
    ...buildAdditionalEvmRequirementsV2(endpoint, payTo),
    buildSolanaPaymentRequirementsV2(endpoint, solanaPayTo),
  ];
}

export function buildBazaarExtensions(endpoint) {
  return {
    bazaar: {
      info: {
        input: {
          type: 'http',
          method: 'POST',
          bodyType: 'json',
          body: endpoint.sampleRequest || {},
        },
        output: {
          type: 'json',
          example: endpoint.sampleResponse || {},
        },
      },
      schema: {
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        type: 'object',
        properties: {
          input: {
            type: 'object',
            properties: {
              type: { type: 'string', const: 'http' },
              method: { type: 'string', enum: ['POST', 'GET'] },
              bodyType: { type: 'string', enum: ['json'] },
              body: endpoint.inputSchema,
            },
            required: ['type', 'method', 'body'],
          },
          output: {
            type: 'object',
            properties: {
              type: { type: 'string', const: 'json' },
              example: endpoint.outputSchemaShape,
            },
          },
        },
      },
    },
  };
}

export function build402Response(
  endpoint,
  resourceUrl,
  errorMessage = 'X-PAYMENT header is required',
  payTo = PAY_TO,
  solanaPayTo = SOLANA_PAY_TO,
) {
  const extensions = buildBazaarExtensions(endpoint);
  const v1Body = {
    x402Version: 1,
    error: errorMessage,
    accepts: buildAllAcceptsV1(endpoint, resourceUrl, payTo, solanaPayTo),
    extensions,
  };

  const v2HeaderPayload = {
    x402Version: 2,
    error: errorMessage,
    resource: {
      url: resourceUrl,
      description: endpoint.description,
      mimeType: 'application/json',
    },
    accepts: buildAllAcceptsV2(endpoint, payTo, solanaPayTo),
    extensions,
  };

  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'PAYMENT-REQUIRED': toBase64Json(v2HeaderPayload),
    'WWW-Authenticate': `x402 scheme="exact", network="base", chainId="8453", asset="${BASE_USDC_ASSET}", payTo="${payTo}", maxAmountRequired="${endpoint.amountAtomic}"`,
    'Access-Control-Expose-Headers':
      'PAYMENT-REQUIRED, X-PAYMENT-RESPONSE, PAYMENT-RESPONSE, WWW-Authenticate',
    'Cache-Control': 'no-store',
  };

  return {
    statusCode: 402,
    headers,
    body: v1Body,
  };
}

export function extractPaymentCredential(reqHeaders = {}, mcpMeta = null) {
  const xPayment = reqHeaders['x-payment'];
  if (xPayment) {
    return { kind: 'x402', source: 'x-payment', raw: Array.isArray(xPayment) ? xPayment[0] : xPayment };
  }
  const paymentSig = reqHeaders['payment-signature'];
  if (paymentSig) {
    return {
      kind: 'x402',
      source: 'payment-signature',
      raw: Array.isArray(paymentSig) ? paymentSig[0] : paymentSig,
    };
  }
  if (mcpMeta && mcpMeta['x402/payment']) {
    return { kind: 'x402', source: 'mcp-meta', raw: mcpMeta['x402/payment'] };
  }
  const solSig = reqHeaders['x-solana-tx-sig'] || reqHeaders['x-solana-tx-hash'];
  if (solSig) {
    return {
      kind: 'solana-tx-sig',
      source: 'x-solana-tx-sig',
      raw: (Array.isArray(solSig) ? solSig[0] : solSig).trim(),
    };
  }
  const evmChainHeaders = [
    ['x-celo-tx-hash', 'celo'],
    ['x-arbitrum-tx-hash', 'arbitrum'],
    ['x-polygon-tx-hash', 'polygon'],
    ['x-optimism-tx-hash', 'optimism'],
    ['x-avalanche-tx-hash', 'avalanche'],
    ['x-tx-hash', 'base'],
    ['x-base-tx-hash', 'base'],
  ];
  for (const [hdr, chainKind] of evmChainHeaders) {
    const val = reqHeaders[hdr];
    if (val) {
      return {
        kind: 'tx-hash',
        chainKind,
        source: hdr,
        raw: (Array.isArray(val) ? val[0] : val).trim(),
      };
    }
  }
  return null;
}

export class X402GatewayEngine {
  constructor({
    payTo = PAY_TO,
    solanaPayTo = SOLANA_PAY_TO,
    facilitatorUrls = DEFAULT_FACILITATOR_URLS,
    celoFacilitatorUrls = DEFAULT_CELO_FACILITATOR_URLS,
    baseRpcUrls = DEFAULT_BASE_RPC_URLS,
    celoRpcUrls = DEFAULT_CELO_RPC_URLS,
    solanaRpcUrls = DEFAULT_SOLANA_RPC_URLS,
    ledgerPath = null,
    fetchFn = globalThis.fetch,
    nowFn = () => Math.floor(Date.now() / 1000),
  } = {}) {
    this.payTo = payTo;
    this.solanaPayTo = solanaPayTo;
    this.facilitatorUrls = facilitatorUrls.map((u) => u.replace(/\/+$/, ''));
    this.celoFacilitatorUrls = celoFacilitatorUrls.map((u) => u.replace(/\/+$/, ''));
    this.baseRpcUrls = baseRpcUrls;
    this.celoRpcUrls = celoRpcUrls;
    this.solanaRpcUrls = solanaRpcUrls;
    this.ledger = new SettledLedger(ledgerPath);
    this.fetchFn = fetchFn;
    this.nowFn = nowFn;
  }

  async _postJson(url, body, timeoutMs = 12000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await this.fetchFn(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'User-Agent': 'x402-web3-fin-gateway/1.2',
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await res.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
      return { ok: res.ok, status: res.status, json, text };
    } finally {
      clearTimeout(timer);
    }
  }

  _facilitatorsForChain(chainKind) {
    if (chainKind === 'celo' || chainKind === 'optimism') {
      return [...new Set([...this.celoFacilitatorUrls, ...this.facilitatorUrls])];
    }
    if (chainKind === 'solana' || chainKind === 'base') {
      return this.facilitatorUrls;
    }
    return [...new Set([...this.facilitatorUrls, ...this.celoFacilitatorUrls])];
  }

  _evmChainMeta(chainKind) {
    if (chainKind === 'celo') {
      return {
        label: 'Celo Mainnet',
        chainId: CELO_CHAIN_ID,
        v1Network: CELO_V1_NETWORK,
        caip2Network: CELO_CAIP2_NETWORK,
        rpcUrls: this.celoRpcUrls,
        assets: CELO_PAYMENT_ASSETS.map((t) => t.asset),
      };
    }
    if (chainKind === 'base') {
      return {
        label: 'Base Mainnet',
        chainId: BASE_CHAIN_ID,
        v1Network: BASE_V1_NETWORK,
        caip2Network: BASE_CAIP2_NETWORK,
        rpcUrls: this.baseRpcUrls,
        assets: [BASE_USDC_ASSET],
      };
    }
    const extra = ADDITIONAL_EVM_BY_KEY.get(chainKind);
    if (extra) {
      return {
        label: extra.label,
        chainId: extra.chainId,
        v1Network: extra.v1Network,
        caip2Network: extra.caip2Network,
        rpcUrls: extra.rpcUrls,
        assets: [extra.asset],
      };
    }
    return null;
  }

  _validateAndNormalizeX402(rawPayment, endpoint) {
    let parsed;
    try {
      parsed = parsePaymentHeaderValue(rawPayment);
    } catch {
      return { ok: false, error: 'Malformed X-PAYMENT / PAYMENT-SIGNATURE header (invalid Base64 or JSON).' };
    }

    if (!parsed || typeof parsed !== 'object') {
      return { ok: false, error: 'Payment payload must be a JSON object.' };
    }

    const version = parsed.x402Version === 2 ? 2 : 1;
    const scheme = parsed.scheme || parsed.accepted?.scheme;
    const network = parsed.network || parsed.accepted?.network;

    if (scheme !== 'exact') {
      return { ok: false, error: `Unsupported payment scheme "${scheme || ''}". Expected "exact".` };
    }

    const isSolana = network === SOLANA_V1_NETWORK || network === SOLANA_CAIP2_NETWORK;
    const evmChainKind = EVM_NETWORK_LOOKUP.get(network);

    if (!isSolana && !evmChainKind) {
      return {
        ok: false,
        error: `Unsupported payment network "${network || ''}". Supported: base, celo, arbitrum, polygon, optimism, avalanche, solana.`,
      };
    }

    const inner = parsed.payload;
    if (!inner || typeof inner !== 'object') {
      return { ok: false, error: 'Missing `payload` object inside payment header.' };
    }

    // Solana SVM `exact` (`payload.transaction` base64 VersionedTransaction)
    if (isSolana) {
      const txB64 = inner.transaction;
      if (typeof txB64 !== 'string' || txB64.trim().length < 32 || txB64.length > 16384) {
        return {
          ok: false,
          error: 'Solana payment `payload` must contain base64-encoded `transaction`.',
        };
      }
      if (parsed.accepted?.payTo && parsed.accepted.payTo !== this.solanaPayTo) {
        return {
          ok: false,
          error: `Solana recipient mismatch: accepted.payTo must equal ${this.solanaPayTo}.`,
        };
      }
      const txDigest = createHash('sha256').update(txB64.trim()).digest('hex');
      return {
        ok: true,
        isSolana: true,
        version,
        chainKind: 'solana',
        hintedAsset: SOLANA_USDC_MINT,
        paymentPayload: parsed,
        payer: '',
        valueAtomic: String(endpoint.amountAtomic),
        replayKey: `svm:solana:${txDigest}`,
      };
    }

    const auth = inner.authorization;
    const signature = inner.signature;
    if (!auth || typeof auth !== 'object' || typeof signature !== 'string' || !/^0x[0-9a-fA-F]{128,132}$/.test(signature)) {
      return {
        ok: false,
        error: 'Payment `payload` must contain EIP-3009 `authorization` and 65-byte hex `signature`.',
      };
    }

    const { from, to, value, validAfter, validBefore, nonce } = auth;
    if (typeof from !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(from)) {
      return { ok: false, error: 'Invalid `authorization.from` EVM address.' };
    }
    if (typeof to !== 'string' || to.toLowerCase() !== this.payTo.toLowerCase()) {
      return {
        ok: false,
        error: `Recipient mismatch: authorization.to must equal ${this.payTo}.`,
      };
    }
    if (typeof nonce !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(nonce)) {
      return { ok: false, error: 'Invalid `authorization.nonce` (expected 32-byte 0x hex).' };
    }

    let valueBig;
    let afterBig;
    let beforeBig;
    try {
      valueBig = parseDecimalOrHexBigInt(value, 'authorization.value');
      afterBig = parseDecimalOrHexBigInt(validAfter ?? 0, 'authorization.validAfter');
      beforeBig = parseDecimalOrHexBigInt(validBefore, 'authorization.validBefore');
    } catch (err) {
      return { ok: false, error: err.message };
    }

    const requiredBig = BigInt(endpoint.amountAtomic);
    if (valueBig < requiredBig) {
      return {
        ok: false,
        error: `Insufficient USDC payment amount: got ${valueBig.toString()}, required at least ${requiredBig.toString()} atomic units ($${endpoint.priceUsd} USD).`,
      };
    }

    const nowSec = BigInt(this.nowFn());
    if (beforeBig <= nowSec) {
      return { ok: false, error: 'EIP-3009 payment authorization has expired (`validBefore <= now`).' };
    }
    if (afterBig > nowSec + 60n) {
      return { ok: false, error: 'EIP-3009 payment authorization is not yet active (`validAfter > now`).' };
    }

    const hintedAsset = parsed.accepted?.asset || parsed.asset || null;
    const replayKey = `eip3009:${evmChainKind}:${from.toLowerCase()}:${nonce.toLowerCase()}`;
    return {
      ok: true,
      isSolana: false,
      version,
      chainKind: evmChainKind,
      hintedAsset,
      paymentPayload: parsed,
      payer: from,
      valueAtomic: valueBig.toString(),
      replayKey,
    };
  }

  _candidateRequirements(check, endpoint, resourceUrl) {
    if (check.chainKind === 'solana') {
      return [
        check.version === 2
          ? buildSolanaPaymentRequirementsV2(endpoint, this.solanaPayTo)
          : buildSolanaPaymentRequirementsV1(endpoint, resourceUrl, this.solanaPayTo),
      ];
    }
    if (check.chainKind === 'celo') {
      const allReqs =
        check.version === 2
          ? buildCeloPaymentRequirementsV2(endpoint, this.payTo)
          : buildCeloPaymentRequirementsV1(endpoint, resourceUrl, this.payTo);
      if (typeof check.hintedAsset === 'string' && check.hintedAsset.trim() !== '') {
        const wanted = check.hintedAsset.toLowerCase();
        const exactMatch = allReqs.filter((r) => r.asset.toLowerCase() === wanted);
        if (exactMatch.length > 0) return exactMatch;
      }
      return allReqs;
    }
    const extraChain = ADDITIONAL_EVM_BY_KEY.get(check.chainKind);
    if (extraChain) {
      return [
        check.version === 2
          ? buildPaymentRequirementsV2(endpoint, this.payTo, {
              network: extraChain.caip2Network,
              asset: extraChain.asset,
              extra: extraChain.extra,
            })
          : buildPaymentRequirementsV1(endpoint, resourceUrl, this.payTo, {
              network: extraChain.v1Network,
              asset: extraChain.asset,
              extra: extraChain.extra,
            }),
      ];
    }
    return [
      check.version === 2
        ? buildPaymentRequirementsV2(endpoint, this.payTo)
        : buildPaymentRequirementsV1(endpoint, resourceUrl, this.payTo),
    ];
  }

  async _verifyAndExecuteX402({ credential, endpoint, resourceUrl, executeCallback }) {
    const check = this._validateAndNormalizeX402(credential.raw, endpoint);
    if (!check.ok) {
      return { ok: false, error: check.error };
    }

    const lock = this.ledger.acquireLock(check.replayKey);
    if (!lock.ok) {
      return { ok: false, error: lock.reason };
    }

    try {
      const candidateReqs = this._candidateRequirements(check, endpoint, resourceUrl);
      const facList = this._facilitatorsForChain(check.chainKind);
      const evmMeta = check.isSolana ? null : this._evmChainMeta(check.chainKind);
      const chainLabel = check.isSolana ? 'Solana Mainnet' : evmMeta?.label || 'EVM Mainnet';

      let verifiedFacilitator = null;
      let matchedRequirements = null;
      let matchedReqBody = null;
      let verifiedPayer = check.payer;
      let lastFacilitatorErr = `No facilitator reachable for ${chainLabel} verification.`;

      outer: for (const paymentRequirements of candidateReqs) {
        const normalizedPaymentPayload =
          check.version === 2
            ? {
                ...check.paymentPayload,
                x402Version: 2,
                resource: check.paymentPayload.resource || {
                  url: resourceUrl,
                  description: endpoint.description,
                  mimeType: 'application/json',
                },
                accepted: check.paymentPayload.accepted || paymentRequirements,
              }
            : check.paymentPayload;

        const reqBody = {
          x402Version: check.version,
          paymentPayload: normalizedPaymentPayload,
          paymentRequirements,
        };

        for (const facUrl of facList) {
          try {
            const vRes = await this._postJson(`${facUrl}/verify`, reqBody);
            if (vRes.json && vRes.json.isValid === true) {
              verifiedFacilitator = facUrl;
              matchedRequirements = paymentRequirements;
              matchedReqBody = reqBody;
              if (vRes.json.payer) verifiedPayer = vRes.json.payer;
              break outer;
            }
            const reason =
              vRes.json?.invalidReason || vRes.json?.error || vRes.json?.message || `HTTP ${vRes.status}`;
            const lowerReason = String(reason).toLowerCase();
            const isUnsupportedOrTransient =
              vRes.status >= 500 ||
              vRes.status === 404 ||
              lowerReason.includes('unsupported') ||
              lowerReason.includes('network');
            const isSigDomainMismatchOnMultiToken =
              candidateReqs.length > 1 &&
              (lowerReason.includes('signature') || lowerReason.includes('signer') || lowerReason.includes('domain'));
            lastFacilitatorErr = `Payment verification failed: ${reason}`;
            if (!isUnsupportedOrTransient && !isSigDomainMismatchOnMultiToken && vRes.json && vRes.json.isValid === false) {
              return { ok: false, error: lastFacilitatorErr };
            }
            if (isSigDomainMismatchOnMultiToken) {
              break;
            }
          } catch (err) {
            lastFacilitatorErr = `Facilitator ${facUrl} unreachable: ${err.message}`;
          }
        }
      }

      if (!verifiedFacilitator || !matchedReqBody || !matchedRequirements) {
        return { ok: false, error: lastFacilitatorErr };
      }

      // Execute the deterministic tool BEFORE settling so internal failures never charge the buyer!
      const resultPayload = await executeCallback();

      const sRes = await this._postJson(`${verifiedFacilitator}/settle`, matchedReqBody, 20000);
      const settledOk = Boolean(sRes.json && (sRes.json.success === true || sRes.json.transaction || sRes.json.txHash));
      if (!settledOk) {
        const reason =
          sRes.json?.errorReason || sRes.json?.error || sRes.json?.message || `HTTP ${sRes.status}`;
        return { ok: false, error: `On-chain stablecoin settlement failed: ${reason}` };
      }

      const txHash = sRes.json.transaction || sRes.json.txHash || '';
      const receiptNetwork = check.isSolana
        ? check.version === 2
          ? SOLANA_CAIP2_NETWORK
          : SOLANA_V1_NETWORK
        : check.version === 2
          ? evmMeta.caip2Network
          : evmMeta.v1Network;
      const receiptPayTo = check.isSolana ? this.solanaPayTo : this.payTo;

      const receiptObj = {
        success: true,
        transaction: txHash,
        network: receiptNetwork,
        ...(check.isSolana ? {} : { chainId: evmMeta.chainId }),
        payer: sRes.json.payer || verifiedPayer,
        payTo: receiptPayTo,
        asset: matchedRequirements.asset,
        amountAtomic: check.valueAtomic,
        settledVia: verifiedFacilitator,
      };

      this.ledger.recordSettlement({
        replayKey: check.replayKey,
        endpointId: endpoint.id,
        transaction: txHash,
        network: receiptObj.network,
        asset: matchedRequirements.asset,
        payer: receiptObj.payer,
        payTo: receiptPayTo,
        amountAtomic: check.valueAtomic,
        settledVia: verifiedFacilitator,
      });

      const encodedReceipt = toBase64Json(receiptObj);
      return {
        ok: true,
        resultPayload,
        receipt: receiptObj,
        responseHeaders: {
          'X-PAYMENT-RESPONSE': encodedReceipt,
          'PAYMENT-RESPONSE': encodedReceipt,
          'Access-Control-Expose-Headers':
            'PAYMENT-REQUIRED, X-PAYMENT-RESPONSE, PAYMENT-RESPONSE, WWW-Authenticate',
        },
      };
    } catch (err) {
      this.ledger.releaseLock(check.replayKey);
      throw err;
    } finally {
      if (!this.ledger.has(check.replayKey)) {
        this.ledger.releaseLock(check.replayKey);
      }
    }
  }

  async _verifyAndExecuteTxHash({ credential, endpoint, executeCallback }) {
    const txHash = credential.raw;
    const chainKind = credential.chainKind || 'base';
    const meta = this._evmChainMeta(chainKind) || this._evmChainMeta('base');
    const acceptedAssets = new Set(meta.assets.map((a) => a.toLowerCase()));

    if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
      return {
        ok: false,
        error: `Invalid \`${credential.source.toUpperCase()}\` header: expected 0x-prefixed 64-character ${meta.label} transaction hash.`,
      };
    }

    const replayKey = `tx:${chainKind}:${txHash.toLowerCase()}`;
    const lock = this.ledger.acquireLock(replayKey);
    if (!lock.ok) {
      return { ok: false, error: lock.reason };
    }

    try {
      let receipt = null;
      let rpcUsed = null;
      let lastRpcErr = `Unable to reach ${meta.label} RPC.`;

      for (const rpcUrl of meta.rpcUrls) {
        try {
          const rpcRes = await this._postJson(rpcUrl, {
            jsonrpc: '2.0',
            id: 1,
            method: 'eth_getTransactionReceipt',
            params: [txHash],
          });
          if (rpcRes.json && 'result' in rpcRes.json) {
            receipt = rpcRes.json.result;
            rpcUsed = rpcUrl;
            break;
          }
          if (rpcRes.json?.error) {
            lastRpcErr = rpcRes.json.error.message || 'RPC error';
          }
        } catch (err) {
          lastRpcErr = err.message;
        }
      }

      if (!rpcUsed) {
        return { ok: false, error: `${meta.label} RPC verification unavailable: ${lastRpcErr}` };
      }
      if (!receipt) {
        return {
          ok: false,
          error: `Transaction ${txHash} not found or not yet confirmed on ${meta.label} (chainId ${meta.chainId}).`,
        };
      }
      if (receipt.status !== '0x1') {
        return { ok: false, error: `Transaction ${txHash} reverted on-chain (status !== 0x1).` };
      }

      const expectedToTopic = `0x000000000000000000000000${this.payTo.slice(2).toLowerCase()}`;
      let totalPaid = 0n;
      let payer = receipt.from || '';
      let matchedAsset = meta.assets[0];

      for (const log of receipt.logs || []) {
        if (!log || typeof log.address !== 'string') continue;
        if (!acceptedAssets.has(log.address.toLowerCase())) continue;
        const topics = Array.isArray(log.topics) ? log.topics : [];
        if (topics.length < 3) continue;
        if (topics[0].toLowerCase() !== ERC20_TRANSFER_TOPIC0) continue;
        if (topics[2].toLowerCase() !== expectedToTopic) continue;
        if (typeof log.data === 'string' && /^0x[0-9a-fA-F]+$/.test(log.data)) {
          totalPaid += BigInt(log.data);
          matchedAsset = log.address;
          if (topics[1] && topics[1].length === 66) {
            payer = `0x${topics[1].slice(26)}`;
          }
        }
      }

      const requiredBig = BigInt(endpoint.amountAtomic);
      if (totalPaid < requiredBig) {
        return {
          ok: false,
          error: `Transaction ${txHash} transferred ${totalPaid.toString()} atomic units to ${this.payTo} on ${meta.label}; required at least ${requiredBig.toString()} ($${endpoint.priceUsd} USD).`,
        };
      }

      const resultPayload = await executeCallback();

      const receiptObj = {
        success: true,
        transaction: txHash,
        network: meta.caip2Network,
        chainId: meta.chainId,
        payer,
        payTo: this.payTo,
        asset: matchedAsset,
        amountAtomic: totalPaid.toString(),
        settledVia: `${chainKind}-mainnet-rpc`,
      };

      this.ledger.recordSettlement({
        replayKey,
        endpointId: endpoint.id,
        transaction: txHash,
        network: meta.caip2Network,
        asset: matchedAsset,
        payer,
        payTo: this.payTo,
        amountAtomic: totalPaid.toString(),
        settledVia: rpcUsed,
      });

      const encodedReceipt = toBase64Json(receiptObj);
      return {
        ok: true,
        resultPayload,
        receipt: receiptObj,
        responseHeaders: {
          'X-PAYMENT-RESPONSE': encodedReceipt,
          'PAYMENT-RESPONSE': encodedReceipt,
          'Access-Control-Expose-Headers':
            'PAYMENT-REQUIRED, X-PAYMENT-RESPONSE, PAYMENT-RESPONSE, WWW-Authenticate',
        },
      };
    } catch (err) {
      this.ledger.releaseLock(replayKey);
      throw err;
    } finally {
      if (!this.ledger.has(replayKey)) {
        this.ledger.releaseLock(replayKey);
      }
    }
  }

  async _verifyAndExecuteSolanaSig({ credential, endpoint, executeCallback }) {
    const sig = credential.raw;
    if (!/^[1-9A-HJ-NP-Za-km-z]{64,96}$/.test(sig)) {
      return {
        ok: false,
        error: 'Invalid `X-SOLANA-TX-SIG` header: expected Base58 Solana transaction signature.',
      };
    }

    const replayKey = `tx:solana:${sig}`;
    const lock = this.ledger.acquireLock(replayKey);
    if (!lock.ok) {
      return { ok: false, error: lock.reason };
    }

    try {
      let txData = null;
      let rpcUsed = null;
      let lastRpcErr = 'Unable to reach Solana Mainnet RPC.';

      for (const rpcUrl of this.solanaRpcUrls) {
        try {
          const rpcRes = await this._postJson(rpcUrl, {
            jsonrpc: '2.0',
            id: 1,
            method: 'getTransaction',
            params: [sig, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0, commitment: 'confirmed' }],
          });
          if (rpcRes.json && 'result' in rpcRes.json) {
            txData = rpcRes.json.result;
            rpcUsed = rpcUrl;
            break;
          }
          if (rpcRes.json?.error) {
            lastRpcErr = rpcRes.json.error.message || 'RPC error';
          }
        } catch (err) {
          lastRpcErr = err.message;
        }
      }

      if (!rpcUsed) {
        return { ok: false, error: `Solana Mainnet RPC verification unavailable: ${lastRpcErr}` };
      }
      if (!txData) {
        return {
          ok: false,
          error: `Transaction ${sig} not found or not yet confirmed on Solana Mainnet.`,
        };
      }
      if (txData.meta?.err) {
        return { ok: false, error: `Solana transaction ${sig} failed on-chain.` };
      }

      const preMap = new Map();
      for (const b of txData.meta?.preTokenBalances || []) {
        if (b?.mint === SOLANA_USDC_MINT && b?.owner === this.solanaPayTo) {
          preMap.set(b.accountIndex, BigInt(b.uiTokenAmount?.amount || '0'));
        }
      }
      let totalDelta = 0n;
      for (const b of txData.meta?.postTokenBalances || []) {
        if (b?.mint === SOLANA_USDC_MINT && b?.owner === this.solanaPayTo) {
          const postAmt = BigInt(b.uiTokenAmount?.amount || '0');
          const preAmt = preMap.get(b.accountIndex) || 0n;
          if (postAmt > preAmt) {
            totalDelta += postAmt - preAmt;
          }
        }
      }

      const requiredBig = BigInt(endpoint.amountAtomic);
      if (totalDelta < requiredBig) {
        return {
          ok: false,
          error: `Solana transaction ${sig} credited ${totalDelta.toString()} atomic SPL USDC to ${this.solanaPayTo}; required at least ${requiredBig.toString()} ($${endpoint.priceUsd} USDC).`,
        };
      }

      const accountKeys = txData.transaction?.message?.accountKeys || [];
      const firstKey = accountKeys[0];
      const payer = typeof firstKey === 'string' ? firstKey : firstKey?.pubkey || '';

      const resultPayload = await executeCallback();

      const receiptObj = {
        success: true,
        transaction: sig,
        network: SOLANA_CAIP2_NETWORK,
        payer,
        payTo: this.solanaPayTo,
        asset: SOLANA_USDC_MINT,
        amountAtomic: totalDelta.toString(),
        settledVia: 'solana-mainnet-rpc',
      };

      this.ledger.recordSettlement({
        replayKey,
        endpointId: endpoint.id,
        transaction: sig,
        network: SOLANA_CAIP2_NETWORK,
        asset: SOLANA_USDC_MINT,
        payer,
        payTo: this.solanaPayTo,
        amountAtomic: totalDelta.toString(),
        settledVia: rpcUsed,
      });

      const encodedReceipt = toBase64Json(receiptObj);
      return {
        ok: true,
        resultPayload,
        receipt: receiptObj,
        responseHeaders: {
          'X-PAYMENT-RESPONSE': encodedReceipt,
          'PAYMENT-RESPONSE': encodedReceipt,
          'Access-Control-Expose-Headers':
            'PAYMENT-REQUIRED, X-PAYMENT-RESPONSE, PAYMENT-RESPONSE, WWW-Authenticate',
        },
      };
    } catch (err) {
      this.ledger.releaseLock(replayKey);
      throw err;
    } finally {
      if (!this.ledger.has(replayKey)) {
        this.ledger.releaseLock(replayKey);
      }
    }
  }

  async processPaidCall({ endpoint, args, reqHeaders, mcpMeta = null, resourceUrl }) {
    const credential = extractPaymentCredential(reqHeaders, mcpMeta);
    if (!credential) {
      return {
        paid: false,
        challenge: build402Response(
          endpoint,
          resourceUrl,
          'X-PAYMENT header is required',
          this.payTo,
          this.solanaPayTo,
        ),
      };
    }

    // Validate request arguments BEFORE verifying/settling payment (`x402lint` no-charge-on-bad-input rule!)
    endpoint.validateArgs(args);

    const executeCallback = () => endpoint.execute(args, { fetchFn: this.fetchFn });

    let outcome;
    if (credential.kind === 'solana-tx-sig') {
      outcome = await this._verifyAndExecuteSolanaSig({ credential, endpoint, executeCallback });
    } else if (credential.kind === 'tx-hash') {
      outcome = await this._verifyAndExecuteTxHash({ credential, endpoint, executeCallback });
    } else {
      outcome = await this._verifyAndExecuteX402({
        credential,
        endpoint,
        resourceUrl,
        executeCallback,
      });
    }

    if (!outcome.ok) {
      return {
        paid: false,
        challenge: build402Response(endpoint, resourceUrl, outcome.error, this.payTo, this.solanaPayTo),
      };
    }

    return {
      paid: true,
      resultPayload: outcome.resultPayload,
      receipt: outcome.receipt,
      responseHeaders: outcome.responseHeaders,
    };
  }
}

/**
 * Native Direct 0%-Fee x402 (HTTP 402 Payment Required) Engine (`x402.mjs`).
 *
 * - Primary EVM Recipient (`payTo`): `0xfEbDbB880C7f323c145d61683874a45540208a68` (100% direct, 0% middleman fee)
 * - Supported Networks & EIP-3009 Stablecoin Assets:
 *   1. Base Mainnet (`base` / `eip155:8453`, chainId 8453): USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)
 *   2. Celo Mainnet (`celo` / `eip155:42220`, chainId 42220):
 *      - USDC (`0xcebA9300f2b948710d2653dD7B07f33A8B32118C`, EIP-712 `{ name: "USDC", version: "2" }`)
 *      - USDT (`0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e`, EIP-712 `{ name: "Tether USD", version: "1" }`)
 * - Protocol compatibility:
 *   1. x402 v1 (`X-PAYMENT` / `X-PAYMENT-RESPONSE`, `network: "base" | "celo"`, JSON 402 body + `outputSchema`)
 *   2. x402 v2 (`PAYMENT-SIGNATURE` / `PAYMENT-REQUIRED` / `PAYMENT-RESPONSE`, `network: "eip155:8453" | "eip155:42220"`)
 *   3. Direct Mainnet ERC-20 receipt (`X-TX-HASH` / `X-CELO-TX-HASH`, verified via `eth_getTransactionReceipt`)
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

export const PAY_TO = '0xfEbDbB880C7f323c145d61683874a45540208a68';
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
  {
    symbol: 'USDC',
    asset: CELO_USDC_ASSET,
    extra: CELO_USDC_EIP712_EXTRA,
  },
  {
    symbol: 'USDT',
    asset: CELO_USDT_ASSET,
    extra: CELO_USDT_EIP712_EXTRA,
  },
]);

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
  // Support standard Base64 and Base64URL
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

export function build402Response(endpoint, resourceUrl, errorMessage = 'X-PAYMENT header is required', payTo = PAY_TO) {
  const v1Base = buildPaymentRequirementsV1(endpoint, resourceUrl, payTo);
  const v1Celo = buildCeloPaymentRequirementsV1(endpoint, resourceUrl, payTo);
  const extensions = buildBazaarExtensions(endpoint);
  const v1Body = {
    x402Version: 1,
    error: errorMessage,
    accepts: [v1Base, ...v1Celo],
    extensions,
  };

  const v2Base = buildPaymentRequirementsV2(endpoint, payTo);
  const v2Celo = buildCeloPaymentRequirementsV2(endpoint, payTo);
  const v2HeaderPayload = {
    x402Version: 2,
    error: errorMessage,
    resource: {
      url: resourceUrl,
      description: endpoint.description,
      mimeType: 'application/json',
    },
    accepts: [v2Base, ...v2Celo],
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
  const celoTxHash = reqHeaders['x-celo-tx-hash'];
  if (celoTxHash) {
    return {
      kind: 'tx-hash',
      chainKind: 'celo',
      source: 'x-celo-tx-hash',
      raw: (Array.isArray(celoTxHash) ? celoTxHash[0] : celoTxHash).trim(),
    };
  }
  const txHash = reqHeaders['x-tx-hash'] || reqHeaders['x-base-tx-hash'];
  if (txHash) {
    return {
      kind: 'tx-hash',
      chainKind: 'base',
      source: 'x-tx-hash',
      raw: (Array.isArray(txHash) ? txHash[0] : txHash).trim(),
    };
  }
  return null;
}

export class X402GatewayEngine {
  constructor({
    payTo = PAY_TO,
    facilitatorUrls = DEFAULT_FACILITATOR_URLS,
    celoFacilitatorUrls = DEFAULT_CELO_FACILITATOR_URLS,
    baseRpcUrls = DEFAULT_BASE_RPC_URLS,
    celoRpcUrls = DEFAULT_CELO_RPC_URLS,
    ledgerPath = null,
    fetchFn = globalThis.fetch,
    nowFn = () => Math.floor(Date.now() / 1000),
  } = {}) {
    this.payTo = payTo;
    this.facilitatorUrls = facilitatorUrls.map((u) => u.replace(/\/+$/, ''));
    this.celoFacilitatorUrls = celoFacilitatorUrls.map((u) => u.replace(/\/+$/, ''));
    this.baseRpcUrls = baseRpcUrls;
    this.celoRpcUrls = celoRpcUrls;
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
          'User-Agent': 'x402-web3-fin-gateway/1.1',
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

  _validateAndNormalizeEip3009(rawPayment, endpoint) {
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
    const isBase = network === BASE_V1_NETWORK || network === BASE_CAIP2_NETWORK;
    const isCelo = network === CELO_V1_NETWORK || network === CELO_CAIP2_NETWORK;
    if (!isBase && !isCelo) {
      return {
        ok: false,
        error: `Unsupported payment network "${network || ''}". Expected "base" / "eip155:8453" or "celo" / "eip155:42220".`,
      };
    }

    const inner = parsed.payload;
    if (!inner || typeof inner !== 'object') {
      return { ok: false, error: 'Missing `payload` object inside payment header.' };
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
    const chainKind = isCelo ? 'celo' : 'base';
    const replayKey = `eip3009:${chainKind}:${from.toLowerCase()}:${nonce.toLowerCase()}`;
    return {
      ok: true,
      version,
      chainKind,
      hintedAsset,
      paymentPayload: parsed,
      payer: from,
      valueAtomic: valueBig.toString(),
      replayKey,
    };
  }

  _candidateRequirements(check, endpoint, resourceUrl) {
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
    return [
      check.version === 2
        ? buildPaymentRequirementsV2(endpoint, this.payTo)
        : buildPaymentRequirementsV1(endpoint, resourceUrl, this.payTo),
    ];
  }

  async _verifyAndExecuteEip3009({ credential, endpoint, resourceUrl, executeCallback }) {
    const check = this._validateAndNormalizeEip3009(credential.raw, endpoint);
    if (!check.ok) {
      return { ok: false, error: check.error };
    }

    const lock = this.ledger.acquireLock(check.replayKey);
    if (!lock.ok) {
      return { ok: false, error: lock.reason };
    }

    try {
      const candidateReqs = this._candidateRequirements(check, endpoint, resourceUrl);
      const facList = check.chainKind === 'celo' ? this.celoFacilitatorUrls : this.facilitatorUrls;
      const chainLabel = check.chainKind === 'celo' ? 'Celo Mainnet' : 'Base Mainnet';

      let verifiedFacilitator = null;
      let matchedRequirements = null;
      let matchedReqBody = null;
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
              break outer;
            }
            const reason =
              vRes.json?.invalidReason || vRes.json?.error || vRes.json?.message || `HTTP ${vRes.status}`;
            const lowerReason = String(reason).toLowerCase();
            const isUnsupportedOrTransient =
              vRes.status >= 500 ||
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
              // Try next token candidate on Celo (e.g. USDT after USDC when v1 X-PAYMENT omits asset)
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
      const isCelo = check.chainKind === 'celo';
      const receiptObj = {
        success: true,
        transaction: txHash,
        network: isCelo
          ? check.version === 2
            ? CELO_CAIP2_NETWORK
            : CELO_V1_NETWORK
          : check.version === 2
            ? BASE_CAIP2_NETWORK
            : BASE_V1_NETWORK,
        chainId: isCelo ? CELO_CHAIN_ID : BASE_CHAIN_ID,
        payer: sRes.json.payer || check.payer,
        payTo: this.payTo,
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
        payTo: this.payTo,
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
    const isCelo = credential.chainKind === 'celo';
    const chainLabel = isCelo ? 'Celo Mainnet' : 'Base Mainnet';
    const expectedChainId = isCelo ? CELO_CHAIN_ID : BASE_CHAIN_ID;
    const expectedNetwork = isCelo ? CELO_CAIP2_NETWORK : BASE_CAIP2_NETWORK;
    const rpcUrls = isCelo ? this.celoRpcUrls : this.baseRpcUrls;
    const acceptedAssets = isCelo
      ? new Set(CELO_PAYMENT_ASSETS.map((t) => t.asset.toLowerCase()))
      : new Set([BASE_USDC_ASSET.toLowerCase()]);

    if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
      return {
        ok: false,
        error: `Invalid \`${isCelo ? 'X-CELO-TX-HASH' : 'X-TX-HASH'}\` header: expected 0x-prefixed 64-character ${chainLabel} transaction hash.`,
      };
    }

    const replayKey = `tx:${isCelo ? 'celo' : 'base'}:${txHash.toLowerCase()}`;
    const lock = this.ledger.acquireLock(replayKey);
    if (!lock.ok) {
      return { ok: false, error: lock.reason };
    }

    try {
      let receipt = null;
      let rpcUsed = null;
      let lastRpcErr = `Unable to reach ${chainLabel} RPC.`;

      for (const rpcUrl of rpcUrls) {
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
        return { ok: false, error: `${chainLabel} RPC verification unavailable: ${lastRpcErr}` };
      }
      if (!receipt) {
        return {
          ok: false,
          error: `Transaction ${txHash} not found or not yet confirmed on ${chainLabel} (chainId ${expectedChainId}).`,
        };
      }
      if (receipt.status !== '0x1') {
        return { ok: false, error: `Transaction ${txHash} reverted on-chain (status !== 0x1).` };
      }

      const expectedToTopic = `0x000000000000000000000000${this.payTo.slice(2).toLowerCase()}`;
      let totalPaid = 0n;
      let payer = receipt.from || '';
      let matchedAsset = isCelo ? CELO_USDC_ASSET : BASE_USDC_ASSET;

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
          error: `Transaction ${txHash} transferred ${totalPaid.toString()} atomic units to ${this.payTo} on ${chainLabel}; required at least ${requiredBig.toString()} ($${endpoint.priceUsd} USD).`,
        };
      }

      const resultPayload = await executeCallback();

      const receiptObj = {
        success: true,
        transaction: txHash,
        network: expectedNetwork,
        chainId: expectedChainId,
        payer,
        payTo: this.payTo,
        asset: matchedAsset,
        amountAtomic: totalPaid.toString(),
        settledVia: isCelo ? 'celo-mainnet-rpc' : 'base-mainnet-rpc',
      };

      this.ledger.recordSettlement({
        replayKey,
        endpointId: endpoint.id,
        transaction: txHash,
        network: expectedNetwork,
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

  /**
   * Full x402 execution pipeline:
   * 1. No payment header -> immediate HTTP 402 Payment Required (allows unpaid discovery probes with `{}`).
   * 2. Payment header present -> `endpoint.validateArgs(args)` FIRST (HTTP 400 before settling — $0 charged on bad input!).
   * 3. Verify payment -> execute deterministic tool -> settle payment -> HTTP 200 + `X-PAYMENT-RESPONSE`.
   */
  async processPaidCall({ endpoint, args, reqHeaders, mcpMeta = null, resourceUrl }) {
    const credential = extractPaymentCredential(reqHeaders, mcpMeta);
    if (!credential) {
      return {
        paid: false,
        challenge: build402Response(endpoint, resourceUrl, 'X-PAYMENT header is required', this.payTo),
      };
    }

    // Validate request arguments BEFORE verifying/settling payment (`x402lint` no-charge-on-bad-input rule!)
    endpoint.validateArgs(args);

    const executeCallback = () => endpoint.execute(args, { fetchFn: this.fetchFn });

    const outcome =
      credential.kind === 'tx-hash'
        ? await this._verifyAndExecuteTxHash({ credential, endpoint, executeCallback })
        : await this._verifyAndExecuteEip3009({
            credential,
            endpoint,
            resourceUrl,
            executeCallback,
          });

    if (!outcome.ok) {
      return {
        paid: false,
        challenge: build402Response(endpoint, resourceUrl, outcome.error, this.payTo),
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

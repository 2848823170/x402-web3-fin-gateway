/**
 * Direct 0%-Fee Native x402 Base Mainnet USDC API & MCP Gateway (`server.mjs`).
 *
 * Designed for user-space deployment (`127.0.0.1:9102` + outbound Cloudflare HTTPS tunnel):
 * - Zero external npm dependencies (pure Node.js >= 20 built-ins)
 * - 100% direct settlement to `0xfEbDbB880C7f323c145d61683874a45540208a68` on Base Mainnet USDC
 * - Full x402 v1 + v2 + Base RPC `X-TX-HASH` verification, OpenAPI 3.1, `/.well-known/x402.json`, and MCP 2025-06-18
 */

import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ENDPOINTS_BY_MCP_NAME,
  ENDPOINTS_BY_PATH,
  InputValidationError,
  PAID_ENDPOINTS,
} from './catalog.mjs';
import {
  ADDITIONAL_EVM_USDC_CHAINS,
  ARBITRUM_CAIP2_NETWORK,
  ARBITRUM_USDC_ASSET,
  AVALANCHE_CAIP2_NETWORK,
  AVALANCHE_USDC_ASSET,
  BASE_CAIP2_NETWORK,
  BASE_CHAIN_ID,
  BASE_USDC_ASSET,
  BASE_V1_NETWORK,
  buildPaymentRequirementsV1,
  CELO_CAIP2_NETWORK,
  CELO_CHAIN_ID,
  CELO_USDC_ASSET,
  CELO_USDT_ASSET,
  CELO_V1_NETWORK,
  DEFAULT_BASE_RPC_URLS,
  DEFAULT_CELO_FACILITATOR_URLS,
  DEFAULT_CELO_RPC_URLS,
  DEFAULT_FACILITATOR_URLS,
  DEFAULT_SOLANA_RPC_URLS,
  extractPaymentCredential,
  OPTIMISM_CAIP2_NETWORK,
  OPTIMISM_USDC_ASSET,
  PAY_TO,
  POLYGON_CAIP2_NETWORK,
  POLYGON_USDC_ASSET,
  SOLANA_CAIP2_NETWORK,
  SOLANA_PAY_TO,
  SOLANA_USDC_MINT,
  USDC_EIP712_EXTRA,
  X402GatewayEngine,
} from './x402.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MiB hard ceiling
const SUPPORTED_MCP_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];

function parseCsvEnv(val, fallback) {
  if (!val || typeof val !== 'string' || !val.trim()) return fallback;
  return val
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function resolvePublicBaseUrl(req, configuredPublicBaseUrl = '') {
  if (configuredPublicBaseUrl) {
    return configuredPublicBaseUrl.replace(/\/+$/, '');
  }
  const hostHeader = req.headers['x-forwarded-host'] || req.headers.host || '127.0.0.1:9102';
  const host = (Array.isArray(hostHeader) ? hostHeader[0] : hostHeader).split(',')[0].trim();
  const protoHeader = req.headers['x-forwarded-proto'];
  const cfVisitor = String(req.headers['cf-visitor'] || '');
  let proto = (Array.isArray(protoHeader) ? protoHeader[0] : protoHeader || '').split(',')[0].trim();
  if (!proto) {
    proto = cfVisitor.includes('https') || host.endsWith('.trycloudflare.com') ? 'https' : 'http';
  }
  return `${proto}://${host}`;
}

function setCommonHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Accept, Authorization, X-PAYMENT, PAYMENT-SIGNATURE, X-TX-HASH, X-BASE-TX-HASH, X-CELO-TX-HASH, X-ARBITRUM-TX-HASH, X-POLYGON-TX-HASH, X-OPTIMISM-TX-HASH, X-AVALANCHE-TX-HASH, X-SOLANA-TX-SIG, Mcp-Session-Id, MCP-Protocol-Version',
  );
  res.setHeader(
    'Access-Control-Expose-Headers',
    'PAYMENT-REQUIRED, X-PAYMENT-RESPONSE, PAYMENT-RESPONSE, WWW-Authenticate, Mcp-Session-Id',
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

function sendJson(res, statusCode, data, extraHeaders = {}) {
  setCommonHeaders(res);
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  for (const [k, v] of Object.entries(extraHeaders)) {
    res.setHeader(k, v);
  }
  res.end(JSON.stringify(data, null, 2));
}

function sendHtml(res, statusCode, html) {
  setCommonHeaders(res);
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(html);
}

function readRawBody(req) {
  return new Promise((resolveBody, rejectBody) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    req.on('data', (chunk) => {
      if (settled) return;
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        settled = true;
        req.resume();
        const err = new Error(`Request payload exceeds ${MAX_BODY_BYTES} bytes limit.`);
        err.statusCode = 413;
        rejectBody(err);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!settled) {
        settled = true;
        resolveBody(Buffer.concat(chunks).toString('utf8'));
      }
    });
    req.on('error', (err) => {
      if (!settled) {
        settled = true;
        rejectBody(err);
      }
    });
  });
}

function buildWellKnownManifest(baseUrl, payTo, facilitatorUrls) {
  const resources = PAID_ENDPOINTS.map((e) => `${baseUrl}${e.restPath}`);
  const accepts = PAID_ENDPOINTS.map((e) =>
    buildPaymentRequirementsV1(e, `${baseUrl}${e.restPath}`, payTo),
  );
  return {
    version: 1,
    x402Version: 1,
    service: 'x402-web3-fin-gateway',
    description:
      'Direct 0%-fee Base Mainnet USDC x402 API & MCP Gateway: cryptographic multichain address validation, EVM calldata & EIP-712 security auditing, CJK CSV mojibake repair, multi-page table extraction, and financial statement-invoice reconciliation.',
    network: BASE_V1_NETWORK,
    caip2Network: BASE_CAIP2_NETWORK,
    chainId: BASE_CHAIN_ID,
    asset: BASE_USDC_ASSET,
    assetSymbol: 'USDC',
    assetDecimals: 6,
    eip712Domain: USDC_EIP712_EXTRA,
    payTo,
    middlemanFeeBps: 0,
    facilitators: facilitatorUrls,
    mcpEndpoint: `${baseUrl}/mcp`,
    catalogEndpoint: `${baseUrl}/api/catalog`,
    openApiEndpoint: `${baseUrl}/openapi.json`,
    resources,
    accepts,
  };
}

function buildCatalogPayload(baseUrl, engine) {
  return {
    gateway: 'x402-web3-fin-gateway',
    version: '1.0.0',
    protocol: 'x402',
    x402VersionsSupported: [1, 2],
    settlement: {
      network: BASE_V1_NETWORK,
      caip2Network: BASE_CAIP2_NETWORK,
      chainId: BASE_CHAIN_ID,
      asset: BASE_USDC_ASSET,
      assetSymbol: 'USDC',
      decimals: 6,
      payTo: engine.payTo,
      middlemanFeePercent: 0,
      facilitators: engine.facilitatorUrls,
      directOnChainTxHeaderSupported: 'X-TX-HASH',
    },
    discovery: {
      wellKnownX402: `${baseUrl}/.well-known/x402.json`,
      openApiSpec: `${baseUrl}/openapi.json`,
      mcpStreamableHttp: `${baseUrl}/mcp`,
      health: `${baseUrl}/health`,
    },
    telemetry: engine.ledger.stats(),
    endpoints: PAID_ENDPOINTS.map((e) => ({
      id: e.id,
      method: 'POST',
      url: `${baseUrl}${e.restPath}`,
      path: e.restPath,
      mcpToolName: e.mcpName,
      title: e.title,
      category: e.category,
      priceUsdc: e.priceUsd,
      amountAtomicUsdc: e.amountAtomic,
      description: e.description,
      sampleRequest: e.sampleRequest,
    })),
    quickstart: {
      x402FetchTypescript: [
        "import { wrapFetchWithPayment } from 'x402-fetch';",
        "import { privateKeyToAccount } from 'viem/accounts';",
        'const account = privateKeyToAccount(process.env.EVM_PRIVATE_KEY);',
        'const fetchWithPay = wrapFetchWithPayment(fetch, account);',
        `const res = await fetchWithPay('${baseUrl}/api/v1/validate-address', {`,
        "  method: 'POST',",
        "  headers: { 'Content-Type': 'application/json' },",
        `  body: JSON.stringify({ address: '${engine.payTo}', chain: 'evm' }),`,
        '});',
        'console.log(await res.json());',
      ].join('\n'),
      directBaseUsdcTxHashCurl: `curl -X POST "${baseUrl}/api/v1/validate-address" -H "Content-Type: application/json" -H "X-TX-HASH: 0x<settled_base_mainnet_usdc_tx_hash_to_${engine.payTo}>" -d '{"address":"${engine.payTo}","chain":"evm"}'`,
    },
  };
}

function buildOpenApiSpec(baseUrl, payTo, solanaPayTo = SOLANA_PAY_TO) {
  const paths = {
    '/health': {
      get: {
        summary: 'Gateway health & settled USDC telemetry',
        operationId: 'getHealth',
        security: [],
        responses: { '200': { description: 'Healthy status JSON' } },
      },
    },
    '/api/catalog': {
      get: {
        summary: 'Machine-readable catalog of x402 REST & MCP tools',
        operationId: 'getCatalog',
        security: [],
        responses: { '200': { description: 'Catalog JSON' } },
      },
    },
    '/.well-known/x402.json': {
      get: {
        summary: 'x402 Discovery Manifest',
        operationId: 'getWellKnownX402',
        security: [],
        responses: { '200': { description: 'x402 discovery manifest' } },
      },
    },
  };

  for (const e of PAID_ENDPOINTS) {
    paths[e.restPath] = {
      post: {
        summary: `${e.title} ($${e.priceUsd} USDC via x402 across Base, Celo, Arbitrum, Polygon, Optimism, Avalanche & Solana)`,
        description: `${e.description}\n\n**x402 Payment**: \`${e.priceUsd} USDC\` (\`${e.amountAtomic}\` atomic units) settled directly with 0% middleman fee to \`${payTo}\` on EVM (\`Base\`, \`Celo USDC/USDT\`, \`Arbitrum\`, \`Polygon\`, \`Optimism\`, \`Avalanche\`) or \`${solanaPayTo}\` on \`Solana Mainnet\` (\`SPL USDC\`).`,
        operationId: e.mcpName,
        'x-payment-info': {
          protocols: [
            { x402: { network: BASE_CAIP2_NETWORK, asset: BASE_USDC_ASSET, payTo } },
            { x402: { network: CELO_CAIP2_NETWORK, asset: CELO_USDC_ASSET, payTo } },
            { x402: { network: CELO_CAIP2_NETWORK, asset: CELO_USDT_ASSET, payTo } },
            { x402: { network: ARBITRUM_CAIP2_NETWORK, asset: ARBITRUM_USDC_ASSET, payTo } },
            { x402: { network: POLYGON_CAIP2_NETWORK, asset: POLYGON_USDC_ASSET, payTo } },
            { x402: { network: OPTIMISM_CAIP2_NETWORK, asset: OPTIMISM_USDC_ASSET, payTo } },
            { x402: { network: AVALANCHE_CAIP2_NETWORK, asset: AVALANCHE_USDC_ASSET, payTo } },
            { x402: { network: SOLANA_CAIP2_NETWORK, asset: SOLANA_USDC_MINT, payTo: solanaPayTo } },
          ],
          price: {
            mode: 'fixed',
            currency: 'USD',
            amount: e.priceUsd,
          },
        },
        'x-402': {
          scheme: 'exact',
          network: BASE_V1_NETWORK,
          caip2Network: BASE_CAIP2_NETWORK,
          asset: BASE_USDC_ASSET,
          payTo,
          maxAmountRequired: e.amountAtomic,
          priceUsd: e.priceUsd,
        },
        parameters: [
          {
            name: 'X-PAYMENT',
            in: 'header',
            required: false,
            schema: { type: 'string' },
            description: 'Base64-encoded x402 v1 EIP-3009 Base USDC payment payload.',
          },
          {
            name: 'PAYMENT-SIGNATURE',
            in: 'header',
            required: false,
            schema: { type: 'string' },
            description: 'Base64-encoded x402 v2 EIP-3009 Base USDC payment payload.',
          },
          {
            name: 'X-TX-HASH',
            in: 'header',
            required: false,
            schema: { type: 'string' },
            description: 'Direct settled Base Mainnet USDC transfer transaction hash (0x + 64 hex).',
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: e.inputSchema,
              example: e.sampleRequest,
            },
          },
        },
        responses: {
          '200': {
            description: 'Verified & settled deterministic tool output',
            content: {
              'application/json': {
                schema: e.outputSchemaShape,
              },
            },
          },
          '400': {
            description: 'Invalid input arguments (validated BEFORE payment settlement; $0 charged)',
          },
          '402': {
            description: 'x402 Payment Required challenge (`accepts` array for Base Mainnet USDC)',
          },
        },
      },
    };
  }

  return {
    openapi: '3.1.0',
    info: {
      title: 'x402 Web3 Security & Financial Audit Gateway',
      version: '1.0.0',
      description: `Direct 0%-fee native x402 Base Mainnet USDC REST & MCP API Gateway paying directly to ${payTo}.`,
      contact: {
        name: 'x402 Web3 & Financial Security Gateway',
        email: 'chenshulang0223@gmail.com',
        url: baseUrl,
      },
      'x-guidance': `All POST /api/v1/* endpoints are keyless x402 paid routes on Base Mainnet USDC (chainId 8453, asset ${BASE_USDC_ASSET}) settling directly to ${payTo}. Send an unauthenticated POST first to receive the HTTP 402 challenge (both v1 JSON body and v2 PAYMENT-REQUIRED header), sign the EIP-3009 TransferWithAuthorization via x402-fetch / @x402/fetch, and retry with X-PAYMENT or PAYMENT-SIGNATURE. Invalid request bodies return HTTP 400 before settlement ($0 charged).`,
    },
    servers: [{ url: baseUrl }],
    paths,
  };
}

const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#0b1120"/><path d="M18 22h28v6H18zm0 14h20v6H18z" fill="#38bdf8"/><circle cx="46" cy="39" r="6" fill="#22c55e"/></svg>`;

function buildLlmsTxt(baseUrl, payTo) {
  const lines = [
    '# x402 Web3 Security & Financial Audit Gateway',
    '',
    `> Direct 0%-fee native HTTP 402 (x402 v1 & v2) Base Mainnet USDC API & MCP Gateway settling to \`${payTo}\`.`,
    '',
    `- OpenAPI 3.1 Spec: ${baseUrl}/openapi.json`,
    `- x402 Discovery Manifest: ${baseUrl}/.well-known/x402.json`,
    `- Machine Catalog: ${baseUrl}/api/catalog`,
    `- MCP Streamable HTTP: ${baseUrl}/mcp`,
    '',
    '## Paid Endpoints (Base Mainnet USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)',
    ...PAID_ENDPOINTS.map(
      (e) => `- \`POST ${baseUrl}${e.restPath}\` ($${e.priceUsd} USDC / ${e.amountAtomic} atomic): ${e.title}`,
    ),
    '',
  ];
  return lines.join('\n');
}

function buildLandingHtml(baseUrl, payTo) {
  const rows = PAID_ENDPOINTS.map(
    (e) => `<tr>
      <td><code>POST ${e.restPath}</code><br><small style="color:#94a3b8">MCP: <code>${e.mcpName}</code></small></td>
      <td><strong>$${e.priceUsd} USDC</strong><br><small style="color:#94a3b8">${e.amountAtomic} atomic</small></td>
      <td>${e.title}</td>
    </tr>`,
  ).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <title>x402 Web3 & Financial Security Gateway 鈥?Base Mainnet USDC</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; background: #0b1120; color: #e2e8f0; margin: 0; padding: 2.5rem 1.25rem; line-height: 1.6; }
    .wrap { max-width: 960px; margin: 0 auto; }
    .badge { display: inline-block; background: #1e293b; border: 1px solid #38bdf8; color: #38bdf8; border-radius: 999px; padding: 0.2rem 0.75rem; font-size: 0.8rem; font-weight: 600; }
    h1 { font-size: 1.9rem; margin: 0.75rem 0 0.5rem; color: #f8fafc; }
    a { color: #38bdf8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 1.25rem; margin: 1.25rem 0; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.86rem; }
    pre { background: #030712; border: 1px solid #1f2937; border-radius: 8px; padding: 1rem; overflow-x: auto; color: #a5f3fc; }
    table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
    th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #1f2937; vertical-align: top; }
    th { color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
  </style>
</head>
<body>
  <div class="wrap">
    <span class="badge">HTTP 402 Payment Required &bull; Base Mainnet USDC (8453) &bull; 0% Middleman Fee</span>
    <h1>x402 Web3 Security &amp; Financial Audit Gateway</h1>
    <p style="color:#94a3b8">Deterministic, zero-custody REST &amp; MCP tools providing automated technical risk signals and data utilities for software and agent workflows (not investment, financial, or legal advice). Every call settles directly on Base Mainnet USDC (<code>${BASE_USDC_ASSET}</code>) or Celo Mainnet USDC/USDT to <code>${payTo}</code>.</p>
    <div class="card">
      <strong>Discovery Endpoints (Free HTTP 200)</strong><br/>
      &bull; x402 Manifest: <a href="${baseUrl}/.well-known/x402.json">${baseUrl}/.well-known/x402.json</a><br/>
      &bull; Tool Catalog: <a href="${baseUrl}/api/catalog">${baseUrl}/api/catalog</a><br/>
      &bull; OpenAPI 3.1 Spec: <a href="${baseUrl}/openapi.json">${baseUrl}/openapi.json</a><br/>
      &bull; MCP Streamable HTTP: <code>POST ${baseUrl}/mcp</code> (<code>initialize</code> &amp; <code>tools/list</code> free; <code>tools/call</code> x402-gated)
    </div>
    <div class="card">
      <strong>Paid x402 Endpoints (Base Mainnet USDC)</strong>
      <table>
        <thead><tr><th>Endpoint / MCP Tool</th><th>Price</th><th>Capability</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <div class="card">
      <strong>Quickstart (<code>x402-fetch</code> / <code>@x402/fetch</code>)</strong>
      <pre>curl -i -X POST "${baseUrl}/api/v1/validate-address" \\
  -H "Content-Type: application/json" \\
  -d '{"address":"${payTo}","chain":"evm"}'</pre>
    </div>
  </div>
</body>
</html>`;
}

function buildTermsHtml(baseUrl, payTo) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Terms, Data Provenance &amp; Support — x402 Web3 Security Gateway</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; background: #0b1120; color: #e2e8f0; margin: 0; padding: 2.5rem 1.25rem; line-height: 1.65; }
    .wrap { max-width: 820px; margin: 0 auto; }
    h1, h2 { color: #f8fafc; }
    a { color: #38bdf8; }
    code { background: #111827; padding: 0.15rem 0.4rem; border-radius: 4px; }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 1.25rem; margin: 1.25rem 0; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Terms of Service, Refund Policy &amp; Data Provenance</h1>
    <div class="card">
      <h2>1. Operator &amp; Support Contact</h2>
      <p>Operated directly by <strong>Shulang Chen</strong> (<a href="https://github.com/2848823170">@2848823170</a>). Direct payments settle on Base Mainnet (<code>USDC</code>) and Celo Mainnet (<code>USDC</code>, <code>USDT</code>) to <code>${payTo}</code>.</p>
      <p>Support &amp; refund inquiries: <a href="mailto:chenshulang0223@gmail.com">chenshulang0223@gmail.com</a> or <a href="https://github.com/2848823170/x402-web3-fin-gateway/issues">github.com/2848823170/x402-web3-fin-gateway/issues</a>.</p>
    </div>
    <div class="card">
      <h2>2. Pre-Settlement Validation &amp; Refund Policy</h2>
      <p>All paid endpoints validate request arguments <strong>before</strong> calling any x402 facilitator <code>/settle</code> endpoint: malformed or incomplete requests return <code>HTTP 400</code> with <code>settled: false</code> and charge <code>0</code> tokens. Additionally, the deterministic tool computation executes prior to on-chain settlement so internal errors never debit the caller.</p>
      <p>If a settled payment (verifiable by transaction hash on Base or Celo) ever fails to return a valid HTTP 200 tool payload due to network interruption, email the settlement transaction hash and endpoint URL to <a href="mailto:chenshulang0223@gmail.com">chenshulang0223@gmail.com</a> (or open a GitHub issue) for a 100% on-chain refund to the original paying wallet within 48 hours.</p>
    </div>
    <div class="card">
      <h2>3. Data Sources, Privacy &amp; Non-Advisory Notice</h2>
      <p>Address checksum/curve validation, EVM calldata decoding, EIP-712 typed-data risk auditing, CSV repair, table extraction, and statement reconciliation are computed 100% deterministically in-memory by our own open-source engine (<a href="https://github.com/2848823170/x402-web3-fin-gateway">MIT License</a>). Token risk scans read public permissionless blockchain JSON-RPC state on Base Mainnet (<code>8453</code>), Celo Mainnet (<code>42220</code>), and Solana Mainnet. Request payloads are processed statelessly in memory and are not stored or resold.</p>
      <p>Outputs are automated technical risk signals for software and agent workflows, not financial, investment, or legal advice.</p>
      <p><a href="${baseUrl}/">&larr; Back to Gateway Overview</a></p>
    </div>
  </div>
</body>
</html>`;
}

export function createGatewayServer({
  payTo = PAY_TO,
  solanaPayTo = SOLANA_PAY_TO,
  publicBaseUrl = process.env.PUBLIC_BASE_URL || '',
  facilitatorUrls = parseCsvEnv(process.env.X402_FACILITATOR_URLS, DEFAULT_FACILITATOR_URLS),
  celoFacilitatorUrls = parseCsvEnv(process.env.CELO_FACILITATOR_URLS, DEFAULT_CELO_FACILITATOR_URLS),
  baseRpcUrls = parseCsvEnv(process.env.BASE_RPC_URLS, DEFAULT_BASE_RPC_URLS),
  celoRpcUrls = parseCsvEnv(process.env.CELO_RPC_URLS, DEFAULT_CELO_RPC_URLS),
  solanaRpcUrls = parseCsvEnv(process.env.SOLANA_RPC_URLS, DEFAULT_SOLANA_RPC_URLS),
  ledgerPath = process.env.LEDGER_PATH || resolve(__dirname, '..', 'data', 'settled_ledger.jsonl'),
  fetchFn = globalThis.fetch,
  nowFn = () => Math.floor(Date.now() / 1000),
} = {}) {
  const startedAtMs = Date.now();
  const engine = new X402GatewayEngine({
    payTo,
    solanaPayTo,
    facilitatorUrls,
    celoFacilitatorUrls,
    baseRpcUrls,
    celoRpcUrls,
    solanaRpcUrls,
    ledgerPath,
    fetchFn,
    nowFn,
  });

  const server = createServer(async (req, res) => {
    try {
      setCommonHeaders(res);
      const method = (req.method || 'GET').toUpperCase();
      if (method === 'OPTIONS') {
        res.statusCode = 204;
        res.end();
        return;
      }

      const parsedUrl = new URL(req.url || '/', 'http://127.0.0.1');
      const pathname = parsedUrl.pathname.replace(/\/+$/, '') || '/';
      const baseUrl = resolvePublicBaseUrl(req, publicBaseUrl);

      // 1. Landing / Health / Discovery Routes (Free HTTP 200)
      if (method === 'GET' && pathname === '/') {
        const accept = String(req.headers.accept || '');
        if (accept.includes('text/html')) {
          sendHtml(res, 200, buildLandingHtml(baseUrl, engine.payTo));
          return;
        }
        sendJson(res, 200, {
          status: 'ok',
          service: 'x402-web3-fin-gateway',
          version: '1.0.0',
          protocol: 'x402',
          network: BASE_V1_NETWORK,
          caip2Network: BASE_CAIP2_NETWORK,
          chainId: BASE_CHAIN_ID,
          asset: BASE_USDC_ASSET,
          payTo: engine.payTo,
          middlemanFeePercent: 0,
          wellKnownX402: `${baseUrl}/.well-known/x402.json`,
          catalog: `${baseUrl}/api/catalog`,
          openApi: `${baseUrl}/openapi.json`,
          mcp: `${baseUrl}/mcp`,
          telemetry: engine.ledger.stats(),
        });
        return;
      }

      if ((method === 'GET' || method === 'HEAD') && (pathname === '/favicon.svg' || pathname === '/favicon.ico')) {
        setCommonHeaders(res);
        res.statusCode = 200;
        res.setHeader('Content-Type', 'image/svg+xml; charset=utf-8');
        res.end(method === 'HEAD' ? undefined : FAVICON_SVG);
        return;
      }

      if (method === 'GET' && pathname === '/.well-known/402index-verify.txt') {
        setCommonHeaders(res);
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end('2f164d85fb17966b109baa52a3dbb431e786fe557a74afb13082e572f092fe23');
        return;
      }

      if (method === 'GET' && pathname === '/.well-known/botsrated-verify.txt') {
        setCommonHeaders(res);
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end('1119e5789a152623346fd91588d60e2d');
        return;
      }

      if (method === 'GET' && (pathname === '/terms' || pathname === '/legal')) {
        const accept = String(req.headers.accept || '');
        if (accept.includes('application/json') && !accept.includes('text/html')) {
          sendJson(res, 200, {
            operator: 'Shulang Chen (@2848823170)',
            contact: 'chenshulang0223@gmail.com',
            repository: 'https://github.com/2848823170/x402-web3-fin-gateway',
            supportUrl: 'https://github.com/2848823170/x402-web3-fin-gateway/issues',
            payTo: engine.payTo,
            solanaPayTo: engine.solanaPayTo,
            supportedNetworks: [
              BASE_CAIP2_NETWORK,
              CELO_CAIP2_NETWORK,
              ARBITRUM_CAIP2_NETWORK,
              POLYGON_CAIP2_NETWORK,
              OPTIMISM_CAIP2_NETWORK,
              AVALANCHE_CAIP2_NETWORK,
              SOLANA_CAIP2_NETWORK,
            ],
            supportedAssets: {
              base: [BASE_USDC_ASSET],
              celo: [CELO_USDC_ASSET, CELO_USDT_ASSET],
              arbitrum: [ARBITRUM_USDC_ASSET],
              polygon: [POLYGON_USDC_ASSET],
              optimism: [OPTIMISM_USDC_ASSET],
              avalanche: [AVALANCHE_USDC_ASSET],
              solana: [SOLANA_USDC_MINT],
            },
            refundPolicy:
              'Invalid inputs return HTTP 400 prior to settlement ($0 charged). If a settled transaction fails to return its HTTP 200 payload, email chenshulang0223@gmail.com or open a GitHub issue with the txHash/signature for a full on-chain refund to the payer wallet within 48 hours.',
            dataProvenance:
              'Own open-source deterministic static/cryptographic analysis engine plus public permissionless JSON-RPC state on Base (8453), Celo (42220), and Solana Mainnet.',
          });
          return;
        }
        sendHtml(res, 200, buildTermsHtml(baseUrl, engine.payTo));
        return;
      }

      if (method === 'GET' && pathname === '/llms.txt') {
        setCommonHeaders(res);
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end(buildLlmsTxt(baseUrl, engine.payTo));
        return;
      }

      if (method === 'GET' && (pathname === '/health' || pathname === '/ping')) {
        sendJson(res, 200, {
          status: 'ok',
          service: 'x402-web3-fin-gateway',
          uptimeSeconds: Math.floor((Date.now() - startedAtMs) / 1000),
          chainId: BASE_CHAIN_ID,
          asset: BASE_USDC_ASSET,
          payTo: engine.payTo,
          telemetry: engine.ledger.stats(),
        });
        return;
      }

      if (
        method === 'GET' &&
        (pathname === '/.well-known/x402' || pathname === '/.well-known/x402.json')
      ) {
        sendJson(
          res,
          200,
          buildWellKnownManifest(baseUrl, engine.payTo, engine.facilitatorUrls),
        );
        return;
      }

      if (method === 'GET' && pathname === '/api/catalog') {
        sendJson(res, 200, buildCatalogPayload(baseUrl, engine));
        return;
      }

      if (method === 'GET' && pathname === '/openapi.json') {
        sendJson(res, 200, buildOpenApiSpec(baseUrl, engine.payTo, engine.solanaPayTo));
        return;
      }

      // 1b. Free Deterministic Sample Routes (`/api/sample?endpoint=<id>` or `/api/v1/<id>/sample`)
      if (method === 'GET' && (pathname === '/api/sample' || /^\/api\/v1\/[a-z0-9-]+\/sample$/.test(pathname))) {
        const sampleId =
          pathname === '/api/sample'
            ? (parsedUrl.searchParams.get('endpoint') || 'validate-address').trim()
            : pathname.split('/')[3];
        const targetEp = PAID_ENDPOINTS.find((e) => e.id === sampleId);
        if (!targetEp) {
          sendJson(res, 404, {
            status: 'not_found',
            error: `Unknown sample endpoint "${sampleId}".`,
            availableSamples: PAID_ENDPOINTS.map((e) => `${baseUrl}${e.restPath}/sample`),
          });
          return;
        }
        const sampleOutput = await targetEp.execute(targetEp.sampleRequest, {
          fetchFn: engine.fetchFn,
        });
        sendJson(res, 200, {
          status: 'ok',
          sampleOnly: true,
          note: 'Fixed synthetic sample execution (custom inputs require x402 payment on the live endpoint).',
          endpoint: `${baseUrl}${targetEp.restPath}`,
          priceUsdc: targetEp.priceUsd,
          payTo: engine.payTo,
          sampleInput: targetEp.sampleRequest,
          sampleOutput,
        });
        return;
      }

      // 2. Paid REST Routes (`/api/v1/*`) 鈥?supports POST JSON body and GET query parameters
      const paidEndpoint = ENDPOINTS_BY_PATH.get(pathname);
      if (paidEndpoint) {
        const resourceUrl =
          method === 'GET' && parsedUrl.search
            ? `${baseUrl}${paidEndpoint.restPath}${parsedUrl.search}`
            : `${baseUrl}${paidEndpoint.restPath}`;
        const hasPayment = Boolean(extractPaymentCredential(req.headers));

        if (method === 'HEAD') {
          if (!hasPayment) {
            const unauth = await engine.processPaidCall({
              endpoint: paidEndpoint,
              args: {},
              reqHeaders: {},
              resourceUrl: `${baseUrl}${paidEndpoint.restPath}`,
            });
            setCommonHeaders(res);
            res.statusCode = unauth.challenge.statusCode;
            for (const [k, v] of Object.entries(unauth.challenge.headers)) {
              res.setHeader(k, v);
            }
            res.end();
            return;
          }
          res.setHeader('Allow', 'GET, POST, HEAD, OPTIONS');
          sendJson(res, 405, {
            error: 'Method Not Allowed for paid execution. Use GET with query params or POST with JSON body.',
          });
          return;
        }

        if (method !== 'POST' && method !== 'GET') {
          res.setHeader('Allow', 'GET, POST, HEAD, OPTIONS');
          sendJson(res, 405, {
            error: 'Method Not Allowed. Use GET with query params or POST with JSON body.',
            settled: false,
          });
          return;
        }

        let parsedBody = {};
        if (method === 'GET') {
          const props = paidEndpoint.inputSchema?.properties || {};
          for (const [k, rawVal] of parsedUrl.searchParams.entries()) {
            const propType = props[k]?.type;
            if (propType === 'number' || propType === 'integer') {
              const num = Number(rawVal);
              parsedBody[k] = Number.isNaN(num) ? rawVal : num;
            } else if (propType === 'boolean') {
              parsedBody[k] = rawVal === 'true' || rawVal === '1';
            } else if ((propType === 'array' || propType === 'object' || k === 'typedData') && (rawVal.trim().startsWith('{') || rawVal.trim().startsWith('['))) {
              try {
                parsedBody[k] = JSON.parse(rawVal);
              } catch {
                parsedBody[k] = rawVal;
              }
            } else {
              parsedBody[k] = rawVal;
            }
          }
          // Bare unpaid GET probe (`GET /api/v1/validate-address` with no query params) -> return 402 quote immediately
          if (!hasPayment && Object.keys(parsedBody).length === 0) {
            const unauth = await engine.processPaidCall({
              endpoint: paidEndpoint,
              args: {},
              reqHeaders: {},
              resourceUrl: `${baseUrl}${paidEndpoint.restPath}`,
            });
            sendJson(
              res,
              unauth.challenge.statusCode,
              unauth.challenge.body,
              unauth.challenge.headers,
            );
            return;
          }
        } else {
          const rawBody = await readRawBody(req);
          if (rawBody.trim() !== '') {
            try {
              parsedBody = JSON.parse(rawBody);
            } catch {
              if (!hasPayment) {
                parsedBody = {};
              } else {
                sendJson(res, 400, {
                  status: 'error',
                  error: 'Request body is not valid JSON. Payment was NOT settled.',
                  settled: false,
                });
                return;
              }
            }
          }
        }

        try {
          const outcome = await engine.processPaidCall({
            endpoint: paidEndpoint,
            args: parsedBody,
            reqHeaders: req.headers,
            resourceUrl,
          });

          if (!outcome.paid) {
            sendJson(
              res,
              outcome.challenge.statusCode,
              outcome.challenge.body,
              outcome.challenge.headers,
            );
            return;
          }

          sendJson(
            res,
            200,
            {
              ...outcome.resultPayload,
              payment: outcome.receipt,
            },
            outcome.responseHeaders,
          );
          return;
        } catch (err) {
          if (err instanceof InputValidationError || err?.statusCode === 400) {
            sendJson(res, 400, {
              status: 'error',
              error: err.message,
              settled: false,
            });
            return;
          }
          throw err;
        }
      }

      // 3. MCP Streamable HTTP Endpoint (`/mcp`)
      if (pathname === '/mcp') {
        if (method === 'DELETE') {
          sendJson(res, 200, { status: 'session_terminated' });
          return;
        }
        if (method === 'GET') {
          sendJson(res, 200, {
            status: 'ok',
            transport: 'streamable-http',
            mcpEndpoint: `${baseUrl}/mcp`,
            x402PayTo: engine.payTo,
            asset: BASE_USDC_ASSET,
            chainId: BASE_CHAIN_ID,
            toolsCount: PAID_ENDPOINTS.length,
            note: 'Send JSON-RPC 2.0 POST requests to /mcp. initialize & tools/list are free; tools/call uses x402 Base Mainnet USDC.',
          });
          return;
        }
        if (method !== 'POST') {
          sendJson(res, 405, { error: 'Method Not Allowed' });
          return;
        }

        const rawBody = await readRawBody(req);
        let rpc;
        try {
          rpc = JSON.parse(rawBody);
        } catch {
          sendJson(res, 400, {
            jsonrpc: '2.0',
            id: null,
            error: { code: -32700, message: 'Parse error: invalid JSON' },
          });
          return;
        }

        const sessionId = req.headers['mcp-session-id'] || randomUUID();
        const mcpHeaders = { 'Mcp-Session-Id': String(sessionId) };

        if (!rpc || typeof rpc !== 'object' || rpc.jsonrpc !== '2.0' || typeof rpc.method !== 'string') {
          sendJson(
            res,
            400,
            {
              jsonrpc: '2.0',
              id: rpc?.id ?? null,
              error: { code: -32600, message: 'Invalid JSON-RPC 2.0 request' },
            },
            mcpHeaders,
          );
          return;
        }

        // Notifications (`id === undefined`)
        if (rpc.id === undefined) {
          setCommonHeaders(res);
          res.statusCode = 202;
          res.setHeader('Mcp-Session-Id', String(sessionId));
          res.end();
          return;
        }

        if (rpc.method === 'initialize') {
          const clientVer = rpc.params?.protocolVersion;
          const negotiated = SUPPORTED_MCP_VERSIONS.includes(clientVer)
            ? clientVer
            : SUPPORTED_MCP_VERSIONS[0];
          sendJson(
            res,
            200,
            {
              jsonrpc: '2.0',
              id: rpc.id,
              result: {
                protocolVersion: negotiated,
                capabilities: {
                  tools: { listChanged: false },
                  resources: { subscribe: false, listChanged: false },
                  prompts: { listChanged: false },
                },
                serverInfo: {
                  name: 'x402-web3-fin-gateway',
                  version: '1.0.0',
                },
                instructions: `Direct 0%-fee x402 Base Mainnet USDC MCP Gateway. Discovery (initialize, tools/list) is free. Calling tools/call requires an x402 Base Mainnet USDC payment header (X-PAYMENT or PAYMENT-SIGNATURE) or X-TX-HASH settled to ${engine.payTo}.`,
              },
            },
            mcpHeaders,
          );
          return;
        }

        if (rpc.method === 'ping') {
          sendJson(res, 200, { jsonrpc: '2.0', id: rpc.id, result: {} }, mcpHeaders);
          return;
        }

        if (rpc.method === 'tools/list') {
          sendJson(
            res,
            200,
            {
              jsonrpc: '2.0',
              id: rpc.id,
              result: {
                tools: PAID_ENDPOINTS.map((e) => ({
                  name: e.mcpName,
                  title: `${e.title} ($${e.priceUsd} Base USDC)`,
                  description: `${e.description} [x402 Base Mainnet USDC: $${e.priceUsd} (${e.amountAtomic} atomic) -> ${engine.payTo}]`,
                  inputSchema: e.inputSchema,
                  annotations: {
                    title: `${e.title} ($${e.priceUsd} USDC)`,
                    readOnlyHint: true,
                    destructiveHint: false,
                    idempotentHint: true,
                    openWorldHint: false,
                  },
                })),
              },
            },
            mcpHeaders,
          );
          return;
        }

        if (rpc.method === 'resources/list') {
          sendJson(
            res,
            200,
            {
              jsonrpc: '2.0',
              id: rpc.id,
              result: {
                resources: [
                  {
                    uri: 'x402://gateway/catalog',
                    name: 'x402 Tool Catalog & Pricing',
                    mimeType: 'application/json',
                    description: 'Full catalog of x402 Base Mainnet USDC endpoints and settlement details.',
                  },
                ],
              },
            },
            mcpHeaders,
          );
          return;
        }

        if (rpc.method === 'resources/read') {
          sendJson(
            res,
            200,
            {
              jsonrpc: '2.0',
              id: rpc.id,
              result: {
                contents: [
                  {
                    uri: rpc.params?.uri || 'x402://gateway/catalog',
                    mimeType: 'application/json',
                    text: JSON.stringify(buildCatalogPayload(baseUrl, engine), null, 2),
                  },
                ],
              },
            },
            mcpHeaders,
          );
          return;
        }

        if (rpc.method === 'resources/templates/list') {
          sendJson(res, 200, { jsonrpc: '2.0', id: rpc.id, result: { resourceTemplates: [] } }, mcpHeaders);
          return;
        }

        if (rpc.method === 'prompts/list') {
          sendJson(res, 200, { jsonrpc: '2.0', id: rpc.id, result: { prompts: [] } }, mcpHeaders);
          return;
        }

        if (rpc.method === 'tools/call') {
          const toolName = rpc.params?.name;
          const toolArgs = rpc.params?.arguments || {};
          const mcpMeta = rpc.params?._meta || null;
          const endpoint = ENDPOINTS_BY_MCP_NAME.get(toolName);

          if (!endpoint) {
            sendJson(
              res,
              200,
              {
                jsonrpc: '2.0',
                id: rpc.id,
                error: { code: -32602, message: `Unknown MCP tool: "${toolName || ''}"` },
              },
              mcpHeaders,
            );
            return;
          }

          try {
            const outcome = await engine.processPaidCall({
              endpoint,
              args: toolArgs,
              reqHeaders: req.headers,
              mcpMeta,
              resourceUrl: `${baseUrl}/mcp`,
            });

            if (!outcome.paid) {
              sendJson(
                res,
                outcome.challenge.statusCode,
                outcome.challenge.body,
                {
                  ...mcpHeaders,
                  ...outcome.challenge.headers,
                },
              );
              return;
            }

            sendJson(
              res,
              200,
              {
                jsonrpc: '2.0',
                id: rpc.id,
                result: {
                  content: [
                    {
                      type: 'text',
                      text: JSON.stringify(outcome.resultPayload, null, 2),
                    },
                  ],
                  structuredContent: outcome.resultPayload,
                  _meta: {
                    'x402/payment-response': outcome.receipt,
                  },
                  isError: false,
                },
              },
              {
                ...mcpHeaders,
                ...outcome.responseHeaders,
              },
            );
            return;
          } catch (err) {
            if (err instanceof InputValidationError || err?.statusCode === 400) {
              sendJson(
                res,
                400,
                {
                  jsonrpc: '2.0',
                  id: rpc.id,
                  error: {
                    code: -32602,
                    message: `${err.message} (Payment was NOT settled.)`,
                  },
                },
                mcpHeaders,
              );
              return;
            }
            throw err;
          }
        }

        sendJson(
          res,
          200,
          {
            jsonrpc: '2.0',
            id: rpc.id,
            error: { code: -32601, message: `Method not found: ${rpc.method}` },
          },
          mcpHeaders,
        );
        return;
      }

      sendJson(res, 404, {
        status: 'not_found',
        error: `No route for ${method} ${pathname}`,
        catalog: `${baseUrl}/api/catalog`,
        wellKnownX402: `${baseUrl}/.well-known/x402.json`,
      });
    } catch (err) {
      const code = err?.statusCode === 413 ? 413 : 500;
      sendJson(res, code, {
        status: 'error',
        error: code === 413 ? err.message : 'Internal server error (payment was not settled).',
      });
    }
  });

  return { server, engine };
}

// Start HTTP listener when executed directly (`node src/server.mjs`)
const isDirectRun =
  process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isDirectRun) {
  const host = process.env.HOST || '127.0.0.1';
  const port = Number(process.env.PORT || 9102);
  const { server, engine } = createGatewayServer();
  server.listen(port, host, () => {
    console.log(
      JSON.stringify({
        event: 'x402_gateway_listening',
        host,
        port,
        payTo: engine.payTo,
        asset: BASE_USDC_ASSET,
        chainId: BASE_CHAIN_ID,
        facilitators: engine.facilitatorUrls,
      }),
    );
  });
}
